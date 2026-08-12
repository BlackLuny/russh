//! S2a WriterTask: independent outbound wire task.
//!
//! Owns the socket **write half** and drains sealed wire frames from Session.
//! Sealing (`PacketWriter` / outbound cipher) remains on Session in S2a.
//!
//! Ordering: all sealed ciphertext is FIFO on the bulk queue. Kex control
//! (Install/Shutdown) never reorders wire bytes.

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use log::{debug, warn};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

use crate::server::supervisor::AtomicWriteProgress;
use crate::Error;

/// Capacity of the kex-control queue (§4.3: 16, try_push, full → Cancelling).
pub const KEX_QUEUE_CAP: usize = 16;

/// Capacity of the ordered sealed-frame queue.
pub const BULK_QUEUE_CAP: usize = 256;

/// Soft cap on Writer-local `out_q` items before pausing bulk pull (not byte HWM).
const OUT_Q_SOFT_CAP: usize = 64;

/// Result of a non-blocking wire enqueue.
#[derive(Debug)]
pub enum TrySendWireError {
    Full(Bytes),
    Closed,
}

/// Session → Writer ordered sealed frames + bulk control.
#[derive(Debug)]
pub enum WriterCmd {
    WireBytes(Bytes),
    Shutdown(oneshot::Sender<()>),
}

/// Session → Writer kex **control** commands (cap 16, try_send).
#[derive(Debug)]
pub enum KexCmd {
    InstallOutboundEpoch {
        generation: u64,
        ack: oneshot::Sender<Result<(), Error>>,
    },
    Shutdown(oneshot::Sender<()>),
}

/// Writer → Session events.
#[derive(Debug)]
pub enum WriterEvent {
    InstallAckOutbound { generation: u64 },
    KexQueueFull,
    WriteError(std::io::ErrorKind),
}

/// Handle held by Session after Writer spawn.
#[derive(Debug, Clone)]
pub struct WriterHandle {
    bulk_tx: mpsc::Sender<WriterCmd>,
    kex_tx: mpsc::Sender<KexCmd>,
    /// Sealed bytes accepted by Writer but not yet on the socket (bulk + out_q + current).
    pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// Capacity wake: `notify_one` keeps a single permit if Session is not waiting.
    capacity: Arc<Notify>,
}

impl WriterHandle {
    pub fn try_send_wire(&self, bytes: Bytes) -> Result<(), TrySendWireError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.pending_bytes
            .fetch_add(bytes.len(), std::sync::atomic::Ordering::Release);
        match self.bulk_tx.try_send(WriterCmd::WireBytes(bytes)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(WriterCmd::WireBytes(b))) => {
                self.pending_bytes
                    .fetch_sub(b.len(), std::sync::atomic::Ordering::Release);
                Err(TrySendWireError::Full(b))
            }
            Err(mpsc::error::TrySendError::Full(other)) => {
                if let WriterCmd::WireBytes(b) = other {
                    self.pending_bytes
                        .fetch_sub(b.len(), std::sync::atomic::Ordering::Release);
                }
                Err(TrySendWireError::Closed)
            }
            Err(mpsc::error::TrySendError::Closed(WriterCmd::WireBytes(b))) => {
                self.pending_bytes
                    .fetch_sub(b.len(), std::sync::atomic::Ordering::Release);
                Err(TrySendWireError::Closed)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TrySendWireError::Closed),
        }
    }

    /// try_push InstallOutboundEpoch. Full/Closed → fail closed.
    pub fn try_install_outbound_epoch(
        &self,
        generation: u64,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.kex_tx
            .try_send(KexCmd::InstallOutboundEpoch {
                generation,
                ack: ack_tx,
            })
            .map_err(|_| Error::SendError)?;
        Ok(ack_rx)
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn capacity_notify(&self) -> Arc<Notify> {
        self.capacity.clone()
    }

    /// Non-blocking shutdown request (never awaits a full bulk queue).
    pub fn request_shutdown(&self) {
        let (tx, _rx) = oneshot::channel();
        if self.kex_tx.try_send(KexCmd::Shutdown(tx)).is_err() {
            let (tx2, _rx2) = oneshot::channel();
            let _ = self.bulk_tx.try_send(WriterCmd::Shutdown(tx2));
        }
    }
}

/// Production Writer teardown: single absolute grace, abort + await completion.
///
/// - Signals cancel + request_shutdown.
/// - Waits for the join until `grace_at` without nesting a second relative timeout.
/// - On timeout: `abort()` then **await** join so the write half is dropped.
/// - Does not treat JoinError::Panic as a clean success (logs it).
pub async fn stop_writer_task(
    cancel_tx: &watch::Sender<bool>,
    writer: Option<&WriterHandle>,
    join: &mut Option<JoinHandle<()>>,
    grace_at: tokio::time::Instant,
) {
    let _ = cancel_tx.send(true);
    if let Some(w) = writer {
        w.request_shutdown();
    }
    let Some(mut handle) = join.take() else {
        return;
    };
    let abort = handle.abort_handle();
    let mut timed_out = false;
    loop {
        tokio::select! {
            biased;
            res = &mut handle => {
                match res {
                    Ok(()) => {}
                    Err(e) if e.is_cancelled() => {
                        debug!("writer join: cancelled (expected after abort)");
                    }
                    Err(e) if e.is_panic() => {
                        warn!("writer task panicked during stop: {e}");
                    }
                    Err(e) => {
                        warn!("writer join error: {e}");
                    }
                }
                return;
            }
            _ = tokio::time::sleep_until(grace_at), if !timed_out => {
                debug!("writer grace elapsed → abort");
                abort.abort();
                timed_out = true;
                // loop: await the cancelled join so the task (and write half) fully drop
            }
        }
    }
}

/// Spawn the Writer task.
pub fn spawn_writer<W>(
    mut stream_write: W,
    progress: Arc<AtomicWriteProgress>,
    mut cancel: watch::Receiver<bool>,
) -> (
    WriterHandle,
    JoinHandle<()>,
    mpsc::UnboundedReceiver<WriterEvent>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<WriterCmd>(BULK_QUEUE_CAP);
    let (kex_tx, mut kex_rx) = mpsc::channel::<KexCmd>(KEX_QUEUE_CAP);
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<WriterEvent>();
    let pending_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending_bytes_w = pending_bytes.clone();
    let capacity = Arc::new(Notify::new());
    let capacity_w = capacity.clone();

    let handle = WriterHandle {
        bulk_tx,
        kex_tx,
        pending_bytes,
        capacity,
    };

    let join = tokio::spawn(async move {
        let mut out_q: VecDeque<Bytes> = VecDeque::new();
        let mut flush_cursor: usize = 0;
        let mut current: Option<Bytes> = None;
        let mut shutting_down = false;
        let mut shutdown_ack: Option<oneshot::Sender<()>> = None;
        let mut bulk_closed = false;
        // After cancel true OR watch sender dropped, never poll cancel.changed again.
        let mut poll_cancel = true;

        loop {
            progress.store_eligible(
                pending_bytes_w.load(std::sync::atomic::Ordering::Acquire) as u64,
            );

            // Observe cancel value without spinning on changed() when already true.
            if poll_cancel && *cancel.borrow_and_update() {
                shutting_down = true;
                poll_cancel = false;
                debug!("writer: cancel=true observed, graceful drain then exit");
            }

            // Non-blocking kex control poll.
            while let Ok(cmd) = kex_rx.try_recv() {
                match cmd {
                    KexCmd::InstallOutboundEpoch { generation, ack } => {
                        debug!("writer: InstallAck Outbound gen={generation}");
                        let _ = ack.send(Ok(()));
                        let _ = evt_tx.send(WriterEvent::InstallAckOutbound { generation });
                    }
                    KexCmd::Shutdown(ack) => {
                        shutting_down = true;
                        poll_cancel = false;
                        shutdown_ack = Some(ack);
                    }
                }
            }

            // Graceful drain: pull accepted bulk items into out_q while shutting down.
            if shutting_down && !bulk_closed {
                loop {
                    match bulk_rx.try_recv() {
                        Ok(WriterCmd::WireBytes(b)) => out_q.push_back(b),
                        Ok(WriterCmd::Shutdown(ack)) => {
                            if shutdown_ack.is_none() {
                                shutdown_ack = Some(ack);
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            bulk_closed = true;
                            break;
                        }
                    }
                }
            }

            let has_out = current.is_some() || !out_q.is_empty();

            // ── P0-1 empty-queue exit BEFORE select! (never enter select with all arms off) ──
            if shutting_down && !has_out {
                // Final bulk sweep.
                if !bulk_closed {
                    while let Ok(cmd) = bulk_rx.try_recv() {
                        match cmd {
                            WriterCmd::WireBytes(b) => out_q.push_back(b),
                            WriterCmd::Shutdown(ack) => {
                                if shutdown_ack.is_none() {
                                    shutdown_ack = Some(ack);
                                }
                            }
                        }
                    }
                }
                if current.is_none() && out_q.is_empty() {
                    let _ = stream_write.shutdown().await;
                    if let Some(ack) = shutdown_ack.take() {
                        let _ = ack.send(());
                    }
                    break;
                }
                // Sweep found bytes — fall through to drain via select (has_out true).
            }

            let has_out = current.is_some() || !out_q.is_empty();
            let can_pull_bulk =
                !shutting_down && !bulk_closed && out_q.len() < OUT_Q_SOFT_CAP;

            tokio::select! {
                biased;

                // Explicit match: sender drop (Err) must only be consumed once (P0-1 r2).
                changed = cancel.changed(), if poll_cancel => {
                    match changed {
                        Ok(()) => {
                            if *cancel.borrow_and_update() {
                                shutting_down = true;
                                poll_cancel = false;
                                debug!("writer: cancel.changed(Ok true) → graceful drain");
                            }
                        }
                        Err(_sender_dropped) => {
                            // Last sender gone while value may still be false.
                            shutting_down = true;
                            poll_cancel = false;
                            debug!("writer: cancel watch closed → graceful drain");
                        }
                    }
                }

                cmd = kex_rx.recv(), if !shutting_down => {
                    match cmd {
                        Some(KexCmd::InstallOutboundEpoch { generation, ack }) => {
                            debug!("writer: InstallAck Outbound gen={generation}");
                            let _ = ack.send(Ok(()));
                            let _ = evt_tx.send(WriterEvent::InstallAckOutbound { generation });
                        }
                        Some(KexCmd::Shutdown(ack)) => {
                            shutting_down = true;
                            poll_cancel = false;
                            shutdown_ack = Some(ack);
                        }
                        None => {
                            shutting_down = true;
                            poll_cancel = false;
                        }
                    }
                }

                // Continuous drain — do NOT split into single-write arms.
                result = drain_writes(
                    &mut stream_write,
                    &mut current,
                    &mut out_q,
                    &mut flush_cursor,
                    &progress,
                    &pending_bytes_w,
                    &capacity_w,
                ), if has_out => {
                    if let Err(e) = result {
                        warn!("writer: socket write error: {e}");
                        let _ = evt_tx.send(WriterEvent::WriteError(e.kind()));
                        break;
                    }
                }

                cmd = bulk_rx.recv(), if can_pull_bulk => {
                    match cmd {
                        Some(WriterCmd::WireBytes(b)) => out_q.push_back(b),
                        Some(WriterCmd::Shutdown(ack)) => {
                            shutting_down = true;
                            poll_cancel = false;
                            shutdown_ack = Some(ack);
                        }
                        None => {
                            bulk_closed = true;
                            shutting_down = true;
                            poll_cancel = false;
                        }
                    }
                }
            }
        }
        progress.store_eligible(0);
        capacity_w.notify_one();
        debug!("writer: task exit");
    });

    (handle, join, evt_rx)
}

/// Drain pending sealed frames until empty or write awaits.
/// Uses `notify_one` so a permit is retained if Session has not yet registered.
async fn drain_writes<W: AsyncWrite + Unpin>(
    w: &mut W,
    current: &mut Option<Bytes>,
    out_q: &mut VecDeque<Bytes>,
    flush_cursor: &mut usize,
    progress: &AtomicWriteProgress,
    pending_bytes: &std::sync::atomic::AtomicUsize,
    capacity: &Notify,
) -> std::io::Result<()> {
    loop {
        if current.is_none() {
            *current = out_q.pop_front();
            *flush_cursor = 0;
        }
        let Some(buf) = current.as_ref() else {
            capacity.notify_one();
            return Ok(());
        };
        if *flush_cursor >= buf.len() {
            *current = None;
            *flush_cursor = 0;
            continue;
        }
        let n = w.write(&buf[*flush_cursor..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write zero",
            ));
        }
        *flush_cursor += n;
        progress.note_write(n);
        let _ = pending_bytes.fetch_update(
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
            |cur| Some(cur.saturating_sub(n)),
        );
        // Single-consumer permit: merges if already pending; kept if no waiter yet.
        capacity.notify_one();

        if *flush_cursor >= buf.len() {
            *current = None;
            *flush_cursor = 0;
            if out_q.is_empty() {
                w.flush().await?;
                capacity.notify_one();
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    struct HangWrite;

    impl AsyncWrite for HangWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// Production `stop_writer_task` aborts a permanently-pending Writer after absolute grace.
    #[tokio::test(flavor = "current_thread")]
    async fn writer_join_finishes_after_grace_abort() {
        let progress = AtomicWriteProgress::new();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (handle, join, _evt) = spawn_writer(HangWrite, progress, cancel_rx);

        let _ = handle.try_send_wire(Bytes::from(vec![1u8; 64]));
        tokio::task::yield_now().await;

        let mut join = Some(join);
        let grace_at = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        // Must call production helper — not a hand-rolled abort.
        stop_writer_task(&cancel_tx, Some(&handle), &mut join, grace_at).await;
        assert!(join.is_none(), "join handle consumed by stop_writer_task");
    }

    /// Cancel-before-first-poll with empty queues must exit without select! panic.
    #[tokio::test(flavor = "current_thread")]
    async fn writer_empty_queue_shutdown_no_panic() {
        let progress = AtomicWriteProgress::new();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (_handle, join, _evt) = spawn_writer(tokio::io::sink(), progress, cancel_rx);

        // Cancel before the Writer task is polled (empty bulk/out_q/current).
        let _ = cancel_tx.send(true);

        let res = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("writer joined with error (panic?): {e}"),
            Err(_) => panic!("writer did not exit within 2s (likely select! hang/panic)"),
        }
    }

    /// `notify_one` retains a permit when notify happens before waiter registration.
    #[tokio::test(flavor = "current_thread")]
    async fn capacity_notify_before_waiter_is_not_lost() {
        let progress = AtomicWriteProgress::new();
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        // Use a real sink so drain can complete.
        let (handle, join, _evt) = spawn_writer(tokio::io::sink(), progress, cancel_rx);
        let cap = handle.capacity_notify();

        // Enqueue and let Writer drain (notify_one fires with no waiter yet).
        handle
            .try_send_wire(Bytes::from(vec![7u8; 32]))
            .expect("send");
        // Yield until pending drains to 0.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while handle.pending_bytes() > 0 {
            if tokio::time::Instant::now() >= deadline {
                panic!("writer did not drain");
            }
            tokio::task::yield_now().await;
        }

        // Register waiter AFTER notify — permit must still wake us immediately.
        let woke = tokio::time::timeout(std::time::Duration::from_millis(200), cap.notified())
            .await;
        assert!(woke.is_ok(), "notify_one permit must survive pre-waiter drain");

        join.abort();
        let _ = join.await;
    }
}

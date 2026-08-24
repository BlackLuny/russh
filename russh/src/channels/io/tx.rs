use std::collections::VecDeque;
use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use futures::FutureExt;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::oneshot;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

use bytes::Bytes;

use super::ChannelMsg;
use crate::ChannelId;
use crate::channels::{ChannelAcked, OutboundLiveSet};

/// S9 P1: how far one acked writer may run ahead of the authority.
///
/// K = 1 is the original lockstep: every packet costs a full
/// producer → Session → Writer → producer round trip, so the session
/// loop runs one whole iteration (and the Writer one socket write) per
/// packet, and `MAX_MESSAGES_PER_BATCH` never engages. K > 1 lets the
/// batch drain and the Writer's gather actually see a queue.
///
/// The peer window stays the sole authority — credit only bounds how far
/// a producer may run ahead of it, so a stalled channel's un-drained
/// backlog grows by at most `K * max_packet_size` beyond what K = 1
/// allowed. That must stay far below `max_pending_outbound_bytes`
/// (default 16 MB), hence the byte budget rather than a flat count.
const ACKED_CREDIT_BYTES: usize = 256 * 1024;
const ACKED_CREDIT_MAX: usize = 8;

fn acked_credit(max_packet_size: u32) -> usize {
    let mp = (max_packet_size as usize).max(1);
    (ACKED_CREDIT_BYTES / mp).clamp(1, ACKED_CREDIT_MAX)
}

/// `_test_hooks`: invert D2 (park-before-register) and fix1 (bound-2
/// discard of a Ready that may be this write's ack).
///
/// `invert_lockstep_ack` restores the pre-S9 mechanism wholesale: one
/// packet in flight, ack observed through the shared per-channel
/// `Notify` instead of the packet's own oneshot. Both D2 inverts are
/// only reachable through it, since that is the code they perturb.
#[cfg(feature = "_test_hooks")]
pub struct ChannelTxTestHooks {
    pub invert_park_before_register: std::sync::atomic::AtomicBool,
    pub invert_bound2_discard_ready: std::sync::atomic::AtomicBool,
    pub invert_lockstep_ack: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "_test_hooks")]
pub static CHANNEL_TX_HOOKS: ChannelTxTestHooks = ChannelTxTestHooks {
    invert_park_before_register: std::sync::atomic::AtomicBool::new(false),
    invert_bound2_discard_ready: std::sync::atomic::AtomicBool::new(false),
    invert_lockstep_ack: std::sync::atomic::AtomicBool::new(false),
};

type BoxedThreadsafeFuture<T> = Pin<Box<dyn Sync + Send + std::future::Future<Output = T>>>;
type OwnedPermitFuture<S> =
    BoxedThreadsafeFuture<Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>>;

struct WatchNotification(Pin<Box<dyn Sync + Send + Future<Output = ()>>>);

/// A single future that becomes ready once the window size
/// changes to a positive value
impl WatchNotification {
    fn new(n: Arc<Notify>) -> Self {
        Self(Box::pin(async move { n.notified().await }))
    }
}

impl Future for WatchNotification {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.deref_mut().0.as_mut();
        ready!(inner.poll(cx));
        Poll::Ready(())
    }
}

pub struct ChannelTx<S> {
    sender: mpsc::Sender<S>,
    send_fut: Option<OwnedPermitFuture<S>>,
    acked_send_fut: Option<BoxedThreadsafeFuture<Result<usize, ()>>>,
    id: ChannelId,
    window_size_fut: Option<BoxedThreadsafeFuture<OwnedMutexGuard<u32>>>,
    window_size: Arc<Mutex<u32>>,
    notify: Arc<Notify>,
    window_size_notication: WatchNotification,
    max_packet_size: u32,
    ext: Option<u32>,
    use_acked: bool,
    live: Option<Arc<OutboundLiveSet>>,
    /// Lockstep-only park flag (`_test_hooks` invert path).
    #[cfg(feature = "_test_hooks")]
    acked_waiting: bool,
    acked_n: usize,
    /// S9 P1 credit window: acks not yet resolved, oldest at the front.
    /// Each entry is the packet's own oneshot, so a wake cannot be stolen
    /// by a sibling writer the way a shared `Notify` permit can.
    inflight: VecDeque<oneshot::Receiver<()>>,
    /// Ack receiver belonging to the send still sitting in `acked_send_fut`.
    pending_ack: Option<oneshot::Receiver<()>>,
    /// Max entries in `inflight` before this writer parks.
    credit: usize,
    /// Sticky: an ack resolved `Err` (sender dropped = payload discarded).
    acked_dead: bool,
}

impl<S> ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + ChannelAcked + 'static + Send + Sync,
{
    pub fn new(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window_size: Arc<Mutex<u32>>,
        window_size_notification: Arc<Notify>,
        max_packet_size: u32,
        ext: Option<u32>,
        use_acked: bool,
        live: Option<Arc<OutboundLiveSet>>,
    ) -> Self {
        Self {
            sender,
            send_fut: None,
            acked_send_fut: None,
            id,
            notify: Arc::clone(&window_size_notification),
            window_size_notication: WatchNotification::new(window_size_notification),
            window_size,
            window_size_fut: None,
            max_packet_size,
            ext,
            use_acked,
            live,
            #[cfg(feature = "_test_hooks")]
            acked_waiting: false,
            acked_n: 0,
            inflight: VecDeque::new(),
            pending_ack: None,
            credit: acked_credit(max_packet_size),
            acked_dead: false,
        }
    }

    fn known_dead(&self) -> bool {
        self.live.as_ref().is_some_and(|l| !l.contains(self.id))
    }

    fn start_acked_send(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        if self.known_dead() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"));
        }
        if self.max_packet_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero max packet size",
            ));
        }
        let writable = (self.max_packet_size as usize).min(buf.len());
        let data = Bytes::copy_from_slice(buf.get(..writable).unwrap_or(&[]));
        let (ack_tx, ack_rx) = oneshot::channel();
        let Some(msg) = S::try_data_acked(self.id, self.ext, data, ack_tx) else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "acked DATA not supported",
            ));
        };
        use futures::TryFutureExt;
        self.acked_n = writable;
        // Held until the send future completes; only then does this packet
        // count against credit (a send that never lands has no ack coming).
        self.pending_ack = Some(ack_rx);
        self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
        self.acked_send_fut = Some(Box::pin(
            self.sender
                .clone()
                .reserve_owned()
                .map_ok(move |p| {
                    p.send(msg);
                    writable
                })
                .map_err(|_| ()),
        ));
        Ok(())
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>, buf_len: usize) -> Poll<NonZeroUsize> {
        let window_size = self.window_size.clone();
        let window_size_fut = self
            .window_size_fut
            .get_or_insert_with(|| Box::pin(window_size.lock_owned()));
        let mut window_size = ready!(window_size_fut.poll_unpin(cx));
        self.window_size_fut.take();

        let writable = (self.max_packet_size).min(*window_size).min(buf_len as u32) as usize;

        match NonZeroUsize::try_from(writable) {
            Ok(w) => {
                *window_size -= writable as u32;
                if *window_size > 0 {
                    self.notify.notify_one();
                }
                Poll::Ready(w)
            }
            Err(_) => {
                drop(window_size);
                ready!(self.window_size_notication.poll_unpin(cx));
                self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_mk_msg(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<(ChannelMsg, NonZeroUsize)> {
        let writable = ready!(self.poll_writable(cx, buf.len()));

        #[allow(clippy::indexing_slicing)] // Clamped to maximum `buf.len()` with `.poll_writable`
        let data = Bytes::copy_from_slice(&buf[..writable.into()]);

        let msg = match self.ext {
            None => ChannelMsg::Data { data },
            Some(ext) => ChannelMsg::ExtendedData { data, ext },
        };

        Poll::Ready((msg, writable))
    }

    fn activate(&mut self, msg: ChannelMsg, writable: usize) -> &mut OwnedPermitFuture<S> {
        use futures::TryFutureExt;
        self.send_fut.insert(Box::pin(
            self.sender
                .clone()
                .reserve_owned()
                .map_ok(move |p| (p, msg, writable)),
        ))
    }

    fn handle_write_result(
        &mut self,
        r: Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>,
    ) -> Result<usize, io::Error> {
        self.send_fut = None;
        match r {
            Ok((permit, msg, writable)) => {
                permit.send((self.id, msg).into());
                Ok(writable)
            }
            Err(SendError(())) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
        }
    }

    /// Register `window_size_notication` as a `Notify` waiter.
    ///
    /// One poll. On the acked path every Ready is a live signal (this
    /// write's ack, or a stale permit — both complete early, same as
    /// the `acked_waiting` branch). There is no discardable Ready:
    /// eating one and parking on a fresh `notified()` hangs a single
    /// writer that will not see a second `notify_one`.
    #[cfg(feature = "_test_hooks")]
    fn register_window_notify(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if CHANNEL_TX_HOOKS
            .invert_bound2_discard_ready
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return self.register_window_notify_bound2(cx);
        }
        match self.window_size_notication.poll_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
                Poll::Ready(())
            }
        }
    }

    /// S8b bound-2: treat the first Ready as stale, rebuild, park.
    /// Invert-only — that Ready may be this write's ack.
    #[cfg(feature = "_test_hooks")]
    fn register_window_notify_bound2(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        const REGISTER_BOUND: usize = 2;
        for attempt in 0..REGISTER_BOUND {
            match self.window_size_notication.poll_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
                    if attempt + 1 == REGISTER_BOUND {
                        return Poll::Ready(());
                    }
                }
            }
        }
        Poll::Pending
    }

    /// S9 P1 production acked write: up to `credit` packets in flight.
    ///
    /// Wake source is the packet's own `oneshot`, not the shared
    /// per-channel `Notify`. Every ack is either resolved `Ok` (peer
    /// window absorbed the payload) or dropped (`finalize_close`,
    /// `discard_channel_outbound`, channel already gone) — both wake this
    /// receiver, so the D2 lost-wake class the `Notify` protocol had to
    /// defend against cannot occur here: there is no shared permit to
    /// steal and nothing to re-register.
    fn poll_write_acked_credit(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.known_dead() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        }
        // Reap every resolved ack, not just a front prefix: acks can
        // resolve out of order (a later packet fully absorbed by the peer
        // window is Ok'd inline while an earlier one is still parked in
        // `outbound_acks`).
        self.reap_acks();
        if self.acked_dead {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        }
        if self.inflight.len() >= self.credit {
            // At the cap: park on the oldest outstanding ack. Exactly-once
            // release guarantees it resolves or is dropped, so this cannot
            // hang; polling only the front keeps the bound tight.
            let Some(front) = self.inflight.front_mut() else {
                unreachable!("credit >= 1 and inflight is at cap")
            };
            match Pin::new(front).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    self.inflight.pop_front();
                }
                Poll::Ready(Err(_dropped)) => {
                    self.inflight.pop_front();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "channel closed",
                    )));
                }
            }
        }
        if self.acked_send_fut.is_none() {
            if let Err(e) = self.start_acked_send(buf) {
                return Poll::Ready(Err(e));
            }
        }
        let Some(fut) = self.acked_send_fut.as_mut() else {
            // `start_acked_send` above either installed it or returned Err.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "acked send future missing",
            )));
        };
        let r = ready!(fut.as_mut().poll_unpin(cx));
        self.acked_send_fut = None;
        match r {
            Ok(_) => {
                if let Some(rx) = self.pending_ack.take() {
                    self.inflight.push_back(rx);
                }
                Poll::Ready(Ok(self.acked_n))
            }
            Err(()) => {
                self.pending_ack = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "channel closed",
                )))
            }
        }
    }

    /// Non-blocking sweep of `inflight`; a dropped sender latches
    /// `acked_dead` (that payload was discarded, never delivered).
    fn reap_acks(&mut self) {
        self.inflight.retain_mut(|rx| match rx.try_recv() {
            Ok(()) => false,
            Err(oneshot::error::TryRecvError::Closed) => {
                self.acked_dead = true;
                false
            }
            Err(oneshot::error::TryRecvError::Empty) => true,
        });
    }

    /// Pre-S9 lockstep acked write: one packet in flight, ack observed
    /// through the shared per-channel `Notify`. `_test_hooks` only — it is
    /// the tree the D2 / S8b / S8c object gates perturb.
    #[cfg(feature = "_test_hooks")]
    #[allow(clippy::too_many_lines)]
    fn poll_write_acked_lockstep(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.acked_waiting {
            // Stale `notify_one` permits (absorb/release with no
            // waiter) may complete this poll early. That is tolerated:
            // the next write re-enters acked_waiting and parks again
            // if the backlog is still pending. Do not "fix" by
            // clearing permits — extra wakes coalesce.
            ready!(self.window_size_notication.poll_unpin(cx));
            self.acked_waiting = false;
            self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify));
            if self.known_dead() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "channel closed",
                )));
            }
            return Poll::Ready(Ok(self.acked_n));
        }
        if self.acked_send_fut.is_none() {
            if let Err(e) = self.start_acked_send(buf) {
                return Poll::Ready(Err(e));
            }
            // Notification is created here (natural object) but
            // not registered yet. Registering before the send
            // future is polled would enqueue this writer as a
            // waiter and steal `notify_one` from an already
            // parked sibling on the same Notify.
        }
        let fut = self.acked_send_fut.as_mut().expect("acked send");
        let r = ready!(fut.as_mut().poll_unpin(cx));
        self.acked_send_fut = None;
        // Lockstep never uses the packet's own oneshot; dropping it here
        // keeps the sender alive exactly as long as the message.
        self.pending_ack = None;
        match r {
            Ok(_) => {
                if CHANNEL_TX_HOOKS
                    .invert_park_before_register
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    // Old order: park, register on the *next* poll.
                    self.acked_waiting = true;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                match self.register_window_notify(cx) {
                    Poll::Ready(()) => {
                        // Already signalled (stale permit or a
                        // notify during register). Early Ok is
                        // tolerated: the next write re-enters
                        // acked_waiting if backlog is still pending.
                        // Same post-check list as the
                        // `acked_waiting` Ready arm: known_dead
                        // first (discard is remove-then-wake).
                        self.acked_waiting = false;
                        if self.known_dead() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "channel closed",
                            )));
                        }
                        Poll::Ready(Ok(self.acked_n))
                    }
                    Poll::Pending => {
                        // Registered. No wake_by_ref: Notify holds
                        // `cx.waker()`. The old self-wake existed
                        // only to force a second poll that
                        // registered — that second poll *was* the
                        // lost-wake window.
                        self.acked_waiting = true;
                        Poll::Pending
                    }
                }
            }
            Err(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),
        }
    }
}

impl<S> AsyncWrite for ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + ChannelAcked + 'static + Send + Sync,
{
    #[allow(clippy::too_many_lines)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "cannot send empty buffer",
            )));
        }
        if self.use_acked {
            #[cfg(feature = "_test_hooks")]
            if CHANNEL_TX_HOOKS
                .invert_lockstep_ack
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return self.poll_write_acked_lockstep(cx, buf);
            }
            return self.poll_write_acked_credit(cx, buf);
        }
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            let (msg, writable) = ready!(self.poll_mk_msg(cx, buf));
            self.activate(msg, writable.into())
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx));
        Poll::Ready(self.handle_write_result(r))
    }

    /// Flush = "the authority has taken every byte written so far".
    ///
    /// Under lockstep that was true on return from the last `poll_write`;
    /// with a credit window up to `credit` packets may still be
    /// outstanding, so drain them here. A dropped ack is not reported: the
    /// pre-S9 flush was infallible, and a discard is surfaced by the next
    /// `poll_write` exactly as before.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        while let Some(front) = self.inflight.front_mut() {
            match Pin::new(front).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    self.inflight.pop_front();
                }
                Poll::Ready(Err(_dropped)) => {
                    self.inflight.pop_front();
                    self.acked_dead = true;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            self.activate(ChannelMsg::Eof, 0)
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx)).map(|(p, _, _)| (p, ChannelMsg::Eof, 0));
        Poll::Ready(self.handle_write_result(r).map(drop))
    }
}

impl<S> Drop for ChannelTx<S> {
    fn drop(&mut self) {
        // Allow other writers to make progress
        self.notify.notify_one();
    }
}

/// Object-level D2 gate (manual poll, no tokio scheduling).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S8bObjectClass {
    BothReady,
    LostWake {
        lost: usize,
        ready: usize,
    },
    AckReady,
    AckBeforeRegisterParked,
    SendNotAccepted,
    /// Early Ok after discard removed the id from `OutboundLiveSet`.
    /// Pre-D2-P2 production path (the "invert" is the unfixed tree).
    DeadReportedOk,
    /// Early-Ok arm returned BrokenPipe because `known_dead()`.
    DeadBrokenPipe,
    Unexpected,
}

#[cfg(feature = "_test_hooks")]
static INVERT_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "_test_hooks")]
pub struct InvertParkGuard;

#[cfg(feature = "_test_hooks")]
impl Drop for InvertParkGuard {
    fn drop(&mut self) {
        CHANNEL_TX_HOOKS
            .invert_park_before_register
            .store(false, std::sync::atomic::Ordering::SeqCst);
        CHANNEL_TX_HOOKS
            .invert_bound2_discard_ready
            .store(false, std::sync::atomic::Ordering::SeqCst);
        CHANNEL_TX_HOOKS
            .invert_lockstep_ack
            .store(false, std::sync::atomic::Ordering::SeqCst);
        INVERT_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "_test_hooks")]
fn acquire_hooks(park: bool, bound2: bool, lockstep: bool) -> InvertParkGuard {
    while INVERT_BUSY
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    CHANNEL_TX_HOOKS
        .invert_park_before_register
        .store(park, std::sync::atomic::Ordering::SeqCst);
    CHANNEL_TX_HOOKS
        .invert_bound2_discard_ready
        .store(bound2, std::sync::atomic::Ordering::SeqCst);
    CHANNEL_TX_HOOKS
        .invert_lockstep_ack
        .store(lockstep, std::sync::atomic::Ordering::SeqCst);
    InvertParkGuard
}

/// E2E carrier: `invert = true` restores the whole pre-S9 tree
/// (lockstep + park-before-register). `invert = false` leaves production
/// on the S9 credit path.
#[cfg(feature = "_test_hooks")]
pub fn acquire_invert_park_before_register(invert: bool) -> InvertParkGuard {
    acquire_hooks(invert, false, invert)
}

/// Object rounds: pin the lockstep protocol on, with the named invert.
/// Production for these rounds means "lockstep as shipped pre-S9, D2
/// fixed" — the credit path has its own gates (`s9_object_credit_*`).
#[cfg(feature = "_test_hooks")]
pub fn acquire_lockstep_round(park: bool, bound2: bool) -> InvertParkGuard {
    acquire_hooks(park, bound2, true)
}

#[cfg(feature = "_test_hooks")]
pub fn acquire_invert_bound2_discard_ready() -> InvertParkGuard {
    acquire_hooks(false, true, true)
}

#[cfg(feature = "_test_hooks")]
struct ProbeMsg(Option<oneshot::Sender<()>>);

#[cfg(feature = "_test_hooks")]
impl From<(ChannelId, ChannelMsg)> for ProbeMsg {
    fn from(_: (ChannelId, ChannelMsg)) -> Self {
        Self(None)
    }
}

#[cfg(feature = "_test_hooks")]
impl ChannelAcked for ProbeMsg {
    fn try_data_acked(
        _id: ChannelId,
        _ext: Option<u32>,
        _data: Bytes,
        ack: oneshot::Sender<()>,
    ) -> Option<Self> {
        Some(Self(Some(ack)))
    }
}

/// Outcome classes for the S9 credit-window gates.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9CreditClass {
    /// Parked after exactly `credit` un-acked packets.
    ParkedAtCredit { credit: usize },
    /// Parked before the window was full (throughput bug, not a safety one).
    ParkedEarly { at: usize },
    /// Never parked: the producer can outrun the authority without bound.
    Unbounded { accepted: usize },
    /// A resolved ack released the parked writer.
    Resumed,
    /// A dropped ack surfaced `BrokenPipe`.
    DeadBrokenPipe,
    /// A dropped ack was reported as a successful write.
    DroppedAckReportedOk,
    /// The wake never arrived.
    StillParked,
    Unexpected,
}

/// S9 P1 credit gate: with the mpsc wide open and no ack ever resolved,
/// a credit-`K` writer must accept exactly `K` packets and then park.
///
/// `invert = true` raises the cap so nothing ever parks — the unbounded
/// producer the peer window cannot throttle (must-red).
#[cfg(feature = "_test_hooks")]
pub fn s9_object_credit_round(invert: bool) -> S9CreditClass {
    let _guard = acquire_hooks(false, false, false);
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1024);
    let notify = Arc::new(Notify::new());
    let window = Arc::new(Mutex::new(0u32));
    let mut w = ChannelTx::new(
        tx,
        ChannelId(1),
        window,
        notify,
        32,
        None,
        true,
        None,
    );
    if invert {
        w.credit = usize::MAX;
    }
    let credit = w.credit;
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let buf = [0u8; 8];

    // Bounded probe: a correct writer parks at `credit`; the invert never
    // does, so cap the loop instead of hanging.
    let probe = credit.saturating_add(4).min(64);
    let mut accepted = 0usize;
    let mut parked_at = None;
    for _ in 0..probe {
        match Pin::new(&mut w).poll_write(&mut cx, &buf) {
            Poll::Ready(Ok(_)) => accepted += 1,
            Poll::Pending => {
                parked_at = Some(accepted);
                break;
            }
            Poll::Ready(Err(_)) => return S9CreditClass::Unexpected,
        }
    }
    let mut queued = 0usize;
    while rx.try_recv().is_ok() {
        queued += 1;
    }
    if queued != accepted {
        return S9CreditClass::Unexpected;
    }
    match parked_at {
        None => {
            eprintln!("s9 credit Unbounded accepted={accepted} credit={credit} invert={invert}");
            S9CreditClass::Unbounded { accepted }
        }
        Some(n) if n == credit => S9CreditClass::ParkedAtCredit { credit },
        Some(n) => {
            eprintln!("s9 credit ParkedEarly at={n} credit={credit}");
            S9CreditClass::ParkedEarly { at: n }
        }
    }
}

/// S9 P1 liveness/teardown gate: fill the credit window, then either
/// resolve the oldest ack (`drop_ack = false`) — the parked writer must
/// resume — or drop its sender (`drop_ack = true`, i.e. discard /
/// finalize_close) — the writer must surface `BrokenPipe`, never a fake
/// Ok for bytes that were thrown away.
#[cfg(feature = "_test_hooks")]
pub fn s9_object_credit_release_round(drop_ack: bool) -> S9CreditClass {
    let _guard = acquire_hooks(false, false, false);
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1024);
    let notify = Arc::new(Notify::new());
    let window = Arc::new(Mutex::new(0u32));
    let mut w = ChannelTx::new(
        tx,
        ChannelId(1),
        window,
        notify,
        32,
        None,
        true,
        None,
    );
    let credit = w.credit;
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let buf = [0u8; 8];

    let mut acks = Vec::new();
    for _ in 0..credit {
        match Pin::new(&mut w).poll_write(&mut cx, &buf) {
            Poll::Ready(Ok(_)) => {}
            _ => return S9CreditClass::Unexpected,
        }
        match rx.try_recv() {
            Ok(ProbeMsg(Some(ack))) => acks.push(ack),
            _ => return S9CreditClass::Unexpected,
        }
    }
    if !Pin::new(&mut w).poll_write(&mut cx, &buf).is_pending() {
        return S9CreditClass::Unexpected;
    }
    // Oldest first: that is the one the parked write is waiting on.
    let oldest = acks.remove(0);
    if drop_ack {
        drop(oldest);
    } else {
        let _ = oldest.send(());
    }
    match Pin::new(&mut w).poll_write(&mut cx, &buf) {
        Poll::Ready(Ok(_)) if !drop_ack => S9CreditClass::Resumed,
        Poll::Ready(Err(e)) if drop_ack && e.kind() == io::ErrorKind::BrokenPipe => {
            S9CreditClass::DeadBrokenPipe
        }
        Poll::Ready(Ok(_)) => {
            eprintln!("s9 credit DroppedAckReportedOk");
            S9CreditClass::DroppedAckReportedOk
        }
        Poll::Pending => {
            eprintln!("s9 credit StillParked drop_ack={drop_ack}");
            S9CreditClass::StillParked
        }
        Poll::Ready(Err(_)) => S9CreditClass::Unexpected,
    }
}

/// Two acked writers, same Notify. Poll to "send accepted, Pending",
/// then `notify_one` ×2 with no intervening poll, then poll both.
/// Production: both Ready(Ok). Invert: exactly one Ready, one Pending.
#[cfg(feature = "_test_hooks")]
pub fn s8b_object_register_round(invert: bool) -> S8bObjectClass {
    let _guard = acquire_lockstep_round(invert, false);
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(4);
    let notify = Arc::new(Notify::new());
    let window = Arc::new(Mutex::new(0u32));
    let id = ChannelId(1);
    let mut w0 = ChannelTx::new(
        tx.clone(),
        id,
        Arc::clone(&window),
        Arc::clone(&notify),
        32,
        None,
        true,
        None,
    );
    let mut w1 = ChannelTx::new(tx, id, window, Arc::clone(&notify), 32, Some(1), true, None);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let buf = [0u8; 8];

    let p0 = Pin::new(&mut w0).poll_write(&mut cx, &buf);
    let p1 = Pin::new(&mut w1).poll_write(&mut cx, &buf);

    let mut accepted = 0usize;
    while rx.try_recv().is_ok() {
        accepted += 1;
    }
    if accepted < 2 {
        return S8bObjectClass::SendNotAccepted;
    }
    if !p0.is_pending() || !p1.is_pending() {
        return S8bObjectClass::Unexpected;
    }

    // No further poll — this is the unregistered window invert restores.
    notify.notify_one();
    notify.notify_one();

    let r0 = Pin::new(&mut w0).poll_write(&mut cx, &buf);
    let r1 = Pin::new(&mut w1).poll_write(&mut cx, &buf);
    let ready0 = matches!(r0, Poll::Ready(Ok(_)));
    let ready1 = matches!(r1, Poll::Ready(Ok(_)));
    let pend0 = r0.is_pending();
    let pend1 = r1.is_pending();
    match (ready0, ready1, pend0, pend1) {
        (true, true, _, _) => S8bObjectClass::BothReady,
        (true, false, _, true) => {
            eprintln!("s8b LostWake lost=writer1 ready=writer0 invert={invert}");
            S8bObjectClass::LostWake { lost: 1, ready: 0 }
        }
        (false, true, true, _) => {
            eprintln!("s8b LostWake lost=writer0 ready=writer1 invert={invert}");
            S8bObjectClass::LostWake { lost: 0, ready: 1 }
        }
        _ => S8bObjectClass::Unexpected,
    }
}

/// Single acked writer: first poll parks on a full mpsc (send Pending).
/// Drain the filler (session can accept) and `notify_one` (ack) *before*
/// the next poll. That next poll completes send and then registers —
/// the permit is already stored. Production must `Ready(Ok)`. Bound-2
/// discard of that Ready parks forever → `AckBeforeRegisterParked`.
#[cfg(feature = "_test_hooks")]
pub fn s8b_object_ack_before_register_round(bound2: bool) -> S8bObjectClass {
    let _guard = if bound2 {
        acquire_invert_bound2_discard_ready()
    } else {
        acquire_lockstep_round(false, false)
    };
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1);
    if tx.try_send(ProbeMsg(None)).is_err() {
        return S8bObjectClass::Unexpected;
    }
    let notify = Arc::new(Notify::new());
    let window = Arc::new(Mutex::new(0u32));
    let mut w = ChannelTx::new(
        tx,
        ChannelId(1),
        window,
        Arc::clone(&notify),
        32,
        None,
        true,
        None,
    );
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let buf = [0u8; 8];

    if !Pin::new(&mut w).poll_write(&mut cx, &buf).is_pending() {
        return S8bObjectClass::Unexpected;
    }
    if rx.try_recv().is_err() {
        return S8bObjectClass::SendNotAccepted;
    }
    notify.notify_one();

    match Pin::new(&mut w).poll_write(&mut cx, &buf) {
        Poll::Ready(Ok(_)) => S8bObjectClass::AckReady,
        Poll::Pending => {
            eprintln!("s8b AckBeforeRegisterParked bound2={bound2}");
            S8bObjectClass::AckBeforeRegisterParked
        }
        Poll::Ready(Err(_)) => S8bObjectClass::Unexpected,
    }
}

/// Single acked writer + `OutboundLiveSet`. First poll parks on a
/// full mpsc (notification created, not registered). Then optionally
/// `live.remove` + `notify_one` (S5b discard: remove then wake) and
/// drain the filler. Second poll hits the early-Ok arm.
///
/// Production after D2-P2: `remove=true` → `DeadBrokenPipe`.
/// Pre-fix: `remove=true` → `DeadReportedOk` (the unfixed tree is
/// the invert; no new hook). `remove=false`: `AckReady` — the
/// stale-permit early Ok must survive the `known_dead` check.
#[cfg(feature = "_test_hooks")]
pub fn s8c_object_known_dead_round(remove: bool) -> S8bObjectClass {
    // Shares INVERT_BUSY with the S8b rounds so parallel siblings cannot arm an invert under this round.
    let _guard = acquire_lockstep_round(false, false);
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1);
    if tx.try_send(ProbeMsg(None)).is_err() {
        return S8bObjectClass::Unexpected;
    }
    let notify = Arc::new(Notify::new());
    let window = Arc::new(Mutex::new(0u32));
    let id = ChannelId(1);
    let live = Arc::new(OutboundLiveSet::default());
    live.insert(id);
    let mut w = ChannelTx::new(
        tx,
        id,
        window,
        Arc::clone(&notify),
        32,
        None,
        true,
        Some(Arc::clone(&live)),
    );
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let buf = [0u8; 8];

    if !Pin::new(&mut w).poll_write(&mut cx, &buf).is_pending() {
        return S8bObjectClass::Unexpected;
    }

    if remove {
        live.remove(id);
    }
    notify.notify_one();
    if rx.try_recv().is_err() {
        return S8bObjectClass::SendNotAccepted;
    }

    match Pin::new(&mut w).poll_write(&mut cx, &buf) {
        Poll::Ready(Ok(_)) => {
            if remove {
                eprintln!("s8c DeadReportedOk remove={remove}");
                S8bObjectClass::DeadReportedOk
            } else {
                S8bObjectClass::AckReady
            }
        }
        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
            if remove {
                S8bObjectClass::DeadBrokenPipe
            } else {
                S8bObjectClass::Unexpected
            }
        }
        Poll::Pending | Poll::Ready(Err(_)) => S8bObjectClass::Unexpected,
    }
}

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
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

use bytes::Bytes;

use super::ChannelMsg;
use crate::ChannelId;
use crate::channels::{ChannelAcked, OutboundLiveSet};

/// `_test_hooks`: invert D2 (park-before-register) and fix1 (bound-2
/// discard of a Ready that may be this write's ack).
#[cfg(feature = "_test_hooks")]
pub struct ChannelTxTestHooks {
    pub invert_park_before_register: std::sync::atomic::AtomicBool,
    pub invert_bound2_discard_ready: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "_test_hooks")]
pub static CHANNEL_TX_HOOKS: ChannelTxTestHooks = ChannelTxTestHooks {
    invert_park_before_register: std::sync::atomic::AtomicBool::new(false),
    invert_bound2_discard_ready: std::sync::atomic::AtomicBool::new(false),
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
    acked_waiting: bool,
    acked_n: usize,
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
            acked_waiting: false,
            acked_n: 0,
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
        let (ack_tx, _ack_rx) = tokio::sync::oneshot::channel();
        let Some(msg) = S::try_data_acked(self.id, self.ext, data, ack_tx) else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "acked DATA not supported",
            ));
        };
        use futures::TryFutureExt;
        self.acked_n = writable;
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
    fn register_window_notify(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        #[cfg(feature = "_test_hooks")]
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
            match r {
                Ok(_) => {
                    #[cfg(feature = "_test_hooks")]
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
                            return Poll::Ready(Ok(self.acked_n));
                        }
                        Poll::Pending => {
                            // Registered. No wake_by_ref: Notify holds
                            // `cx.waker()`. The old self-wake existed
                            // only to force a second poll that
                            // registered — that second poll *was* the
                            // lost-wake window.
                            self.acked_waiting = true;
                            return Poll::Pending;
                        }
                    }
                }
                Err(()) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "channel closed",
                    )));
                }
            }
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
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
        INVERT_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "_test_hooks")]
pub fn acquire_invert_park_before_register(invert: bool) -> InvertParkGuard {
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
        .store(invert, std::sync::atomic::Ordering::SeqCst);
    CHANNEL_TX_HOOKS
        .invert_bound2_discard_ready
        .store(false, std::sync::atomic::Ordering::SeqCst);
    InvertParkGuard
}

#[cfg(feature = "_test_hooks")]
pub fn acquire_invert_bound2_discard_ready() -> InvertParkGuard {
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
        .store(false, std::sync::atomic::Ordering::SeqCst);
    CHANNEL_TX_HOOKS
        .invert_bound2_discard_ready
        .store(true, std::sync::atomic::Ordering::SeqCst);
    InvertParkGuard
}

#[cfg(feature = "_test_hooks")]
struct ProbeMsg;

#[cfg(feature = "_test_hooks")]
impl From<(ChannelId, ChannelMsg)> for ProbeMsg {
    fn from(_: (ChannelId, ChannelMsg)) -> Self {
        Self
    }
}

#[cfg(feature = "_test_hooks")]
impl ChannelAcked for ProbeMsg {
    fn try_data_acked(
        _id: ChannelId,
        _ext: Option<u32>,
        _data: Bytes,
        _ack: tokio::sync::oneshot::Sender<()>,
    ) -> Option<Self> {
        Some(Self)
    }
}

/// Two acked writers, same Notify. Poll to "send accepted, Pending",
/// then `notify_one` ×2 with no intervening poll, then poll both.
/// Production: both Ready(Ok). Invert: exactly one Ready, one Pending.
#[cfg(feature = "_test_hooks")]
pub fn s8b_object_register_round(invert: bool) -> S8bObjectClass {
    let _guard = acquire_invert_park_before_register(invert);
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
        acquire_invert_park_before_register(false)
    };
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1);
    if tx.try_send(ProbeMsg).is_err() {
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
    let (tx, mut rx) = mpsc::channel::<ProbeMsg>(1);
    if tx.try_send(ProbeMsg).is_err() {
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

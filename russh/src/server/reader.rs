//! S3b ReaderTask: inbound epoch + per-channel lanes + ctrl.
//!
//! Channel-scoped messages (`DATA`/`EXT`/`EOF`/`CLOSE`/`REQUEST`/
//! `SUCCESS`/`FAILURE`) go to a dual-bound per-channel lane. Everything
//! else (kex / DISCONNECT / SERVICE / GLOBAL / OPEN / unknown)
//! is `try_push`ed onto a 2 MiB fail-closed ctrl queue. Inbound
//! `CHANNEL_WINDOW_ADJUST` is routed three ways by lane state: a
//! *confirmed* lane posts to the in-flight `PeerCreditBoard` (not
//! lane/ctrl/Writer); a live but *unconfirmed* (server-open) lane
//! falls through to ctrl so the credit stays behind `OPEN_CONFIRMATION`
//! in wire FIFO; an unknown id is dropped at Reader by lane membership
//! (same silent ignore as the old established-gate path). Session's
//! established gate is backup. malformed 落 ctrl 定罪.
//!
//! Inbound epoch install is a **capacity-1** Session→Reader channel.
//! `cipher::read` never sees a newly installed key mid-packet: install
//! is received only at a packet boundary after NEWKEYS, never selected
//! against an in-flight read.

use std::collections::HashSet;
use std::num::Wrapping;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicBool, AtomicU32};

use bytes::Bytes;
use log::debug;
use ssh_encoding::Decode;
use tokio::io::AsyncRead;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use crate::cipher::{self, OpeningKey};
use crate::compression::{Compression, Decompress};
use crate::msg;
use crate::server::inbound_lane::{
    ExpandCap, LaneItem, LanePush, LaneTable, PeerCreditBoard, INBOUND_CTRL_BUDGET,
    INBOUND_LANE_COUNT_SLACK, INBOUND_LANE_MIN_PACKET,
};
use crate::sshbuffer::{IncomingSshPacket, SSHBuffer};
use crate::ChannelId;
use crate::Error;

/// Session → Reader inbound epoch (capacity 1).
pub struct InstallInboundEpoch {
    pub generation: u64,
    pub cipher: Box<dyn OpeningKey + Send>,
    pub compression: Compression,
    pub activate_decompress: bool,
    pub reset_seqn: bool,
}

impl std::fmt::Debug for InstallInboundEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallInboundEpoch")
            .field("generation", &self.generation)
            .field("activate_decompress", &self.activate_decompress)
            .field("reset_seqn", &self.reset_seqn)
            .finish()
    }
}

#[derive(Debug)]
pub enum TryInstallInboundError {
    /// Capacity-1 slot still occupied (previous epoch not yet applied).
    Full(InstallInboundEpoch),
    /// Reader task is gone.
    Closed(InstallInboundEpoch),
}

/// Reader → Session events (unbounded; never used for bulk DATA).
#[derive(Debug)]
pub enum ReaderEvent {
    InstallAckInbound { generation: u64 },
    ReadError,
    Eof,
    /// Ctrl byte budget exhausted (I2' fail-closed).
    CtrlFull,
}

/// Reader → Session control path (kex / OPEN / lifecycle / ADJUST).
#[derive(Debug)]
pub enum CtrlMsg {
    Packet(IncomingSshPacket),
    WireClose {
        id: ChannelId,
        generation: u64,
    },
    Overflow {
        id: ChannelId,
        generation: u64,
    },
    /// Lane was full (or absent): Close marker dropped after WireClose.
    CloseDropped {
        id: ChannelId,
        generation: u64,
    },
}

impl CtrlMsg {
    pub fn byte_len(&self) -> usize {
        match self {
            CtrlMsg::Packet(p) => p.buffer.len(),
            CtrlMsg::WireClose { .. }
            | CtrlMsg::Overflow { .. }
            | CtrlMsg::CloseDropped { .. } => 16,
        }
    }
}

/// Enable deferred inbound decompress after auth (`zlib@openssh.com`).
pub struct EnableInboundDecompress {
    pub compression: Compression,
}

/// Test/production hooks for ReaderTask.
#[derive(Clone, Default)]
pub struct ReaderHooks {
    #[cfg(feature = "_test_hooks")]
    pub observe: Option<Arc<ReaderObserveSlot>>,
    /// When held, Reader waits at the packet boundary *before* starting
    /// `cipher::read` (and stays out of `cipher::read` while held). An
    /// `InstallInboundEpoch` sitting in the capacity-1 channel must not
    /// be applied.
    #[cfg(feature = "_test_hooks")]
    pub read_hold: Option<Arc<ReadHoldGate>>,
    /// When armed, the read half returns `Pending` after `hold_after` bytes
    /// so `cipher::read` is in-flight mid-packet (risk-2 hard test).
    #[cfg(feature = "_test_hooks")]
    pub mid_packet_hold: Option<Arc<MidPacketHold>>,
    /// Next successful transport read is turned into `ReaderEvent::ReadError`.
    #[cfg(feature = "_test_hooks")]
    pub fail_next_read: Option<Arc<AtomicBool>>,
    /// When held, Reader parks after `cipher::read` returns a full packet
    /// and *before* the post-read enable drain / decompress. Pins the
    /// deferred-zlib race: enable queued after the read arm wins.
    #[cfg(feature = "_test_hooks")]
    pub post_read_hold: Option<Arc<ReadHoldGate>>,
    /// When held, Reader parks after receiving the inbound epoch and before
    /// `apply_epoch` (N5: hang Writer first, then prove apply).
    #[cfg(feature = "_test_hooks")]
    pub apply_hold: Option<Arc<ReadHoldGate>>,
    /// Next ctrl `try_push` fails (Q7).
    #[cfg(feature = "_test_hooks")]
    pub force_ctrl_full: Option<Arc<AtomicBool>>,
    /// Share this packets atomic with Session (S6a wrap-near inject).
    #[cfg(feature = "_test_hooks")]
    pub packets_override: Option<Arc<AtomicU64>>,
    /// Share this bytes atomic with Session (S6a W6 inject).
    #[cfg(feature = "_test_hooks")]
    pub bytes_override: Option<Arc<AtomicU64>>,
    /// S6c invert: do not rebuild Decompress on epoch install.
    #[cfg(feature = "_test_hooks")]
    pub invert_keep_old_decompress: bool,
    #[cfg(feature = "_test_hooks")]
    pub compression_observe: Option<Arc<crate::server::supervisor::CompressionObserveSlot>>,
    #[cfg(feature = "_test_hooks")]
    pub lane_observe: Option<Arc<crate::server::inbound_lane::LaneObserveSlot>>,
    /// After the next real DATA, push this many empty DATA items (Q3).
    #[cfg(feature = "_test_hooks")]
    pub inject_zero_data: Option<Arc<AtomicU64>>,
    /// After the next real DATA, keep pushing 64-byte items until the
    /// lane Overflows (Q5: a window-ignoring peer).
    #[cfg(feature = "_test_hooks")]
    pub inject_until_overflow: Option<Arc<AtomicBool>>,
    /// After the next real DATA, inject CHANNEL_CLOSE for this id
    /// (0 = off). Used to send a ghost CLOSE on a never-opened id.
    #[cfg(feature = "_test_hooks")]
    pub inject_close_for: Option<Arc<AtomicU32>>,
    #[cfg(feature = "_test_hooks")]
    pub window_observe: Option<Arc<crate::server::inbound_lane::WindowObserveSlot>>,
}

/// Live Reader observation (`_test_hooks`).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct ReaderObserveSlot {
    /// Session successfully queued an inbound epoch (channel occupied).
    queued: AtomicBool,
    /// Sticky: queued was true at least once (N1 cannot miss a 20ms window).
    queued_ever: AtomicBool,
    /// Reader is blocked after NEWKEYS waiting for the epoch (NEWKEYS-first).
    awaiting: AtomicBool,
    awaiting_ever: AtomicBool,
    /// Last generation actually installed into the OpeningKey. 0 = none yet
    /// (initial clear epoch is not counted).
    applied_gen: AtomicU64,
    /// How many times `apply_epoch` ran (N3: exactly one apply per rekey).
    applies: AtomicU64,
    last_reset_seqn: AtomicBool,
    packets_this_epoch: AtomicU64,
    bytes_this_epoch: AtomicU64,
    in_read_hold: AtomicBool,
    in_post_read_hold: AtomicBool,
    seqn: AtomicU32,
    stopped: AtomicBool,
}

#[cfg(feature = "_test_hooks")]
impl ReaderObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_queued(&self, v: bool) {
        self.queued.store(v, Ordering::SeqCst);
        if v {
            self.queued_ever.store(true, Ordering::SeqCst);
        }
    }
    pub fn queued_ever(&self) -> bool {
        self.queued_ever.load(Ordering::SeqCst)
    }

    /// Clear sticky latches after the initial handshake so a rekey can
    /// prove its own park/await edges.
    pub fn reset_latches(&self) {
        self.queued_ever.store(false, Ordering::SeqCst);
        self.awaiting_ever.store(false, Ordering::SeqCst);
        self.queued.store(false, Ordering::SeqCst);
        self.awaiting.store(false, Ordering::SeqCst);
    }
    pub fn queued(&self) -> bool {
        self.queued.load(Ordering::SeqCst)
    }
    pub fn set_awaiting(&self, v: bool) {
        self.awaiting.store(v, Ordering::SeqCst);
        if v {
            self.awaiting_ever.store(true, Ordering::SeqCst);
        }
    }
    pub fn awaiting_ever(&self) -> bool {
        self.awaiting_ever.load(Ordering::SeqCst)
    }
    pub fn awaiting(&self) -> bool {
        self.awaiting.load(Ordering::SeqCst)
    }
    pub fn set_applied_gen(&self, g: u64) {
        self.applied_gen.store(g, Ordering::SeqCst);
    }
    pub fn applied_gen(&self) -> u64 {
        self.applied_gen.load(Ordering::SeqCst)
    }
    pub fn mark_apply(&self) {
        self.applies.fetch_add(1, Ordering::SeqCst);
    }
    pub fn applies(&self) -> u64 {
        self.applies.load(Ordering::SeqCst)
    }
    pub fn set_last_reset_seqn(&self, v: bool) {
        self.last_reset_seqn.store(v, Ordering::SeqCst);
    }
    pub fn last_reset_seqn(&self) -> bool {
        self.last_reset_seqn.load(Ordering::SeqCst)
    }
    pub fn set_packets_this_epoch(&self, n: u64) {
        self.packets_this_epoch.store(n, Ordering::SeqCst);
    }
    pub fn packets_this_epoch(&self) -> u64 {
        self.packets_this_epoch.load(Ordering::SeqCst)
    }
    pub fn set_bytes_this_epoch(&self, n: u64) {
        self.bytes_this_epoch.store(n, Ordering::SeqCst);
    }
    pub fn bytes_this_epoch(&self) -> u64 {
        self.bytes_this_epoch.load(Ordering::SeqCst)
    }
    pub fn set_in_read_hold(&self, v: bool) {
        self.in_read_hold.store(v, Ordering::SeqCst);
    }
    pub fn in_read_hold(&self) -> bool {
        self.in_read_hold.load(Ordering::SeqCst)
    }
    pub fn set_in_post_read_hold(&self, v: bool) {
        self.in_post_read_hold.store(v, Ordering::SeqCst);
    }
    pub fn in_post_read_hold(&self) -> bool {
        self.in_post_read_hold.load(Ordering::SeqCst)
    }
    pub fn set_seqn(&self, s: u32) {
        self.seqn.store(s, Ordering::SeqCst);
    }
    pub fn seqn(&self) -> u32 {
        self.seqn.load(Ordering::SeqCst)
    }
    pub fn set_stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Gate: hold Reader at the packet boundary before `cipher::read`.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct ReadHoldGate {
    held: AtomicBool,
    notify: tokio::sync::Notify,
}

#[cfg(feature = "_test_hooks")]
impl ReadHoldGate {
    pub fn new_held() -> Arc<Self> {
        Arc::new(Self {
            held: AtomicBool::new(true),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn is_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    pub fn hold(&self) {
        self.held.store(true, Ordering::SeqCst);
    }

    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait_released(&self) {
        loop {
            if !self.held.load(Ordering::SeqCst) {
                return;
            }
            let n = self.notify.notified();
            if !self.held.load(Ordering::SeqCst) {
                return;
            }
            n.await;
        }
    }
}

/// `_test_hooks`: stall the socket `AsyncRead` after `hold_after` bytes so
/// `cipher::read` is parked mid-packet (length consumed, body pending).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct MidPacketHold {
    hold_after: AtomicUsize,
    delivered: AtomicUsize,
    held: AtomicBool,
    in_flight: AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

#[cfg(feature = "_test_hooks")]
impl MidPacketHold {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Deliver `after` bytes, then `Poll::Pending` until [`release`].
    pub fn arm(&self, after: usize) {
        self.hold_after.store(after, Ordering::SeqCst);
        self.delivered.store(0, Ordering::SeqCst);
        self.held.store(true, Ordering::SeqCst);
        self.in_flight.store(false, Ordering::SeqCst);
    }

    pub fn in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.waker.lock() {
            if let Some(w) = g.take() {
                w.wake();
            }
        }
    }
}

#[cfg(feature = "_test_hooks")]
struct MidPacketHoldRead<R> {
    inner: R,
    gate: Option<Arc<MidPacketHold>>,
}

#[cfg(feature = "_test_hooks")]
impl<R: AsyncRead + Unpin> tokio::io::AsyncRead for MidPacketHoldRead<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(g) = this.gate.as_ref() else {
            return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        let after = g.hold_after.load(Ordering::SeqCst);
        if after > 0
            && g.held.load(Ordering::SeqCst)
            && g.delivered.load(Ordering::SeqCst) >= after
        {
            g.in_flight.store(true, Ordering::SeqCst);
            if let Ok(mut w) = g.waker.lock() {
                *w = Some(cx.waker().clone());
            }
            return std::task::Poll::Pending;
        }
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let n = buf.filled().len().saturating_sub(before);
                g.delivered.fetch_add(n, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[derive(Clone)]
pub struct ReaderHandle {
    install_tx: mpsc::Sender<InstallInboundEpoch>,
    enable_tx: mpsc::Sender<EnableInboundDecompress>,
    lanes: Arc<Mutex<LaneTable>>,
    ready: Arc<Notify>,
    ctrl_bytes: Arc<AtomicUsize>,
    /// I5 inbound packet count this key-epoch (Session-readable).
    packets_this_epoch: Arc<AtomicU64>,
    /// I5 inbound plaintext-payload bytes this key-epoch (Session-readable).
    bytes_this_epoch: Arc<AtomicU64>,
    #[cfg(feature = "_test_hooks")]
    observe: Option<Arc<ReaderObserveSlot>>,
}

impl std::fmt::Debug for ReaderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderHandle").finish_non_exhaustive()
    }
}

impl ReaderHandle {
    /// Capacity-1 try_push. Full → caller must Cancelling (I2'). Never await.
    pub fn try_install_inbound(
        &self,
        epoch: InstallInboundEpoch,
    ) -> Result<(), TryInstallInboundError> {
        match self.install_tx.try_send(epoch) {
            Ok(()) => {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref o) = self.observe {
                    o.set_queued(true);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(e)) => Err(TryInstallInboundError::Full(e)),
            Err(mpsc::error::TrySendError::Closed(e)) => Err(TryInstallInboundError::Closed(e)),
        }
    }

    /// Packets opened on the current inbound epoch (I5).
    pub fn packets_this_epoch(&self) -> u64 {
        self.packets_this_epoch.load(Ordering::Acquire)
    }

    /// Opened plaintext-payload bytes on the current inbound epoch (I5).
    pub fn bytes_this_epoch(&self) -> u64 {
        self.bytes_this_epoch.load(Ordering::Acquire)
    }

    pub fn try_enable_decompress(
        &self,
        compression: Compression,
    ) -> Result<(), EnableInboundDecompress> {
        self.enable_tx
            .try_send(EnableInboundDecompress { compression })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(x) | mpsc::error::TrySendError::Closed(x) => x,
            })
    }

    pub fn open_lane(
        &self,
        id: ChannelId,
        generation: u64,
        window: u32,
        max_packet: u32,
        confirmed: bool,
    ) {
        if let Ok(mut g) = self.lanes.lock() {
            g.open(id, generation, window, max_packet, confirmed);
        }
    }

    pub fn confirm_lane(&self, id: ChannelId) {
        if let Ok(mut g) = self.lanes.lock() {
            g.confirm(id);
        }
    }

    pub fn close_lane(&self, id: ChannelId, generation: u64) {
        if let Ok(mut g) = self.lanes.lock() {
            g.close(id, generation);
        }
    }

    #[cfg(test)]
    pub(crate) fn test_stub(lanes: Arc<Mutex<LaneTable>>) -> Self {
        let (install_tx, _) = mpsc::channel(1);
        let (enable_tx, _) = mpsc::channel(1);
        Self {
            install_tx,
            enable_tx,
            lanes,
            ready: Arc::new(Notify::new()),
            ctrl_bytes: Arc::new(AtomicUsize::new(0)),
            packets_this_epoch: Arc::new(AtomicU64::new(0)),
            bytes_this_epoch: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "_test_hooks")]
            observe: None,
        }
    }

    pub fn occupancy_bytes(&self, id: ChannelId) -> usize {
        self.lanes
            .lock()
            .ok()
            .map(|g| g.occupancy_bytes(id))
            .unwrap_or(0)
    }

    /// Occupancy and window remaining in one lock (grant planning).
    pub fn grant_plan(&self, id: ChannelId) -> Option<(usize, u32)> {
        self.lanes.lock().ok().and_then(|g| g.grant_plan(id))
    }

    pub fn occupancy_count(&self, id: ChannelId) -> usize {
        self.lanes
            .lock()
            .ok()
            .map(|g| g.occupancy_count(id))
            .unwrap_or(0)
    }

    pub fn total_occupancy_bytes(&self) -> usize {
        self.lanes
            .lock()
            .ok()
            .map(|g| g.total_occupancy_bytes())
            .unwrap_or(0)
    }

    pub fn total_occupancy_count(&self) -> usize {
        self.lanes
            .lock()
            .ok()
            .map(|g| g.total_occupancy_count())
            .unwrap_or(0)
    }

    pub fn pop_any(&self) -> Option<(ChannelId, LaneItem)> {
        self.lanes.lock().ok().and_then(|mut g| g.pop_any())
    }

    pub fn pop_any_except(&self, skip: &HashSet<ChannelId>) -> Option<(ChannelId, LaneItem)> {
        self.lanes
            .lock()
            .ok()
            .and_then(|mut g| g.pop_any_except(skip))
    }

    pub fn pop_any_non_payload_except(
        &self,
        skip: &HashSet<ChannelId>,
    ) -> Option<(ChannelId, LaneItem)> {
        self.lanes
            .lock()
            .ok()
            .and_then(|mut g| g.pop_any_non_payload_except(skip))
    }

    pub fn peek_gated(
        &self,
        hold_data: &HashSet<ChannelId>,
        hold_all: &HashSet<ChannelId>,
        non_payload_only: bool,
    ) -> Option<ChannelId> {
        self.lanes
            .lock()
            .ok()
            .and_then(|g| g.peek_gated(hold_data, hold_all, non_payload_only))
    }

    pub fn pop_channel(&self, id: ChannelId) -> Option<LaneItem> {
        self.lanes.lock().ok().and_then(|mut g| g.pop_channel(id))
    }

    pub fn close_queued(&self, id: ChannelId) -> bool {
        self.lanes
            .lock()
            .ok()
            .is_some_and(|g| g.close_queued(id))
    }

    pub fn close_queued_ids(&self) -> Vec<ChannelId> {
        self.lanes
            .lock()
            .ok()
            .map(|g| g.close_queued_ids())
            .unwrap_or_default()
    }

    pub fn head_needs_app(&self, id: ChannelId) -> bool {
        self.lanes
            .lock()
            .ok()
            .is_some_and(|g| g.head_needs_app(id))
    }

    pub fn has_ready(&self) -> bool {
        self.lanes.lock().ok().is_some_and(|g| g.has_ready())
    }

    pub fn lane_ready(&self) -> Arc<Notify> {
        self.ready.clone()
    }

    pub fn lane_gen(&self, id: ChannelId) -> Option<u64> {
        self.lanes.lock().ok().and_then(|g| g.generation(id))
    }

    #[cfg(feature = "_test_hooks")]
    pub fn lane_count(&self) -> usize {
        self.lanes.lock().ok().map(|g| g.len()).unwrap_or(0)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn lane_has(&self, id: ChannelId) -> bool {
        self.is_confirmed(id).is_some()
    }

    #[cfg(feature = "_test_hooks")]
    pub fn is_confirmed(&self, id: ChannelId) -> Option<bool> {
        self.lanes.lock().ok().and_then(|g| g.is_confirmed(id))
    }

    #[cfg(any(test, feature = "_test_hooks"))]
    pub fn debug_consume_window(&self, id: ChannelId, len: usize) {
        if let Ok(mut g) = self.lanes.lock() {
            g.consume_window(id, len);
        }
    }

    /// Single inbound-window ledger. Session must not independently `-=`.
    pub fn sender_window(&self, id: ChannelId) -> Option<u32> {
        self.lanes.lock().ok().and_then(|g| g.window_remaining(id))
    }

    /// try_push ExpandInboundCap. Never await. Full cannot happen.
    pub fn try_expand_inbound_cap(
        &self,
        id: ChannelId,
        generation: u64,
        add: u32,
    ) -> ExpandCap {
        self.lanes
            .lock()
            .ok()
            .map(|mut g| g.try_expand(id, generation, add))
            .unwrap_or(ExpandCap::NoLane)
    }

    /// Raise occupancy DoS bounds to a larger committed target.
    /// Never awaits. No-op (Expanded) when the new bound is not bigger.
    pub fn try_raise_inbound_caps(
        &self,
        id: ChannelId,
        generation: u64,
        window: u32,
        max_packet: u32,
    ) -> ExpandCap {
        self.lanes
            .lock()
            .ok()
            .map(|mut g| g.try_raise_occupancy(id, generation, window, max_packet))
            .unwrap_or(ExpandCap::NoLane)
    }

    pub fn release_ctrl(&self, n: usize) {
        let _ = self
            .ctrl_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_sub(n))
            });
    }
}

pub const INBOUND_EPOCH_CAP: usize = 1;

/// Spawn Reader owning `stream_read` + inbound cipher + `SSHBuffer`.
pub fn spawn_reader<R>(
    stream_read: R,
    cipher: Box<dyn OpeningKey + Send>,
    buffer: SSHBuffer,
    cancel: watch::Receiver<bool>,
    hooks: ReaderHooks,
) -> (
    ReaderHandle,
    JoinHandle<()>,
    mpsc::UnboundedReceiver<CtrlMsg>,
    mpsc::UnboundedReceiver<ReaderEvent>,
)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    spawn_reader_with_budget(
        stream_read,
        cipher,
        buffer,
        cancel,
        hooks,
        INBOUND_CTRL_BUDGET,
        INBOUND_LANE_MIN_PACKET,
        INBOUND_LANE_COUNT_SLACK,
        PeerCreditBoard::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_reader_with_budget<R>(
    stream_read: R,
    cipher: Box<dyn OpeningKey + Send>,
    buffer: SSHBuffer,
    cancel: watch::Receiver<bool>,
    hooks: ReaderHooks,
    ctrl_budget: usize,
    min_packet: usize,
    count_slack: usize,
    credit: Arc<PeerCreditBoard>,
) -> (
    ReaderHandle,
    JoinHandle<()>,
    mpsc::UnboundedReceiver<CtrlMsg>,
    mpsc::UnboundedReceiver<ReaderEvent>,
)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (install_tx, install_rx) = mpsc::channel::<InstallInboundEpoch>(INBOUND_EPOCH_CAP);
    let (enable_tx, enable_rx) = mpsc::channel::<EnableInboundDecompress>(4);
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<CtrlMsg>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<ReaderEvent>();
    let lanes = Arc::new(Mutex::new({
        let table = LaneTable::new(min_packet, count_slack);
        #[cfg(feature = "_test_hooks")]
        let table = {
            let mut table = table;
            if let Some(o) = hooks.lane_observe.clone() {
                table.set_observe(o);
            }
            table
        };
        table
    }));
    let ready = Arc::new(Notify::new());
    let ctrl_bytes = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "_test_hooks")]
    let packets_this_epoch = hooks
        .packets_override
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    #[cfg(not(feature = "_test_hooks"))]
    let packets_this_epoch = Arc::new(AtomicU64::new(0));
    #[cfg(feature = "_test_hooks")]
    let bytes_this_epoch = hooks
        .bytes_override
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    #[cfg(not(feature = "_test_hooks"))]
    let bytes_this_epoch = Arc::new(AtomicU64::new(0));

    let handle = ReaderHandle {
        install_tx,
        enable_tx,
        lanes: lanes.clone(),
        ready: ready.clone(),
        ctrl_bytes: ctrl_bytes.clone(),
        packets_this_epoch: packets_this_epoch.clone(),
        bytes_this_epoch: bytes_this_epoch.clone(),
        #[cfg(feature = "_test_hooks")]
        observe: hooks.observe.clone(),
    };

    let join = tokio::spawn(reader_loop(
        stream_read,
        cipher,
        buffer,
        cancel,
        install_rx,
        enable_rx,
        ctrl_tx,
        ctrl_bytes,
        ctrl_budget,
        lanes,
        ready,
        evt_tx,
        hooks,
        credit,
        packets_this_epoch,
        bytes_this_epoch,
    ));

    (handle, join, ctrl_rx, evt_rx)
}

fn apply_epoch(
    cipher: &mut Box<dyn OpeningKey + Send>,
    decompress: &mut Decompress,
    buffer: &mut SSHBuffer,
    packets_this_epoch: &AtomicU64,
    bytes_this_epoch: &AtomicU64,
    epoch: InstallInboundEpoch,
    #[cfg(feature = "_test_hooks")] observe: &Option<Arc<ReaderObserveSlot>>,
    #[cfg(feature = "_test_hooks")] invert_keep_old_decompress: bool,
    #[cfg(feature = "_test_hooks")]
    compression_observe: &Option<Arc<crate::server::supervisor::CompressionObserveSlot>>,
) -> u64 {
    let generation = epoch.generation;
    *cipher = epoch.cipher;
    #[cfg(feature = "_test_hooks")]
    // Invert only on rekey (gen>0). Initial kex (gen 0) must still
    // install, otherwise a zlib-first handshake cannot authenticate.
    let skip_rebuild = invert_keep_old_decompress && epoch.generation > 0;
    #[cfg(not(feature = "_test_hooks"))]
    let skip_rebuild = false;
    if !skip_rebuild {
        if epoch.activate_decompress {
            #[cfg(all(feature = "_test_hooks", feature = "flate2"))]
            let had_zlib = matches!(decompress, Decompress::Zlib(_));
            epoch.compression.init_decompress(decompress);
            #[cfg(all(feature = "_test_hooks", feature = "flate2"))]
            if had_zlib {
                if let Some(o) = compression_observe {
                    o.mark_zlib_reset();
                }
            }
        } else {
            *decompress = Decompress::None;
        }
    }
    #[cfg(feature = "_test_hooks")]
    if let Some(o) = compression_observe {
        o.set_inbound_activated(epoch.activate_decompress && !skip_rebuild);
    }
    if epoch.reset_seqn {
        buffer.seqn = Wrapping(0);
    }
    // I5 count reset is independent of strict-kex wire seqn reset.
    packets_this_epoch.store(0, Ordering::Release);
    bytes_this_epoch.store(0, Ordering::Release);
    #[cfg(feature = "_test_hooks")]
    if let Some(o) = observe {
        o.set_applied_gen(generation);
        o.mark_apply();
        o.set_last_reset_seqn(epoch.reset_seqn);
        o.set_queued(false);
        o.set_awaiting(false);
        o.set_packets_this_epoch(0);
        o.set_bytes_this_epoch(0);
        o.set_seqn(buffer.seqn.0);
    }
    debug!("reader: installed inbound epoch gen={generation} reset_seqn={}", epoch.reset_seqn);
    generation
}

fn try_push_ctrl(
    ctrl_tx: &mpsc::UnboundedSender<CtrlMsg>,
    ctrl_bytes: &AtomicUsize,
    cap: usize,
    msg: CtrlMsg,
    #[cfg(feature = "_test_hooks")] force_full: bool,
) -> Result<(), ()> {
    #[cfg(feature = "_test_hooks")]
    if force_full {
        return Err(());
    }
    let n = msg.byte_len();
    loop {
        let cur = ctrl_bytes.load(Ordering::Acquire);
        if cur.saturating_add(n) > cap {
            return Err(());
        }
        match ctrl_bytes.compare_exchange_weak(
            cur,
            cur.saturating_add(n),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    if ctrl_tx.send(msg).is_err() {
        ctrl_bytes.fetch_sub(n, Ordering::AcqRel);
        return Err(());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_inbound(
    pkt: IncomingSshPacket,
    lanes: &Mutex<LaneTable>,
    ready: &Notify,
    ctrl_tx: &mpsc::UnboundedSender<CtrlMsg>,
    ctrl_bytes: &AtomicUsize,
    ctrl_budget: usize,
    evt_tx: &mpsc::UnboundedSender<ReaderEvent>,
    hooks: &ReaderHooks,
    credit: &PeerCreditBoard,
) -> bool {
    #[cfg(feature = "_test_hooks")]
    let force_full = hooks
        .force_ctrl_full
        .as_ref()
        .is_some_and(|f| f.load(Ordering::SeqCst));
    #[cfg(not(feature = "_test_hooks"))]
    let _ = hooks;

    let msg = pkt.buffer.first().copied();
    let scoped = match msg {
        Some(msg::CHANNEL_DATA)
        | Some(msg::CHANNEL_EXTENDED_DATA)
        | Some(msg::CHANNEL_EOF)
        | Some(msg::CHANNEL_CLOSE)
        | Some(msg::CHANNEL_REQUEST)
        | Some(msg::CHANNEL_SUCCESS)
        | Some(msg::CHANNEL_FAILURE) => true,
        _ => false,
    };

    if pkt.buffer.first() == Some(&msg::CHANNEL_WINDOW_ADJUST) {
        if let Some((id, amount)) = parse_window_adjust(&pkt) {
            // Membership + confirmed under the lanes lock, then drop
            // that lock before credit.post (board lock). Never nest.
            let confirmed = lanes.lock().ok().and_then(|g| g.is_confirmed(id));
            match confirmed {
                None => {
                    // Silent drop: same semantic as the old established-gate
                    // ignore. Do not send to ctrl.
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = hooks.window_observe {
                        o.note_unknown_adjust();
                    }
                    return true;
                }
                Some(true) => {
                    // TOCTOU: lane closed after the check, before post → at most
                    // O(in-flight teardowns) stale entries; next loop-top
                    // take_all + established gate drops them.
                    credit.post(id, amount);
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = hooks.window_observe {
                        o.note_adjust_bypass();
                    }
                    return true;
                }
                Some(false) => {
                    // Unconfirmed server-open: fall through to !scoped
                    // try_push_ctrl so ADJUST joins OPEN_CONFIRMATION on
                    // ctrl and wire FIFO is preserved. An unconfirmed
                    // ADJUST flood eats the 2 MiB fail-closed ctrl
                    // budget; overflow is PeerError. Bounded and intended.
                    //
                    // Monotonicity: if Reader observed !confirmed and
                    // queued ctrl, Session confirming later still sees
                    // this ADJUST *after* CONFIRMATION in ctrl → old
                    // handler applies it. The reverse (Reader sees
                    // confirmed=true while a prior CONFIRMATION is still
                    // sitting unprocessed in ctrl) cannot happen:
                    // confirm_lane runs in the same Session turn that
                    // processes ctrl CONFIRMATION, so Reader cannot
                    // observe confirmed=true before that turn.
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = hooks.window_observe {
                        o.note_unconfirmed_adjust();
                    }
                }
            }
        }
        // malformed 落 ctrl 定罪; unconfirmed 落 ctrl 保序
    }

    if !scoped {
        if try_push_ctrl(
            ctrl_tx,
            ctrl_bytes,
            ctrl_budget,
            CtrlMsg::Packet(pkt),
            #[cfg(feature = "_test_hooks")]
            force_full,
        )
        .is_err()
        {
            let _ = evt_tx.send(ReaderEvent::CtrlFull);
            return false;
        }
        return true;
    }

    match parse_lane_item(&pkt) {
        None => {
            if try_push_ctrl(
                ctrl_tx,
                ctrl_bytes,
                ctrl_budget,
                CtrlMsg::Packet(pkt),
                #[cfg(feature = "_test_hooks")]
                force_full,
            )
            .is_err()
            {
                let _ = evt_tx.send(ReaderEvent::CtrlFull);
                return false;
            }
            true
        }
        Some((id, item)) => dispatch_lane_item(
            id,
            item,
            lanes,
            ready,
            ctrl_tx,
            ctrl_bytes,
            ctrl_budget,
            evt_tx,
            hooks,
            #[cfg(feature = "_test_hooks")]
            force_full,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_lane_item(
    id: ChannelId,
    item: LaneItem,
    lanes: &Mutex<LaneTable>,
    ready: &Notify,
    ctrl_tx: &mpsc::UnboundedSender<CtrlMsg>,
    ctrl_bytes: &AtomicUsize,
    ctrl_budget: usize,
    evt_tx: &mpsc::UnboundedSender<ReaderEvent>,
    hooks: &ReaderHooks,
    #[cfg(feature = "_test_hooks")]
    force_full: bool,
) -> bool {
    let is_close = matches!(item, LaneItem::Close);
    let generation = lanes.lock().ok().and_then(|g| g.generation(id)).unwrap_or(0);

    // Risk 1 / Q6: ctrl WireClose first (try_push, never await). Lane
    // Close is best-effort afterwards; full lane drops the marker and
    // signals CloseDropped so Session still finalizes.
    if is_close {
        if try_push_ctrl(
            ctrl_tx,
            ctrl_bytes,
            ctrl_budget,
            CtrlMsg::WireClose { id, generation },
            #[cfg(feature = "_test_hooks")]
            force_full,
        )
        .is_err()
        {
            let _ = evt_tx.send(ReaderEvent::CtrlFull);
            return false;
        }
        let push = if let Ok(mut g) = lanes.lock() {
            g.try_push(id, LaneItem::Close)
        } else {
            LanePush::NoLane
        };
        note_push(hooks, &push, true);
        match push {
            LanePush::Accepted => ready.notify_one(),
            LanePush::DroppedDup => {}
            LanePush::DroppedZero
            | LanePush::DroppedOverWindow
            | LanePush::NoLane
            | LanePush::Overflow => {
                if try_push_ctrl(
                    ctrl_tx,
                    ctrl_bytes,
                    ctrl_budget,
                    CtrlMsg::CloseDropped { id, generation },
                    #[cfg(feature = "_test_hooks")]
                    force_full,
                )
                .is_err()
                {
                    let _ = evt_tx.send(ReaderEvent::CtrlFull);
                    return false;
                }
            }
        }
        return true;
    }

    let push = if let Ok(mut g) = lanes.lock() {
        // I1: consume at receive. Over-window DATA/EXT is dropped, not queued
        // (RFC 4254 §5.2). Occupancy Overflow stays the DoS gate for inject.
        let p = g.ingest(id, item);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = hooks.lane_observe {
            o.set_occ(g.occupancy_bytes(id), g.occupancy_count(id));
            if let (Some(bc), Some(cc)) = (g.byte_cap(id), g.count_cap(id)) {
                o.set_caps(bc, cc);
            }
        }
        p
    } else {
        LanePush::NoLane
    };
    note_push(hooks, &push, false);
    match push {
        LanePush::Accepted => {
            ready.notify_one();
            #[cfg(feature = "_test_hooks")]
            if let Some(n) = hooks
                .inject_zero_data
                .as_ref()
                .map(|c| c.swap(0, Ordering::SeqCst))
            {
                if n > 0 {
                    if let Ok(mut g) = lanes.lock() {
                        for _ in 0..n {
                            let p = g.try_push(id, LaneItem::Data(Bytes::new()));
                            note_push(hooks, &p, false);
                        }
                    }
                }
            }
            #[cfg(feature = "_test_hooks")]
            if hooks
                .inject_until_overflow
                .as_ref()
                .is_some_and(|f| f.swap(false, Ordering::SeqCst))
            {
                let overflowed = if let Ok(mut g) = lanes.lock() {
                    let mut hit = false;
                    for _ in 0..4096 {
                        let p = g.try_push(id, LaneItem::Data(Bytes::from(vec![0u8; 64])));
                        note_push(hooks, &p, false);
                        if matches!(p, LanePush::Overflow) {
                            hit = true;
                            break;
                        }
                        if !matches!(p, LanePush::Accepted) {
                            break;
                        }
                    }
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = hooks.lane_observe {
                        o.set_occ(g.occupancy_bytes(id), g.occupancy_count(id));
                    }
                    hit
                } else {
                    false
                };
                if overflowed
                    && try_push_ctrl(
                        ctrl_tx,
                        ctrl_bytes,
                        ctrl_budget,
                        CtrlMsg::Overflow { id, generation },
                        #[cfg(feature = "_test_hooks")]
                        force_full,
                    )
                    .is_err()
                {
                    let _ = evt_tx.send(ReaderEvent::CtrlFull);
                    return false;
                }
            }
            #[cfg(feature = "_test_hooks")]
            if let Some(raw) = hooks
                .inject_close_for
                .as_ref()
                .map(|c| c.swap(0, Ordering::SeqCst))
            {
                if raw != 0 {
                    let ghost = crate::ChannelId(raw);
                    if !dispatch_lane_item(
                        ghost,
                        LaneItem::Close,
                        lanes,
                        ready,
                        ctrl_tx,
                        ctrl_bytes,
                        ctrl_budget,
                        evt_tx,
                        hooks,
                        force_full,
                    ) {
                        return false;
                    }
                }
            }
            true
        }
        LanePush::DroppedZero
        | LanePush::DroppedDup
        | LanePush::DroppedOverWindow
        | LanePush::NoLane => true,
        LanePush::Overflow => {
            if try_push_ctrl(
                ctrl_tx,
                ctrl_bytes,
                ctrl_budget,
                CtrlMsg::Overflow { id, generation },
                #[cfg(feature = "_test_hooks")]
                force_full,
            )
            .is_err()
            {
                let _ = evt_tx.send(ReaderEvent::CtrlFull);
                return false;
            }
            true
        }
    }
}

fn note_push(hooks: &ReaderHooks, push: &LanePush, is_close: bool) {
    #[cfg(feature = "_test_hooks")]
    if let Some(ref o) = hooks.lane_observe {
        match push {
            LanePush::DroppedZero => o.note_zero(),
            LanePush::DroppedOverWindow => o.note_over_window(),
            LanePush::DroppedDup => o.note_dup(),
            LanePush::NoLane if is_close => o.note_close_dropped(),
            LanePush::NoLane => o.note_unknown(),
            LanePush::Overflow if is_close => o.note_close_dropped(),
            LanePush::Overflow => o.note_overflow(),
            LanePush::Accepted => {}
        }
    }
    #[cfg(not(feature = "_test_hooks"))]
    {
        let _ = (hooks, push, is_close);
    }
}

fn parse_window_adjust(pkt: &IncomingSshPacket) -> Option<(ChannelId, u32)> {
    let rest = pkt.buffer.get(1..)?;
    let mut r = rest;
    let id = ChannelId::decode(&mut r).ok()?;
    let amount = u32::decode(&mut r).ok()?;
    crate::parsing::ensure_end(&r).ok()?;
    Some((id, amount))
}

fn parse_lane_item(pkt: &IncomingSshPacket) -> Option<(ChannelId, LaneItem)> {
    let (first, rest) = pkt.buffer.split_first()?;
    let mut r = rest;
    match *first {
        msg::CHANNEL_DATA => {
            let id = ChannelId::decode(&mut r).ok()?;
            let data = Bytes::decode(&mut r).ok()?;
            // Same tail check as encrypted.rs DATA. Remainder → None so
            // ctrl/reply/ensure_end convicts (old reject, not deliver).
            crate::parsing::ensure_end(&r).ok()?;
            Some((id, LaneItem::Data(data)))
        }
        msg::CHANNEL_EXTENDED_DATA => {
            let id = ChannelId::decode(&mut r).ok()?;
            let ext = u32::decode(&mut r).ok()?;
            let data = Bytes::decode(&mut r).ok()?;
            crate::parsing::ensure_end(&r).ok()?;
            Some((id, LaneItem::ExtendedData { ext, data }))
        }
        msg::CHANNEL_EOF => {
            let id = ChannelId::decode(&mut r).ok()?;
            crate::parsing::ensure_end(&r).ok()?;
            Some((id, LaneItem::Eof))
        }
        msg::CHANNEL_CLOSE => {
            let id = ChannelId::decode(&mut r).ok()?;
            crate::parsing::ensure_end(&r).ok()?;
            Some((id, LaneItem::Close))
        }
        // REQUEST/SUCCESS/FAILURE: whole remainder is forwarded; tail
        // check happens in server_read_authenticated (variable fields).
        msg::CHANNEL_REQUEST => {
            let mut peek = rest;
            let id = ChannelId::decode(&mut peek).ok()?;
            Some((
                id,
                LaneItem::Request {
                    payload: Bytes::copy_from_slice(rest),
                },
            ))
        }
        msg::CHANNEL_SUCCESS => {
            let mut peek = rest;
            let id = ChannelId::decode(&mut peek).ok()?;
            Some((
                id,
                LaneItem::Success {
                    payload: Bytes::copy_from_slice(rest),
                },
            ))
        }
        msg::CHANNEL_FAILURE => {
            let mut peek = rest;
            let id = ChannelId::decode(&mut peek).ok()?;
            Some((
                id,
                LaneItem::Failure {
                    payload: Bytes::copy_from_slice(rest),
                },
            ))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn reader_loop<R: AsyncRead + Unpin>(
    mut stream: R,
    mut cipher: Box<dyn OpeningKey + Send>,
    mut buffer: SSHBuffer,
    mut cancel: watch::Receiver<bool>,
    mut install_rx: mpsc::Receiver<InstallInboundEpoch>,
    mut enable_rx: mpsc::Receiver<EnableInboundDecompress>,
    ctrl_tx: mpsc::UnboundedSender<CtrlMsg>,
    ctrl_bytes: Arc<AtomicUsize>,
    ctrl_budget: usize,
    lanes: Arc<Mutex<LaneTable>>,
    ready: Arc<Notify>,
    evt_tx: mpsc::UnboundedSender<ReaderEvent>,
    hooks: ReaderHooks,
    credit: Arc<PeerCreditBoard>,
    packets_this_epoch: Arc<AtomicU64>,
    bytes_this_epoch: Arc<AtomicU64>,
) {
    #[cfg(not(feature = "_test_hooks"))]
    let _ = &hooks;
    let mut decompress = Decompress::None;
    #[cfg(feature = "_test_hooks")]
    let observe = hooks.observe.clone();
    #[cfg(feature = "_test_hooks")]
    let mut stream = MidPacketHoldRead {
        inner: stream,
        gate: hooks.mid_packet_hold.clone(),
    };

    'reader: loop {
        if *cancel.borrow_and_update() {
            debug!("reader: cancel observed");
            break;
        }

        // Drain enable-decompress at packet boundary (and during read via select).
        while let Ok(en) = enable_rx.try_recv() {
            en.compression.init_decompress(&mut decompress);
        }

        // S3a mid-read / risk-2 hook: do not start cipher::read while held.
        // InstallInboundEpoch may sit in install_rx the whole time — not applied.
        #[cfg(feature = "_test_hooks")]
        if let Some(ref hold) = hooks.read_hold {
            if hold.is_held() {
                if let Some(ref o) = observe {
                    o.set_in_read_hold(true);
                }
                tokio::select! {
                    _ = hold.wait_released() => {}
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            if let Some(ref o) = observe {
                                o.set_in_read_hold(false);
                            }
                            break;
                        }
                    }
                }
                if let Some(ref o) = observe {
                    o.set_in_read_hold(false);
                }
                if *cancel.borrow() {
                    break;
                }
            }
        }

        // In-flight read: NEVER recv install here (risk 2). The epoch stays
        // in the capacity-1 channel. Enable-decompress is safe mid-read;
        // if the read arm wins the same poll, the post-read drain below
        // still applies it before decompress of this packet.
        let n = {
            let read_fut = cipher::read(&mut stream, &mut buffer, &mut *cipher);
            tokio::pin!(read_fut);
            loop {
                tokio::select! {
                    r = &mut read_fut => break r,
                    Some(en) = enable_rx.recv() => {
                        en.compression.init_decompress(&mut decompress);
                    }
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            debug!("reader: cancel during read");
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref o) = observe {
                                o.set_stopped();
                            }
                            return;
                        }
                    }
                }
            }
        };

        let n = match n {
            Ok(n) => n,
            Err(Error::IO(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = evt_tx.send(ReaderEvent::Eof);
                break;
            }
            Err(_) => {
                let _ = evt_tx.send(ReaderEvent::ReadError);
                break;
            }
        };
        #[cfg(feature = "_test_hooks")]
        if hooks
            .fail_next_read
            .as_ref()
            .is_some_and(|f| f.swap(false, Ordering::SeqCst))
        {
            let _ = evt_tx.send(ReaderEvent::ReadError);
            break;
        }
        if n == 0 || buffer.buffer.len() < 5 {
            let _ = evt_tx.send(ReaderEvent::Eof);
            break;
        }

        // I5: every packet that consumed a wire seqn (open succeeded).
        // Payload bytes = decrypted inner payload (buffer[5..]), matching
        // outbound SSHBuffer.bytes / cipher.write payload_len.
        let payload_len = buffer.buffer.len().saturating_sub(5) as u64;
        let pkts = packets_this_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        let bytes = bytes_this_epoch.fetch_add(payload_len, Ordering::AcqRel) + payload_len;
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = observe {
            o.set_packets_this_epoch(pkts);
            o.set_bytes_this_epoch(bytes);
            o.set_seqn(buffer.seqn.0);
        }
        #[cfg(not(feature = "_test_hooks"))]
        let _ = (pkts, bytes);

        // Pin: after a full packet is open, before decompress.
        #[cfg(feature = "_test_hooks")]
        if let Some(ref hold) = hooks.post_read_hold {
            if hold.is_held() {
                if let Some(ref o) = observe {
                    o.set_in_post_read_hold(true);
                }
                tokio::select! {
                    _ = hold.wait_released() => {}
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            if let Some(ref o) = observe {
                                o.set_in_post_read_hold(false);
                            }
                            break;
                        }
                    }
                }
                if let Some(ref o) = observe {
                    o.set_in_post_read_hold(false);
                }
                if *cancel.borrow() {
                    break;
                }
            }
        }

        // Drain enable again: if enable and a complete-packet read became
        // ready in the same select poll, the read arm wins and the mid-read
        // `enable_rx.recv()` arm is not taken. Without this drain the packet
        // would decompress under the old `Decompress::None`.
        //
        // Cutover semantics (zlib@openssh.com): the server enables inbound
        // decompress at the auth-success turn, so every packet not yet
        // decompressed at that point is decoded as compressed. This matches
        // the pre-Reader single loop (`complete_auth_compress_barrier` called
        // `init_decompress` in the reply turn, and read→decompress were
        // adjacent, so the next packet read was already decoded as
        // compressed) and OpenSSH `packet.c`, whose
        // `ssh_packet_enable_delayed_compress` opens MODE_IN together with
        // MODE_OUT when the server *sends* USERAUTH_SUCCESS.
        //
        // Known consequence, unchanged from both of those: RFC 4252 §5.1 lets
        // a client pipeline auth requests, and one sent before it saw
        // USERAUTH_SUCCESS is legally uncompressed — it is decoded as
        // compressed and convicted. No packet-boundary cutover fixes this
        // (that packet *is* the first one after the boundary); only
        // try-compressed-then-raw tolerance would, which neither the draft
        // nor OpenSSH implements. Out of scope here.
        while let Ok(en) = enable_rx.try_recv() {
            en.compression.init_decompress(&mut decompress);
        }

        let pkt = match decompress_packet(&mut decompress, &buffer) {
            Ok(p) => p,
            Err(_) => {
                let _ = evt_tx.send(ReaderEvent::ReadError);
                break;
            }
        };

        let is_newkeys = pkt.buffer.first() == Some(&msg::NEWKEYS);

        if !dispatch_inbound(
            pkt,
            &lanes,
            &ready,
            &ctrl_tx,
            &ctrl_bytes,
            ctrl_budget,
            &evt_tx,
            &hooks,
            &credit,
        ) {
            break 'reader;
        }

        if is_newkeys {
            // Opened NEWKEYS with the OLD epoch and forwarded it. Now wait
            // for the new inbound epoch (already in the channel if key-first).
            // Do not start the next cipher::read until it is installed.
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = observe {
                o.set_awaiting(true);
            }
            let epoch = loop {
                tokio::select! {
                    e = install_rx.recv() => break e,
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            break 'reader;
                        }
                    }
                }
            };
            let Some(epoch) = epoch else {
                debug!("reader: install channel closed while awaiting NEWKEYS epoch");
                break;
            };
            #[cfg(feature = "_test_hooks")]
            if let Some(ref hold) = hooks.apply_hold {
                while hold.is_held() {
                    tokio::select! {
                        _ = hold.wait_released() => {}
                        _ = cancel.changed() => {
                            if *cancel.borrow() {
                                break 'reader;
                            }
                        }
                    }
                }
            }
            let installed_gen = apply_epoch(
                &mut cipher,
                &mut decompress,
                &mut buffer,
                &packets_this_epoch,
                &bytes_this_epoch,
                epoch,
                #[cfg(feature = "_test_hooks")]
                &observe,
                #[cfg(feature = "_test_hooks")]
                hooks.invert_keep_old_decompress,
                #[cfg(feature = "_test_hooks")]
                &hooks.compression_observe,
            );
            let _ = evt_tx.send(ReaderEvent::InstallAckInbound { generation: installed_gen });
        }
    }

    #[cfg(feature = "_test_hooks")]
    if let Some(ref o) = observe {
        o.set_stopped();
        o.set_awaiting(false);
        o.set_in_read_hold(false);
        o.set_in_post_read_hold(false);
    }
}

fn decompress_packet(
    decompress: &mut Decompress,
    buffer: &SSHBuffer,
) -> Result<IncomingSshPacket, Error> {
    let mut decomp = Vec::new();
    Ok(IncomingSshPacket {
        #[allow(clippy::indexing_slicing)] // length checked by caller
        buffer: decompress
            .decompress(&buffer.buffer[5..], &mut decomp)?
            .into(),
        seqn: buffer.seqn,
    })
}

/// Join a Reader task against the shared absolute `grace_at`.
#[cfg(all(test, feature = "_test_hooks"))]
mod mid_read_tests {
    use super::*;
    use crate::msg;
    use crate::sshbuffer::PacketWriter;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    /// Epoch-tagged OpeningKey: XOR payload with `tag`. Wrong epoch cannot
    /// recover msg type (copied from Session unit tests).
    struct TagOpen(u8);
    impl OpeningKey for TagOpen {
        fn decrypt_packet_length(&self, _seqn: u32, packet_length: &[u8]) -> [u8; 4] {
            let mut out = [0u8; 4];
            out.copy_from_slice(&packet_length[..4]);
            out
        }
        fn tag_len(&self) -> usize {
            0
        }
        fn open<'a>(
            &mut self,
            _seqn: u32,
            ciphertext_and_tag: &'a mut [u8],
        ) -> Result<&'a [u8], crate::Error> {
            if ciphertext_and_tag.len() < 5 {
                return Err(crate::Error::IndexOutOfBounds);
            }
            for b in &mut ciphertext_and_tag[5..] {
                *b ^= self.0;
            }
            Ok(&ciphertext_and_tag[4..])
        }
    }

    struct TagSeal(u8);
    impl crate::cipher::SealingKey for TagSeal {
        fn padding_length(&self, payload: &[u8]) -> usize {
            let block_size = 8;
            let padding_len = block_size - ((5 + payload.len()) % block_size);
            if padding_len < 4 {
                padding_len + block_size
            } else {
                padding_len
            }
        }
        fn fill_padding(&self, padding_out: &mut [u8]) {
            for b in padding_out {
                *b = 0;
            }
        }
        fn tag_len(&self) -> usize {
            0
        }
        fn seal(&mut self, _seqn: u32, plaintext: &mut [u8], _tag: &mut [u8]) {
            if plaintext.len() > 5 {
                for b in &mut plaintext[5..] {
                    *b ^= self.0;
                }
            }
        }
    }

    fn seal_with(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut pw = PacketWriter::clear();
        pw.set_cipher(Box::new(TagSeal(tag)));
        pw.packet_raw(payload).unwrap();
        pw.take_pending_wire_bytes().to_vec()
    }

    /// Risk 2 (hard): install while `cipher::read` is mid-packet (`read_exact`
    /// body pending) must not apply. Release → that packet opens with the
    /// **old** tag; NEWKEYS then apply; next packet opens with the **new** tag.
    #[tokio::test]
    async fn mid_read_install_does_not_apply() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let observe = ReaderObserveSlot::new();
        let mid = MidPacketHold::new();
        let hooks = ReaderHooks {
            observe: Some(observe.clone()),
            read_hold: None,
            mid_packet_hold: Some(mid.clone()),
            fail_next_read: None,
            post_read_hold: None,
            apply_hold: None,
            force_ctrl_full: None,
            lane_observe: None,
            inject_zero_data: None,
            inject_until_overflow: None,
            inject_close_for: None,
            window_observe: None,
            ..Default::default()
        };
        let (handle, join, mut ctrl, mut evts) = spawn_reader(
            server,
            Box::new(TagOpen(0x11)),
            SSHBuffer::new(),
            cancel_rx,
            hooks,
        );

        // Warm-up packet, full write, old key.
        let ign = seal_with(0x11, &[msg::IGNORE, 0, 0, 0, 0]);
        client.write_all(&ign).await.unwrap();
        async fn recv_pkt(ctrl: &mut mpsc::UnboundedReceiver<CtrlMsg>) -> IncomingSshPacket {
            match tokio::time::timeout(Duration::from_secs(2), ctrl.recv())
                .await
                .expect("ctrl pkt")
                .expect("ctrl open")
            {
                CtrlMsg::Packet(p) => p,
                other => panic!("expected Packet, got {other:?}"),
            }
        }

        let first = recv_pkt(&mut ctrl).await;
        assert_eq!(first.buffer.first(), Some(&msg::IGNORE));

        // Second IGNORE: deliver only the 4-byte length so cipher::read is
        // parked inside the body `read_exact`.
        let ign2 = seal_with(0x11, &[msg::IGNORE, 0, 0, 0, 1]);
        assert!(ign2.len() > 4, "sealed packet must be longer than length field");
        mid.arm(4);
        client.write_all(&ign2[..4]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !mid.in_flight() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cipher::read in-flight mid-packet");

        handle
            .try_install_inbound(InstallInboundEpoch {
                generation: 7,
                cipher: Box::new(TagOpen(0x22)),
                compression: Compression::None,
                activate_decompress: true,
                reset_seqn: true,
            })
            .expect("cap-1 install");
        assert!(observe.queued(), "epoch must sit in the channel");
        assert_eq!(
            observe.applied_gen(),
            0,
            "HARD: must not apply while cipher::read is mid-packet"
        );
        assert_eq!(observe.applies(), 0);

        client.write_all(&ign2[4..]).await.unwrap();
        mid.release();
        let second = recv_pkt(&mut ctrl).await;
        assert_eq!(
            second.buffer.first(),
            Some(&msg::IGNORE),
            "HARD: in-flight packet must open with OLD tag 0x11 (new tag 0x22 would scramble type)"
        );
        assert_eq!(observe.applied_gen(), 0, "IGNORE is not NEWKEYS");

        // NEWKEYS under old tag → apply new tag.
        let nk = seal_with(0x11, &[msg::NEWKEYS]);
        client.write_all(&nk).await.unwrap();
        let nk_pkt = recv_pkt(&mut ctrl).await;
        assert_eq!(nk_pkt.buffer.first(), Some(&msg::NEWKEYS));
        tokio::time::timeout(Duration::from_secs(2), async {
            while observe.applied_gen() != 7 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("applied after NEWKEYS");
        assert_eq!(observe.applies(), 1);
        let ev = evts.recv().await.expect("ack event");
        match ev {
            ReaderEvent::InstallAckInbound { generation } => assert_eq!(generation, 7),
            other => panic!("expected inbound ack, got {other:?}"),
        }

        // Post-install packet must open with NEW tag.
        let ign3 = seal_with(0x22, &[msg::IGNORE, 0, 0, 0, 2]);
        client.write_all(&ign3).await.unwrap();
        let third = recv_pkt(&mut ctrl).await;
        assert_eq!(
            third.buffer.first(),
            Some(&msg::IGNORE),
            "HARD: post-NEWKEYS packet must open with NEW tag 0x22"
        );

        drop(client);
        let _ = join.await;
    }

    /// Enable arriving after `cipher::read` returns, before decompress:
    /// the production race (read arm wins the same poll as `enable_rx`).
    /// Without the post-read drain this IGNORE is junk; with it, zlib applies.
    #[cfg(feature = "flate2")]
    #[tokio::test]
    async fn enable_after_read_before_decompress_applies() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let observe = ReaderObserveSlot::new();
        let post = ReadHoldGate::new();
        let hooks = ReaderHooks {
            observe: Some(observe.clone()),
            read_hold: None,
            mid_packet_hold: None,
            fail_next_read: None,
            post_read_hold: Some(post.clone()),
            apply_hold: None,
            force_ctrl_full: None,
            lane_observe: None,
            inject_zero_data: None,
            inject_until_overflow: None,
            inject_close_for: None,
            window_observe: None,
            ..Default::default()
        };
        let (handle, join, mut ctrl, _evts) = spawn_reader(
            server,
            Box::new(TagOpen(0x11)),
            SSHBuffer::new(),
            cancel_rx,
            hooks,
        );

        async fn recv_pkt(ctrl: &mut mpsc::UnboundedReceiver<CtrlMsg>) -> IncomingSshPacket {
            match tokio::time::timeout(Duration::from_secs(2), ctrl.recv())
                .await
                .expect("ctrl pkt")
                .expect("ctrl open")
            {
                CtrlMsg::Packet(p) => p,
                other => panic!("expected Packet, got {other:?}"),
            }
        }

        // Warm-up uncompressed IGNORE so seqn/cipher are live.
        let ign = seal_with(0x11, &[msg::IGNORE, 0, 0, 0, 0]);
        client.write_all(&ign).await.unwrap();
        let first = recv_pkt(&mut ctrl).await;
        assert_eq!(first.buffer.first(), Some(&msg::IGNORE));

        // Arm hold *after* warmup so it pins the compressed packet.
        post.hold();
        let payload = [msg::IGNORE, 0, 0, 0, 1];
        let mut compress = crate::compression::Compress::None;
        Compression::ZlibOpenSSH.init_compress(&mut compress);
        let mut tmp = Vec::new();
        let compressed = compress.compress(&payload, &mut tmp).unwrap().to_vec();
        assert_ne!(
            compressed.first(),
            Some(&msg::IGNORE),
            "compressed bytes must not look like plaintext IGNORE"
        );
        let zlib_ign = seal_with(0x11, &compressed);
        client.write_all(&zlib_ign).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !observe.in_post_read_hold() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("reader parked after open, before decompress");

        assert!(
            handle.try_enable_decompress(Compression::ZlibOpenSSH).is_ok(),
            "enable queue"
        );
        post.release();

        let second = recv_pkt(&mut ctrl).await;
        assert_eq!(
            second.buffer.as_slice(),
            payload.as_slice(),
            "HARD: enable queued after read must apply before decompress"
        );

        drop(client);
        let _ = join.await;
    }
}

pub async fn stop_reader_task(
    join: &mut Option<JoinHandle<()>>,
    grace_at: tokio::time::Instant,
) {
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
                        debug!("reader join: cancelled (expected after abort)");
                    }
                    Err(e) if e.is_panic() => {
                        log::warn!("reader task panicked during stop: {e}");
                    }
                    Err(e) => {
                        log::warn!("reader join error: {e}");
                    }
                }
                return;
            }
            _ = tokio::time::sleep_until(grace_at), if !timed_out => {
                debug!("reader grace elapsed → abort");
                abort.abort();
                timed_out = true;
            }
        }
    }
}

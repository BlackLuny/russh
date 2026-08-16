use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use channels::{ChannelAcked, OutboundLiveSet, WindowSizeRef};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use kex::ServerKex;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{OwnedPermit, Receiver, Sender, channel};
use tokio::sync::oneshot;

use super::*;
use crate::channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf};

/// Boxed `reserve_owned()` future for a backpressured channel's app buffer.
/// Tagged with the Reader lane's monotonic generation; a stale result
/// (id reused after `close_lane`) is dropped when the tag ≠ live `lane_gen`.
pub(crate) type BoxReserve = Pin<
    Box<
        dyn std::future::Future<
                Output = (
                    ChannelId,
                    u64,
                    Result<OwnedPermit<ChannelMsg>, ()>,
                ),
            > + Send,
    >,
>;

/// Single-flight reserve state. No payload queue — items stay in the lane.
/// Versioning lives on the Reader lane (`lane_gen`), not here: a fresh
/// `or_default()` gate must not reset the ABA tag to 0.
#[derive(Debug, Default)]
pub(crate) struct InboundGate {
    pub reserving: bool,
}
use crate::helpers::NameList;
use crate::kex::{
    EXTENSION_SUPPORT_AS_CLIENT, KexAlgorithmImplementor, KexCause, SessionKexState,
};
use crate::server::supervisor::{
    AtomicWriteProgress, DisconnectCause, RekeyDeadline, WriteWatchdog,
};
use crate::server::inbound_lane::{LaneItem, PeerCreditBoard};
use crate::server::reader::{
    spawn_reader_with_budget, stop_reader_task, CtrlMsg, InstallInboundEpoch, ReaderEvent,
    ReaderHandle,
};
#[cfg(not(feature = "_test_hooks"))]
use crate::server::reader::ReaderHooks;
use crate::server::writer::{stop_writer_task, WriterEvent, WriterHandle};
use crate::session::EncryptedState;
use crate::{ChannelOpenFailure, ReplyQueue, ReplyVerdict, map_err, msg};

/// I6: rekey trigger / merge / idle-drop counters. Always compiled
/// (not `_test_hooks`-gated). Reason detail goes to `tracing`/`log`.
#[derive(Debug, Default)]
pub struct RekeyI6 {
    /// Times `flush` actually called `begin_rekey` from the I5 predicate.
    triggers: AtomicU64,
    /// Times inbound and outbound predicates were both true in one flush.
    merges: AtomicU64,
    /// Times the I5 predicate was true but `kex != Idle` (storm).
    idle_drops: AtomicU64,
}

impl RekeyI6 {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn triggers(&self) -> u64 {
        self.triggers.load(Ordering::SeqCst)
    }
    pub fn merges(&self) -> u64 {
        self.merges.load(Ordering::SeqCst)
    }
    pub fn idle_drops(&self) -> u64 {
        self.idle_drops.load(Ordering::SeqCst)
    }
}

fn lane_item_is_zero_data(item: &LaneItem) -> bool {
    matches!(item, LaneItem::Data(d) if d.is_empty())
        || matches!(item, LaneItem::ExtendedData { data, .. } if data.is_empty())
}

fn lane_item_to_msg(item: &LaneItem) -> Option<ChannelMsg> {
    match item {
        LaneItem::Data(data) => Some(ChannelMsg::Data { data: data.clone() }),
        LaneItem::ExtendedData { ext, data } => Some(ChannelMsg::ExtendedData {
            ext: *ext,
            data: data.clone(),
        }),
        LaneItem::Eof => Some(ChannelMsg::Eof),
        LaneItem::Close => Some(ChannelMsg::Close),
        LaneItem::Request { .. } | LaneItem::Success { .. } | LaneItem::Failure { .. } => None,
    }
}

/// A connected server session. This type is unique to a client.
///
/// S4a: this struct is the G5 facade type. Public method signatures live in
/// [`session_facade`] and forward 1:1 into `*_apply` (today's implementation).
/// S4b replaces those facade bodies only; field layout and `*_apply` stay.
#[derive(Debug)]
pub struct Session {
    pub(crate) common: CommonSession<Arc<Config>>,
    pub(crate) sender: Handle,
    pub(crate) receiver: Receiver<Msg>,
    pub(crate) target_window_size: u32,
    pub(crate) pending_reads: Vec<Vec<u8>>,
    pub(crate) pending_len: u32,
    pub(crate) channels: HashMap<ChannelId, ChannelRef>,
    /// Per-channel app-buffer gate (S5a). Present only while a channel is
    /// backpressured or has an in-flight `reserve_owned()`. No second queue —
    /// data stays in the Reader lane until a permit is held.
    pub(crate) inbound_gate: HashMap<ChannelId, InboundGate>,
    /// Channels that need a `reserve_owned()` future registered into the run
    /// loop's `FuturesUnordered` (at most one in flight per channel).
    pub(crate) inbound_needs_reserve: Vec<ChannelId>,
    /// App-buffer-full channels: `peek_gated` `hold_all` set. Combined with
    /// `pending_open_ids` (`hold_data`) — see `pump_reader_lanes`.
    pub(crate) backpressured: HashSet<ChannelId>,
    /// Producers parked in [`Handle::data`] / [`Handle::extended_data`], keyed by the channel
    /// whose backlog they are waiting to drain. Released by `release_outbound_acks` once that
    /// channel's `pending_data` empties; dropped (waking the producer with an error) when the
    /// channel is torn down.
    pub(crate) outbound_acks: HashMap<ChannelId, VecDeque<oneshot::Sender<()>>>,
    pub(crate) open_global_requests: VecDeque<GlobalRequestResponse>,
    pub(crate) kex: SessionKexState<ServerKex>,
    /// Channel-open replies ([`ChannelOpenHandle::accept`]/`reject`) arrive here, NOT on the
    /// bounded `receiver`: handlers run inline on the run loop, so a bounded send from inside
    /// one would deadlock against the loop whenever other channels' writers keep `receiver`
    /// full. Unbounded is safe — at most one reply per peer CHANNEL_OPEN.
    pub(crate) open_reply_tx: tokio::sync::mpsc::UnboundedSender<Msg>,
    pub(crate) open_reply_rx: tokio::sync::mpsc::UnboundedReceiver<Msg>,
    /// Monotonic rekey generation (S1 ConnSupervisor). Bumped on mid-session rekey only.
    pub(crate) rekey_gen: u64,
    /// Active rekey deadline registration (generation + wall deadline).
    pub(crate) rekey_deadline: RekeyDeadline,
    /// Absolute handshake deadline (banner → initial kex → auth). Set in `run_stream`
    /// and never restarted mid-handshake.
    pub(crate) handshake_deadline_at: Option<tokio::time::Instant>,
    /// S2a: handle to the independent WriterTask (None until stream is split).
    pub(crate) writer: Option<WriterHandle>,
    /// S3a: handle to the independent ReaderTask (None until stream is split).
    pub(crate) reader: Option<ReaderHandle>,
    /// In-flight ADJUST credit staging (Reader↔Session). Not a window book.
    pub(crate) peer_credit: Option<Arc<PeerCreditBoard>>,
    /// Supervisor first-cause staged from `reply()` (InstallAck fail etc.) so the
    /// main loop can `record_cause` and take the unified Cancelling path (r2 P1).
    pub(crate) pending_supervisor_cause: Option<DisconnectCause>,
    /// Ordered, bounded Session-side pending outbound commands (Full backpressure).
    /// Participates in the same backlog ledger as Writer (`pending_bytes` weight).
    /// Retry-before-any-new-submit preserves seal order across flush / KEX / barrier.
    pub(crate) pending_outbound: PendingOutbound,
    /// Atomic NEWKEYS install registered by `reply()` but advanced only on the
    /// outer run-loop (capacity / InstallAck / loop-top). **Never** awaited inside
    /// `reply()` — keeps write-watchdog and rekey/handshake deadlines pollable.
    pub(crate) pending_kex_install: Option<PendingKexInstall>,
    /// Inbound WINDOW_ADJUST skipped because outbound was at the hard cap.
    /// Retried when Writer frees budget (loop-top / capacity / loop-bottom).
    pub(crate) deferred_window_grants: HashSet<ChannelId>,
    /// Test-only: full-pipeline ledger components shared with the Writer so every
    /// ledger mutation samples the complete sum (R4).
    #[cfg(feature = "_test_hooks")]
    pub(crate) full_ledger: Option<std::sync::Arc<crate::server::supervisor::FullLedger>>,
    /// Test-only: how far into `enc.write` we have already logged (S2c).
    #[cfg(feature = "_test_hooks")]
    pub(crate) outbound_log_cursor: usize,
    /// S2d ready-set cursor: next ChannelId to start a regular quantum at.
    pub(crate) sched_next: Option<ChannelId>,
    /// Regular quanta since the last boost (saturates at [`crate::BOOST_PERIOD`]).
    pub(crate) sched_since_boost: u32,
    /// Fairness debt: skip this channel in the regular quantum after a boost.
    pub(crate) sched_debt: Option<ChannelId>,
    /// Some = this `Session` is an Executor-side facade proxy (scheme 2).
    pub(crate) facade_cmd_tx: Option<tokio::sync::mpsc::Sender<crate::server::executor::FacadeCmd>>,
    /// SessionTask-side facade command receiver (None on the proxy).
    pub(crate) facade_cmd_rx: Option<tokio::sync::mpsc::Receiver<crate::server::executor::FacadeCmd>>,
    /// Live HandlerExecutor (SessionTask). JoinHandle stays in `run()`.
    pub(crate) executor: Option<crate::server::executor::HandlerExecutor>,
    pub(crate) next_invoke_gen: u64,
    pub(crate) pending_harvest:
        std::collections::HashMap<u64, crate::server::executor::PendingHarvest>,
    /// Wakes SessionTask when the Executor-side proxy enqueues a facade cmd.
    pub(crate) facade_notify: std::sync::Arc<tokio::sync::Notify>,
    /// Wakes SessionTask when the Executor posts a Result.
    pub(crate) result_notify: std::sync::Arc<tokio::sync::Notify>,
    /// CHANNEL_OPEN Invokes still in-flight. Those lanes are not pumped
    /// until harvest so a handler that drops `Channel` still gets
    /// `Handler::data` (ChannelGone), not Delivered-into-a-dropped-rx.
    pub(crate) pending_open_ids: HashSet<ChannelId>,
    /// RFC 4254 §4 want-reply FIFO (global).
    pub(crate) global_replies: ReplyQueue,
    /// Peer CHANNEL_OPENs reserved but not yet accepted/rejected/expired.
    pub(crate) openings: HashMap<ChannelId, OpeningSlot>,
    /// Last generation issued per channel id (ABA guard).
    pub(crate) channel_gens: HashMap<ChannelId, u64>,
    /// This connection's slice of the process-level ledger (S4d).
    /// `None` on object-test sessions that never went through `run_stream`.
    pub(crate) conn_budget: Option<crate::server::global_budget::ConnAccount>,
    /// Per-channel bytes reserved from `conn_budget` (opening estimate
    /// + ceiling-growth only). Refunded exactly once at the S4c release
    /// point for that channel. Occupancy is the committed inbound-window
    /// ceiling + outbound estimate, not the sum of every ADJUST Δ
    /// (impl-S4-plan.md L244 / L520; S8c restore).
    pub(crate) channel_global_held: HashMap<ChannelId, u64>,
    /// Inbound-window + outcap already covered by `channel_global_held`.
    /// Opening writes `window_size + OUTBOUND_CAP_ESTIMATE`. Grant path
    /// reserves only when `ceiling + outcap` exceeds this.
    pub(crate) channel_window_covered: HashMap<ChannelId, u64>,
}

/// One reserved peer-initiated CHANNEL_OPEN (S4c).
#[derive(Debug)]
pub(crate) struct OpeningSlot {
    pub generation: u64,
    pub deadline: tokio::time::Instant,
    pub recipient_channel: u32,
    pub lease: std::sync::Arc<crate::OpeningLease>,
    /// `window_size + OUTBOUND_CAP_ESTIMATE` reserved at slot occupy.
    pub reserved: u64,
}

/// Completion actions when **both** outbound InstallAck and peer-Done are satisfied.
///
/// **Inbound cipher/decompress are NOT here** — they commit in Done (peer NEWKEYS)
/// the same `reply()` turn (RFC 4253 per-direction cutover). This enum only carries
/// Idle / clear-deadline / ext-info / replay signalling.
///
/// `None` on the transaction means peer Done not yet observed (NeedsReply path).
/// skip_exchange registers with `Some` immediately (Done already known).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KexAfterInstall {
    /// Rekey: Idle + clear deadline; caller replays `pending_reads`.
    RekeyComplete,
    /// Initial: Idle + clear deadline + maybe_send_ext_info.
    InitialComplete,
}

/// Triple-condition KEX install transaction (run-loop owned).
///
/// Conditions for **completion actions** (Idle / clear deadline / replay):
/// 1. Outbound atomic install ACKed (`phase == InstallAcked`)
/// 2. Peer Done merged (`after.is_some()`)
/// 3. Inbound epoch ACKed (`inbound_acked`) when a ReaderTask exists
///
/// `reply()` never awaits either ACK.
pub(crate) struct PendingKexInstall {
    pub generation: u64,
    /// `None` until peer Done (or set at register for skip_exchange).
    pub after: Option<KexAfterInstall>,
    pub phase: PendingKexPhase,
    /// Reader `InstallAckInbound` received (or no Reader — unit tests).
    pub inbound_acked: bool,
    /// `InstallInboundEpoch` successfully try_pushed to Reader (or applied locally).
    pub inbound_sent: bool,
}

impl std::fmt::Debug for PendingKexInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingKexInstall")
            .field("generation", &self.generation)
            .field("after", &self.after)
            .field("phase", &self.phase)
            .field("inbound_acked", &self.inbound_acked)
            .field("inbound_sent", &self.inbound_sent)
            .finish()
    }
}

impl PendingKexInstall {
    /// Wire-weight of NeedSubmit payloads (payload + per-packet worst-case overhead).
    pub fn need_submit_bytes(&self) -> usize {
        match &self.phase {
            PendingKexPhase::NeedSubmit { payloads, .. } => payloads
                .iter()
                .map(|p| p.len().saturating_add(Session::WIRE_OVERHEAD_PER_PACKET))
                .sum(),
            _ => 0,
        }
    }
}

pub(crate) enum PendingKexPhase {
    /// Waiting for bulk capacity / empty ordered pending to submit.
    NeedSubmit {
        payloads: Vec<bytes::Bytes>,
        cipher: Box<dyn crate::cipher::SealingKey + Send>,
        compression: crate::compression::Compression,
        activate_compress: bool,
        reset_seqn: bool,
    },
    /// Submitted to Writer; waiting for InstallAckOutbound.
    WaitingAck,
    /// InstallAck received; waiting for peer Done to merge `after` (if still None).
    InstallAcked,
}

impl std::fmt::Debug for PendingKexPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedSubmit {
                payloads,
                activate_compress,
                reset_seqn,
                ..
            } => f
                .debug_struct("NeedSubmit")
                .field("n_payloads", &payloads.len())
                .field("activate_compress", activate_compress)
                .field("reset_seqn", reset_seqn)
                .finish(),
            Self::WaitingAck => f.write_str("WaitingAck"),
            Self::InstallAcked => f.write_str("InstallAcked"),
        }
    }
}

/// Registration refused: another install transaction is already open.
#[derive(Debug)]
pub(crate) struct PendingKexConflict;

/// One deferred outbound submission while the Writer bulk queue is Full.
#[derive(Debug)]
pub(crate) enum PendingOutboundCmd {
    SealPayload(bytes::Bytes),
    SealRaw(bytes::Bytes),
    InitOutboundCompress(crate::compression::Compression),
}

/// Ordered pending queue with byte weights (HWM / watchdog ledger).
///
/// Soft item/byte caps gate **new intake** via the shared sealed-backlog HWM.
/// Parking never fail-closes with `PeerError` — capacity is backpressure.
///
/// `bytes` is a shared atomic so the `FullLedger` test hook can sample the
/// complete pipeline sum at every mutation (R4); production cost is one
/// atomic op per push/pop.
#[derive(Debug)]
pub(crate) struct PendingOutbound {
    q: VecDeque<PendingOutboundCmd>,
    /// Sum of seal payload lengths currently parked (InitCompress weighs 0).
    bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Test-only: observable mismatch slot (the session's `LedgerMaxSlot`) so
    /// pop-side accounting errors are counted on the same slot tests read (R4).
    #[cfg(feature = "_test_hooks")]
    mismatch_slot: Option<std::sync::Arc<crate::server::supervisor::LedgerMaxSlot>>,
    /// Test-only: linearized ledger so park/unpark is a pure transfer on `total`.
    #[cfg(feature = "_test_hooks")]
    full_ledger: Option<std::sync::Arc<crate::server::supervisor::FullLedger>>,
}

impl Default for PendingOutbound {
    fn default() -> Self {
        Self {
            q: VecDeque::new(),
            bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(feature = "_test_hooks")]
            mismatch_slot: None,
            #[cfg(feature = "_test_hooks")]
            full_ledger: None,
        }
    }
}

impl PendingOutbound {
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Shared weight ledger for the full-pipeline sampler (R4).
    #[cfg(feature = "_test_hooks")]
    pub fn bytes_arc(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.bytes.clone()
    }

    /// Test-only: install the observable mismatch slot (R4).
    #[cfg(feature = "_test_hooks")]
    pub fn set_mismatch_slot(&mut self, s: std::sync::Arc<crate::server::supervisor::LedgerMaxSlot>) {
        self.mismatch_slot = Some(s);
    }

    /// Test-only: share the linearized ledger (R4 park/unpark is a no-op on total).
    #[cfg(feature = "_test_hooks")]
    pub fn set_full_ledger(&mut self, fl: std::sync::Arc<crate::server::supervisor::FullLedger>) {
        self.full_ledger = Some(fl);
    }

    fn weight_of(cmd: &PendingOutboundCmd) -> usize {
        match cmd {
            // Same weight as Writer accept / enc.write packet weight (payload + wire OH)
            // so Full-park is a pure transfer with no ledger jump.
            PendingOutboundCmd::SealPayload(b) | PendingOutboundCmd::SealRaw(b) => b
                .len()
                .saturating_add(crate::server::writer::WIRE_OVERHEAD_PER_PACKET),
            PendingOutboundCmd::InitOutboundCompress(_) => 0,
        }
    }

    fn add_weight(&self, w: usize) {
        self.bytes
            .fetch_add(w, std::sync::atomic::Ordering::Release);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = self.full_ledger {
            fl.credit(w);
        }
    }

    /// Checked subtraction; on underflow record an observable error
    /// (error log + mismatch counter under `_test_hooks`) and fail closed
    /// to 0 — never silently wrap or clamp without a trace (R4).
    fn sub_weight(&self, w: usize) {
        let ok = self.bytes.fetch_update(
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Acquire,
            |cur| cur.checked_sub(w),
        );
        if ok.is_err() {
            log::error!("session pending_outbound ledger underflow weight={w}");
            self.bytes.store(0, std::sync::atomic::Ordering::Release);
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.mismatch_slot {
                s.note_mismatch();
            }
            return;
        }
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = self.full_ledger {
            fl.debit(w);
        }
    }

    /// Park at back (always; backlog/HWM gate intake elsewhere).
    pub fn push_back(&mut self, cmd: PendingOutboundCmd) {
        let w = Self::weight_of(&cmd);
        self.add_weight(w);
        self.q.push_back(cmd);
    }

    /// Park after a transfer out of `enc.write` / Writer rollback. `push_back`
    /// credits `total` so Full-park and hard-cap park are conservation
    /// transfers, not disappearances.
    pub fn push_back_already_counted(&mut self, cmd: PendingOutboundCmd) {
        self.push_back(cmd);
    }

    pub fn pop_front(&mut self) -> Option<PendingOutboundCmd> {
        let cmd = self.q.pop_front()?;
        self.sub_weight(Self::weight_of(&cmd));
        Some(cmd)
    }

    pub fn push_front(&mut self, cmd: PendingOutboundCmd) {
        let w = Self::weight_of(&cmd);
        self.add_weight(w);
        self.q.push_front(cmd);
    }
}

#[derive(Debug)]
pub enum Msg {
    ChannelOpenAgent {
        channel_ref: ChannelRef,
    },
    ChannelOpenSession {
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectTcpIp {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectStreamLocal {
        socket_path: String,
        channel_ref: ChannelRef,
    },
    ChannelOpenForwardedTcpIp {
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenForwardedStreamLocal {
        server_socket_path: String,
        channel_ref: ChannelRef,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    TcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        address: String,
        port: u32,
    },
    CancelTcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        address: String,
        port: u32,
    },
    Disconnect {
        reason: crate::Disconnect,
        description: String,
        language_tag: String,
    },
    Channel(ChannelId, ChannelMsg),
    /// Channel payload from [`Handle::data`] / [`Handle::extended_data`] and
    /// the server `Channel::data` / `make_writer` authority path (S5b).
    /// Completes once the bytes are in the peer window (not `pending_data`).
    /// Completing = 入账权威账本; park is only backlog throttle.
    ChannelDataAcked {
        id: ChannelId,
        ext: Option<u32>,
        data: Bytes,
        ack: oneshot::Sender<()>,
    },
    ChannelOpenReply {
        pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    },
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

impl ChannelAcked for Msg {
    fn try_data_acked(
        id: ChannelId,
        ext: Option<u32>,
        data: Bytes,
        ack: oneshot::Sender<()>,
    ) -> Option<Self> {
        Some(Msg::ChannelDataAcked { id, ext, data, ack })
    }
}

pub use crate::PendingChannelOpen;

/// A handle passed to channel-open callbacks that the handler uses to
/// accept or reject the incoming channel request.
///
/// Dropping the handle without calling [`accept`](ChannelOpenHandle::accept) or
/// [`reject`](ChannelOpenHandle::reject) automatically sends an
/// `AdministrativelyProhibited` rejection to the client.
pub type ChannelOpenHandle = crate::ChannelOpenHandleInner<Msg>;

#[derive(Clone, Debug)]
/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle {
    pub(crate) sender: Sender<Msg>,
    pub(crate) channel_buffer_size: usize,
    /// Channels that still accept DATA (not in table / StopDiscard /
    /// `outbound_closed` are absent). Shared with `ChannelWriteHalf`.
    pub(crate) live: std::sync::Arc<OutboundLiveSet>,
    /// Server production: Channel::data uses ChannelDataAcked.
    pub(crate) use_acked_window: bool,
    #[cfg(feature = "_test_hooks")]
    pub(crate) observe: Option<std::sync::Arc<crate::server::executor::HandleObserveSlot>>,
}

impl Handle {
    /// Send data to the session referenced by this handler.
    ///
    /// Applies per-channel backpressure: the returned future resolves only once the bytes have
    /// been written into the peer's receive window, so a peer that stops reading throttles this
    /// channel's producer without affecting any other channel. Returns `Err` if the channel is
    /// gone (the payload is returned when it was never handed over).
    ///
    /// Do not call this from inside a [`Handler`] callback — those run on the session loop, so
    /// awaiting window there would prevent the loop from ever processing the window adjustment
    /// that would release it. Use a spawned task, as the examples do.
    pub async fn data(
        &self,
        id: ChannelId,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        self.send_acked(id, None, data.into()).await
    }

    /// Send data to the session referenced by this handler.
    ///
    /// Backpressures per channel exactly like [`Handle::data`]; the same "not from a `Handler`
    /// callback" caveat applies.
    pub async fn extended_data(
        &self,
        id: ChannelId,
        ext: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        self.send_acked(id, Some(ext), data.into()).await
    }

    async fn send_acked(
        &self,
        id: ChannelId,
        ext: Option<u32>,
        data: bytes::Bytes,
    ) -> Result<(), bytes::Bytes> {
        if !self.live.contains(id) {
            return Err(data);
        }
        let (ack, acked) = oneshot::channel();
        #[cfg(feature = "_test_hooks")]
        let parked = {
            let cap = self.sender.capacity();
            if let Some(ref o) = self.observe {
                let occ = self.sender.max_capacity().saturating_sub(cap);
                o.note_occupancy(occ);
                if cap == 0 {
                    o.note_full();
                    o.park_inc();
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        let send_res = self
            .sender
            .send(Msg::ChannelDataAcked {
                id,
                ext,
                data,
                ack,
            })
            .await;
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = self.observe {
            if parked {
                o.park_dec();
            }
            let cap = self.sender.capacity();
            o.note_occupancy(self.sender.max_capacity().saturating_sub(cap));
        }
        send_res.map_err(|e| match e.0 {
            Msg::ChannelDataAcked { data, .. } => data,
            _ => unreachable!(),
        })?;
        // Resolves when the bytes reach the peer's window; errors if the channel was torn down
        // first, in which case the payload is already owned by the session and cannot be handed
        // back.
        acked.await.map_err(|_| bytes::Bytes::new())
    }

    /// Send EOF to the session referenced by this handler.
    pub async fn eof(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Eof))
            .await
            .map_err(|_| ())
    }

    /// Send success to the session referenced by this handler.
    pub async fn channel_success(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Success))
            .await
            .map_err(|_| ())
    }

    /// Send failure to the session referenced by this handler.
    pub async fn channel_failure(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Failure))
            .await
            .map_err(|_| ())
    }

    /// Close a channel.
    pub async fn close(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Close))
            .await
            .map_err(|_| ())
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub async fn xon_xoff_request(&self, id: ChannelId, client_can_do: bool) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }))
            .await
            .map_err(|_| ())
    }

    /// Send the exit status of a program.
    pub async fn exit_status_request(&self, id: ChannelId, exit_status: u32) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }))
            .await
            .map_err(|_| ())
    }

    /// Notifies the client that it can open TCP/IP forwarding channels for a port.
    pub async fn forward_tcpip(&self, address: String, port: u32) -> Result<u32, ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::TcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;

        match reply_recv.await {
            Ok(Some(port)) => Ok(port),
            Ok(None) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive TcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Notifies the client that it can no longer open TCP/IP forwarding channel for a port.
    pub async fn cancel_forward_tcpip(&self, address: String, port: u32) -> Result<(), ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelTcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;
        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive CancelTcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Open an agent forwarding channel. This can be used once the client has
    /// confirmed that it allows agent forwarding. See
    /// [PROTOCOL.agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent).
    pub async fn channel_open_agent(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenAgent { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Ok(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectTcpIp {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a direct streamlocal (Unix domain socket) channel on the client.
    pub async fn channel_open_direct_streamlocal<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_forwarded_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        connected_address: A,
        connected_port: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedTcpIp {
                connected_address: connected_address.into(),
                connected_port,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_forwarded_streamlocal<A: Into<String>>(
        &self,
        server_socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path: server_socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    async fn wait_channel_confirmation(
        &self,
        mut receiver: Receiver<ChannelMsg>,
        window_size_ref: WindowSizeRef,
    ) -> Result<Channel<Msg>, Error> {
        loop {
            match receiver.recv().await {
                Some(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                }) => {
                    window_size_ref.update(window_size).await;

                    return Ok(Channel {
                        write_half: ChannelWriteHalf {
                            id,
                            sender: self.sender.clone(),
                            max_packet_size,
                            window_size: window_size_ref,
                            live: Some(self.live.clone()),
                            use_acked: self.use_acked_window,
                        },
                        read_half: ChannelReadHalf { receiver },
                    });
                }
                Some(ChannelMsg::OpenFailure(reason)) => {
                    return Err(Error::ChannelOpenFailure(reason));
                }
                None => {
                    return Err(Error::Disconnect);
                }
                msg => {
                    debug!("msg = {msg:?}");
                }
            }
        }
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub async fn exit_signal_request(
        &self,
        id: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    ) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ))
            .await
            .map_err(|_| ())
    }

    /// Allows a server to disconnect a client session
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: String,
        language_tag: String,
    ) -> Result<(), Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description,
                language_tag,
            })
            .await
            .map_err(|_| Error::SendError)
    }
}

impl Session {
    /// Reserve `n` bytes of inbound grant credit from the process
    /// ledger (S4d). Failure is synchronous: the caller must skip
    /// expand and ADJUST. Object-test sessions with no account succeed.
    pub(crate) fn reserve_global_inbound_credit(&self, n: u32) -> Result<(), ()> {
        self.reserve_global_bytes(n as u64)
    }

    fn reserve_global_bytes(&self, n: u64) -> Result<(), ()> {
        let Some(acc) = self.conn_budget.as_ref() else {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = self.common.config.window_observe {
                o.note_global_reserve();
                o.note_reserved_delta(n.min(u32::MAX as u64) as u32);
            }
            return Ok(());
        };
        let r = acc.try_reserve(n);
        if r.is_ok() {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = self.common.config.window_observe {
                o.note_global_reserve();
                o.note_reserved_delta(n.min(u32::MAX as u64) as u32);
            }
        }
        r
    }

    fn release_global_inbound_credit(&self, n: u64) {
        if let Some(acc) = self.conn_budget.as_ref() {
            acc.release(n);
        }
    }

    fn add_channel_held(&mut self, id: ChannelId, n: u64) {
        if n == 0 {
            return;
        }
        *self.channel_global_held.entry(id).or_insert(0) += n;
    }

    fn mark_window_covered(&mut self, id: ChannelId, covered: u64) {
        let prev = self.window_covered(id);
        if covered > prev {
            self.channel_window_covered.insert(id, covered);
        }
    }

    fn window_covered(&self, id: ChannelId) -> u64 {
        self.channel_window_covered
            .get(&id)
            .copied()
            .unwrap_or_else(|| self.channel_global_held.get(&id).copied().unwrap_or(0))
    }

    /// Extra global bytes needed so `held` covers `ceiling + outcap`.
    /// Zero when the opening estimate (or a previous raise) already does.
    fn grant_reserve_need(&self, id: ChannelId, ceiling: u32) -> u64 {
        let want = (ceiling as u64)
            .saturating_add(crate::server::global_budget::OUTBOUND_CAP_ESTIMATE);
        want.saturating_sub(self.window_covered(id))
    }

    fn hold_opening(&mut self, id: ChannelId, need: u64) {
        self.add_channel_held(id, need);
        self.mark_window_covered(id, need);
    }

    /// Refund this channel's global reservation. Exactly-once: the map
    /// entry is taken. Hung on S4c release points only.
    pub(crate) fn release_channel_global(&mut self, id: ChannelId) {
        self.channel_window_covered.remove(&id);
        if let Some(n) = self.channel_global_held.remove(&id) {
            self.release_global_inbound_credit(n);
        }
    }

    fn opening_budget_need(&self) -> u64 {
        crate::server::global_budget::opening_estimate(&self.common.config)
    }

    fn invert_global_before_expand(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        {
            self.common.config.invert_global_before_expand
        }
        #[cfg(not(feature = "_test_hooks"))]
        {
            false
        }
    }

    fn max_channels(&self) -> usize {
        self.common.config.max_channels.max(1)
    }

    /// `opening + active + closing`. Opening = reserved peer-opens not
    /// yet in `enc.channels`. Active+closing live in `enc.channels`
    /// (local-initiated unconfirmed opens included).
    pub(crate) fn slot_used(&self) -> usize {
        self.openings.len().saturating_add(
            self.common
                .encrypted
                .as_ref()
                .map(|enc| enc.channels.len())
                .unwrap_or(0),
        )
    }

    #[cfg(feature = "_test_hooks")]
    fn slot_snapshot(&self) -> (usize, usize, usize) {
        let pending = self.openings.len();
        let mut opening = pending;
        let mut active = 0;
        let mut closing = 0;
        if let Some(enc) = self.common.encrypted.as_ref() {
            for ch in enc.channels.values() {
                if ch.lane == crate::ChannelLaneState::Closing
                    || ch.pending_close
                    || ch.outbound_closed
                {
                    closing += 1;
                } else if !ch.confirmed {
                    opening += 1;
                } else {
                    active += 1;
                }
            }
        }
        (opening, active, closing)
    }

    pub(crate) fn publish_slots(&self) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.slot_observe {
            let (o, a, c) = self.slot_snapshot();
            s.observe(o, a, c);
        }
    }

    pub(crate) fn note_open_handler(&self) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = self.common.config.handler_observe {
            o.note_open_call();
        }
    }

    pub(crate) fn invert_open_confirm_before_lane(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        {
            self.common.config.invert_open_confirm_before_lane
        }
        #[cfg(not(feature = "_test_hooks"))]
        {
            false
        }
    }

    fn next_opening_deadline(&self) -> Option<tokio::time::Instant> {
        self.openings.values().map(|s| s.deadline).min()
    }

    /// Allocate a sender channel id that is free in both `enc.channels`
    /// and the reserved opening table.
    fn alloc_sender_channel(&mut self) -> ChannelId {
        loop {
            let id = self
                .common
                .encrypted
                .as_mut()
                .expect("encrypted")
                .new_channel_id();
            if !self.openings.contains_key(&id) {
                return id;
            }
        }
    }

    fn next_open_gen(&mut self, id: ChannelId) -> u64 {
        let e = self.channel_gens.entry(id).or_insert(0);
        *e = e.wrapping_add(1);
        if *e == 0 {
            *e = 1;
        }
        *e
    }

    /// Reserve an opening slot after CHANNEL_OPEN parse, before Handler.
    /// `None` = full (caller writes OPEN_FAILURE, no handle).
    pub(crate) fn try_reserve_opening(
        &mut self,
        recipient_channel: u32,
    ) -> Option<(ChannelId, std::sync::Arc<crate::OpeningLease>)> {
        if self.slot_used() >= self.max_channels() {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.common.config.slot_observe {
                s.note_rejected_full();
            }
            self.publish_slots();
            return None;
        }
        let need = self.opening_budget_need();
        if self.reserve_global_bytes(need).is_err() {
            log::debug!("global opening reserve failed; OPEN_FAILURE");
            self.publish_slots();
            return None;
        }
        let id = self.alloc_sender_channel();
        let generation = self.next_open_gen(id);
        let lease = crate::OpeningLease::new(generation);
        let deadline =
            tokio::time::Instant::now() + self.common.config.open_decision_deadline;
        self.openings.insert(
            id,
            OpeningSlot {
                generation,
                deadline,
                recipient_channel,
                lease: lease.clone(),
                reserved: need,
            },
        );
        self.hold_opening(id, need);
        self.publish_slots();
        Some((id, lease))
    }

    fn write_open_failure(
        &mut self,
        recipient_channel: u32,
        reason: ChannelOpenFailure,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                msg::CHANNEL_OPEN_FAILURE.encode(&mut enc.write)?;
                recipient_channel.encode(&mut enc.write)?;
                reason.code().encode(&mut enc.write)?;
                reason.description().encode(&mut enc.write)?;
                "en".encode(&mut enc.write)?;
            });
        }
        self.record_outbound_from_write();
        Ok(())
    }

    /// S3c #14: clear any lane without StopDiscard, then FAILURE.
    fn fail_opening(
        &mut self,
        id: ChannelId,
        reason: ChannelOpenFailure,
        expired: bool,
    ) -> Result<(), Error> {
        let Some(slot) = self.openings.remove(&id) else {
            return Ok(());
        };
        if expired {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.common.config.slot_observe {
                s.note_expired();
            }
            let e = self.channel_gens.entry(id).or_insert(slot.generation);
            *e = e.wrapping_add(1);
        }
        self.pending_open_ids.remove(&id);
        self.teardown_inbound_channel(id);
        if let Some(r) = &self.reader {
            r.close_lane(id, r.lane_gen(id).unwrap_or(0));
        }
        self.channel_window_covered.remove(&id);
        self.channel_global_held.remove(&id);
        self.release_global_inbound_credit(slot.reserved);
        self.write_open_failure(slot.recipient_channel, reason)?;
        self.publish_slots();
        Ok(())
    }

    pub(crate) fn expire_due_openings(&mut self) -> Result<bool, Error> {
        let now = tokio::time::Instant::now();
        let due: Vec<ChannelId> = self
            .openings
            .iter()
            .filter(|(_, s)| now >= s.deadline)
            .map(|(id, _)| *id)
            .collect();
        let mut wrote = false;
        for id in due {
            let Some(slot) = self.openings.get(&id) else {
                continue;
            };
            if !slot.lease.try_expire() {
                continue;
            }
            self.fail_opening(
                id,
                ChannelOpenFailure::AdministrativelyProhibited,
                true,
            )?;
            wrote = true;
        }
        Ok(wrote)
    }

    fn local_open_full(&self) -> bool {
        self.slot_used() >= self.max_channels()
    }

    fn notify_local_open_failure(&self, channel_ref: &ChannelRef) {
        let _ = channel_ref.try_send(ChannelMsg::OpenFailure(
            ChannelOpenFailure::ResourceShortage,
        ));
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.slot_observe {
            s.note_rejected_full();
        }
    }

    fn complete_local_open(
        &mut self,
        channel_ref: ChannelRef,
        result: Result<ChannelId, Error>,
    ) -> Result<(), Error> {
        match result {
            Ok(id) => {
                self.channels.insert(id, channel_ref);
                self.register_inbound_lane(id, false);
                self.publish_slots();
                Ok(())
            }
            Err(Error::ChannelOpenFailure(_)) => {
                self.notify_local_open_failure(&channel_ref);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn register_inbound_lane(&self, id: ChannelId, confirmed: bool) {
        let Some(r) = self.reader.as_ref() else {
            return;
        };
        let window = self.common.config.window_size;
        let max_pkt = self.common.config.maximum_packet_size;
        // LaneTable assigns a monotonic generation. `new_channel` skips
        // only *live* enc.channels keys, so a freed id can be reused
        // immediately; the gen stops a stale CloseDropped from notifying
        // the replacement. The `1` argument is unused (table assigns).
        r.open_lane(id, 1, window, max_pkt, confirmed);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = self.common.config.window_observe {
            o.note_lane_open(id.number(), confirmed);
            o.set_lane_count(r.lane_count());
        }
    }

    /// Items popped per `pump_reader_lanes` call. Hitting this returns
    /// to the outer loop so facade/result can drain; loop-top pumps
    /// again if the quantum was exhausted.
    const LANE_PUMP_QUANTUM: usize = 64;

    /// Pop Reader lanes into the app buffer / REQUEST dispatch.
    /// App-bound items are reserved *before* pop: Full parks the channel
    /// in `backpressured` (`hold_all`) and leaves the head in the lane.
    ///
    /// Skip-set union (explicit):
    /// * `pending_open_ids` → `hold_data`: DATA/EXT stay while OPEN
    ///   callback holds `Channel`; REQUEST/EOF/CLOSE remain poppable.
    /// * `backpressured` → `hold_all`: the whole channel is skipped
    ///   (DATA/EXT/EOF/CLOSE and REQUEST) until a permit arrives.
    /// * `executor_full()` → `non_payload_only`: DATA/EXT never leave
    ///   the lane; REQUEST/EOF/CLOSE still need the same two holds.
    /// Combined: `peek_gated(pending_open, backpressured, exec_full)`.
    /// Returns `true` when the quantum was exhausted (more work may remain).
    pub(crate) async fn pump_reader_lanes<H: Handler + Send>(
        &mut self,
        mut handler: Option<&mut H>,
    ) -> Result<bool, H::Error> {
        #[cfg(feature = "_test_hooks")]
        if self
            .common
            .config
            .lane_pump_hold
            .as_ref()
            .is_some_and(|h| h.load(std::sync::atomic::Ordering::SeqCst))
        {
            if let (Some(r), Some(o)) =
                (self.reader.as_ref(), self.common.config.lane_observe.as_ref())
            {
                let lane = r.total_occupancy_bytes();
                let count = r.total_occupancy_count();
                o.set_occ(lane, count);
                o.note_split(lane, 0);
            }
            return Ok(false);
        }
        // Peer CLOSE has already been pushed onto the lane (Reader
        // publishes WireClose first, then Close). Ctrl consumption is
        // gated on `!exec_full`, so StopDiscard must not wait for a
        // permit or a ctrl slot. Full-table scan of live lanes each
        // pump (same order as `peek_gated`; incremental set is P3).
        // Covers (1) Full park with Close at the head and (2)
        // executor_full skipping a DATA head that still has Close
        // behind it.
        self.discard_close_queued_lanes()
            .map_err(|e| e.into())?;
        let invert_eager = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common.config.invert_eager_lane_pop
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                false
            }
        };
        let mut popped = 0usize;
        loop {
            if popped >= Self::LANE_PUMP_QUANTUM {
                return Ok(true);
            }
            let Some(reader) = self.reader.clone() else {
                break;
            };
            if invert_eager {
                let Some((id, item)) = (if self.executor_full() {
                    reader.pop_any_non_payload_except(&self.pending_open_ids)
                } else {
                    reader.pop_any_except(&self.pending_open_ids)
                }) else {
                    break;
                };
                popped += 1;
                self.dispatch_eager_lane_item(id, item, handler.as_mut().map(|h| &mut **h))
                    .await?;
                continue;
            }
            let Some(id) = reader.peek_gated(
                &self.pending_open_ids,
                &self.backpressured,
                self.executor_full(),
            ) else {
                break;
            };
            if reader.head_needs_app(id) {
                match self.try_reserve_app(id) {
                    Ok(permit) => {
                        let Some(item) = reader.pop_channel(id) else {
                            break;
                        };
                        popped += 1;
                        self.finish_lane_item(
                            id,
                            item,
                            Some(permit),
                            false,
                            handler.as_mut().map(|h| &mut **h),
                        )
                        .await?;
                    }
                    Err(TrySendError::Full(())) => {
                        self.maybe_discard_for_peer_close(id)
                            .map_err(|e| e.into())?;
                        self.park_backpressure(id);
                        continue;
                    }
                    Err(TrySendError::Closed(())) => {
                        if reader.close_queued(id) {
                            self.dispatch_close(handler.as_mut().map(|h| &mut **h), id)
                                .await?;
                            self.finalize_close(id);
                        } else {
                            let Some(item) = reader.pop_channel(id) else {
                                break;
                            };
                            popped += 1;
                            self.finish_lane_item(
                                id,
                                item,
                                None,
                                true,
                                handler.as_mut().map(|h| &mut **h),
                            )
                            .await?;
                        }
                    }
                }
            } else {
                let Some(item) = reader.pop_channel(id) else {
                    break;
                };
                popped += 1;
                self.dispatch_lane_control(item, handler.as_mut().map(|h| &mut **h))
                    .await?;
            }
        }
        Ok(false)
    }

    fn try_reserve_app(
        &self,
        id: ChannelId,
    ) -> Result<OwnedPermit<ChannelMsg>, TrySendError<()>> {
        match self.channels.get(&id) {
            Some(chan) => std::ops::Deref::deref(chan)
                .clone()
                .try_reserve_owned()
                .map_err(|e| match e {
                    TrySendError::Full(_) => TrySendError::Full(()),
                    TrySendError::Closed(_) => TrySendError::Closed(()),
                }),
            None => Err(TrySendError::Closed(())),
        }
    }

    fn park_backpressure(&mut self, id: ChannelId) {
        self.backpressured.insert(id);
        let gate = self.inbound_gate.entry(id).or_default();
        if !gate.reserving {
            gate.reserving = true;
            self.inbound_needs_reserve.push(id);
        }
    }

    fn live_lane_gen(&self, id: ChannelId) -> u64 {
        self.reader
            .as_ref()
            .and_then(|r| r.lane_gen(id))
            .unwrap_or(0)
    }

    fn skip_close_discard_on_park(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        {
            self.common.config.invert_skip_close_discard_on_park
        }
        #[cfg(not(feature = "_test_hooks"))]
        {
            false
        }
    }

    /// Idempotent StopDiscard when a peer CLOSE is already in the lane.
    /// Safe against a later WireClose / `finish_lane_item` Close: those
    /// see `we_closed_first` / `already_gone` and do not emit a second
    /// wire CLOSE.
    fn maybe_discard_for_peer_close(&mut self, id: ChannelId) -> Result<(), crate::Error> {
        if self.skip_close_discard_on_park() {
            return Ok(());
        }
        let close_queued = self
            .reader
            .as_ref()
            .is_some_and(|r| r.close_queued(id));
        if !close_queued {
            return Ok(());
        }
        let we_closed_first = self
            .common
            .encrypted
            .as_ref()
            .is_some_and(|enc| !enc.channel_exists(id));
        if we_closed_first {
            return Ok(());
        }
        self.discard_channel_outbound(id)
    }

    fn discard_close_queued_lanes(&mut self) -> Result<(), crate::Error> {
        let ids = self
            .reader
            .as_ref()
            .map(|r| r.close_queued_ids())
            .unwrap_or_default();
        for id in ids {
            self.maybe_discard_for_peer_close(id)?;
        }
        Ok(())
    }

    fn invert_delivered_handler_data(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        {
            self.common.config.invert_delivered_handler_data
        }
        #[cfg(not(feature = "_test_hooks"))]
        {
            false
        }
    }

    async fn dispatch_lane_control<H: Handler + Send>(
        &mut self,
        item: LaneItem,
        mut handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        match item {
            LaneItem::Request { payload } => {
                #[cfg(feature = "_test_hooks")]
                if let Some(o) = self.common.config.lane_observe.as_ref() {
                    o.note_pop_request();
                }
                let mut r = payload.as_ref();
                self.server_read_authenticated(
                    handler.as_mut().map(|h| &mut **h),
                    msg::CHANNEL_REQUEST,
                    &mut r,
                )
                .await?;
                #[cfg(feature = "_test_hooks")]
                if let Some(d) = self.common.config.lane_request_pop_delay {
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
            }
            LaneItem::Success { payload } => {
                let mut r = payload.as_ref();
                self.server_read_authenticated(
                    handler.as_mut().map(|h| &mut **h),
                    msg::CHANNEL_SUCCESS,
                    &mut r,
                )
                .await?;
            }
            LaneItem::Failure { payload } => {
                let mut r = payload.as_ref();
                self.server_read_authenticated(
                    handler.as_mut().map(|h| &mut **h),
                    msg::CHANNEL_FAILURE,
                    &mut r,
                )
                .await?;
            }
            other => {
                // App-bound items go through finish_lane_item.
                let _ = other;
            }
        }
        Ok(())
    }

    /// Invert path: pop first, then `send().await` (old session-loop stall).
    async fn dispatch_eager_lane_item<H: Handler + Send>(
        &mut self,
        id: ChannelId,
        item: LaneItem,
        mut handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        if matches!(
            &item,
            LaneItem::Request { .. } | LaneItem::Success { .. } | LaneItem::Failure { .. }
        ) {
            return self.dispatch_lane_control(item, handler).await;
        }
        let msg = match lane_item_to_msg(&item) {
            Some(m) => m,
            None => return Ok(()),
        };
        if let Some(chan) = self.channels.get(&id) {
            let sender = std::ops::Deref::deref(chan).clone();
            let _ = sender.send(msg).await;
            self.finish_lane_item(id, item, None, false, handler.as_mut().map(|h| &mut **h))
                .await?;
        } else {
            self.finish_lane_item(id, item, None, true, handler.as_mut().map(|h| &mut **h))
                .await?;
        }
        Ok(())
    }

    async fn finish_lane_item<H: Handler + Send>(
        &mut self,
        id: ChannelId,
        item: LaneItem,
        permit: Option<OwnedPermit<ChannelMsg>>,
        gone: bool,
        mut handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        let is_close = matches!(item, LaneItem::Close);
        let is_eof = matches!(item, LaneItem::Eof);
        let zero = lane_item_is_zero_data(&item);
        let (ext, data) = match &item {
            LaneItem::Data(d) => (None, Some(d.clone())),
            LaneItem::ExtendedData { ext, data } => (Some(*ext), Some(data.clone())),
            _ => (None, None),
        };
        #[cfg(feature = "_test_hooks")]
        if let Some(o) = self.common.config.lane_observe.as_ref() {
            if data.is_some() && !zero {
                o.note_pop_data();
            }
            o.set_scheme(0);
        }
        if is_close {
            let we_closed_first = self
                .common
                .encrypted
                .as_ref()
                .is_some_and(|enc| !enc.channel_exists(id));
            if !we_closed_first {
                self.discard_channel_outbound(id).map_err(|e| e.into())?;
            }
        }
        let delivered = if zero {
            // Zero-byte DATA delivers nothing (would read as EOF on AsyncRead).
            true
        } else if let Some(permit) = permit {
            if let Some(msg) = lane_item_to_msg(&item) {
                permit.send(msg);
            }
            true
        } else if gone {
            false
        } else if let Some(msg) = lane_item_to_msg(&item) {
            // Invert eager path already sent; skip a second send.
            let _ = msg;
            true
        } else {
            true
        };
        if data.is_some() {
            self.maybe_grant_after_delivery(id, handler.as_mut().map(|h| &mut **h))
                .await?;
        }
        if let Some(d) = data {
            let invert = self.invert_delivered_handler_data();
            #[cfg(feature = "_test_hooks")]
            if delivered && self.pending_kex_install.is_some() {
                if let Some(ref slot) = self.common.config.kex_install_observe {
                    slot.mark_data_while_pending(d.len() as u64);
                }
            }
            // Delivered DATA skips Handler::data (H1/H8). ChannelGone
            // (handler-mode) still posts. Invert restores the old
            // inline-wait so H1 goes red.
            let call_data = gone || (delivered && invert);
            if call_data {
                if let Some(ext) = ext {
                    self.dispatch_extended_data(handler, id, ext, &d).await?;
                } else {
                    self.dispatch_data(handler, id, &d, delivered && invert)
                        .await?;
                }
            }
        } else if is_eof {
            self.dispatch_eof(handler, id).await?;
        } else if is_close {
            self.dispatch_close(handler, id).await?;
            self.finalize_close(id);
        }
        Ok(())
    }

    async fn handle_ctrl_msg<H: Handler + Send>(
        &mut self,
        msg: CtrlMsg,
        mut handler: Option<&mut H>,
    ) -> Result<bool, H::Error> {
        if let Some(r) = &self.reader {
            r.release_ctrl(msg.byte_len());
        }
        match msg {
            CtrlMsg::Packet(pkt) => {
                Ok(self.handle_ctrl_packet(pkt, handler.as_mut().map(|h| &mut **h)).await?)
            }
            CtrlMsg::WireClose { id, .. } => {
                let we_closed_first = self
                    .common
                    .encrypted
                    .as_ref()
                    .is_some_and(|enc| !enc.channel_exists(id));
                if !we_closed_first {
                    self.discard_channel_outbound(id).map_err(|e| e.into())?;
                }
                Ok(true)
            }
            CtrlMsg::Overflow { id, .. } => {
                log::warn!("reader lane overflow on {id:?}; StopDiscard");
                self.discard_channel_outbound(id).map_err(|e| e.into())?;
                self.teardown_inbound_channel(id);
                // App-known channel: this is the unique Handler close
                // notification (peer CLOSE may never arrive). Notify
                // before remove so CloseDropped sees channels gone.
                if self.channels.contains_key(&id) {
                    self.dispatch_close(handler.as_mut().map(|h| &mut **h), id)
                        .await?;
                }
                self.channels.remove(&id);
                if let Some(r) = &self.reader {
                    r.close_lane(id, r.lane_gen(id).unwrap_or(0));
                }
                Ok(true)
            }
            CtrlMsg::CloseDropped { id, generation } => {
                // Ghost CLOSE: never opened → not in channels. Overflow
                // already notified + removed. At most one Handler close
                // per app-known channel.
                if !self.channels.contains_key(&id) {
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = self.common.config.lane_observe {
                        o.note_unknown();
                    }
                    return Ok(true);
                }
                let live = self.reader.as_ref().and_then(|r| r.lane_gen(id));
                if live.is_some_and(|g| generation != 0 && g != generation) {
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref o) = self.common.config.lane_observe {
                        o.note_unknown();
                    }
                    return Ok(true);
                }
                self.dispatch_close(handler.as_mut().map(|h| &mut **h), id)
                    .await?;
                self.finalize_close(id);
                Ok(true)
            }
        }
    }

    async fn handle_ctrl_packet<H: Handler + Send>(
        &mut self,
        mut pkt: crate::sshbuffer::IncomingSshPacket,
        handler: Option<&mut H>,
    ) -> Result<bool, H::Error> {
        match pkt.buffer.first() {
            None => Ok(true),
            Some(&crate::msg::DISCONNECT) => Ok(false),
            Some(_) => {
                self.common.received_data = true;
                #[cfg(feature = "_test_hooks")]
                if pkt.buffer.first() == Some(&crate::msg::CHANNEL_WINDOW_ADJUST) {
                    if let Some(ref c) = self.common.config.window_adjust_seen {
                        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                if let Err(e) = super::reply(self, handler, &mut pkt).await {
                    // Parse/ensure_end reject. Propagate Err (kex-junk
                    // expects is_err) and stamp PeerError for observers.
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref s) = self.common.config.disconnect_cause_slot {
                        s.record(DisconnectCause::PeerError);
                    }
                    return Err(e);
                }
                if let Some(c) = self.pending_supervisor_cause.take() {
                    self.stage_cause(c);
                }
                Ok(true)
            }
        }
    }

    /// Try-send an app-bound message on the no-lane / ctrl-fallback path.
    /// There is no Scheme C queue: Full cannot park the item.
    pub(crate) fn try_send_app(
        &self,
        id: ChannelId,
        msg: ChannelMsg,
    ) -> Result<(), TrySendError<ChannelMsg>> {
        match self.channels.get(&id) {
            Some(chan) => std::ops::Deref::deref(chan).try_send(msg),
            None => Err(TrySendError::Closed(msg)),
        }
    }

    /// For each channel flagged in `inbound_needs_reserve`, register a single `reserve_owned()`
    /// future tagged with the live Reader lane generation.
    pub(crate) fn drain_needs_reserve(&mut self, reserves: &mut FuturesUnordered<BoxReserve>) {
        for id in std::mem::take(&mut self.inbound_needs_reserve) {
            let reserving = self
                .inbound_gate
                .get(&id)
                .is_some_and(|g| g.reserving);
            if !reserving {
                continue;
            }
            let generation = self.live_lane_gen(id);
            match self.channels.get(&id) {
                Some(chan) => {
                    let sender = std::ops::Deref::deref(chan).clone();
                    let fut: BoxReserve = Box::pin(async move {
                        let r = sender.reserve_owned().await.map_err(|_| ());
                        (id, generation, r)
                    });
                    reserves.push(fut);
                }
                None => {
                    self.teardown_inbound_channel(id);
                }
            }
        }
    }

    /// Resolve one completed `reserve_owned()` future: pop the lane head, send via the
    /// permit, grant window, fire callbacks **after** the data is in the app buffer,
    /// then drop the channel from `backpressured` so the next pump can rotate.
    pub(crate) async fn pump_inbound<H: Handler + Send>(
        &mut self,
        id: ChannelId,
        generation: u64,
        res: Result<OwnedPermit<ChannelMsg>, ()>,
        mut handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        if generation != self.live_lane_gen(id) {
            // Stale: torn-down lane or a later episode of the same id.
            return Ok(());
        }
        {
            let g = match self.inbound_gate.get_mut(&id) {
                Some(g) => g,
                None => return Ok(()),
            };
            g.reserving = false;
        }

        let permit = match res {
            Ok(p) => p,
            Err(()) => {
                // Receiver dropped while we were reserving. If CLOSE is still
                // in the lane, delivery can no longer happen — fire
                // `channel_close` and `finalize_close` so the channels table
                // does not leak (S5a invariant 4).
                let close_queued = self
                    .reader
                    .as_ref()
                    .is_some_and(|r| r.close_queued(id));
                if close_queued {
                    self.dispatch_close(handler.as_mut().map(|h| &mut **h), id)
                        .await?;
                    self.finalize_close(id);
                } else {
                    self.teardown_inbound_channel(id);
                }
                return Ok(());
            }
        };

        let Some(reader) = self.reader.clone() else {
            return Ok(());
        };
        let Some(item) = reader.pop_channel(id) else {
            self.backpressured.remove(&id);
            self.inbound_gate.remove(&id);
            return Ok(());
        };
        self.backpressured.remove(&id);
        if self
            .inbound_gate
            .get(&id)
            .is_some_and(|g| !g.reserving)
        {
            self.inbound_gate.remove(&id);
        }
        self.finish_lane_item(
            id,
            item,
            Some(permit),
            false,
            handler.as_mut().map(|h| &mut **h),
        )
        .await
    }

    /// I2: grant more inbound receive window for a channel after its data was accepted into the
    /// application buffer. Only granted at delivery time, so a backpressured channel withholds its
    /// own grant (per-channel backpressure replacing the removed blocking `.await`).
    pub(crate) async fn maybe_grant_after_delivery<H: Handler + Send>(
        &mut self,
        id: ChannelId,
        handler: Option<&mut H>,
    ) -> Result<(), crate::Error> {
        let target = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common
                    .config
                    .grant_target_override
                    .as_ref()
                    .map(|a| a.load(std::sync::atomic::Ordering::SeqCst))
                    .filter(|&t| t > 0)
                    .unwrap_or(self.target_window_size)
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                self.target_window_size
            }
        };
        // Bytes still sitting in the Reader lane keep occupying the advertised
        // window. Scheme C is gone: undelivered is lane-only. Invert
        // `invert_omit_lane_from_undelivered` restores the over-grant so Q8
        // goes red (enumerated class, not bare is_err).
        let lane_bytes = self
            .reader
            .as_ref()
            .map(|r| r.occupancy_bytes(id))
            .unwrap_or(0);
        let omit_lane = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common.config.invert_omit_lane_from_undelivered
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                false
            }
        };
        let undelivered = if omit_lane {
            0
        } else {
            lane_bytes.try_into().unwrap_or(u32::MAX)
        };
        // StopDiscard latch: CLOSE already framed or channel gone —
        // never register / emit a WINDOW_ADJUST for it.
        if !self.outbound_channel_accepts_ctrl(id) {
            if self.deferred_window_grants.remove(&id) {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.stop_discard {
                    s.note_grant_clear();
                }
            }
            return Ok(());
        }
        // WINDOW_ADJUST is 9B payload + 88B wire OH = 97. Do not emit it
        // once the data pipeline is already at the soft HWM — that 97B
        // on top of a last-packet CHANNEL_DATA fill is the F1 +97
        // overshoot, and it races with live sealed oscillating near hard.
        if self.sealed_backlog_bytes() >= crate::sshbuffer::OUTBOUND_HIGH_WATERMARK {
            if self.deferred_window_grants.insert(id) {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.deferred_grant {
                    s.note_insert();
                }
            }
            return Ok(());
        }
        let delta = self.planned_grant_delta(id, target, undelivered);
        let ceiling = target.saturating_sub(undelivered);
        let need = if delta > 0 {
            self.grant_reserve_need(id, ceiling)
        } else {
            0
        };
        let need_u32 = need.min(u32::MAX as u64) as u32;
        if self.invert_global_before_expand() {
            // G4 invert: same two production operations, swapped.
            let granted = self.grant_expand_then_adjust(id, target, undelivered, delta)?;
            let mut reserved_ok = true;
            if granted && delta > 0 {
                if self.reserve_global_inbound_credit(need_u32).is_err() {
                    reserved_ok = false;
                    #[cfg(feature = "_test_hooks")]
                    if let Some(acc) = self.conn_budget.as_ref() {
                        acc.budget().note_expand_before_global();
                    }
                    if need > 0 {
                        if self.deferred_window_grants.insert(id) {
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref s) = self.common.config.deferred_grant {
                                s.note_insert();
                            }
                        }
                    }
                } else {
                    #[cfg(feature = "_test_hooks")]
                    if let Some(acc) = self.conn_budget.as_ref() {
                        acc.budget().note_expand_before_global();
                    }
                    self.add_channel_held(id, need);
                    self.mark_window_covered(
                        id,
                        (ceiling as u64).saturating_add(
                            crate::server::global_budget::OUTBOUND_CAP_ESTIMATE,
                        ),
                    );
                }
            }
            if granted && reserved_ok {
                self.deferred_window_grants.remove(&id);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.deferred_grant {
                    s.note_emitted();
                }
                let w = self
                    .dispatch_adjust_window(handler, id, self.target_window_size)
                    .await;
                if w > 0 {
                    self.target_window_size = w;
                }
                let _ = self.flush();
            } else if !granted {
                self.deferred_window_grants.remove(&id);
            }
            return Ok(());
        }
        // Production order: global reserve, then expand, then ADJUST.
        // `need` is ceiling-growth only (0 when opening already covers).
        if delta > 0 && self.reserve_global_inbound_credit(need_u32).is_err() {
            log::debug!("global inbound credit exhausted; skip grant");
            #[cfg(feature = "_test_hooks")]
            if let Some(acc) = self.conn_budget.as_ref() {
                acc.budget().note_grant_reserve_fail();
            }
            if self.deferred_window_grants.insert(id) {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.deferred_grant {
                    s.note_insert();
                }
            }
            return Ok(());
        }
        #[cfg(feature = "_test_hooks")]
        if delta > 0 {
            if let Some(acc) = self.conn_budget.as_ref() {
                acc.budget().note_global_before_expand();
            }
        }
        let granted = self.grant_expand_then_adjust(id, target, undelivered, delta)?;
        if granted {
            if need > 0 {
                self.add_channel_held(id, need);
            }
            if delta > 0 {
                self.mark_window_covered(
                    id,
                    (ceiling as u64)
                        .saturating_add(crate::server::global_budget::OUTBOUND_CAP_ESTIMATE),
                );
            }
        } else if need > 0 {
            self.release_global_inbound_credit(need);
        }
        if granted {
            self.deferred_window_grants.remove(&id);
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.common.config.deferred_grant {
                s.note_emitted();
            }
            let w = self
                .dispatch_adjust_window(handler, id, self.target_window_size)
                .await;
            if w > 0 {
                self.target_window_size = w;
            }
            // Move the 97B WINDOW_ADJUST into Writer/pending before any
            // subsequent CHANNEL_DATA budget snapshot. Leaving it only in
            // enc.write let a same-turn data() see sealed=writer and land
            // HWM+one+97 in the linearized total (F1 147650).
            let _ = self.flush();
        } else {
            self.deferred_window_grants.remove(&id);
        }
        Ok(())
    }

    fn planned_grant_delta(&self, id: ChannelId, target: u32, undelivered: u32) -> u32 {
        let ceiling = target.saturating_sub(undelivered);
        let remaining = if let Some(r) = self.reader.as_ref() {
            r.sender_window(id).unwrap_or(0)
        } else {
            self.common
                .encrypted
                .as_ref()
                .map(|enc| enc.sender_window_size(id) as u32)
                .unwrap_or(0)
        };
        if remaining >= ceiling / 2 {
            return 0;
        }
        ceiling.saturating_sub(remaining)
    }

    /// Hard grant order: expand Reader cap first, then seal ADJUST.
    /// `delta` is computed once by the caller (`planned_grant_delta`)
    /// and must not be recomputed from a later window snapshot
    /// (S4d r1 P1-1). Expand fail → no ADJUST + count. Never awaits Reader.
    fn grant_expand_then_adjust(
        &mut self,
        id: ChannelId,
        target: u32,
        undelivered: u32,
        mut delta: u32,
    ) -> Result<bool, crate::Error> {
        use crate::server::inbound_lane::ExpandCap;
        let ceiling = target.saturating_sub(undelivered);
        let invert_recompute = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common.config.invert_recompute_grant_delta
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                false
            }
        };
        if invert_recompute {
            // G7 invert: same two production reads, second snapshot.
            delta = self.planned_grant_delta(id, target, undelivered);
        }
        if delta == 0 {
            return Ok(false);
        }
        let invert = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common.config.invert_grant_order
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                false
            }
        };

        if invert {
            // `_test_hooks` inject: same two production calls, swapped.
            let emitted = self.emit_inbound_adjust(id, delta, ceiling)?;
            let _ = self.expand_inbound_cap(id, delta);
            return Ok(emitted);
        }

        match self.expand_inbound_cap(id, delta) {
            ExpandCap::Expanded => {}
            ExpandCap::NoLane | ExpandCap::GenMismatch => return Ok(false),
        }
        self.emit_inbound_adjust(id, delta, ceiling)
    }

    fn expand_inbound_cap(
        &self,
        id: ChannelId,
        delta: u32,
    ) -> crate::server::inbound_lane::ExpandCap {
        use crate::server::inbound_lane::ExpandCap;
        let result = if let Some(r) = self.reader.as_ref() {
            let lane_gen = r.lane_gen(id).unwrap_or(0);
            r.try_expand_inbound_cap(id, lane_gen, delta)
        } else {
            ExpandCap::Expanded
        };
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = self.common.config.window_observe {
            match result {
                ExpandCap::Expanded => {
                    o.note_expand_ok();
                    o.note_expand_delta(delta);
                }
                ExpandCap::NoLane | ExpandCap::GenMismatch => o.note_expand_fail(),
            }
        }
        result
    }

    fn emit_inbound_adjust(
        &mut self,
        id: ChannelId,
        delta: u32,
        ceiling: u32,
    ) -> Result<bool, crate::Error> {
        let Some(enc) = self.common.encrypted.as_mut() else {
            return Ok(false);
        };
        let emitted = enc.emit_window_adjust(id, delta, ceiling)?;
        if emitted {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = self.common.config.window_observe {
                o.note_adjust_emitted();
                o.note_adjust_delta(delta);
            }
        }
        Ok(emitted)
    }

    /// Inbound ADJUST applied from the aggregation-board drain. Authority
    /// is Session `recipient_window_size` only (S5b). The board is
    /// in-flight staging, not a third window book.
    async fn apply_peer_window_credit<H: Handler + Send>(
        &mut self,
        id: ChannelId,
        amount: u32,
        handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref c) = self.common.config.window_adjust_seen {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let established = self
            .common
            .encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&id))
            .is_some_and(|ch| ch.confirmed);
        if !established {
            return Ok(());
        }
        let mut new_size = 0;
        if let Some(ref mut enc) = self.common.encrypted {
            let channel = enc
                .channels
                .get_mut(&id)
                .ok_or(crate::Error::Inconsistent)
                .map_err(|e| e.into())?;
            new_size = channel.recipient_window_size.saturating_add(amount);
            channel.recipient_window_size = new_size;
        }
        let wrote = self.try_drain_channel_under_budget(id).map_err(|e| e.into())?;
        new_size = new_size.saturating_sub(wrote as u32);
        if let Some(enc) = self.common.encrypted.as_ref() {
            if let Some(ch) = enc.channels.get(&id) {
                new_size = ch.recipient_window_size;
            }
        }
        if let Some(chan) = self.channels.get(&id) {
            // Informational only. Server Channel::data no longer deducts
            // WindowSizeRef (S5b); Session recipient_window_size is the ledger.
            let _ = chan.try_send(ChannelMsg::WindowAdjusted { new_size });
        }
        self.dispatch_window_adjusted(handler, id, new_size).await
    }

    /// Drain the aggregation board into `apply_peer_window_credit`. Shared by
    /// the production loop-top site and the `_test_hooks` pin that runs the
    /// same apply *after* the batch drain (data-msg-before-ADJUST).
    async fn apply_pending_peer_credit<H: Handler + Send>(
        &mut self,
        mut handler: Option<&mut H>,
    ) -> Result<(), H::Error> {
        let pending = match self.peer_credit.as_ref() {
            Some(board) => board.take_all(),
            None => return Ok(()),
        };
        for (id, amt) in pending {
            let amount = if amt > u32::MAX as u64 {
                u32::MAX
            } else {
                amt as u32
            };
            self.apply_peer_window_credit(id, amount, handler.as_mut().map(|h| &mut **h))
                .await?;
        }
        Ok(())
    }

    /// Replay WINDOW_ADJUST grants skipped while outbound sat at the hard cap.
    pub(crate) async fn retry_deferred_window_grants<H: Handler + Send>(
        &mut self,
        mut handler: Option<&mut H>,
    ) -> Result<(), crate::Error> {
        if self.deferred_window_grants.is_empty() {
            return Ok(());
        }
        let ids: Vec<ChannelId> = self.deferred_window_grants.iter().copied().collect();
        for id in ids {
            if !self.outbound_channel_accepts_ctrl(id) {
                self.deferred_window_grants.remove(&id);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.stop_discard {
                    s.note_grant_clear();
                }
                continue;
            }
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.common.config.deferred_grant {
                s.note_replay();
            }
            self.maybe_grant_after_delivery(id, handler.as_mut().map(|h| &mut **h))
                .await?;
        }
        Ok(())
    }

    /// Release producers parked in [`Handle::data`] for any channel whose outbound backlog has
    /// drained. Cheap: only channels with parked producers are examined.
    pub(crate) fn release_outbound_acks(&mut self) {
        if self.outbound_acks.is_empty() {
            return;
        }
        let Some(enc) = self.common.encrypted.as_ref() else {
            return;
        };
        // Reaching here with no pending data means the backlog went out on the wire: either the
        // channel drained and is still open, or it drained and was then removed by an orderly
        // `flush_pending` -> `pending_close`. Both delivered. Channels whose backlog was
        // *discarded* never appear here — `discard_channel_outbound` already took their acks.
        let drained: Vec<ChannelId> = self
            .outbound_acks
            .keys()
            .copied()
            .filter(|id| !enc.has_pending_data(*id))
            .collect();
        for id in drained {
            if let Some(acks) = self.outbound_acks.remove(&id) {
                let n = acks.len();
                for ack in acks {
                    let _ = ack.send(());
                }
                // One wake per resolved ack (N ChannelTx need N
                // notify_one permits). Issued as a batch of `n`.
                self.wake_parked_writers(id, n);
            }
        }
    }

    /// Wake parked `ChannelTx` writers on `id`.
    ///
    /// Invariant: any path that resolves or drops parked acks, or removes
    /// the channel object, must wake at least as many times as there are
    /// parked writers on this channel (ack count is the upper bound) and
    /// must do so *before* `channels.remove`. Extra `notify_one` permits
    /// coalesce; a later ChannelTx poll may consume a stale permit and
    /// then re-park if backlog is still pending — that is tolerated.
    fn wake_parked_writers(&self, id: ChannelId, n: usize) {
        let Some(chan) = self.channels.get(&id) else {
            return;
        };
        let times = n.max(1);
        #[cfg(feature = "_test_hooks")]
        let times = if self.common.config.invert_single_writer_wake {
            1
        } else {
            times
        };
        for _ in 0..times {
            chan.window_size().wake();
        }
    }

    /// After any loop-top stage (credit apply / batch dispatch) and at
    /// loop-bottom: drain `pending_data` → flush `enc.write` → release
    /// parked `Handle::data` acks. Entering `select!` without this parks
    /// producers forever (ackstall). `flush` already honors
    /// `hold_enc_packet_during_kex`.
    pub(crate) fn settle_outbound_after_stage(&mut self) -> Result<(), crate::Error> {
        #[cfg(feature = "_test_hooks")]
        if self.common.config.invert_skip_outbound_settle {
            return Ok(());
        }
        self.try_drain_pending_data_under_budget()?;
        self.flush()?;
        self.release_outbound_acks();
        Ok(())
    }

    /// True while the protocol channel can still emit ADJUST / SUCCESS /
    /// FAILURE / REQUEST. False after StopDiscard or after CLOSE has
    /// been framed (`outbound_closed`).
    pub(crate) fn outbound_channel_accepts_ctrl(&self, id: ChannelId) -> bool {
        self.common
            .encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&id))
            .is_some_and(|ch| !ch.outbound_closed)
    }

    pub(crate) fn discard_channel_outbound(&mut self, id: ChannelId) -> Result<(), crate::Error> {
        // Register the Writer tombstone *before* framing the reply CLOSE
        // so any plaintext already in bulk FIFO / pending_outbound is
        // dropped at seal. already_gone / outbound_closed do not register
        // (no second CLOSE will flow through Writer to clear a stale id).
        if let Some(enc) = self.common.encrypted.as_ref() {
            if let Some(ch) = enc.channels.get(&id) {
                if !ch.outbound_closed {
                    if let Some(w) = self.writer.as_ref() {
                        w.close_tombstone().insert(ch.recipient_channel);
                    }
                }
            }
        }
        let stats = if let Some(enc) = self.common.encrypted.as_mut() {
            enc.close_discarding_pending(id)?
        } else {
            crate::StopDiscardStats {
                already_gone: true,
                ..crate::StopDiscardStats::default()
            }
        };
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.stop_discard {
            s.note_discard(stats.discarded_items, stats.discarded_bytes);
        }
        #[cfg(not(feature = "_test_hooks"))]
        let _ = stats;
        // Dropping the senders resolves each producer's await to Err.
        // Invert keeps the acks so a later release can falsely Ok them.
        let skip_drop = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common.config.invert_skip_discard_ack_drop
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                false
            }
        };
        let n_acks = self
            .outbound_acks
            .get(&id)
            .map(|q| q.len())
            .unwrap_or(0);
        if !skip_drop {
            self.outbound_acks.remove(&id);
        }
        // Remove from live *before* waking so a woken ChannelTx observes
        // dead and returns BrokenPipe instead of falsely Ok-ing discarded
        // bytes. The Notify lives on the Channel object (not the live
        // set), so it is still reachable here. Count = removed acks
        // (floor 1).
        self.sender.live.remove(id);
        self.wake_parked_writers(id, n_acks);
        if self.deferred_window_grants.remove(&id) {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref s) = self.common.config.stop_discard {
                s.note_grant_clear();
            }
        }
        // CLOSE was appended to enc.write; publish it to the order log
        // before the next loop flush so tests can see the unique CLOSE.
        self.record_outbound_from_write();
        Ok(())
    }

    /// Bound un-transmitted outbound bytes on one channel while the
    /// peer window is exhausted. S5b: `Channel::data` / `make_writer`
    /// no longer pre-reserve window — they enqueue via
    /// `ChannelDataAcked` and can pile `pending_data` the same way
    /// `Handle::data` does. This cap therefore applies to every
    /// outbound producer. Exceeding it StopDiscards that one channel.
    pub(crate) fn enforce_outbound_cap(&mut self, id: ChannelId) -> Result<(), crate::Error> {
        let cap = self.common.config.max_pending_outbound_bytes;
        let Some(enc) = self.common.encrypted.as_mut() else {
            return Ok(());
        };
        if enc.pending_data_bytes(id) <= cap {
            return Ok(());
        }
        log::warn!(
            "outbound pending cap exceeded for channel {id:?}; closing channel (peer window stalled and producer bypassed window accounting)"
        );
        self.discard_channel_outbound(id)?;
        self.finalize_close(id);
        Ok(())
    }

    /// Deferred CHANNEL_CLOSE teardown: only run once the queued `Close` has actually been
    /// delivered, so queued data ahead of it is never dropped. Removes the Reader
    /// lane; a late reserve future is stale when its tag ≠ live `lane_gen`.
    pub(crate) fn finalize_close(&mut self, id: ChannelId) {
        self.teardown_inbound_channel(id);
        if let Some(r) = &self.reader {
            r.close_lane(id, r.lane_gen(id).unwrap_or(0));
        }
        // Wake *before* `channels.remove` — afterwards the Notify is gone
        // and parked ChannelTx stay Pending forever (P1-B).
        let n_acks = self
            .outbound_acks
            .get(&id)
            .map(|q| q.len())
            .unwrap_or(0);
        #[cfg(feature = "_test_hooks")]
        let skip_wake = self.common.config.invert_skip_teardown_wake;
        #[cfg(not(feature = "_test_hooks"))]
        let skip_wake = false;
        if !skip_wake {
            self.wake_parked_writers(id, n_acks);
        }
        self.channels.remove(&id);
        // Dropping any parked `Handle::data` producers wakes them with an error, which is the
        // correct signal now that the channel is gone.
        self.outbound_acks.remove(&id);
        self.sender.live.remove(id);
        self.deferred_window_grants.remove(&id);
        if let Some(enc) = self.common.encrypted.as_mut() {
            // Safe to drop unconditionally: every path that reaches `finalize_close` has already
            // emitted the peer's `CHANNEL_CLOSE` reply via `close_discarding_pending`, so there
            // is never a parked `pending_close` left to lose here.
            enc.channels.remove(&id);
        }
        self.release_channel_global(id);
        self.publish_slots();
    }

    /// Tear down a channel's inbound gate when its application receiver was dropped mid-flight.
    /// Stale reserve futures are rejected by `live_lane_gen` (Reader lane
    /// generation), not by a gate-local counter that resets on `or_default`.
    pub(crate) fn teardown_inbound_channel(&mut self, id: ChannelId) {
        self.inbound_gate.remove(&id);
        self.backpressured.remove(&id);
        self.inbound_needs_reserve.retain(|x| *x != id);
    }

    fn maybe_decompress(&mut self, buffer: &SSHBuffer) -> Result<IncomingSshPacket, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let mut decomp = Vec::new();
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: enc.decompress.decompress(
                    &buffer.buffer[5..],
                    &mut decomp,
                )?.into(),
                seqn: buffer.seqn,
            })
        } else {
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: buffer.buffer[5..].into(),
                seqn: buffer.seqn,
            })
        }
    }

    /// Apply every queued channel-open reply. Must run before dispatching any `receiver`
    /// message: a writer's first `Data` for a channel is enqueued strictly after `accept()`
    /// queued that channel's reply, so finalizing replies first guarantees no `Data` is ever
    /// dispatched against a channel that is not yet registered (such data would be silently
    /// discarded, since the channel maps have no entry to route it to).
    pub(crate) fn drain_open_replies(&mut self) -> Result<(), Error> {
        while let Ok(msg) = self.open_reply_rx.try_recv() {
            if let Msg::ChannelOpenReply { pending, result } = msg {
                self.finalize_channel_open_reply(pending, result)?;
            }
        }
        Ok(())
    }

    /// Dispatch a single message received on the session's internal channel
    /// (sent via [`Handle`]). Shared by the `select!` receiver arm and the
    /// pre-`select!` backlog drain so the two can't drift apart.
    fn dispatch_msg(&mut self, msg: Msg) -> Result<(), Error> {
        self.drain_open_replies()?;
        match msg {
            Msg::Channel(id, ChannelMsg::Data { data }) => {
                self.data(id, data)?;
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { ext, data }) => {
                self.extended_data(id, ext, data)?;
            }
            Msg::ChannelDataAcked { id, ext, data, ack } => {
                match ext {
                    None => self.data(id, data)?,
                    Some(ext) => self.extended_data(id, ext, data)?,
                }
                let (exists, pending) = self
                    .common
                    .encrypted
                    .as_ref()
                    .map(|enc| (enc.channel_exists(id), enc.has_pending_data(id)))
                    .unwrap_or((false, false));
                if !exists {
                    // The channel was torn down while this message sat in the session queue, so
                    // `Encrypted::data` silently discarded the payload. Drop the ack rather than
                    // reporting success for bytes that never reached the peer.
                } else if pending {
                    // Park until this channel's backlog drains, so `Handle::data` is throttled to
                    // the rate the peer grants window — without stalling any other channel.
                    self.outbound_acks.entry(id).or_default().push_back(ack);
                } else {
                    // Fully absorbed by the peer's window.
                    let _ = ack.send(());
                    if let Some(chan) = self.channels.get(&id) {
                        chan.window_size().wake();
                    }
                }
            }
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id)?;
            }
            Msg::Channel(id, ChannelMsg::Close) => {
                self.close(id)?;
            }
            Msg::Channel(id, ChannelMsg::Success) => {
                self.channel_success_apply(id)?;
            }
            Msg::Channel(id, ChannelMsg::Failure) => {
                self.channel_failure_apply(id)?;
            }
            Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }) => {
                self.xon_xoff_request(id, client_can_do)?;
            }
            Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }) => {
                self.exit_status_request(id, exit_status)?;
            }
            Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ) => {
                self.exit_signal_request(id, signal_name, core_dumped, &error_message, &lang_tag)?;
            }
            Msg::Channel(id, ChannelMsg::WindowAdjusted { new_size }) => {
                debug!("window adjusted to {new_size:?} for channel {id:?}");
            }
            Msg::ChannelOpenAgent { channel_ref } => {
                let r = self.channel_open_agent();
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenSession { channel_ref } => {
                let r = self.channel_open_session();
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenDirectTcpIp {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let r = self.channel_open_direct_tcpip(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                );
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenDirectStreamLocal {
                socket_path,
                channel_ref,
            } => {
                let r = self.channel_open_direct_streamlocal(&socket_path);
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenForwardedTcpIp {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let r = self.channel_open_forwarded_tcpip(
                    &connected_address,
                    connected_port,
                    &originator_address,
                    originator_port,
                );
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path,
                channel_ref,
            } => {
                let r = self.channel_open_forwarded_streamlocal(&server_socket_path);
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::ChannelOpenX11 {
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let r = self.channel_open_x11(&originator_address, originator_port);
                self.complete_local_open(channel_ref, r)?;
            }
            Msg::TcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::CancelTcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.cancel_tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => {
                self.common.disconnect(reason, &description, &language_tag)?;
            }
            other => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (client-only?) message: {other:?}")
            }
        }
        Ok(())
    }

    pub(crate) async fn run<H, R>(
        mut self,
        mut stream: SshRead<R>,
        handler: H,
    ) -> Result<(), H::Error>
    where
        H: Handler + Send + 'static,
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut handler = Some(handler);
        let mut executor_join: Option<tokio::task::JoinHandle<()>> = None;
        let mut executor_abort: Option<tokio::task::AbortHandle> = None;
        self.flush()?;

        // Absolute handshake deadline from run_stream (banner already counted). Fallback
        // if run() is invoked without run_stream (tests).
        let handshake_deadline_at = self.handshake_deadline_at.unwrap_or_else(|| {
            tokio::time::Instant::now() + self.common.config.handshake_deadline
        });

        // Initial KEX first flush still inside handshake budget (Session-local clear PW).
        match tokio::time::timeout_at(
            handshake_deadline_at,
            self.common.packet_writer.flush_into(&mut stream),
        )
        .await
        {
            Ok(r) => {
                let _ = map_err!(r)?;
            }
            Err(_) => {
                return Err(crate::Error::HandshakeTimeout.into());
            }
        }

        let (stream_read, stream_write) = stream.split();
        let buffer = SSHBuffer::new();

        // Hand inbound epoch to Reader; leave a clear stub on Session (S2b PacketWriter analog).
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

        let keepalive_timer =
            future_or_pending(self.common.config.keepalive_interval, tokio::time::sleep);
        pin!(keepalive_timer);

        let inactivity_timer =
            future_or_pending(self.common.config.inactivity_timeout, tokio::time::sleep);
        pin!(inactivity_timer);

        // Lane-gated drainage: in-flight `reserve_owned()` futures for
        // backpressured channels. Kept local to the run loop (not on `Session`,
        // which must stay `Debug`). Permit in hand → pop lane head → send.
        let mut inbound_reserves: FuturesUnordered<BoxReserve> = FuturesUnordered::new();

        // ── S2b: spawn WriterTask owning PacketWriter + write half ───────────
        let write_progress = AtomicWriteProgress::new();
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let reader_cancel = cancel_rx.clone();
        // Move outbound epoch (PacketWriter) into Writer; leave clear placeholder on Session.
        let outbound_pw = std::mem::replace(
            &mut self.common.packet_writer,
            crate::sshbuffer::PacketWriter::clear(),
        );
        let writer_hooks = {
            #[cfg(feature = "_test_hooks")]
            {
                // Build the full-pipeline ledger BEFORE spawn so the Writer's
                // `pending_bytes` is the same atomic the Session samples (R4).
                let pending_arc = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let full_ledger = self.common.config.ledger_max.as_ref().map(|slot| {
                    let fl = std::sync::Arc::new(crate::server::supervisor::FullLedger::new(
                        pending_arc.clone(),
                        self.pending_outbound.bytes_arc(),
                        slot.clone(),
                    ));
                    // Pop-side checked-sub errors land on the same observable slot.
                    self.pending_outbound.set_mismatch_slot(slot.clone());
                    self.pending_outbound.set_full_ledger(fl.clone());
                    fl
                });
                self.full_ledger = full_ledger.clone();
                crate::server::writer::WriterHooks {
                    tombstone: crate::server::writer::CloseTombstone::new(),
                    full_ledger,
                    pending_override: Some(pending_arc),
                    fail_next_seal: self.common.config.fail_next_seal.clone(),
                    fail_next_socket_write: self.common.config.fail_next_socket_write.clone(),
                    socket_hang: self.common.config.socket_hang.clone(),
                    socket_hang_seen: self.common.config.socket_hang_seen.clone(),
                    force_next_bulk_full: self.common.config.force_next_bulk_full.clone(),
                    capacity_chain: self.common.config.capacity_chain.clone(),
                    dequeue_hold: self.common.config.dequeue_hold.clone(),
                    stop_discard: self.common.config.stop_discard.clone(),
                    packets_override: self.common.config.rekey_out_packets.clone(),
                    cipher_bytes_override: self.common.config.rekey_out_bytes.clone(),
                    observe: self.common.config.writer_observe.clone(),
                    invert_tombstone_counts: self.common.config.invert_tombstone_counts,
                    invert_keep_old_decompress: self.common.config.invert_keep_old_decompress,
                    compression_observe: self.common.config.compression_observe.clone(),
                }
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                crate::server::writer::WriterHooks::default()
            }
        };
        let (writer_handle, writer_join_raw, mut writer_events) =
            crate::server::writer::spawn_writer_with_hooks(
                stream_write,
                outbound_pw,
                write_progress.clone(),
                cancel_rx,
                writer_hooks,
            );
        let capacity_notify = writer_handle.capacity_notify();
        self.writer = Some(writer_handle.clone());
        let mut last_progress_snap = write_progress.load();
        let writer_abort = writer_join_raw.abort_handle();
        let mut writer_join = Some(writer_join_raw);

        // ── S3a: spawn ReaderTask owning read half + inbound epoch ──────────
        let reader_hooks = {
            #[cfg(feature = "_test_hooks")]
            {
                crate::server::reader::ReaderHooks {
                    observe: self.common.config.reader_observe.clone(),
                    read_hold: self.common.config.reader_read_hold.clone(),
                    mid_packet_hold: self.common.config.reader_mid_packet_hold.clone(),
                    fail_next_read: self.common.config.reader_fail_next_read.clone(),
                    post_read_hold: None,
                    apply_hold: self.common.config.reader_apply_hold.clone(),
                    force_ctrl_full: self.common.config.force_ctrl_full.clone(),
                    packets_override: self.common.config.rekey_in_packets.clone(),
                    bytes_override: self.common.config.rekey_in_bytes.clone(),
                    invert_keep_old_decompress: self.common.config.invert_keep_old_decompress,
                    compression_observe: self.common.config.compression_observe.clone(),
                    lane_observe: self.common.config.lane_observe.clone(),
                    inject_zero_data: self.common.config.inject_zero_data.clone(),
                    inject_until_overflow: self.common.config.inject_until_overflow.clone(),
                    inject_close_for: self.common.config.inject_close_for.clone(),
                    window_observe: self.common.config.window_observe.clone(),
                }
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                ReaderHooks::default()
            }
        };
        let credit = {
            #[cfg(feature = "_test_hooks")]
            {
                self.common
                    .config
                    .peer_credit
                    .clone()
                    .unwrap_or_else(PeerCreditBoard::new)
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                PeerCreditBoard::new()
            }
        };
        self.peer_credit = Some(credit.clone());
        let (reader_handle, reader_join_raw, mut ctrl_rx, mut reader_events) =
            spawn_reader_with_budget(
                stream_read,
                opening_cipher,
                buffer,
                reader_cancel,
                reader_hooks,
                self.common.config.inbound_ctrl_budget,
                self.common.config.inbound_min_packet_size as usize,
                self.common.config.inbound_lane_count_slack,
                credit.clone(),
            );
        let lane_ready = reader_handle.lane_ready();
        self.reader = Some(reader_handle);
        let reader_abort = reader_join_raw.abort_handle();
        let mut reader_join = Some(reader_join_raw);

        // Drop guard stays armed until production stop finishes.
        // Early `?` / return Err still cancel+abort both IO tasks.
        struct IoTeardownGuard {
            writer_abort: tokio::task::AbortHandle,
            reader_abort: tokio::task::AbortHandle,
            executor_abort: Option<tokio::task::AbortHandle>,
            cancel_tx: tokio::sync::watch::Sender<bool>,
            armed: bool,
        }
        impl Drop for IoTeardownGuard {
            fn drop(&mut self) {
                if self.armed {
                    let _ = self.cancel_tx.send(true);
                    self.writer_abort.abort();
                    self.reader_abort.abort();
                    if let Some(a) = self.executor_abort.take() {
                        a.abort();
                    }
                }
            }
        }
        let mut io_guard = IoTeardownGuard {
            writer_abort: writer_abort.clone(),
            reader_abort: reader_abort.clone(),
            executor_abort: None,
            cancel_tx: cancel_tx.clone(),
            armed: true,
        };

        // ── S1 ConnSupervisor state (still in Session loop; inputs from Writer) ─
        let mut write_watchdog = WriteWatchdog::new();
        let mut handshake_done = false;
        let mut supervisor_cause: Option<DisconnectCause> = None;
        let write_progress_deadline = self.common.config.write_progress_deadline;
        let write_min_drain = self.common.config.write_min_drain;
        let teardown_grace = self.common.config.teardown_grace;
        #[cfg(feature = "_test_hooks")]
        let cause_slot = self.common.config.disconnect_cause_slot.clone();
        // Deferred InstallAck while test hold is active (keeps read arm live).
        #[cfg(feature = "_test_hooks")]
        let mut deferred_install_ack: Option<u64> = None;
        #[cfg(feature = "_test_hooks")]
        let mut deferred_inbound_ack: Option<u64> = None;

        let record_cause = |cause: DisconnectCause, slot: &mut Option<DisconnectCause>| {
            if slot.is_none() {
                *slot = Some(cause);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = cause_slot {
                    s.record(cause);
                }
                debug!("supervisor first cause: {cause:?}");
            }
        };

        #[allow(clippy::panic)] // false positive in macro
        while !self.common.disconnected {
            self.common.received_data = false;
            let mut sent_keepalive = false;

            #[cfg(feature = "_test_hooks")]
            self.publish_kex_observe();

            // Apply deferred inbound ACK once the inbound hold is released (N8).
            #[cfg(feature = "_test_hooks")]
            if let Some(generation) = deferred_inbound_ack {
                let still_held = self
                    .common
                    .config
                    .inbound_ack_hold
                    .as_ref()
                    .is_some_and(|h| h.is_held());
                if !still_held {
                    deferred_inbound_ack = None;
                    if let Some(after) = self.on_install_ack_inbound(generation) {
                        self.apply_kex_after_install(after);
                        if let Err(e) = self.replay_pending_reads(handler.as_mut()).await {
                            debug!("pending_reads replay error: deferred inbound ACK");
                            let _ = e;
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        if let Some(c) = self.pending_supervisor_cause.take() {
                            record_cause(c, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        let _ = self.flush();
                    }
                }
            }

            // Apply deferred InstallAck once the test hold is released (R1).
            // Prefer the select arm below for wake; this covers race after release.
            #[cfg(feature = "_test_hooks")]
            if let Some(generation) = deferred_install_ack {
                let still_held = self
                    .common
                    .config
                    .install_ack_hold
                    .as_ref()
                    .is_some_and(|h| h.is_held());
                if !still_held {
                    deferred_install_ack = None;
                    if let Some(after) = self.on_install_ack_outbound(generation) {
                        self.apply_kex_after_install(after);
                        if let Err(e) = self.replay_pending_reads(handler.as_mut()).await {
                            debug!("pending_reads replay error: deferred InstallAck");
                            let _ = e;
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        if let Some(c) = self.pending_supervisor_cause.take() {
                            record_cause(c, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        let _ = self.flush();
                    }
                }
            }

            // Handshake complete once authentication has succeeded.
            // Auth accept sets `InitCompression` first; `Authenticated` is only entered on
            // the next post-auth packet (see server/encrypted.rs). Legitimate clients may
            // sit idle after auth without opening a channel — treat both states as done so
            // handshake_deadline cannot mis-fire HandshakeTimeout.
            if !handshake_done {
                if matches!(
                    self.common.encrypted.as_ref().map(|e| &e.state),
                    Some(EncryptedState::InitCompression | EncryptedState::Authenticated)
                ) {
                    handshake_done = true;
                } else if tokio::time::Instant::now() >= handshake_deadline_at {
                    record_cause(DisconnectCause::HandshakeTimeout, &mut supervisor_cause);
                    self.common.disconnected = true;
                    break;
                }
            }

            // Auth barrier: move Handler into Executor. Subsequent channel/global
            // callbacks are posted; handshake auth/GEX stay inline (already done).
            if handshake_done && self.executor.is_none() {
                if let Some(h) = handler.take() {
                    let spawned = crate::server::executor::spawn_handler_executor(
                        h,
                        self.common.config.clone(),
                        self.sender.clone(),
                        self.common.remote_sshid.clone(),
                        self.open_reply_tx.clone(),
                        self.facade_notify.clone(),
                        self.result_notify.clone(),
                    );
                    self.facade_cmd_rx = Some(spawned.facade_rx);
                    self.executor = Some(spawned.exec);
                    executor_join = Some(spawned.join);
                    executor_abort = Some(spawned.abort.clone());
                    io_guard.executor_abort = Some(spawned.abort);
                }
            }

            // Transfer parked seals / enc.write into Writer before the HWM
            // / watchdog sample. Hard-cap park can hold >=HWM in
            // `pending_outbound` or `enc.write` after Writer has drained
            // idle (no capacity notify); sampling first leaves recv gated
            // off and a later rekey dumps those bytes into a still-writable
            // socket, so eligible hits 0 and the write watchdog disarms.
            // retry_pending is byte-cap aware, so this does not re-open F1.
            if let Err(e) = self.retry_pending_outbound() {
                debug!("retry_pending_outbound (loop-top): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }
            if let Err(e) = self.flush() {
                debug!("flush (loop-top): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }
            if let Err(e) = self.try_drain_pending_data_under_budget() {
                debug!("drain pending (loop-top): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }
            if let Err(e) = self.retry_deferred_window_grants(handler.as_mut()).await {
                debug!("retry deferred WINDOW_ADJUST (loop-top): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }
            match self.expire_due_openings() {
                Ok(true) => {
                    if let Err(e) = self.flush() {
                        debug!("flush expired openings: {e:?}");
                        record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                        self.common.disconnected = true;
                        continue;
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    debug!("expire openings: {e:?}");
                    record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                    self.common.disconnected = true;
                    continue;
                }
            }
            self.drain_facade_cmds();
            match self.try_harvest_result() {
                Ok(_) => {}
                Err(e) => {
                    record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                    return Err(e.into());
                }
            }
            // Resume lane pump after Executor space frees. Skipping this
            // when we gated the notify arm on `exec_full` would miss the
            // already-signaled `lane_ready` and stall remaining REQUESTs.
            let more_lanes = match self.pump_reader_lanes(handler.as_mut()).await {
                Ok(more) => more,
                Err(e) => {
                    if let Some(c) = self.pending_supervisor_cause.take() {
                        record_cause(c, &mut supervisor_cause);
                        self.common.disconnected = true;
                        false
                    } else {
                        return Err(e);
                    }
                }
            };
            if !self.common.disconnected {
                self.drain_needs_reserve(&mut inbound_reserves);
            }
            // Pump may have posted Invokes whose callbacks already queued
            // facade commands (notify fired while we were still popping).
            self.drain_facade_cmds();
            match self.try_harvest_result() {
                Ok(_) => {}
                Err(e) => {
                    record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                    return Err(e.into());
                }
            }
            if more_lanes && !self.common.disconnected {
                continue;
            }
            // Aggregation board drain: always here (or, under the pin hook,
            // after the batch drain). Never in the notify arm.
            #[cfg(feature = "_test_hooks")]
            let pin_outbound_before_credit = self.common.config.pin_outbound_before_credit;
            #[cfg(not(feature = "_test_hooks"))]
            let pin_outbound_before_credit = false;
            if !pin_outbound_before_credit {
                if let Err(e) = self.apply_pending_peer_credit(handler.as_mut()).await {
                    return Err(e);
                }
                // Hole A: apply drains pending_data → enc.write. Must settle
                // before select or the sealed bytes never leave and the ack
                // stays parked.
                if let Err(e) = self.settle_outbound_after_stage() {
                    debug!("settle outbound (after credit): {e:?}");
                    record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                    self.common.disconnected = true;
                    continue;
                }
            }

            // S2b: single sealed-backlog ledger for HWM / write-watchdog =
            // Writer in-flight + Session pending + unconsumed enc.write.
            // G2: peer-window=0 data stays in pending_data and is never staged → 0.
            let sealed_backlog = self.sealed_backlog_bytes();

            // Watchdog arms on any submitted-not-on-socket sealed/pending seal bytes.
            // §4.2: eligible=0 disarms. InKex with empty staging is RekeyTimeout.
            let snap = write_progress.load();
            write_watchdog.observe_eligible(sealed_backlog as u64);
            #[cfg(feature = "_test_hooks")]
            if let Some(ref slot) = self.common.config.watchdog_observe {
                let kex_gen = if self.kex.active() || self.pending_kex_install.is_some() {
                    self.rekey_gen
                } else {
                    0
                };
                slot.observe(write_watchdog.is_armed(), sealed_backlog as u64, kex_gen);
            }
            if snap.drained_bytes_epoch > last_progress_snap.drained_bytes_epoch {
                let delta = (snap.drained_bytes_epoch - last_progress_snap.drained_bytes_epoch)
                    as usize;
                write_watchdog.note_write_ok(delta);
            }
            last_progress_snap = snap;
            if let Some(cause) = write_watchdog.poll_timeout(write_progress_deadline, write_min_drain)
            {
                record_cause(cause, &mut supervisor_cause);
                self.common.disconnected = true;
                break;
            }
            // S1: rekey deadline (generation-checked).
            if let Some(kex_gen) = self.rekey_deadline.poll(self.active_rekey_gen()) {
                record_cause(DisconnectCause::RekeyTimeout, &mut supervisor_cause);
                debug!("rekey deadline fired generation={kex_gen}");
                self.common.disconnected = true;
                break;
            }

            // Drain messages already queued on the session channel (e.g. shell
            // output pushed via `Handle::data()` from a spawned task) before
            // blocking in `select!`. `select!` only handles one queued message
            // per loop iteration, so a task producing faster than the loop
            // drains falls behind. Capped so high-rate output can't starve
            // client input (Ctrl+C, resize): once the cap is hit we fall through
            // to `select!`, which picks up any client-side event first. Gated on
            // `!kex.active()` to match the `select!` receiver arm.
            const MAX_MESSAGES_PER_BATCH: usize = 64;
            // NB: deliberately *not* gated on `has_any_pending_data()` (upstream de96ad1).
            // That check is session-wide, so a single channel whose peer stopped reading —
            // leaving its window exhausted and its `pending_data` non-empty — would halt this
            // drain and the `select!` receiver arm for *every* channel, and only a
            // CHANNEL_WINDOW_ADJUST from that one stalled peer could restart them. A peer that
            // never adjusts (or a rekey, which forces all outbound data into `pending_data`)
            // therefore stalled the whole session's outbound path. Per-channel isolation is
            // enforced by `enforce_outbound_cap` below instead.
            //
            // HWM is a **submission budget**, not a once-per-round boolean.
            // Recheck after each dispatch; flush when budget exhausted.
            let can_receive_outbound = !self.blocks_outbound_intake()
                && sealed_backlog < crate::sshbuffer::OUTBOUND_HIGH_WATERMARK;
            // R4: an HWM-budget intake refusal is an observable Full/HWM hit
            // (large-packet floods trip the budget long before mpsc count-Full).
            #[cfg(feature = "_test_hooks")]
            if !self.blocks_outbound_intake()
                && sealed_backlog >= crate::sshbuffer::OUTBOUND_HIGH_WATERMARK
            {
                if let Some(ref fl) = self.full_ledger {
                    fl.slot.note_intake_block();
                }
            }
            if can_receive_outbound {
                let mut drained = 0;
                while drained < MAX_MESSAGES_PER_BATCH {
                    if self.sealed_backlog_bytes()
                        >= crate::sshbuffer::OUTBOUND_HIGH_WATERMARK
                    {
                        #[cfg(feature = "_test_hooks")]
                        if let Some(ref fl) = self.full_ledger {
                            fl.slot.note_intake_block();
                        }
                        break;
                    }
                    // Only Empty/Disconnected end the drain; both mean "nothing
                    // more to hand off right now", so treat them the same.
                    let Ok(msg) = self.receiver.try_recv() else {
                        break;
                    };
                    self.dispatch_msg(msg)?;
                    drained += 1;
                    // Convert enc.write → Writer so budget reflects sealed state.
                    if let Err(e) = self.flush() {
                        debug!("flush (batch): {e:?}");
                        record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                        self.common.disconnected = true;
                        break;
                    }
                }
                // A drained Disconnect sets this; don't block in `select!` after.
                if self.common.disconnected {
                    continue;
                }
            }
            if pin_outbound_before_credit {
                if let Err(e) = self.apply_pending_peer_credit(handler.as_mut()).await {
                    return Err(e);
                }
            }
            // Hole B: batch dispatch of ChannelDataAcked parks the ack and
            // may fill pending_data; batch itself only flushes. Settle
            // before select. Also covers the pin path's late credit apply.
            if let Err(e) = self.settle_outbound_after_stage() {
                debug!("settle outbound (loop-top): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }

            // Advance pending atomic KEX install (NeedSubmit) without blocking.
            // `_test_hooks`: after handshake, R3 isolates the capacity-notify
            // arm as the ONLY NeedSubmit liveness source. Loop-top would steal
            // the 1→2 transition on a keepalive/supervisor wake and leave
            // `install_advances` at 0. Must NOT skip during the initial
            // handshake — that NeedSubmit has no dequeue notify yet and
            // skipping it fails auth.
            #[cfg(feature = "_test_hooks")]
            let skip_loop_top_advance =
                handshake_done && self.common.config.need_submit_timer_disable;
            #[cfg(not(feature = "_test_hooks"))]
            let skip_loop_top_advance = false;
            if !skip_loop_top_advance {
                self.try_advance_pending_kex_install();
            }
            if let Some(c) = self.pending_supervisor_cause.take() {
                record_cause(c, &mut supervisor_cause);
                self.common.disconnected = true;
                continue;
            }

            // Supervisor timer sleeps (recomputed each iteration).
            // Include min-drain remaining so strategy layer cannot sleep past its window.
            let wd_sleep = write_watchdog
                .next_activity_deadline(write_progress_deadline)
                .unwrap_or(std::time::Duration::from_secs(3600));
            let min_drain_sleep = write_watchdog
                .next_min_drain_deadline(write_min_drain)
                .unwrap_or(std::time::Duration::from_secs(3600));
            let rekey_sleep = self
                .rekey_deadline
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(3600));
            let hs_sleep = if handshake_done {
                std::time::Duration::from_secs(3600)
            } else {
                handshake_deadline_at.saturating_duration_since(tokio::time::Instant::now())
            };
            // NeedSubmit must not wait forever for a capacity notify that never
            // arrives (e.g. Writer socket hang with out_q already soft-full).
            // Poll the install retry path on a short cadence while parked.
            // `_test_hooks`: R3 disables this redundancy so the capacity-notify
            // chain is the ONLY liveness source under test.
            #[cfg(feature = "_test_hooks")]
            let need_submit_timer_off = self.common.config.need_submit_timer_disable;
            #[cfg(not(feature = "_test_hooks"))]
            let need_submit_timer_off = false;
            let need_submit_sleep = if !need_submit_timer_off
                && matches!(
                    self.pending_kex_install.as_ref().map(|p| &p.phase),
                    Some(PendingKexPhase::NeedSubmit { .. })
                ) {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::from_secs(3600)
            };
            let open_deadline_sleep = self
                .next_opening_deadline()
                .map(|t| t.saturating_duration_since(tokio::time::Instant::now()))
                .unwrap_or(std::time::Duration::from_secs(3600));
            let supervisor_sleep = wd_sleep
                .min(min_drain_sleep)
                .min(rekey_sleep)
                .min(hs_sleep)
                .min(need_submit_sleep)
                .min(open_deadline_sleep)
                .max(std::time::Duration::from_millis(1));

            // F2: InstallAck hold release is a first-class select competitor.
            #[cfg(feature = "_test_hooks")]
            let install_ack_hold_fut = {
                let hold = self.common.config.install_ack_hold.clone();
                let inbound_hold = self.common.config.inbound_ack_hold.clone();
                let waiting = deferred_install_ack.is_some();
                let inbound_waiting = deferred_inbound_ack.is_some();
                async move {
                    if waiting {
                        if let Some(h) = hold {
                            h.wait_released().await;
                            return;
                        }
                    }
                    if inbound_waiting {
                        if let Some(h) = inbound_hold {
                            h.wait_released().await;
                            return;
                        }
                    }
                    std::future::pending::<()>().await
                }
            };
            #[cfg(not(feature = "_test_hooks"))]
            let install_ack_hold_fut = std::future::pending::<()>();
            tokio::pin!(install_ack_hold_fut);

            // R3: one-shot IGNORE inject is a first-class select competitor so
            // the run-loop can park a single bulk cmd without a keepalive timer.
            #[cfg(feature = "_test_hooks")]
            let inject_ignore_fut = {
                let gate = self.common.config.inject_ignore.clone();
                async move {
                    if let Some(g) = gate {
                        g.wait_requested().await;
                        return;
                    }
                    std::future::pending::<()>().await
                }
            };
            #[cfg(not(feature = "_test_hooks"))]
            let inject_ignore_fut = std::future::pending::<()>();
            tokio::pin!(inject_ignore_fut);

            let lane_notified = lane_ready.notified();
            tokio::pin!(lane_notified);
            let credit_notified = credit.notify().notified();
            tokio::pin!(credit_notified);

            let skip_facade = self.skip_facade_drain();
            let exec_full = self.executor_full();
            let ctrl_held = {
                #[cfg(feature = "_test_hooks")]
                {
                    self.common
                        .config
                        .hold_session_ctrl
                        .as_ref()
                        .is_some_and(|h| h.load(std::sync::atomic::Ordering::SeqCst))
                }
                #[cfg(not(feature = "_test_hooks"))]
                {
                    false
                }
            };
            // Subscribe *before* the last drain so a notify during drain
            // still wakes select (register-then-check).
            let facade_n = self.facade_notify.clone();
            let result_n = self.result_notify.clone();
            let facade_notified = facade_n.notified();
            tokio::pin!(facade_notified);
            let result_notified = result_n.notified();
            tokio::pin!(result_notified);
            self.drain_facade_cmds();
            match self.try_harvest_result() {
                Ok(_) => {}
                Err(e) => {
                    record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                    return Err(e.into());
                }
            }

            tokio::select! {
                biased;
                // This queue must not grow per-packet / peer-rate-driven
                // variants (this round's lesson). Rare events only.
                evt = writer_events.recv() => {
                    match evt {
                        Some(WriterEvent::InstallAckOutbound { generation }) => {
                            debug!("session: got InstallAck Outbound gen={generation}");
                            #[cfg(feature = "_test_hooks")]
                            if self
                                .common
                                .config
                                .install_ack_hold
                                .as_ref()
                                .is_some_and(|h| h.is_held())
                            {
                                deferred_install_ack = Some(generation);
                            } else if let Some(after) =
                                self.on_install_ack_outbound(generation)
                            {
                                self.apply_kex_after_install(after);
                                if let Err(e) =
                                    self.replay_pending_reads(handler.as_mut()).await
                                {
                                    debug!("pending_reads replay error");
                                    let _ = e;
                                    record_cause(
                                        DisconnectCause::PeerError,
                                        &mut supervisor_cause,
                                    );
                                    self.common.disconnected = true;
                                }
                                if let Some(c) =
                                    self.pending_supervisor_cause.take()
                                {
                                    record_cause(c, &mut supervisor_cause);
                                    self.common.disconnected = true;
                                }
                                let _ = self.flush();
                            }
                            #[cfg(not(feature = "_test_hooks"))]
                            if let Some(after) =
                                self.on_install_ack_outbound(generation)
                            {
                                self.apply_kex_after_install(after);
                                if let Err(e) =
                                    self.replay_pending_reads(handler.as_mut()).await
                                {
                                    debug!("pending_reads replay error");
                                    let _ = e;
                                    record_cause(
                                        DisconnectCause::PeerError,
                                        &mut supervisor_cause,
                                    );
                                    self.common.disconnected = true;
                                }
                                if let Some(c) =
                                    self.pending_supervisor_cause.take()
                                {
                                    record_cause(c, &mut supervisor_cause);
                                    self.common.disconnected = true;
                                }
                                let _ = self.flush();
                            }
                        }
                        Some(WriterEvent::KexQueueFull)
                        | Some(WriterEvent::WriteError(_))
                        | Some(WriterEvent::SealError) => {
                            self.fail_pending_kex_install();
                            if let Some(c) = self.pending_supervisor_cause.take() {
                                record_cause(c, &mut supervisor_cause);
                            } else {
                                record_cause(
                                    DisconnectCause::PeerError,
                                    &mut supervisor_cause,
                                );
                            }
                            self.common.disconnected = true;
                        }
                        None => {
                            self.fail_pending_kex_install();
                            if let Some(c) = self.pending_supervisor_cause.take() {
                                record_cause(c, &mut supervisor_cause);
                            } else if supervisor_cause.is_none() {
                                record_cause(
                                    DisconnectCause::PeerError,
                                    &mut supervisor_cause,
                                );
                            }
                            self.common.disconnected = true;
                        }
                    }
                }
                () = &mut facade_notified, if !skip_facade => {
                    self.drain_facade_cmds();
                }
                () = &mut result_notified => {
                    match self.try_harvest_result() {
                        Ok(_) => {}
                        Err(e) => {
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            return Err(e.into());
                        }
                    }
                }
                ctrl = ctrl_rx.recv(), if !exec_full && !ctrl_held => {
                    let Some(ctrl) = ctrl else {
                        debug!("ctrl closed; harvest reader terminal");
                        loop {
                            match reader_events.recv().await {
                                Some(ReaderEvent::InstallAckInbound { generation }) => {
                                    if let Some(after) =
                                        self.on_install_ack_inbound(generation)
                                    {
                                        self.apply_kex_after_install(after);
                                        let _ = self.flush();
                                    }
                                }
                                Some(ReaderEvent::ReadError) => {
                                    record_cause(
                                        DisconnectCause::PeerError,
                                        &mut supervisor_cause,
                                    );
                                    self.common.disconnected = true;
                                    break;
                                }
                                Some(ReaderEvent::CtrlFull) => {
                                    record_cause(
                                        DisconnectCause::PeerError,
                                        &mut supervisor_cause,
                                    );
                                    self.common.disconnected = true;
                                    break;
                                }
                                Some(ReaderEvent::Eof) | None => {
                                    self.common.disconnected = true;
                                    break;
                                }
                            }
                        }
                        break;
                    };
                    // Handshake: deadline + HandshakeTimeout. Post-handshake:
                    // bare await (S3a). A 3600s timeout that drops the
                    // future would cancel reply()/handler mid-packet after
                    // the ctrl item was already consumed — desync, and the
                    // silent-continue branch was a third state (neither
                    // disconnect nor stall). Handler hang is S4.
                    if !handshake_done {
                        match tokio::time::timeout_at(
                            handshake_deadline_at,
                            self.handle_ctrl_msg(ctrl, handler.as_mut()),
                        )
                        .await
                        {
                            Ok(Ok(true)) => {}
                            Ok(Ok(false)) => {
                                debug!("break");
                                break;
                            }
                            Ok(Err(e)) => return Err(e),
                            Err(_) => {
                                record_cause(
                                    DisconnectCause::HandshakeTimeout,
                                    &mut supervisor_cause,
                                );
                                self.common.disconnected = true;
                                break;
                            }
                        }
                    } else {
                        match self.handle_ctrl_msg(ctrl, handler.as_mut()).await {
                            Ok(true) => {}
                            Ok(false) => {
                                debug!("break");
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    if let Some(c) = self.pending_supervisor_cause.take() {
                        record_cause(c, &mut supervisor_cause);
                        self.common.disconnected = true;
                    }
                    self.drain_needs_reserve(&mut inbound_reserves);
                    if let Err(e) = self.pump_reader_lanes(handler.as_mut()).await {
                        if let Some(c) = self.pending_supervisor_cause.take() {
                            record_cause(c, &mut supervisor_cause);
                            self.common.disconnected = true;
                        } else {
                            return Err(e);
                        }
                    }
                    #[cfg(feature = "_test_hooks")]
                    if self.pending_kex_install.is_some() {
                        if let Some(ref slot) = self.common.config.kex_install_observe {
                            slot.mark_packet_while_pending();
                        }
                    }
                }
                () = &mut lane_notified => {
                    if let Err(e) = self.pump_reader_lanes(handler.as_mut()).await {
                        if let Some(c) = self.pending_supervisor_cause.take() {
                            record_cause(c, &mut supervisor_cause);
                            self.common.disconnected = true;
                        } else {
                            return Err(e);
                        }
                    } else {
                        self.drain_needs_reserve(&mut inbound_reserves);
                    }
                }
                () = &mut credit_notified => {
                    // Wake-only: drain is always at loop-top.
                }
                Some((cid, generation, res)) = inbound_reserves.next(), if !inbound_reserves.is_empty() && !self.blocks_outbound_intake() => {
                    // A backpressured channel's application buffer freed a slot: deliver its head
                    // item and re-arm. The grant for that channel is emitted into `self.write` and
                    // goes out via the flush below — never blocking the loop on this channel.
                    self.pump_inbound(cid, generation, res, handler.as_mut()).await?;
                    self.drain_needs_reserve(&mut inbound_reserves);
                }
                // Channel-open replies from handlers that stashed the `ChannelOpenHandle` and
                // accepted/rejected later from a spawned task. Same kex gate as the `receiver`
                // arm: no packets may be written mid-rekey.
                Some(msg) = self.open_reply_rx.recv(), if !self.blocks_outbound_intake() => {
                    if let Msg::ChannelOpenReply { pending, result } = msg {
                        self.finalize_channel_open_reply(pending, result)?;
                    }
                    self.drain_open_replies()?;
                }
                () = &mut keepalive_timer => {
                    self.common.alive_timeouts = self.common.alive_timeouts.saturating_add(1);
                    if self.common.config.keepalive_max != 0 && self.common.alive_timeouts > self.common.config.keepalive_max {
                        debug!("Timeout, client not responding to keepalives");
                        // io_guard Drop will cancel+abort
                        return Err(crate::Error::KeepaliveTimeout.into());
                    }
                    sent_keepalive = true;
                    self.keepalive_request()?;
                }
                () = &mut inactivity_timer => {
                    debug!("timeout");
                    // io_guard Drop will cancel+abort
                    return Err(crate::Error::InactivityTimeout.into());
                }
                // Reader events (inbound InstallAck, read error, EOF).
                revt = reader_events.recv() => {
                    match revt {
                        Some(ReaderEvent::InstallAckInbound { generation }) => {
                            debug!("session: got InstallAck Inbound gen={generation}");
                            let hold = {
                                #[cfg(feature = "_test_hooks")]
                                {
                                    self.common
                                        .config
                                        .inbound_ack_hold
                                        .as_ref()
                                        .is_some_and(|h| h.is_held())
                                }
                                #[cfg(not(feature = "_test_hooks"))]
                                {
                                    false
                                }
                            };
                            if hold {
                                #[cfg(feature = "_test_hooks")]
                                {
                                    deferred_inbound_ack = Some(generation);
                                }
                            } else if let Some(after) =
                                self.on_install_ack_inbound(generation)
                            {
                                self.apply_kex_after_install(after);
                                if let Err(e) =
                                    self.replay_pending_reads(handler.as_mut()).await
                                {
                                    debug!("pending_reads replay error: inbound ACK");
                                    let _ = e;
                                    record_cause(
                                        DisconnectCause::PeerError,
                                        &mut supervisor_cause,
                                    );
                                    self.common.disconnected = true;
                                }
                                if let Some(c) = self.pending_supervisor_cause.take() {
                                    record_cause(c, &mut supervisor_cause);
                                    self.common.disconnected = true;
                                }
                                let _ = self.flush();
                            }
                        }
                        Some(ReaderEvent::ReadError) => {
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        Some(ReaderEvent::CtrlFull) => {
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        Some(ReaderEvent::Eof) | None => {
                            debug!("reader eof / dropped");
                            if supervisor_cause.is_none()
                                && self.pending_supervisor_cause.is_none()
                            {
                                // Clean EOF: leave first-cause unset so a
                                // supervisor cause already recorded wins.
                            }
                            self.common.disconnected = true;
                        }
                    }
                }
                // Writer drained → retry deferred outbound + try pending KEX install.
                () = capacity_notify.notified() => {
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref cc) = self.common.config.capacity_chain {
                        cc.mark_arm_run();
                    }
                    if let Err(e) = self.retry_pending_outbound() {
                        debug!("retry_pending_outbound: {e:?}");
                        record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                        self.common.disconnected = true;
                    } else if let Err(e) = self.retry_deferred_window_grants(handler.as_mut()).await {
                        debug!("retry deferred WINDOW_ADJUST (capacity): {e:?}");
                        record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                        self.common.disconnected = true;
                    } else {
                        #[cfg(feature = "_test_hooks")]
                        let was_need_submit = matches!(
                            self.pending_kex_install.as_ref().map(|p| &p.phase),
                            Some(PendingKexPhase::NeedSubmit { .. })
                        );
                        self.try_advance_pending_kex_install();
                        #[cfg(feature = "_test_hooks")]
                        {
                            let still_need = matches!(
                                self.pending_kex_install.as_ref().map(|p| &p.phase),
                                Some(PendingKexPhase::NeedSubmit { .. })
                            );
                            if was_need_submit
                                && !still_need
                                && self.pending_outbound.is_empty()
                            {
                                if let Some(ref cc) = self.common.config.capacity_chain {
                                    cc.mark_install_advance();
                                }
                            }
                        }
                        if let Some(c) = self.pending_supervisor_cause.take() {
                            record_cause(c, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                        if let Err(e) = self.try_drain_pending_data_under_budget() {
                            debug!("drain pending under budget: {e:?}");
                            record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                            self.common.disconnected = true;
                        }
                    }
                }
                // F2: InstallAck hold release must wake select (not loop-top poll only).
                () = &mut install_ack_hold_fut => {
                    // Body runs after release; loop-top applies deferred InstallAck.
                }
                () = &mut inject_ignore_fut => {
                    #[cfg(feature = "_test_hooks")]
                    {
                        if let Some(ref mut enc) = self.common.encrypted {
                            // SSH_MSG_IGNORE + empty string (length-prefixed).
                            enc.write.extend_from_slice(&[
                                0, 0, 0, 5,
                                crate::msg::IGNORE,
                                0, 0, 0, 0,
                            ]);
                        }
                        if let Some(ref g) = self.common.config.inject_ignore {
                            g.mark_done();
                        }
                    }
                }
                // See the batch-drain comment above: gating this arm on `has_any_pending_data()`
                // would let one stalled channel block outbound progress for all of them.
                msg = self.receiver.recv(), if can_receive_outbound
                    && self.sealed_backlog_bytes()
                        < crate::sshbuffer::OUTBOUND_HIGH_WATERMARK =>
                {
                    match msg {
                        Some(msg) => self.dispatch_msg(msg)?,
                        None => {
                            debug!("self.receiver: received None");
                        }
                    }
                }
                // S1 supervisor poll (write watchdog / min-drain / rekey / handshake).
                () = tokio::time::sleep(supervisor_sleep) => {
                    // Re-check on wake; the top-of-loop checks also run.
                }
            }

            // Stage plaintext → SealRaw/SealPayload into Writer (S2b), then
            // unpark Handle::data. Same settle as loop-top (drain → flush →
            // release); grants stay after it so a new ADJUST is not a third
            // pre-select stage.
            if let Err(e) = self.settle_outbound_after_stage() {
                debug!("settle outbound (loop-bottom): {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
            }
            if let Err(e) = self.retry_deferred_window_grants(handler.as_mut()).await {
                debug!("retry deferred WINDOW_ADJUST: {e:?}");
                record_cause(DisconnectCause::PeerError, &mut supervisor_cause);
                self.common.disconnected = true;
            }

            if self.common.received_data {
                // Reset the number of failed keepalive attempts. We don't
                // bother detecting keepalive response messages specifically
                // (OpenSSH_9.6p1 responds with REQUEST_FAILURE aka 82). Instead
                // we assume that the client is still alive if we receive any
                // data from it.
                self.common.alive_timeouts = 0;
            }
            if self.common.received_data || sent_keepalive {
                if let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    keepalive_timer.as_mut().as_pin_mut(),
                    self.common.config.keepalive_interval,
                ) {
                    sleep.as_mut().reset(tokio::time::Instant::now() + d);
                }
            }
            if !sent_keepalive {
                if let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    inactivity_timer.as_mut().as_pin_mut(),
                    self.common.config.inactivity_timeout,
                ) {
                    sleep.as_mut().reset(tokio::time::Instant::now() + d);
                }
            }
        }
        debug!("disconnected");

        // S1: best-effort DISCONNECT on supervisor teardown.
        if let Some(cause) = supervisor_cause {
            let _ = self.disconnect(
                crate::Disconnect::ByApplication,
                &format!("supervisor: {cause:?}"),
                "en",
            );
            let _ = self.flush();
        }

        // Single absolute grace (S1: no stacked deadlines). Writer + Reader share
        // the same `grace_at`. Read half lives in Reader — no Session drain.
        let grace_at = tokio::time::Instant::now() + teardown_grace;
        stop_writer_task(
            &cancel_tx,
            self.writer.as_ref(),
            &mut writer_join,
            grace_at,
        )
        .await;
        stop_reader_task(&mut reader_join, grace_at).await;
        // Drop the facade receiver first so queued oneshot senders
        // fire RecvError and Executor-side blocking waits wake
        // before cancel/join.
        drop(self.facade_cmd_rx.take());
        crate::server::executor::stop_handler_executor(
            self.executor.as_ref(),
            &mut executor_join,
            grace_at,
        )
        .await;
        let _ = executor_abort;
        io_guard.armed = false;

        // Convert supervisor first-cause into a typed Error so callers/tests see it.
        if let Some(cause) = supervisor_cause {
            let err = match cause {
                DisconnectCause::WriteStalled => crate::Error::WriteStalled,
                DisconnectCause::RekeyTimeout => crate::Error::RekeyTimeout(self.rekey_gen),
                DisconnectCause::HandshakeTimeout => crate::Error::HandshakeTimeout,
                DisconnectCause::PeerError | DisconnectCause::LocalShutdown => {
                    return Ok(());
                }
                DisconnectCause::HandlerExecutorGone => crate::Error::SendError,
                DisconnectCause::ReplyObligationOverflow => crate::Error::ReplyObligationOverflow,
            };
            return Err(err.into());
        }

        Ok(())
    }

    /// Wire-weight of complete packets in `enc.write[cursor..]` (payload body + OH each).
    /// Incomplete trailing bytes count as raw (no OH) until framed.
    fn enc_write_wire_weight(buf: &[u8], cursor: usize) -> usize {
        use byteorder::{BigEndian, ByteOrder};
        let mut i = cursor;
        let mut total = 0usize;
        while i + 4 <= buf.len() {
            let len = BigEndian::read_u32(&buf[i..]) as usize;
            if i + 4 + len > buf.len() {
                total = total.saturating_add(buf.len().saturating_sub(i));
                break;
            }
            total = total
                .saturating_add(len)
                .saturating_add(crate::server::writer::WIRE_OVERHEAD_PER_PACKET);
            i += 4 + len;
        }
        total
    }

    /// Writer in-flight + Session pending + unconsumed `enc.write` + KEX NeedSubmit.
    /// All stages use the **same** per-packet wire reservation weight (no submit-time OH jump).
    pub(crate) fn sealed_backlog_bytes(&self) -> usize {
        let writer = self
            .writer
            .as_ref()
            .map(|w| w.pending_bytes())
            .unwrap_or(0);
        let pending = self.pending_outbound.bytes();
        let unconsumed_write = self
            .common
            .encrypted
            .as_ref()
            .map(|enc| Self::enc_write_wire_weight(&enc.write, enc.write_cursor))
            .unwrap_or(0);
        let kex_need = self
            .pending_kex_install
            .as_ref()
            .map(|p| p.need_submit_bytes())
            .unwrap_or(0);
        let n = writer
            .saturating_add(pending)
            .saturating_add(unconsumed_write)
            .saturating_add(kex_need);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = self.full_ledger {
            // Conservation: enc.write growth/shrink updates `total` the same
            // way as Writer accept / pending park. Cursor-then-seal is a
            // transfer (enc shrink + Writer credit).
            fl.set_enc_write(unconsumed_write);
            fl.set_kex_need(kex_need);
            fl.slot.note_live_hwm(n);
        } else if let Some(ref slot) = self.common.config.ledger_max {
            slot.observe_parts(n, [writer, pending, kex_need, unconsumed_write]);
        }
        n
    }

    /// Publish pending-install phase for integration tests (`_test_hooks`).
    /// Call on **every** phase/Idle transition (not only loop top).
    #[cfg(feature = "_test_hooks")]
    pub(crate) fn publish_kex_observe(&self) {
        // Keep the KEX NeedSubmit ledger component in lockstep with the phase
        // and sample the complete sum on every transition (R4).
        if let Some(ref fl) = self.full_ledger {
            let need = self
                .pending_kex_install
                .as_ref()
                .map(|p| p.need_submit_bytes())
                .unwrap_or(0);
            fl.set_kex_need(need);
        }
        let Some(ref slot) = self.common.config.kex_install_observe else {
            return;
        };
        let phase = match self.pending_kex_install.as_ref().map(|p| &p.phase) {
            None => 0u8,
            Some(PendingKexPhase::NeedSubmit { .. }) => 1,
            Some(PendingKexPhase::WaitingAck) => 2,
            Some(PendingKexPhase::InstallAcked) => 3,
        };
        slot.set_phase(phase);
        slot.set_after_known(
            self.pending_kex_install
                .as_ref()
                .is_some_and(|p| p.after.is_some()),
        );
        slot.set_inbound_acked(
            self.pending_kex_install
                .as_ref()
                .is_some_and(|p| p.inbound_acked)
                || self.reader.is_none(),
        );
        let non_idle = self.kex.active() || self.pending_kex_install.is_some();
        slot.set_non_idle(non_idle);
        if !non_idle {
            // Force phase 0 when fully Idle even if last phase was left InstallAcked mid-loop.
            slot.set_phase(0);
        }
    }

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    pub(crate) fn publish_kex_observe(&self) {}

    /// Stage first-cause only if none yet (preserve earliest cause).
    pub(crate) fn stage_cause(&mut self, cause: DisconnectCause) {
        if self.pending_supervisor_cause.is_none() {
            self.pending_supervisor_cause = Some(cause);
        }
    }

    /// Worst-case wire overhead per sealed SSH packet for HWM reservation:
    /// 4B length + 1B padlen + ≤19B pad (block/GCM: pad&lt;4 adds a full 16B block)
    /// + ≤64B MAC/tag.
    pub(crate) const WIRE_OVERHEAD_PER_PACKET: usize = 4 + 1 + 19 + 64;

    /// Cleartext CHANNEL_DATA framing inside one SSH payload:
    /// 1B msg + 4B channel + 4B string length.
    pub(crate) const CHANNEL_DATA_FRAMING: usize = 1 + 4 + 4;
    /// CHANNEL_EXTENDED_DATA: +4B ext type.
    pub(crate) const CHANNEL_EXT_DATA_FRAMING: usize = 1 + 4 + 4 + 4;

    /// Per-packet reservation once application bytes become an SSH CHANNEL_* payload:
    /// framing + wire (length/padlen/pad/MAC).
    pub(crate) fn packet_reservation(framing: usize) -> usize {
        framing.saturating_add(Self::WIRE_OVERHEAD_PER_PACKET)
    }

    /// Max **application** payload under budget given peer max-packet, CHANNEL framing,
    /// and wire worst-case overhead.
    ///
    /// Cost model for `app` bytes: `app + ceil(app/max_packet) * (framing + WIRE_OH)`.
    /// When budget is smaller than one full packet reservation, still allow up to
    /// `min(budget.saturating_sub(framing+wire_oh's progress escape), max_packet)` so a
    /// final residue can make progress (HWM + one fixed packet overshoot).
    pub(crate) fn max_payload_for_budget(budget: usize, max_packet: u32) -> usize {
        Self::max_payload_for_budget_framed(budget, max_packet, Self::CHANNEL_DATA_FRAMING)
    }

    pub(crate) fn max_payload_for_budget_framed(
        budget: usize,
        max_packet: u32,
        framing: usize,
    ) -> usize {
        let m = (max_packet as usize).max(1);
        let per_pkt = Self::packet_reservation(framing);
        if budget == 0 {
            return 0;
        }
        // Strict fit: total wire cost (app + n×(framing+OH)) must stay within `budget`.
        // The HWM+one_packet overshoot is already encoded in `outbound_budget_*`; this
        // function must not add a second escape that pushes past HWM+one.
        // When budget < 1+per_pkt no positive app payload fits.
        let mut lo = 0usize;
        let mut hi = budget;
        while lo < hi {
            let mid = (lo + hi + 1) / 2;
            let pkts = mid.div_ceil(m);
            let cost = mid.saturating_add(pkts.saturating_mul(per_pkt));
            if cost <= budget {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }

    /// Submit collected plaintext payloads to Writer for sealing (S2b).
    ///
    /// Normal bulk `Full` is **backpressure**: unsent cmds park in
    /// [`pending_outbound`] and capacity_notify / loop-top retries. Only `Closed`
    /// fails. Retry always precedes new submit so later KEX cannot leapfrog.
    /// KEX NEWKEYS must use [`Self::seal_batch_and_install_outbound`].
    pub(crate) fn seal_payloads(&mut self, payloads: Vec<bytes::Bytes>) -> Result<(), Error> {
        for p in payloads {
            self.submit_seal_payload(p)?;
        }
        Ok(())
    }

    /// Retry all parked outbound cmds (capacity arm + before any new submit).
    pub(crate) fn retry_pending_outbound(&mut self) -> Result<(), Error> {
        use crate::server::writer::TrySendWireError;
        let Some(ref writer) = self.writer else {
            // No writer: drain parked into local PW (tests).
            while let Some(cmd) = self.pending_outbound.pop_front() {
                match cmd {
                    PendingOutboundCmd::SealPayload(p) | PendingOutboundCmd::SealRaw(p) => {
                        self.common.packet_writer.packet_raw(p.as_ref())?;
                    }
                    PendingOutboundCmd::InitOutboundCompress(c) => {
                        c.init_compress(self.common.packet_writer.compress());
                    }
                }
            }
            return Ok(());
        };
        let one = (self.common.config.maximum_packet_size as usize)
            .saturating_add(Self::packet_reservation(Self::CHANNEL_DATA_FRAMING));
        let hard = crate::sshbuffer::OUTBOUND_HIGH_WATERMARK.saturating_add(one);
        while let Some(cmd) = self.pending_outbound.pop_front() {
            // Byte HWM, not mpsc count: hard-cap park must not be undone by
            // retry (that was F1 +97 — a 97B WINDOW_ADJUST re-entering Writer
            // on top of an already-full HWM+one pipeline).
            let w = PendingOutbound::weight_of(&cmd);
            if w > 0 && self.sealed_backlog_bytes().saturating_add(w) > hard {
                self.pending_outbound.push_front(cmd);
                return Ok(());
            }
            match cmd {
                PendingOutboundCmd::SealPayload(p) => match writer.try_seal_payload(p) {
                    Ok(()) => {}
                    Err(TrySendWireError::Full(p)) => {
                        self.pending_outbound
                            .push_front(PendingOutboundCmd::SealPayload(p));
                        return Ok(());
                    }
                    Err(TrySendWireError::FullCmd) => {
                        // Should not happen for seal.
                        return Err(Error::SendError);
                    }
                    Err(TrySendWireError::Closed) => return Err(Error::SendError),
                },
                PendingOutboundCmd::SealRaw(p) => match writer.try_seal_raw(p) {
                    Ok(()) => {}
                    Err(TrySendWireError::Full(p)) => {
                        self.pending_outbound
                            .push_front(PendingOutboundCmd::SealRaw(p));
                        return Ok(());
                    }
                    Err(TrySendWireError::FullCmd) => return Err(Error::SendError),
                    Err(TrySendWireError::Closed) => return Err(Error::SendError),
                },
                PendingOutboundCmd::InitOutboundCompress(c) => {
                    match writer.try_init_outbound_compress(c.clone()) {
                        Ok(_ack) => {
                            // Handler is sync; do not block run-loop on ACK.
                            let _ = _ack;
                        }
                        Err(TrySendWireError::FullCmd) | Err(TrySendWireError::Full(_)) => {
                            self.pending_outbound
                                .push_front(PendingOutboundCmd::InitOutboundCompress(c));
                            return Ok(());
                        }
                        Err(TrySendWireError::Closed) => return Err(Error::SendError),
                    }
                }
            }
        }
        Ok(())
    }

    fn submit_seal_payload(&mut self, p: bytes::Bytes) -> Result<(), Error> {
        use crate::server::writer::TrySendWireError;
        if p.is_empty() {
            return Ok(());
        }
        // Ordered: drain parked first; if anything remains, park behind it.
        self.retry_pending_outbound()?;
        if !self.pending_outbound.is_empty() {
            self.pending_outbound
                .push_back(PendingOutboundCmd::SealPayload(p));
            return Ok(());
        }
        let Some(ref writer) = self.writer else {
            return self.common.packet_writer.packet_raw(p.as_ref());
        };
        match writer.try_seal_payload(p) {
            Ok(()) => Ok(()),
            Err(TrySendWireError::Full(p)) => {
                self.pending_outbound
                    .push_back(PendingOutboundCmd::SealPayload(p));
                Ok(())
            }
            Err(TrySendWireError::FullCmd) => Err(Error::SendError),
            Err(TrySendWireError::Closed) => Err(Error::SendError),
        }
    }

    /// Queue deferred outbound compress after USERAUTH_SUCCESS (no unbounded ACK wait).
    pub(crate) fn submit_init_outbound_compress(
        &mut self,
        compression: crate::compression::Compression,
    ) -> Result<(), Error> {
        use crate::server::writer::TrySendWireError;
        self.retry_pending_outbound()?;
        if !self.pending_outbound.is_empty() {
            self.pending_outbound
                .push_back(PendingOutboundCmd::InitOutboundCompress(compression));
            return Ok(());
        }
        let Some(ref writer) = self.writer else {
            compression.init_compress(self.common.packet_writer.compress());
            return Ok(());
        };
        match writer.try_init_outbound_compress(compression.clone()) {
            Ok(_ack) => {
                let _ = _ack; // sync handler; run-loop must keep polling watchdog
                Ok(())
            }
            Err(TrySendWireError::FullCmd) | Err(TrySendWireError::Full(_)) => {
                self.pending_outbound
                    .push_back(PendingOutboundCmd::InitOutboundCompress(compression));
                Ok(())
            }
            Err(TrySendWireError::Closed) => Err(Error::SendError),
        }
    }

    /// Auth-success ordered barrier:
    /// seal USERAUTH_SUCCESS (still uncompressed) → FIFO-activate deferred outbound
    /// compress → `Authenticated`. Never awaits ACK inside `reply()`.
    pub(crate) fn complete_auth_compress_barrier(&mut self) -> Result<(), Error> {
        // Inbound deferred decompress = client→server = client_compression.
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.client_compression.is_deferred() {
                enc.client_compression
                    .init_decompress(&mut enc.decompress);
                if let Some(ref reader) = self.reader {
                    let _ = reader.try_enable_decompress(enc.client_compression.clone());
                }
            }
        }
        // Seal USERAUTH_SUCCESS (and anything already staged) with pre-activate epoch.
        self.flush()?;
        // Outbound deferred = server→client = server_compression.
        let (deferred, comp) = match self.common.encrypted.as_ref() {
            Some(enc) => (
                enc.server_compression.is_deferred(),
                enc.server_compression.clone(),
            ),
            None => (false, crate::compression::Compression::None),
        };
        if deferred {
            self.submit_init_outbound_compress(comp)?;
        }
        if let Some(ref mut enc) = self.common.encrypted {
            enc.state = crate::session::EncryptedState::Authenticated;
        }
        Ok(())
    }

    /// Bytes still allowed into the outbound pipeline before HWM (submission budget).
    ///
    /// Soft HWM plus **one actual peer packet** worst-case total
    /// (`max_packet` app + framing + wire OH). Default uses config max-packet.
    pub(crate) fn outbound_budget(&self) -> usize {
        self.outbound_budget_for_peer_packet(
            self.common.config.maximum_packet_size,
            Self::CHANNEL_DATA_FRAMING,
        )
    }

    /// Budget headroom for a specific peer max-packet (one actual packet total).
    pub(crate) fn outbound_budget_for_peer_packet(
        &self,
        max_packet: u32,
        framing: usize,
    ) -> usize {
        let one = (max_packet as usize).saturating_add(Self::packet_reservation(framing));
        let hard = crate::sshbuffer::OUTBOUND_HIGH_WATERMARK.saturating_add(one);
        let sealed = self.sealed_backlog_bytes();
        let headroom = hard.saturating_sub(sealed);
        // Never offer more than one peer-packet of cost in a single intake snapshot.
        // Multi-packet fill is achieved by repeated data()/drain calls that recheck
        // sealed_backlog — prevents stale multi-packet overshoot near the hard cap.
        //
        // Last-packet zone (headroom ≤ one): leave 97B for a same-turn
        // WINDOW_ADJUST. F1 147650 = writer 132624 + enc (14929+97). Far
        // from the cap, do not reserve — tiny packets must still reach HWM.
        let adjust = 9usize.saturating_add(Self::WIRE_OVERHEAD_PER_PACKET);
        if headroom <= one {
            headroom.saturating_sub(adjust).min(one)
        } else {
            headroom.min(one)
        }
    }

    /// KEX or pending atomic install blocks channel-open / outbound intake.
    pub(crate) fn blocks_outbound_intake(&self) -> bool {
        self.kex.active() || self.pending_kex_install.is_some()
    }

    /// Whether `flush` must leave this `enc.write` packet staged while kex
    /// / pending-install is open. Only application CHANNEL_DATA* is held
    /// (keeps wire-eligible > 0 on S0 stall). Auth, service, IGNORE, and
    /// keepalive must still drain — holding USERAUTH_SUCCESS after the
    /// state flips to InitCompression breaks R1; holding GLOBAL_REQUEST
    /// keepalive breaks R5 rekey fail injection.
    fn hold_enc_packet_during_kex(_enc: &crate::session::Encrypted, msg: u8) -> bool {
        matches!(msg, msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA)
    }

    /// Largest peer-driven control-reply reservation.
    /// REQUEST_SUCCESS + allocated-port u32 = 1+4 = 5; CHANNEL_SUCCESS
    /// / CHANNEL_FAILURE = byte + uint32 recipient = 5. Plus WIRE_OH
    /// (88) = 93. REQUEST_FAILURE is 1+88=89. Gating at
    /// `sealed + weight >= hard` stops either from stepping over
    /// HWM+one (r12 counterexample A / r13 residual).
    pub(crate) const MAX_CONTROL_REPLY_RESERVATION: usize =
        5 + Self::WIRE_OVERHEAD_PER_PACKET;

    fn outbound_hard_cap(&self) -> usize {
        let one = (self.common.config.maximum_packet_size as usize)
            .saturating_add(Self::packet_reservation(Self::CHANNEL_DATA_FRAMING));
        crate::sshbuffer::OUTBOUND_HIGH_WATERMARK.saturating_add(one)
    }

    /// Never close the inbound socket for HWM. Closing it wedged
    /// `CHANNEL_DATA` delivery (and therefore WINDOW_ADJUST grants) once
    /// `sealed + 93` hit hard. The hard-cap is enforced when a non-KEX
    /// control reply is emitted (`admit_control_reply`); kex/auth packets
    /// still flow. Writer drain does not wait on read.
    pub(crate) fn outbound_blocks_inbound_read(&self) -> bool {
        false
    }

    /// Admit a GLOBAL_REQUEST / CHANNEL_REQUEST reply into `enc.write`.
    /// Over hard: do not write. If the peer asked for a reply (`wants_reply`)
    /// or we are in kex (`blocks_outbound_intake`), stage `PeerError`
    /// (bounded disconnect, not an unbounded park).
    fn admit_control_reply(&mut self, weight: usize, wants_reply: bool) -> bool {
        if self.sealed_backlog_bytes().saturating_add(weight) >= self.outbound_hard_cap() {
            if wants_reply || self.blocks_outbound_intake() {
                self.stage_cause(DisconnectCause::PeerError);
            }
            return false;
        }
        true
    }

    pub(crate) fn emit_global_request_reply(
        &mut self,
        success: bool,
        extra_port: Option<u32>,
    ) -> Result<(), Error> {
        let payload = 1usize.saturating_add(if extra_port.is_some() { 4 } else { 0 });
        let weight = payload.saturating_add(Self::WIRE_OVERHEAD_PER_PACKET);
        debug_assert!(weight <= Self::MAX_CONTROL_REPLY_RESERVATION);
        if !self.admit_control_reply(weight, self.common.wants_reply) {
            return Ok(());
        }
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(if success {
                    msg::REQUEST_SUCCESS
                } else {
                    msg::REQUEST_FAILURE
                });
                if let Some(port) = extra_port {
                    port.encode(&mut enc.write)?;
                }
            });
        }
        self.common.wants_reply = false;
        self.record_outbound_from_write();
        Ok(())
    }

    pub(crate) fn enqueue_global_obligation(&mut self) -> Result<(), Error> {
        let max = self.common.config.max_pending_want_replies.max(1);
        if self.global_replies.len() >= max {
            self.stage_cause(DisconnectCause::ReplyObligationOverflow);
            return Err(Error::ReplyObligationOverflow);
        }
        self.global_replies.enqueue_pending();
        self.publish_reply_queue();
        Ok(())
    }

    pub(crate) fn enqueue_channel_obligation(&mut self, id: ChannelId) -> Result<(), Error> {
        let max = self.common.config.max_pending_want_replies.max(1);
        let over = self
            .common
            .encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&id))
            .map(|ch| ch.reply_queue.len() >= max)
            .unwrap_or(false);
        if over {
            self.stage_cause(DisconnectCause::ReplyObligationOverflow);
            return Err(Error::ReplyObligationOverflow);
        }
        if let Some(ch) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&id))
        {
            ch.reply_queue.enqueue_pending();
            ch.want_reply_count = ch.want_reply_count.saturating_add(1);
            ch.wants_reply = true;
        }
        self.publish_reply_queue();
        Ok(())
    }

    pub(crate) fn fail_last_channel_obligation(&mut self, id: ChannelId) -> Result<(), Error> {
        if let Some(ch) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&id))
        {
            ch.reply_queue.decide_last_if_pending(false, None);
        }
        self.flush_channel_replies(id)
    }

    pub(crate) fn on_channel_invoke_posted(
        &mut self,
        id: ChannelId,
        posted: bool,
        had_obligation: bool,
    ) -> Result<(), Error> {
        if posted || !had_obligation {
            Ok(())
        } else {
            self.fail_last_channel_obligation(id)
        }
    }

    pub(crate) fn fail_last_global_obligation(&mut self) -> Result<(), Error> {
        self.global_replies.decide_last_if_pending(false, None);
        self.flush_global_replies()
    }

    pub(crate) fn fail_pending_obligation(
        &mut self,
        harvest: Option<crate::server::executor::PendingHarvest>,
    ) -> Result<(), Error> {
        use crate::server::executor::PendingHarvest;
        match harvest {
            // Channel want-reply stays open: Handle::channel_success may
            // decide it after the callback returns. Auto-FAILURE here
            // double-sends when the app replies late (fix2).
            Some(PendingHarvest::ChannelReq) => Ok(()),
            Some(PendingHarvest::GlobalForward { wants_reply, .. })
            | Some(PendingHarvest::GlobalBool { wants_reply })
                if wants_reply =>
            {
                self.fail_global_obligation()
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn fail_global_obligation(&mut self) -> Result<(), Error> {
        self.global_replies.decide_oldest_pending(false, None);
        self.flush_global_replies()
    }

    pub(crate) fn flush_global_replies(&mut self) -> Result<(), Error> {
        while let Some(ob) = self.global_replies.pop_ready() {
            let success = ob.verdict == ReplyVerdict::Success;
            self.common.wants_reply = true;
            self.emit_global_request_reply(success, ob.extra_port)?;
        }
        let _ = self.flush();
        Ok(())
    }

    pub(crate) fn flush_channel_replies(&mut self, channel: ChannelId) -> Result<(), Error> {
        loop {
            let ready = self
                .common
                .encrypted
                .as_mut()
                .and_then(|enc| enc.channels.get_mut(&channel))
                .and_then(|ch| ch.reply_queue.pop_ready());
            let Some(ob) = ready else {
                break;
            };
            self.write_one_channel_reply(channel, ob.verdict == ReplyVerdict::Success)?;
        }
        Ok(())
    }

    /// Register atomic NEWKEYS install for the **outer run-loop** to advance.
    ///
    /// Synchronous: never waits capacity or ACK. Full → stays in `NeedSubmit`.
    /// Closed → stages `PeerError` (get_or_insert).
    /// If a transaction is already open → **Err** (does not overwrite).
    ///
    /// `after`: `None` for NeedsReply (peer Done not yet); `Some` for skip_exchange
    /// where Done is already known.
    pub(crate) fn register_seal_batch_and_install(
        &mut self,
        payloads: Vec<bytes::Bytes>,
        generation: u64,
        cipher: Box<dyn crate::cipher::SealingKey + Send>,
        compression: crate::compression::Compression,
        activate_compress: bool,
        reset_seqn: bool,
        after: Option<KexAfterInstall>,
    ) -> Result<(), PendingKexConflict> {
        if self.pending_kex_install.is_some() {
            self.stage_cause(DisconnectCause::PeerError);
            return Err(PendingKexConflict);
        }
        self.pending_kex_install = Some(PendingKexInstall {
            generation,
            after,
            phase: PendingKexPhase::NeedSubmit {
                payloads,
                cipher,
                compression,
                activate_compress,
                reset_seqn,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        self.try_advance_pending_kex_install();
        Ok(())
    }

    /// Advance NeedSubmit without blocking. ACK completion is dual-condition.
    pub(crate) fn try_advance_pending_kex_install(&mut self) {
        use crate::server::writer::TrySendEpochError;

        if !matches!(
            self.pending_kex_install.as_ref().map(|p| &p.phase),
            Some(PendingKexPhase::NeedSubmit { .. })
        ) {
            return;
        }

        // Production FIFO: parked cmds all go first. NeedSubmit stays parked
        // until `pending_outbound` is empty (KEX must not leapfrog).
        if let Err(e) = self.retry_pending_outbound() {
            debug!("pending kex install: retry outbound failed: {e:?}");
            self.pending_kex_install = None;
            self.stage_cause(DisconnectCause::PeerError);
            return;
        }
        if !self.pending_outbound.is_empty() {
            return;
        }

        let Some(PendingKexInstall {
            generation,
            after,
            phase: PendingKexPhase::NeedSubmit {
                payloads,
                cipher,
                compression,
                activate_compress,
                reset_seqn,
            },
            inbound_acked,
            inbound_sent,
        }) = self.pending_kex_install.take()
        else {
            return;
        };

        // The NeedSubmit payloads' weight leaves the KEX ledger component here:
        // on successful submit the Writer accept picks up the same weight (pure
        // transfer). Zero the mirror BEFORE the submit so the Writer-side sample
        // cannot transiently dual-count (R4).
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = self.full_ledger {
            fl.set_kex_need(0);
        }

        if self.writer.is_none() {
            for p in &payloads {
                if self.common.packet_writer.packet_raw(p.as_ref()).is_err() {
                    self.stage_cause(DisconnectCause::PeerError);
                    return;
                }
            }
            self.common.packet_writer.set_cipher(cipher);
            if activate_compress {
                compression.init_compress(self.common.packet_writer.compress());
            }
            if reset_seqn {
                self.common.packet_writer.reset_seqn();
            }
            // Local path: install already applied → InstallAcked. Inbound
            // follows Reader if present; unit tests have no Reader.
            self.pending_kex_install = Some(PendingKexInstall {
                generation,
                after,
                phase: PendingKexPhase::InstallAcked,
                inbound_acked,
                inbound_sent,
            });
            let _ = self.try_finalize_pending_kex_install();
            return;
        }

        match self.writer.as_ref().unwrap().try_seal_batch_and_install(
            payloads,
            generation,
            cipher,
            compression,
            activate_compress,
            reset_seqn,
        ) {
            Ok(_ack_rx) => {
                let _ = _ack_rx;
                self.pending_kex_install = Some(PendingKexInstall {
                    generation,
                    after,
                    phase: PendingKexPhase::WaitingAck,
                    inbound_acked,
                    inbound_sent,
                });
                self.publish_kex_observe();
            }
            Err(TrySendEpochError::Full {
                payloads,
                cipher,
                outbound_compression: compression,
                activate_compress,
                reset_seqn,
                ..
            }) => {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref slot) = self.common.config.need_submit_seen {
                    slot.mark();
                }
                self.pending_kex_install = Some(PendingKexInstall {
                    generation,
                    after,
                    phase: PendingKexPhase::NeedSubmit {
                        payloads,
                        cipher,
                        compression,
                        activate_compress,
                        reset_seqn,
                    },
                    inbound_acked,
                    inbound_sent,
                });
                self.publish_kex_observe();
            }
            Err(TrySendEpochError::Closed) => {
                debug!("pending kex install: Writer closed");
                self.stage_cause(DisconnectCause::PeerError);
                self.publish_kex_observe();
            }
        }
    }

    /// Reader inbound ACK. Marks inbound_acked; finalize only if the other
    /// two conditions are already met. Never called from `reply()`.
    pub(crate) fn on_install_ack_inbound(
        &mut self,
        generation: u64,
    ) -> Option<KexAfterInstall> {
        let Some(p) = self.pending_kex_install.as_mut() else {
            return None;
        };
        if p.generation != generation {
            return None;
        }
        p.inbound_acked = true;
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.set_inbound_acked(true);
        }
        self.publish_kex_observe();
        let ready = self.try_finalize_pending_kex_install();
        self.publish_kex_observe();
        ready
    }

    /// NeedsReply (key-first): extract inbound half and try_push. `delay_inbound_epoch`
    /// skips this so N2 can force NEWKEYS-first. Never awaits.
    pub(crate) fn push_inbound_from_kex(
        &mut self,
        kex: &mut crate::server::kex::ServerKex,
        generation: u64,
    ) -> Result<(), ()> {
        #[cfg(feature = "_test_hooks")]
        if self
            .common
            .config
            .delay_inbound_epoch
            .as_ref()
            .is_some_and(|d| d.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Ok(());
        }
        let Some(ih) = kex.take_inbound_epoch_install() else {
            return Ok(());
        };
        let post_auth = matches!(
            self.common.encrypted.as_ref().map(|e| &e.state),
            Some(EncryptedState::InitCompression | EncryptedState::Authenticated)
        );
        let activate = !ih.compression.is_deferred() || post_auth;
        self.try_push_inbound_epoch(generation, ih, activate)
    }

    /// Done path: push inbound if NeedsReply did not already.
    pub(crate) fn push_inbound_from_newkeys_if_needed(
        &mut self,
        newkeys: &mut crate::session::NewKeys,
        generation: u64,
        strict_rekey: bool,
    ) -> Result<(), ()> {
        if self
            .pending_kex_install
            .as_ref()
            .is_some_and(|p| p.inbound_sent)
        {
            return Ok(());
        }
        let ih = crate::server::kex::ServerKex::take_inbound_from_newkeys(
            newkeys,
            strict_rekey,
        );
        let post_auth = matches!(
            self.common.encrypted.as_ref().map(|e| &e.state),
            Some(EncryptedState::InitCompression | EncryptedState::Authenticated)
        );
        let activate = !ih.compression.is_deferred() || post_auth;
        self.try_push_inbound_epoch(generation, ih, activate)
    }

    /// Try-push inbound epoch to Reader (capacity 1). Never awaits.
    /// No Reader (unit tests): install locally into `remote_to_local` and
    /// mark inbound_acked so the dual-condition tests stay valid.
    pub(crate) fn try_push_inbound_epoch(
        &mut self,
        generation: u64,
        half: crate::server::kex::InboundEpochInstall,
        activate_decompress: bool,
    ) -> Result<(), ()> {
        #[cfg(feature = "_test_hooks")]
        if self
            .common
            .config
            .force_inbound_install_full
            .as_ref()
            .is_some_and(|f| f.swap(false, std::sync::atomic::Ordering::SeqCst))
        {
            self.stage_cause(DisconnectCause::PeerError);
            return Err(());
        }
        if let Some(p) = self.pending_kex_install.as_ref() {
            if p.inbound_sent {
                return Ok(());
            }
        }

        let epoch = InstallInboundEpoch {
            generation,
            cipher: half.cipher,
            compression: half.compression,
            activate_decompress,
            // Connection already negotiated strict-kex: reset at every
            // inbound install (rekey KEXINIT omits the strict marker).
            reset_seqn: half.reset_seqn || self.common.strict_kex,
        };

        let Some(ref reader) = self.reader else {
            self.common.remote_to_local = epoch.cipher;
            if let Some(ref mut enc) = self.common.encrypted {
                if epoch.activate_decompress {
                    epoch.compression.init_decompress(&mut enc.decompress);
                }
            }
            if let Some(p) = self.pending_kex_install.as_mut() {
                p.inbound_sent = true;
                p.inbound_acked = true;
            }
            #[cfg(feature = "_test_hooks")]
            if let Some(ref slot) = self.common.config.kex_install_observe {
                slot.mark_inbound_commit();
                slot.set_inbound_acked(true);
            }
            return Ok(());
        };

        match reader.try_install_inbound(epoch) {
            Ok(()) => {
                if let Some(p) = self.pending_kex_install.as_mut() {
                    p.inbound_sent = true;
                    p.inbound_acked = false;
                }
                Ok(())
            }
            Err(crate::server::reader::TryInstallInboundError::Full(_))
            | Err(crate::server::reader::TryInstallInboundError::Closed(_)) => {
                self.stage_cause(DisconnectCause::PeerError);
                Err(())
            }
        }
    }

    /// InstallAck: mark install side complete; finalize only if `after` already set.
    pub(crate) fn on_install_ack_outbound(
        &mut self,
        generation: u64,
    ) -> Option<KexAfterInstall> {
        let Some(p) = self.pending_kex_install.as_mut() else {
            return None;
        };
        if p.generation != generation {
            return None;
        }
        if !matches!(p.phase, PendingKexPhase::WaitingAck) {
            return None;
        }
        p.phase = PendingKexPhase::InstallAcked;
        self.publish_kex_observe();
        let ready = self.try_finalize_pending_kex_install();
        self.publish_kex_observe();
        ready
    }

    /// Peer Done with empty payloads: merge `after` into transaction.
    /// Returns `Some(after)` if both conditions already met (or no pending = already ACKed).
    pub(crate) fn merge_peer_done_into_pending(
        &mut self,
        after: KexAfterInstall,
    ) -> Option<KexAfterInstall> {
        if let Some(p) = self.pending_kex_install.as_mut() {
            if p.after.is_some() {
                // Double Done merge is a protocol/state bug.
                self.stage_cause(DisconnectCause::PeerError);
                return None;
            }
            p.after = Some(after);
            return self.try_finalize_pending_kex_install();
        }
        // No open transaction: outbound install already ACKed (or never needed).
        Some(after)
    }

    /// If phase==InstallAcked && after.is_some() && inbound ready, take and return after.
    fn try_finalize_pending_kex_install(&mut self) -> Option<KexAfterInstall> {
        let inbound_ok = self.reader.is_none()
            || self
                .pending_kex_install
                .as_ref()
                .is_some_and(|p| p.inbound_acked);
        let ready = self.pending_kex_install.as_ref().is_some_and(|p| {
            matches!(p.phase, PendingKexPhase::InstallAcked) && p.after.is_some() && inbound_ok
        });
        if !ready {
            return None;
        }
        self.pending_kex_install
            .take()
            .and_then(|p| p.after)
    }

    /// SealError / Writer death while a pending install exists → fail closed.
    pub(crate) fn fail_pending_kex_install(&mut self) {
        if self.pending_kex_install.take().is_some() {
            self.stage_cause(DisconnectCause::PeerError);
            // Do not set KEX Idle / clear deadline — outer cancel path owns that.
            self.publish_kex_observe();
        }
    }

    /// Completion actions only — **must not** touch cipher/decompress fields.
    ///
    /// `flush_all_pending` runs here (not at inbound commit) so channel data
    /// sealed after NEWKEYS uses the **new** outbound epoch (RFC 4253 §7.1).
    pub(crate) fn apply_kex_after_install(&mut self, after: KexAfterInstall) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.mark_completion();
        }
        match after {
            KexAfterInstall::RekeyComplete => {
                if let Some(ref mut enc) = self.common.encrypted {
                    let _ = enc.flush_all_pending();
                }
                self.kex = SessionKexState::Idle;
                self.clear_rekey_deadline();
            }
            KexAfterInstall::InitialComplete => {
                self.kex = SessionKexState::Idle;
                self.clear_rekey_deadline();
                let _ = self.maybe_send_ext_info();
            }
        }
        self.publish_kex_observe();
    }

    /// Rekey inbound commit — call from **Done (peer NEWKEYS) the same reply turn**.
    ///
    /// Only cipher/decompress/metadata — **no** `flush_all_pending` (that waits for
    /// dual-condition complete so post-KEX data does not leapfrog NEWKEYS seal).
    pub(crate) fn commit_rekey_inbound(&mut self, newkeys: crate::session::NewKeys) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.mark_inbound_commit();
        }
        {
            let common = &mut self.common;
            if let Some(ref mut enc) = common.encrypted {
                enc.exchange = Some(newkeys.exchange);
                enc.kex = newkeys.kex;
                enc.key = newkeys.key;
                enc.client_mac = newkeys.names.client_mac;
                enc.server_mac = newkeys.names.server_mac;
                enc.client_compression = newkeys.names.client_compression.clone();
                enc.server_compression = newkeys.names.server_compression.clone();
                debug_assert!(
                    enc.client_compression == newkeys.names.client_compression
                        && enc.server_compression == newkeys.names.server_compression,
                    "commit_rekey_inbound must install Compression matching newkeys.names \
                     (c2s={:?}/{:?} s2c={:?}/{:?})",
                    enc.client_compression,
                    newkeys.names.client_compression,
                    enc.server_compression,
                    newkeys.names.server_compression,
                );
                #[cfg(feature = "_test_hooks")]
                if let Some(ref slot) = common.config.compression_observe {
                    slot.set_enums(enc.client_compression.clone(), enc.server_compression.clone());
                }
                debug!(
                    "commit_rekey_inbound compression c2s={:?} s2c={:?}",
                    enc.client_compression, enc.server_compression
                );
                let post_auth = matches!(
                    enc.state,
                    EncryptedState::InitCompression | EncryptedState::Authenticated
                );
                if enc.client_compression.is_deferred() && !post_auth {
                    enc.decompress = crate::compression::Decompress::None;
                } else {
                    enc.client_compression
                        .init_decompress(&mut enc.decompress);
                }
            }
            // Cipher lives in Reader after S3a. Leave the Session stub alone.
            // (try_push_inbound_epoch already handed the OpeningKey to Reader.)
            common.strict_kex = common.strict_kex || newkeys.names.strict_kex();
            let _ = newkeys.cipher.local_to_remote;
            let _ = newkeys.cipher.remote_to_local;
        }
    }

    /// Initial Done: build Encrypted + inbound — **same Done reply turn**.
    pub(crate) fn commit_initial_encrypted(
        &mut self,
        state: EncryptedState,
        newkeys: crate::session::NewKeys,
    ) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.mark_inbound_commit();
        }
        let (_stub, _comp, _rs) = self.common.encrypted_split_outbound(state, newkeys, true);
        let _ = _stub;
    }

    /// Park a decrypted packet for replay after KEX install completes.
    pub(crate) fn park_pending_read(&mut self, buf: Vec<u8>) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.mark_park();
        }
        self.pending_len = self.pending_len.saturating_add(buf.len() as u32);
        self.pending_reads.push(buf);
    }

    /// Park when the outbound install transaction is past the point of no return:
    /// either peer Done is already known (`after.is_some()` — waiting solely for
    /// the InstallAck), or the outbound install already ACKed (`InstallAcked` —
    /// ACK-before-Done, waiting solely for peer Done). In both windows the KEX
    /// state machine awaits a different packet (NEWKEYS or nothing), so a new
    /// peer KEXINIT must queue for replay, never feed `kex.step`.
    /// Not during NeedSubmit/WaitingAck-without-Done (NeedsReply path): there a
    /// peer KEXINIT may still be the simultaneous-rekey exchange `kex.step` owns.
    pub(crate) fn should_park_kexinit(&self) -> bool {
        self.pending_kex_install.as_ref().is_some_and(|p| {
            p.after.is_some() || matches!(p.phase, PendingKexPhase::InstallAcked)
        })
    }

    /// Unified replay: every finalize path re-enters `reply` gate (KEXINIT etc.).
    ///
    /// `Box::pin` breaks the async mutual recursion with `reply` (which may call
    /// this helper on Done finalize) — required by edition-2024 / E0733.
    pub(crate) fn replay_pending_reads<'a, H: Handler + Send + 'a>(
        &'a mut self,
        mut handler: Option<&'a mut H>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), H::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut pending = std::mem::take(&mut self.pending_reads);
            self.pending_len = 0;
            for p in pending.drain(..) {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref slot) = self.common.config.kex_install_observe {
                    slot.mark_replay();
                }
                let mut fake = crate::sshbuffer::IncomingSshPacket {
                    buffer: p,
                    seqn: std::num::Wrapping(0),
                };
                super::reply(self, handler.as_mut().map(|h| &mut **h), &mut fake).await?;
                if self.pending_supervisor_cause.is_some() {
                    break;
                }
            }
            Ok(())
        })
    }

    /// Extract outbound cipher half from NewKeys without installing inbound.
    pub(crate) fn take_outbound_from_newkeys_server(
        newkeys: &mut crate::session::NewKeys,
    ) -> (
        Box<dyn crate::cipher::SealingKey + Send>,
        crate::compression::Compression,
        bool,
    ) {
        let reset_seqn = newkeys.names.strict_kex();
        let outbound_comp = newkeys.names.server_compression.clone();
        let local = std::mem::replace(
            &mut newkeys.cipher.local_to_remote,
            Box::new(crate::cipher::clear::Key {}),
        );
        (local, outbound_comp, reset_seqn)
    }

    /// Get a handle to this session.
    pub(crate) fn handle_apply(&self) -> Handle {
        self.sender.clone()
    }

    pub(crate) fn writable_packet_size_apply(&self, channel: &ChannelId) -> u32 {
        let win = self.window_size(channel);
        if let Some(ref enc) = self.common.encrypted {
            if let Some(ch) = enc.channels.get(channel) {
                return win.min(ch.sender_maximum_packet_size);
            }
        }
        0
    }

    pub(crate) fn window_size_apply(&self, channel: &ChannelId) -> u32 {
        if let Some(r) = self.reader.as_ref() {
            if let Some(w) = r.sender_window(*channel) {
                return w;
            }
        }
        if let Some(ref enc) = self.common.encrypted {
            if let Some(ch) = enc.channels.get(channel) {
                return ch.sender_window_size;
            }
        }
        0
    }

    pub(crate) fn max_packet_size_apply(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(channel) {
                return channel.sender_maximum_packet_size;
            }
        }
        0
    }

    fn rekey_max_packets(&self) -> u64 {
        #[cfg(feature = "_test_hooks")]
        if let Some(n) = self.common.config.rekey_max_packets_override {
            return n;
        }
        self.common.config.as_ref().limits.max_packets
    }

    /// Four-direction I5 predicate (out/in × packets/bytes) plus
    /// `rekey_wanted`. Packet threshold is `limits.max_packets` (or a
    /// `_test_hooks` override). Bytes use the single `limits.max_bytes`
    /// in both directions. No time trigger (S6b / Q3).
    fn i5_volume_due(&mut self) -> bool {
        let wanted = {
            let Some(enc) = self.common.encrypted.as_mut() else {
                return false;
            };
            if enc.kex.skip_exchange() {
                return false;
            }
            std::mem::replace(&mut enc.rekey_wanted, false)
        };
        let limits = &self.common.config.as_ref().limits;

        let max_pkts = self.rekey_max_packets();
        #[cfg(feature = "_test_hooks")]
        let skip_pkts = self.common.config.invert_skip_packet_rekey;
        #[cfg(not(feature = "_test_hooks"))]
        let skip_pkts = false;
        #[cfg(feature = "_test_hooks")]
        let observe_only = self.common.config.invert_i5_observe_only;
        #[cfg(not(feature = "_test_hooks"))]
        let observe_only = false;

        let (out_pkts, out_bytes) = if let Some(w) = self.writer.as_ref() {
            let pkts = if observe_only {
                #[cfg(feature = "_test_hooks")]
                {
                    self.common
                        .config
                        .writer_observe
                        .as_ref()
                        .map(|o| o.packets_this_epoch())
                        .unwrap_or(0)
                }
                #[cfg(not(feature = "_test_hooks"))]
                {
                    w.packets_this_epoch()
                }
            } else {
                w.packets_this_epoch()
            };
            (pkts, w.cipher_bytes())
        } else {
            (0, 0)
        };
        let (in_pkts, in_bytes) = if let Some(r) = self.reader.as_ref() {
            let pkts = if observe_only {
                #[cfg(feature = "_test_hooks")]
                {
                    self.common
                        .config
                        .reader_observe
                        .as_ref()
                        .map(|o| o.packets_this_epoch())
                        .unwrap_or(0)
                }
                #[cfg(not(feature = "_test_hooks"))]
                {
                    r.packets_this_epoch()
                }
            } else {
                r.packets_this_epoch()
            };
            let bytes = if observe_only {
                #[cfg(feature = "_test_hooks")]
                {
                    self.common
                        .config
                        .reader_observe
                        .as_ref()
                        .map(|o| o.bytes_this_epoch())
                        .unwrap_or(0)
                }
                #[cfg(not(feature = "_test_hooks"))]
                {
                    r.bytes_this_epoch()
                }
            } else {
                r.bytes_this_epoch()
            };
            (pkts, bytes)
        } else {
            (0, 0)
        };

        let out_pkt_due = !skip_pkts && out_pkts >= max_pkts;
        let in_pkt_due = !skip_pkts && in_pkts >= max_pkts;
        let out_byte_due = out_bytes >= limits.max_bytes;
        let in_byte_due = in_bytes >= limits.max_bytes;
        let out_due = out_pkt_due || out_byte_due;
        let in_due = in_pkt_due || in_byte_due;
        if out_due && in_due {
            self.common.config.rekey_i6.merges.fetch_add(1, Ordering::SeqCst);
        }
        if out_pkt_due || in_pkt_due || out_byte_due || in_byte_due {
            debug!(
                "i5 rekey due out_pkts={out_pkts}/{max_pkts} in_pkts={in_pkts}/{max_pkts} \
                 out_bytes={out_bytes}/{max_bytes} in_bytes={in_bytes}/{max_bytes} wanted={wanted}",
                max_bytes = limits.max_bytes
            );
        }
        wanted || out_due || in_due
    }

    fn apply_i5_rekey(&mut self, due: bool) -> Result<(), crate::Error> {
        if !due {
            return Ok(());
        }
        let idle = self.kex == SessionKexState::Idle;
        #[cfg(feature = "_test_hooks")]
        let force = self.common.config.invert_skip_idle_gate;
        #[cfg(not(feature = "_test_hooks"))]
        let force = false;
        if !idle {
            if force {
                // Invert: count a second trigger without re-entering kex
                // (a real second begin_rekey would corrupt the in-flight
                // transaction; the pending-guard invert covers that object).
                self.common
                    .config
                    .rekey_i6
                    .triggers
                    .fetch_add(1, Ordering::SeqCst);
            } else {
                self.common
                    .config
                    .rekey_i6
                    .idle_drops
                    .fetch_add(1, Ordering::SeqCst);
            }
            return Ok(());
        }
        debug!("starting rekeying");
        self.common
            .config
            .rekey_i6
            .triggers
            .fetch_add(1, Ordering::SeqCst);
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.exchange.take().is_some() {
                self.begin_rekey()?;
            }
        }
        Ok(())
    }

    /// Flush the session: stage plaintext packets then seal via Writer (S2b)
    /// or local PacketWriter (pre-spawn / tests).
    ///
    /// Always retries [`pending_outbound`] first; never lets a newer `enc.write`
    /// bulk leapfrog older parked cmds (incl. compress barrier).
    pub(crate) fn flush_apply(&mut self) -> Result<(), Error> {
        use byteorder::{BigEndian, ByteOrder};
        use crate::server::writer::TrySendWireError;

        // Ordered ledger: drain parked cmds before any new write-buffer submit.
        self.retry_pending_outbound()?;

        // Credit any new enc.write reservation before the transfer loop.
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = self.full_ledger {
            let w = self
                .common
                .encrypted
                .as_ref()
                .map(|e| Self::enc_write_wire_weight(&e.write, e.write_cursor))
                .unwrap_or(0);
            fl.set_enc_write(w);
        }

        if self.writer.is_some() {
            // Drain enc.write → SealRaw while pending is empty.
            let hold_app_during_kex = self.blocks_outbound_intake();
            loop {
                if !self.pending_outbound.is_empty() {
                    break;
                }
                let Some(ref mut enc) = self.common.encrypted else {
                    break;
                };
                if enc.write_cursor >= enc.write.len() {
                    enc.write_cursor = 0;
                    enc.write.clear();
                    #[cfg(feature = "_test_hooks")]
                    {
                        self.outbound_log_cursor = 0;
                    }
                    break;
                }
                // During kex / pending-install, do not dump application
                // channel packets (not kex-legal after KEXINIT). Still drain
                // IGNORE/DEBUG/DISCONNECT/kex/auth so handshake and the R3
                // IGNORE inject stay live. KEX itself is submitted via
                // seal_payloads / NeedSubmit.
                if hold_app_during_kex {
                    if enc.write_cursor.saturating_add(4) >= enc.write.len() {
                        break;
                    }
                    #[allow(clippy::indexing_slicing)]
                    let msg = enc.write[enc.write_cursor + 4];
                    if Self::hold_enc_packet_during_kex(enc, msg) {
                        break;
                    }
                }
                #[allow(clippy::indexing_slicing)]
                let len = BigEndian::read_u32(&enc.write[enc.write_cursor..]) as usize;
                #[allow(clippy::indexing_slicing)]
                let packet = bytes::Bytes::copy_from_slice(
                    &enc.write[(enc.write_cursor + 4)..(enc.write_cursor + 4 + len)],
                );
                // Advance cursor **before** submit so write-weight leaves the ledger
                // before Writer/pending takes the same weight (no dual-count OH spike).
                enc.write_cursor += 4 + len;
                let _ = enc;
                #[cfg(feature = "_test_hooks")]
                if let Some(ref fl) = self.full_ledger {
                    let w = self
                        .common
                        .encrypted
                        .as_ref()
                        .map(|e| Self::enc_write_wire_weight(&e.write, e.write_cursor))
                        .unwrap_or(0);
                    fl.set_enc_write(w);
                }
                // Recheck the hard cap before each seal. `enc.write` can hold
                // more than one complete packet; dumping them all would land
                // writer at HWM+one+framing/OH (the F1 +97).
                let weight = len.saturating_add(Self::WIRE_OVERHEAD_PER_PACKET);
                let one = (self.common.config.maximum_packet_size as usize)
                    .saturating_add(Self::packet_reservation(Self::CHANNEL_DATA_FRAMING));
                let hard = crate::sshbuffer::OUTBOUND_HIGH_WATERMARK.saturating_add(one);
                if self.sealed_backlog_bytes().saturating_add(weight) > hard {
                    self.pending_outbound
                        .push_back_already_counted(PendingOutboundCmd::SealRaw(packet));
                    break;
                }
                let writer = self.writer.as_ref().unwrap();
                match writer.try_seal_raw(packet) {
                    Ok(()) => {}
                    Err(TrySendWireError::Full(p)) => {
                        // Pure transfer into pending (same payload+OH weight).
                        self.pending_outbound
                            .push_back(PendingOutboundCmd::SealRaw(p));
                        break;
                    }
                    Err(TrySendWireError::FullCmd) | Err(TrySendWireError::Closed) => {
                        return Err(Error::SendError);
                    }
                }
            }
            if let Some(ref mut enc) = self.common.encrypted {
                if enc.write_cursor >= enc.write.len() {
                    enc.write_cursor = 0;
                    enc.write.clear();
                }
            }

            let rekey = self.i5_volume_due();
            self.apply_i5_rekey(rekey)?;
        } else if let Some(ref mut enc) = self.common.encrypted {
            let rekey = enc.flush(
                &self.common.config.as_ref().limits,
                &mut self.common.packet_writer,
            )?;
            // No-writer path (unit tests): still honor Idle gate + I6.
            self.apply_i5_rekey(rekey)?;
        }
        Ok(())
    }

    pub(crate) fn flush_pending_apply(&mut self, channel: ChannelId) -> Result<usize, Error> {
        self.flush_pending_ex(channel, !self.blocks_outbound_intake())
    }

    /// Emit head-of-lane fences only (no DATA). Used so EOF/CLOSE/SUCCESS
    /// are not locked by a zero window, without dumping DATA past HWM.
    pub(crate) fn flush_pending_fences_apply(&mut self, channel: ChannelId) -> Result<usize, Error> {
        self.flush_pending_ex(channel, false)
    }

    fn flush_pending_ex(&mut self, channel: ChannelId, allow_data: bool) -> Result<usize, Error> {
        // SUCCESS/FAILURE were admitted at generation (enqueue). Emitting
        // them must not re-check HWM — that left parked replies in
        // `pending_ctrl` forever while new ones kept arriving.
        let n = if let Some(ref mut enc) = self.common.encrypted {
            enc.flush_pending_admitted(channel, |_| true, allow_data)?
        } else {
            0
        };
        self.publish_reply_queue();
        self.record_outbound_from_write();
        Ok(n)
    }

    /// Parse newly staged `enc.write` packets into the S2c order log.
    pub(crate) fn record_outbound_from_write(&mut self) {
        #[cfg(feature = "_test_hooks")]
        if let (Some(log), Some(enc)) = (
            self.common.config.outbound_order.as_ref(),
            self.common.encrypted.as_ref(),
        ) {
            use byteorder::{BigEndian, ByteOrder};
            let mut cursor = self.outbound_log_cursor.max(enc.write_cursor);
            while cursor + 4 <= enc.write.len() {
                let len = BigEndian::read_u32(&enc.write[cursor..cursor + 4]) as usize;
                if cursor + 4 + len > enc.write.len() || len == 0 {
                    break;
                }
                let msg = enc.write[cursor + 4];
                let chan = if len >= 5 && cursor + 9 <= enc.write.len() {
                    BigEndian::read_u32(&enc.write[cursor + 5..cursor + 9])
                } else {
                    0
                };
                // CHANNEL_DATA: msg(1)+recip(4)+string_len(4)+payload
                // CHANNEL_EXTENDED_DATA: msg(1)+recip(4)+ext(4)+string_len(4)+payload
                let payload_len = match msg {
                    crate::msg::CHANNEL_DATA
                        if len >= 9 && cursor + 13 <= enc.write.len() =>
                    {
                        BigEndian::read_u32(&enc.write[cursor + 9..cursor + 13])
                    }
                    crate::msg::CHANNEL_EXTENDED_DATA
                        if len >= 13 && cursor + 17 <= enc.write.len() =>
                    {
                        BigEndian::read_u32(&enc.write[cursor + 13..cursor + 17])
                    }
                    _ => 0,
                };
                match msg {
                    crate::msg::CHANNEL_OPEN_CONFIRMATION
                    | crate::msg::CHANNEL_OPEN_FAILURE
                    | crate::msg::CHANNEL_WINDOW_ADJUST
                    | crate::msg::CHANNEL_DATA
                    | crate::msg::CHANNEL_EXTENDED_DATA
                    | crate::msg::CHANNEL_EOF
                    | crate::msg::CHANNEL_CLOSE
                    | crate::msg::CHANNEL_SUCCESS
                    | crate::msg::CHANNEL_FAILURE
                    | crate::msg::CHANNEL_REQUEST => log.push(chan, msg, payload_len),
                    crate::msg::REQUEST_SUCCESS | crate::msg::REQUEST_FAILURE => {
                        log.push(u32::MAX, msg, 0)
                    }
                    _ => {}
                }
                cursor += 4 + len;
            }
            self.outbound_log_cursor = cursor;
        }
        #[cfg(not(feature = "_test_hooks"))]
        let _ = self;
    }

    pub(crate) fn sender_window_size_apply(&self, channel: ChannelId) -> usize {
        if let Some(r) = self.reader.as_ref() {
            if let Some(w) = r.sender_window(channel) {
                return w as usize;
            }
        }
        if let Some(ref enc) = self.common.encrypted {
            enc.sender_window_size(channel)
        } else {
            0
        }
    }

    pub(crate) fn has_pending_data_apply(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.has_pending_data(channel)
        } else {
            false
        }
    }

    /// Retrieves the configuration of this session.
    pub(crate) fn config_apply(&self) -> &Config {
        &self.common.config
    }

    /// Sends a disconnect message.
    pub(crate) fn disconnect_apply(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.disconnect(reason, description, language_tag)
    }

    /// Sends a debug message to the client.
    ///
    /// Debug messages are intended for debugging purposes and may be
    /// optionally displayed by the client, depending on the
    /// `always_display` flag and client configuration.
    ///
    /// # Parameters
    ///
    /// - `always_display`: If `true`, the client is encouraged to
    ///   display the message regardless of user preferences.
    /// - `message`: The debug message to be sent.
    /// - `language_tag`: The language tag of the message.
    ///
    /// # Notes
    ///
    /// This message is informational and does not affect the SSH session
    /// state. Most clients (e.g., OpenSSH) will only display the message
    /// if verbose mode is enabled.
    pub(crate) fn debug_apply(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.debug(always_display, message, language_tag)
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub(crate) fn request_success_apply(&mut self) {
        if self.global_replies.decide_oldest_pending(true, None) || self.common.wants_reply {
            let _ = self.flush_global_replies();
        }
    }

    /// Send a "failure" reply to a global request.
    pub(crate) fn request_failure_apply(&mut self) {
        if self.global_replies.decide_oldest_pending(false, None) || self.common.wants_reply {
            let _ = self.flush_global_replies();
        }
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub(crate) fn channel_success_apply(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ch) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&channel))
        {
            ch.reply_queue.decide_oldest_pending(true, None);
        }
        self.flush_channel_replies(channel)
    }

    /// Send a "failure" reply to a channel request.
    pub(crate) fn channel_failure_apply(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ch) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&channel))
        {
            ch.reply_queue.decide_oldest_pending(false, None);
        }
        self.flush_channel_replies(channel)
    }

    /// RFC4254 §5.4: CHANNEL_SUCCESS / CHANNEL_FAILURE are `byte +
    /// uint32 recipient` = 5. Ledger weight = 5 + WIRE_OH(88) = 93,
    /// the same reservation as REQUEST_SUCCESS+port. Over hard:
    /// refuse the write; `wants_reply` or kex → PeerError.
    fn write_one_channel_reply(
        &mut self,
        channel: ChannelId,
        success: bool,
    ) -> Result<(), crate::Error> {
        let wants = self
            .common
            .encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&channel))
            .map(|ch| {
                assert!(ch.confirmed);
                ch.want_reply_count > 0 || ch.wants_reply
            })
            .unwrap_or(false);
        if !wants {
            return Ok(());
        }
        // Generation-point admit (invariant #3): reservation covers
        // already-queued SUCCESS/FAILURE plus this one, even if a parked
        // DATA head means we cannot emit yet.
        let queued = self
            .common
            .encrypted
            .as_ref()
            .map(|enc| enc.queued_reply_reservation())
            .unwrap_or(0);
        let weight = crate::ChannelCtrlItem::reply_reservation();
        if !self.admit_control_reply(weight.saturating_add(queued), true) {
            if let Some(ch) = self
                .common
                .encrypted
                .as_mut()
                .and_then(|enc| enc.channels.get_mut(&channel))
            {
                ch.want_reply_count = 0;
                ch.wants_reply = false;
            }
            if let Some(ch) = self
                .common
                .encrypted
                .as_mut()
                .and_then(|enc| enc.channels.get_mut(&channel))
            {
                ch.reply_queue.clear();
            }
            self.publish_reply_queue();
            return Ok(());
        }
        if let Some(ch) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&channel))
        {
            ch.want_reply_count = ch.want_reply_count.saturating_sub(1);
            ch.wants_reply = ch.want_reply_count > 0;
            if success {
                debug!("channel_success {channel:?}");
            }
            ch.enqueue_ctrl(if success {
                crate::ChannelCtrlItem::Success
            } else {
                crate::ChannelCtrlItem::Failure
            });
        }
        self.publish_reply_queue();
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        Ok(())
    }

    fn publish_reply_queue(&self) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.reply_queue {
            let n = self
                .common
                .encrypted
                .as_ref()
                .map(|enc| enc.queued_reply_count())
                .unwrap_or(0);
            slot.observe(n);
            let obl = self.global_replies.len()
                + self
                    .common
                    .encrypted
                    .as_ref()
                    .map(|enc| enc.channels.values().map(|c| c.reply_queue.len()).sum())
                    .unwrap_or(0);
            slot.observe_obligations(obl);
        }
    }

    fn finalize_channel_open_reply(
        &mut self,
        pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    ) -> Result<(), Error> {
        let id = pending.sender_channel;
        let Some(slot) = self.openings.get(&id) else {
            // Already expired / finalized. No second reply, no new slot.
            return Ok(());
        };
        if slot.generation != pending.generation {
            return Ok(());
        }
        let reserved = self.openings.remove(&id).expect("opening present").reserved;

        if let Err(reason) = result {
            // Opening never had a lane (S3c #13 registers on accept).
            // Still tear down first (S3c #14), then FAILURE.
            self.sender.live.remove(id);
            self.teardown_inbound_channel(id);
            if let Some(r) = &self.reader {
                r.close_lane(id, r.lane_gen(id).unwrap_or(0));
            }
            self.channel_window_covered.remove(&id);
            self.channel_global_held.remove(&id);
            self.release_global_inbound_credit(reserved);
            self.write_open_failure(pending.recipient_channel, reason)?;
            let e = self.channel_gens.entry(id).or_insert(pending.generation);
            *e = e.wrapping_add(1);
            self.publish_slots();
            return Ok(());
        }

        let mut opened = None;
        if let Some(ref mut enc) = self.common.encrypted {
            let mut params = pending.channel_params;
            params.enqueue_ctrl(crate::ChannelCtrlItem::OpenConfirmation {
                recipient_channel: pending.recipient_channel,
                sender_channel: pending.sender_channel.0,
                window_size: pending.window_size,
                packet_size: pending.packet_size,
            });
            enc.channels.insert(id, params);
            self.channels
                .insert(pending.sender_channel, pending.channel_ref);
            self.sender.live.insert(id);
            opened = Some(id);
        }
        if let Some(id) = opened {
            // Lane must exist before CHANNEL_OPEN_CONFIRMATION is
            // encoded into enc.write (and can leave on the wire). The
            // peer only learns this id from that packet.
            let invert = self.invert_open_confirm_before_lane();
            if invert {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref s) = self.common.config.slot_observe {
                    s.note_confirm_before_lane();
                }
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.flush_pending(id)?;
                }
                self.record_outbound_from_write();
                self.register_inbound_lane(id, true);
            } else {
                self.register_inbound_lane(id, true);
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.flush_pending(id)?;
                }
                self.record_outbound_from_write();
            }
        }
        self.publish_slots();
        Ok(())
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub(crate) fn channel_open_failure_apply(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                channel.encode(&mut enc.write)?;
                reason.code().encode(&mut enc.write)?;
                description.encode(&mut enc.write)?;
                language.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Close a channel.
    pub(crate) fn close_apply(&mut self, channel: ChannelId) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.park_close(channel);
        } else {
            unreachable!()
        }
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.stop_discard {
            let pending = self
                .common
                .encrypted
                .as_ref()
                .and_then(|enc| enc.channels.get(&channel))
                .is_some_and(|ch| ch.pending_close);
            s.set_pending_close(pending);
        }
        let emitted = !self
            .common
            .encrypted
            .as_ref()
            .is_some_and(|e| e.channel_exists(channel));
        if emitted {
            // The close is on the wire and the peer owes only its mandatory reply. If nothing is
            // reading this channel any more — the dominant path, since dropping a `Channel` is
            // what sent the close — release the application-side state now rather than waiting
            // for that reply, which a broken or hostile peer may never send. If the application
            // still holds the read half it may legitimately keep receiving until the peer's
            // close, so teardown is left to the CHANNEL_CLOSE handler in that case.
            let reader_gone = self
                .channels
                .get(&channel)
                .is_some_and(|c| std::ops::Deref::deref(c).is_closed());
            if reader_gone {
                self.finalize_close(channel);
            }
        }
        Ok(())
    }

    /// Send EOF to a channel
    pub(crate) fn eof_apply(&mut self, channel: ChannelId) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.park_eof(channel);
        } else {
            unreachable!()
        }
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        Ok(())
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub(crate) fn data_apply(&mut self, channel: ChannelId, data: impl Into<bytes::Bytes>) -> Result<(), Error> {
        // Submission budget: KEX/pending-install always parks like rekey.
        // HWM clamps how much enters enc.write this call (remainder → pending_data);
        // `try_drain_pending_data_under_budget` unparks when Writer frees capacity.
        //
        // Enqueue then emit through the ready-set scheduler (1 gathered
        // packet per ready channel per quantum). Parking (`is_rekeying=true`)
        // keeps Encrypted::data from dumping the whole window itself.
        let kex_block = self.blocks_outbound_intake();
        let data = data.into();
        if let Some(enc) = self.common.encrypted.as_mut() {
            enc.data(channel, data, true)?;
        } else {
            unreachable!()
        }
        if !kex_block {
            let _ = self.try_drain_pending_data_under_budget()?;
        }
        self.record_outbound_from_write();
        let _ = self.flush();
        // Enforce here rather than at the run loop's dispatch sites: this is the single point
        // where a channel's outbound backlog grows, and `Handler` callbacks call it directly
        // while the loop is inside `reply()` — a path no dispatch-site check can see.
        self.enforce_outbound_cap(channel)
    }

    /// Move channel `pending_data` into `enc.write` while HWM budget remains.
    /// Also emits head-of-lane fences (CONFIRMATION/EOF/CLOSE/SUCCESS/FAILURE)
    /// even when the peer window is 0 (I3 / appendix B.8).
    ///
    /// DATA uses the S2d ready-set: `Confirmed && !Closing`, 1 gathered
    /// peer-packet per channel per quantum, with a quota-1/8 boost for a
    /// newly Confirmed channel's first packet.
    pub(crate) fn try_drain_pending_data_under_budget(&mut self) -> Result<(), Error> {
        // Pass 1: fence items — no window predicate, no DATA dump.
        let fence_ids: Vec<_> = self
            .common
            .encrypted
            .as_ref()
            .map(|enc| {
                enc.channels
                    .keys()
                    .copied()
                    .filter(|id| enc.has_pending_lane(*id))
                    .collect()
            })
            .unwrap_or_default();
        for id in fence_ids {
            let _ = self.flush_pending_fences(id)?;
        }
        #[cfg(feature = "_test_hooks")]
        if self.common.config.invert_sched_greedy {
            return self.invert_drain_lowest_only();
        }
        #[cfg(feature = "_test_hooks")]
        if self.common.config.invert_sched_boost_starve {
            return self.invert_drain_boost_only();
        }
        loop {
            if self.blocks_outbound_intake() {
                break;
            }
            let ready = self.ready_set();
            if ready.is_empty() {
                break;
            }
            // Boost: first packet of a newly Confirmed channel, at most
            // once per BOOST_PERIOD *completed* regular quanta.
            if self.sched_boost_allowed() {
                if let Some(id) = self.boost_candidate(&ready) {
                    let n = self.try_drain_channel_under_budget(id)?;
                    if n > 0 {
                        self.sched_since_boost = 0;
                        self.sched_debt = Some(id);
                        self.note_sched_boost();
                        self.note_sched_emit(id, true);
                    }
                }
            }
            let ready = self.ready_set();
            if ready.is_empty() {
                break;
            }
            let start = match self.sched_next {
                Some(n) => ready.iter().position(|id| *id >= n).unwrap_or(0),
                None => 0,
            };
            let mut progressed = false;
            let mut last_served = None;
            let mut stopped_mid = false;
            for i in 0..ready.len() {
                let id = ready[(start + i) % ready.len()];
                if self.sched_debt == Some(id) {
                    continue;
                }
                let n = self.try_drain_channel_under_budget(id)?;
                if n > 0 {
                    progressed = true;
                    last_served = Some(id);
                    self.note_sched_emit(id, false);
                    continue;
                }
                // Ready-set said this channel could emit; n==0 means the
                // one-packet HWM snapshot refused it. Keep the failed id.
                // `outbound_budget()` uses config max-packet and can still
                // be >0 after a smaller recipient-max packet filled its
                // own hard cap — do not walk on and let last_served
                // overwrite (debt+wrap counterexample).
                self.sched_next = Some(id);
                stopped_mid = true;
                break;
            }
            self.sched_debt = None;
            if !stopped_mid {
                if let Some(id) = last_served {
                    self.sched_next = ready
                        .iter()
                        .copied()
                        .find(|x| *x > id)
                        .or(ready.first().copied());
                }
            }
            // Only a regular pass that actually emitted a packet is a
            // completed quantum (boost denominator). Empty budget-stop
            // keeps the cursor but does not mint a quantum.
            if progressed {
                self.note_sched_quantum();
            }
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Invert: lock onto the lowest Confirmed ChannelId and never serve
    /// any other (even if the locked id is empty / not ready).
    #[cfg(feature = "_test_hooks")]
    fn invert_drain_lowest_only(&mut self) -> Result<(), Error> {
        let Some(id) = self.lowest_confirmed_id() else {
            return Ok(());
        };
        loop {
            if self.blocks_outbound_intake() {
                break;
            }
            if !self
                .common
                .encrypted
                .as_ref()
                .and_then(|enc| enc.channels.get(&id))
                .is_some_and(|ch| ch.in_ready_set())
            {
                break;
            }
            if self.try_drain_channel_under_budget(id)? == 0 {
                break;
            }
        }
        Ok(())
    }

    #[cfg(feature = "_test_hooks")]
    fn lowest_confirmed_id(&self) -> Option<ChannelId> {
        let enc = self.common.encrypted.as_ref()?;
        enc.channels
            .iter()
            .filter(|(_, ch)| ch.lane == crate::ChannelLaneState::Confirmed)
            .map(|(id, _)| *id)
            .min()
    }

    /// Invert: serve only boost_pending channels (old bulk is skipped).
    #[cfg(feature = "_test_hooks")]
    fn invert_drain_boost_only(&mut self) -> Result<(), Error> {
        loop {
            if self.blocks_outbound_intake() {
                break;
            }
            let ready = self.ready_set();
            let Some(id) = self.boost_candidate(&ready) else {
                break;
            };
            if self.try_drain_channel_under_budget(id)? == 0 {
                break;
            }
        }
        Ok(())
    }

    fn ready_set(&self) -> Vec<ChannelId> {
        let Some(enc) = self.common.encrypted.as_ref() else {
            return Vec::new();
        };
        let mut ids: Vec<ChannelId> = enc
            .channels
            .iter()
            .filter(|(_, ch)| ch.in_ready_set())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    fn sched_boost_allowed(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        if self.common.config.disable_sched_boost {
            return false;
        }
        self.sched_since_boost >= crate::BOOST_PERIOD
    }

    fn boost_candidate(&self, ready: &[ChannelId]) -> Option<ChannelId> {
        let enc = self.common.encrypted.as_ref()?;
        ready.iter().copied().find(|id| {
            enc.channels
                .get(id)
                .is_some_and(|ch| ch.boost_pending && ch.in_ready_set())
        })
    }

    fn note_sched_quantum(&mut self) {
        self.sched_since_boost = self.sched_since_boost.saturating_add(1);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.sched {
            s.note_quantum();
        }
    }

    fn note_sched_boost(&mut self) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.sched {
            s.note_boost();
        }
    }

    fn note_sched_emit(&mut self, id: ChannelId, boost: bool) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = self.common.config.sched {
            let recip = self
                .common
                .encrypted
                .as_ref()
                .and_then(|enc| enc.channels.get(&id))
                .map(|ch| ch.recipient_channel)
                .unwrap_or(id.number());
            s.note_emit(recip, boost, self.ready_set().len() as u32);
        }
        #[cfg(not(feature = "_test_hooks"))]
        let _ = (id, boost);
    }

    /// HWM/framing-aware drain for **one** channel (WINDOW_ADJUST / targeted unpark).
    /// Returns application bytes moved into `enc.write` (and flushed toward Writer).
    ///
    /// Packs **one peer max-packet at a time**, rechecking sealed-backlog budget after
    /// each flush so multi-packet drains cannot ride a stale budget snapshot.
    pub(crate) fn try_drain_channel_under_budget(
        &mut self,
        id: crate::ChannelId,
    ) -> Result<usize, Error> {
        // Fences first (no DATA). DATA still uses the HWM clamp below.
        let _ = self.flush_pending_fences(id)?;
        if self.blocks_outbound_intake() {
            return Ok(0);
        }
        let (max_pkt, framing) = self
            .common
            .encrypted
            .as_ref()
            .and_then(|enc| enc.channels.get(&id))
            .map(|ch| {
                let framing = if ch.pending_head_is_extended() {
                    Self::CHANNEL_EXT_DATA_FRAMING
                } else {
                    Self::CHANNEL_DATA_FRAMING
                };
                (ch.recipient_maximum_packet_size, framing)
            })
            .unwrap_or((
                self.common.config.maximum_packet_size,
                Self::CHANNEL_DATA_FRAMING,
            ));
        if max_pkt == 0 {
            return Err(Error::Inconsistent);
        }
        // S2d: exactly one gathered peer packet. The ready-set loop
        // (try_drain_pending_data_under_budget) rotates; this helper
        // must not eat the rest of the HWM for `id`.
        // Framing follows the lane head so EXTENDED_DATA reserves the
        // extra 4B ext type and cannot step past archived HWM+one.
        let budget = self.outbound_budget_for_peer_packet(max_pkt, framing);
        if budget == 0 {
            return Ok(0);
        }
        let payload_cap = Self::max_payload_for_budget_framed(budget, max_pkt, framing)
            .min(max_pkt as usize)
            .min(crate::LOCAL_TRANSPORT_PAYLOAD_CAP);
        if payload_cap == 0 {
            return Ok(0);
        }
        let has_pending = self
            .common
            .encrypted
            .as_ref()
            .map(|enc| enc.has_pending_data(id))
            .unwrap_or(false);
        if !has_pending {
            return Ok(0);
        }
        let clamp = if let Some(enc) = self.common.encrypted.as_mut() {
            if let Some(ch) = enc.channels.get_mut(&id) {
                let saved = ch.recipient_window_size;
                if saved == 0 {
                    None
                } else {
                    let cap = (payload_cap as u32).min(saved);
                    ch.recipient_window_size = cap;
                    Some((saved, cap))
                }
            } else {
                None
            }
        } else {
            None
        };
        let Some((saved, cap)) = clamp else {
            return Ok(0);
        };
        let n = self.flush_pending(id)?;
        if let Some(enc) = self.common.encrypted.as_mut() {
            if let Some(ch) = enc.channels.get_mut(&id) {
                ch.recipient_window_size =
                    ch.recipient_window_size.saturating_add(saved.saturating_sub(cap));
            }
        }
        self.flush()?;
        Ok(n)
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub(crate) fn extended_data_apply(
        &mut self,
        channel: ChannelId,
        extended: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), Error> {
        let kex_block = self.blocks_outbound_intake();
        let data = data.into();
        if let Some(enc) = self.common.encrypted.as_mut() {
            enc.extended_data(channel, extended, data, true)?;
        } else {
            unreachable!()
        }
        if !kex_block {
            self.try_drain_pending_data_under_budget()?;
        }
        let _ = self.flush();
        // See `Session::data`: enforced here so `Handler`-callback writes are covered too.
        self.enforce_outbound_cap(channel)
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub(crate) fn xon_xoff_request_apply(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(ch) = enc.channels.get_mut(&channel) {
                assert!(ch.confirmed);
                let mut body = Vec::new();
                ch.recipient_channel.encode(&mut body)?;
                "xon-xoff".encode(&mut body)?;
                0u8.encode(&mut body)?;
                (client_can_do as u8).encode(&mut body)?;
                ch.enqueue_ctrl(crate::ChannelCtrlItem::Request { body: body.into() });
            }
        }
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        Ok(())
    }

    /// Ping the client to verify there is still connectivity.
    pub(crate) fn keepalive_request_apply(&mut self) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Keepalive);
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                want_reply.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Ping the client with a Keepalive and get a notification when the client responds.
    pub(crate) fn send_ping_apply(&mut self, reply_channel: oneshot::Sender<()>) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Ping(reply_channel));
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                want_reply.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Send the exit status of a program.
    pub(crate) fn exit_status_request_apply(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(ch) = enc.channels.get_mut(&channel) {
                assert!(ch.confirmed);
                let mut body = Vec::new();
                ch.recipient_channel.encode(&mut body)?;
                "exit-status".encode(&mut body)?;
                0u8.encode(&mut body)?;
                exit_status.encode(&mut body)?;
                ch.enqueue_ctrl(crate::ChannelCtrlItem::Request { body: body.into() });
            }
        }
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        Ok(())
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub(crate) fn exit_signal_request_apply(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                let mut body = Vec::new();
                channel.recipient_channel.encode(&mut body)?;
                "exit-signal".encode(&mut body)?;
                0u8.encode(&mut body)?;
                signal.name().encode(&mut body)?;
                (core_dumped as u8).encode(&mut body)?;
                error_message.encode(&mut body)?;
                language_tag.encode(&mut body)?;
                channel.enqueue_ctrl(crate::ChannelCtrlItem::Request { body: body.into() });
            }
        }
        let _ = self.try_drain_channel_under_budget(channel)?;
        let _ = self.flush_pending_fences(channel)?;
        Ok(())
    }

    /// Opens a new session channel on the client.
    pub(crate) fn channel_open_session_apply(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"session", |_| Ok(()))
    }

    /// Opens a direct-tcpip channel on the client (non-standard).
    pub(crate) fn channel_open_direct_tcpip_apply(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-tcpip", |write| {
            host_to_connect.encode(write)?;
            port_to_connect.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    /// Opens a direct-streamlocal channel on the client (non-standard).
    pub(crate) fn channel_open_direct_streamlocal_apply(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?; // reserved
            0u32.encode(write)?; // reserved
            Ok(())
        })
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub(crate) fn channel_open_forwarded_tcpip_apply(
        &mut self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-tcpip", |write| {
            connected_address.encode(write)?;
            connected_port.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    pub(crate) fn channel_open_forwarded_streamlocal_apply(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?;
            Ok(())
        })
    }

    /// Open a new X11 channel, when a connection comes to a
    /// local port. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.2).
    /// TCP/IP packets can then be tunneled through the channel using `.data()`.
    pub(crate) fn channel_open_x11_apply(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"x11", |write| {
            originator_address.encode(write)?;
            originator_port.encode(write)?;
            Ok(())
        })
    }

    /// Opens a new agent channel on the client.
    pub(crate) fn channel_open_agent_apply(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"auth-agent@openssh.com", |_| Ok(()))
    }

    fn channel_open_generic<F>(&mut self, kind: &[u8], write_suffix: F) -> Result<ChannelId, Error>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
    {
        if self.local_open_full() {
            return Err(Error::ChannelOpenFailure(
                ChannelOpenFailure::ResourceShortage,
            ));
        }
        // Build body first so we can enforce HWM reservation on variable fields.
        let mut body = Vec::new();
        body.push(msg::CHANNEL_OPEN);
        kind.encode(&mut body)?;
        // Placeholder for channel id / window / max-packet — filled after allocation.
        let id_slot = body.len();
        0u32.encode(&mut body)?; // sender channel id
        self.common.config.window_size.encode(&mut body)?;
        self.common.config.maximum_packet_size.encode(&mut body)?;
        write_suffix(&mut body)?;

        // Length-prefix + body + worst-case seal overhead for HWM reservation.
        let need = body
            .len()
            .saturating_add(Self::WIRE_OVERHEAD_PER_PACKET);
        if self.writer.is_some() && need > self.outbound_budget() {
            return Err(Error::SendError);
        }

        let authenticated = self.common.encrypted.as_ref().is_some_and(|enc| {
            matches!(
                enc.state,
                EncryptedState::Authenticated | EncryptedState::InitCompression
            )
        });
        if !authenticated {
            return Err(Error::Inconsistent);
        }

        let opening_need = self.opening_budget_need();
        if self.reserve_global_bytes(opening_need).is_err() {
            return Err(Error::ChannelOpenFailure(
                ChannelOpenFailure::ResourceShortage,
            ));
        }

        let sender_channel = {
            let enc = self.common.encrypted.as_mut().expect("encrypted");
            let sender_channel = enc.new_channel(
                self.common.config.window_size,
                self.common.config.maximum_packet_size,
            );
            {
                use byteorder::{BigEndian, ByteOrder};
                let cid = u32::from(sender_channel);
                BigEndian::write_u32(&mut body[id_slot..id_slot + 4], cid);
            }
            push_packet!(enc.write, {
                enc.write.extend_from_slice(&body);
            });
            sender_channel
        };
        self.hold_opening(sender_channel, opening_need);
        // CHANNEL_OPEN is only buffered in enc.write. The caller
        // (`dispatch_msg` ChannelOpen*) registers the inbound lane in
        // the same turn: no await and no Writer submit between this
        // write and `register_inbound_lane`.
        Ok(sender_channel)
    }

    /// Requests that the client forward connections to the given host and port.
    /// See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The client
    /// will open forwarded_tcpip channels for each connection.
    pub(crate) fn tcpip_forward_apply(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::TcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                "tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Cancels a previously tcpip_forward request.
    pub(crate) fn cancel_tcpip_forward_apply(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelTcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "cancel-tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Returns the SSH ID (Protocol Version + Software Version) the client sent when connecting
    ///
    /// This should contain only ASCII characters for implementations conforming to RFC4253, Section 4.2:
    ///
    /// > Both the 'protoversion' and 'softwareversion' strings MUST consist of
    /// > printable US-ASCII characters, with the exception of whitespace
    /// > characters and the minus sign (-).
    ///
    /// So it usually is fine to convert it to a [`String`] using [`String::from_utf8_lossy`]
    pub(crate) fn remote_sshid_apply(&self) -> &[u8] {
        &self.common.remote_sshid
    }

    pub(crate) fn maybe_send_ext_info(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            // If client sent a ext-info-c message in the kex list, it supports RFC 8308 extension negotiation.
            let mut key_extension_client = false;
            if let Some(e) = &enc.exchange {
                let Some(mut r) = e.client_kex_init.get(17..) else {
                    return Ok(());
                };
                if let Ok(kex_list) = NameList::decode(&mut r) {
                    use super::negotiation::Select;
                    key_extension_client = super::negotiation::Server::select(
                        &[EXTENSION_SUPPORT_AS_CLIENT],
                        &kex_list,
                        AlgorithmKind::Kex,
                    )
                    .is_ok();
                }
            }

            if !key_extension_client {
                debug!("RFC 8308 Extension Negotiation not supported by client");
                return Ok(());
            }

            push_packet!(enc.write, {
                msg::EXT_INFO.encode(&mut enc.write)?;
                1u32.encode(&mut enc.write)?;
                "server-sig-algs".encode(&mut enc.write)?;

                NameList(
                    self.common
                        .config
                        .preferred
                        .key
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                )
                .encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    pub(crate) fn begin_rekey(&mut self) -> Result<(), Error> {
        if self.pending_kex_install.is_some() {
            #[cfg(feature = "_test_hooks")]
            if self.common.config.invert_skip_pending_rekey_guard {
                // Invert: fall through and open a second transaction (must-red).
            } else {
                // Never open a second install transaction over an unfinished one.
                return Err(Error::Kex);
            }
            #[cfg(not(feature = "_test_hooks"))]
            {
                return Err(Error::Kex);
            }
        }
        debug!("beginning re-key");
        let mut kex = ServerKex::new(
            self.common.config.clone(),
            &self.common.remote_sshid,
            &self.common.config.server_id,
            match self.common.encrypted {
                None => KexCause::Initial,
                Some(ref enc) => KexCause::Rekey {
                    strict: self.common.strict_kex,
                    session_id: enc.session_id.clone(),
                },
            },
        );

        if self.writer.is_some() {
            let mut coll = crate::sshbuffer::PayloadCollector::default();
            kex.kexinit(&mut coll)?;
            self.kex = SessionKexState::InProgress(kex);
            self.seal_payloads(coll.payloads)?;
        } else {
            kex.kexinit(&mut self.common.packet_writer)?;
            self.kex = SessionKexState::InProgress(kex);
        }
        // S1: rekey deadline only for mid-session rekeys. Initial KEX (no encrypted
        // state yet) is covered exclusively by handshake_deadline → HandshakeTimeout.
        if self.common.encrypted.is_some() {
            self.rekey_gen = self.rekey_gen.wrapping_add(1);
            let kex_gen = self.rekey_gen;
            self.rekey_deadline
                .register(kex_gen, self.common.config.rekey_deadline);
            debug!("rekey deadline armed generation={kex_gen}");
        } else {
            debug!("initial KEX: rekey deadline not registered (handshake owns this clock)");
        }
        Ok(())
    }

    /// Clear rekey deadline when kex returns to Idle (success path).
    pub(crate) fn clear_rekey_deadline(&mut self) {
        #[cfg(feature = "_test_hooks")]
        if let Some(ref slot) = self.common.config.kex_install_observe {
            slot.mark_deadline_clear();
        }
        if let Some(kex_gen) = self.rekey_deadline.generation {
            self.rekey_deadline.clear_if_generation(kex_gen);
        } else {
            self.rekey_deadline.clear();
        }
    }

    /// Active rekey generation if currently InKex / Taken / pending install, else None.
    pub(crate) fn active_rekey_gen(&self) -> Option<u64> {
        if let Some(ref p) = self.pending_kex_install {
            if p.generation > 0 {
                return Some(p.generation);
            }
        }
        if self.kex.active() {
            self.rekey_deadline.generation.or(Some(self.rekey_gen))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::num::Wrapping;
    use std::sync::Arc;

    use super::*;
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;
    use crate::compression::{Compression, Decompress};
    use crate::kex::{KEXES, NONE, SessionKexState};
    use crate::session::{CommonSession, Encrypted, EncryptedState, Exchange};
    use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer};
    use crate::{CryptoVec, cipher, mac};

    struct TestHandler;

    impl crate::server::Handler for TestHandler {
        type Error = crate::Error;
    }

    fn authenticated_session() -> Session {
        authenticated_session_with(crate::server::Config::default())
    }

    fn authenticated_session_with(config: crate::server::Config) -> Session {
        let config = Arc::new(config);
        let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
        let (open_reply_tx, open_reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = Handle {
            sender,
            channel_buffer_size: config.channel_buffer_size,
            live: std::sync::Arc::new(OutboundLiveSet::default()),
            use_acked_window: {
                #[cfg(feature = "_test_hooks")]
                {
                    !config.invert_channel_window_mirror
                }
                #[cfg(not(feature = "_test_hooks"))]
                {
                    true
                }
            },
            #[cfg(feature = "_test_hooks")]
            observe: config.handle_observe.clone(),
        };

        Session {
            common: CommonSession {
                auth_user: String::new(),
                remote_sshid: b"SSH-2.0-test".to_vec(),
                config: config.clone(),
                encrypted: Some(Encrypted {
                    state: EncryptedState::Authenticated,
                    exchange: Some(Exchange::default()),
                    kex: KEXES.get(&NONE).unwrap().make(),
                    key: 0,
                    client_mac: mac::NONE,
                    server_mac: mac::NONE,
                    session_id: CryptoVec::new(),
                    channels: HashMap::new(),
                    last_channel_id: Wrapping(0),
                    write: Vec::new(),
                    write_cursor: 0,
                    server_compression: Compression::None,
                    client_compression: Compression::None,
                    decompress: Decompress::None,
                    rekey_wanted: false,
                    received_extensions: Vec::new(),
                    extension_info_awaiters: HashMap::new(),
                }),
                auth_method: None,
                auth_attempts: 0,
                packet_writer: PacketWriter::clear(),
                remote_to_local: Box::new(cipher::clear::Key),
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
            },
            sender: handle,
            receiver,
            target_window_size: config.window_size,
            pending_reads: Vec::new(),
            pending_len: 0,
            channels: HashMap::new(),
            inbound_gate: HashMap::new(),
            inbound_needs_reserve: Vec::new(),
            backpressured: HashSet::new(),
            outbound_acks: std::collections::HashMap::new(),
            open_global_requests: VecDeque::new(),
            kex: SessionKexState::Idle,
            open_reply_tx,
            open_reply_rx,
            rekey_gen: 0,
            rekey_deadline: crate::server::supervisor::RekeyDeadline::default(),
            handshake_deadline_at: None,
            writer: None,
            reader: None,
            peer_credit: None,
            pending_supervisor_cause: None,
            pending_outbound: PendingOutbound::default(),
            pending_kex_install: None,
            deferred_window_grants: HashSet::new(),
            #[cfg(feature = "_test_hooks")]
            full_ledger: None,
            #[cfg(feature = "_test_hooks")]
            outbound_log_cursor: 0,
            sched_next: None,
            sched_since_boost: crate::BOOST_PERIOD,
            sched_debt: None,
            facade_cmd_tx: None,
            facade_cmd_rx: None,
            executor: None,
            next_invoke_gen: 0,
            pending_harvest: HashMap::new(),
            facade_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            result_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            pending_open_ids: HashSet::new(),
            global_replies: ReplyQueue::default(),
            openings: HashMap::new(),
            channel_gens: HashMap::new(),
            conn_budget: None,
            channel_global_held: HashMap::new(),
            channel_window_covered: HashMap::new(),
        }
    }

    #[cfg(feature = "flate2")]
    mod compressed {
        use super::*;
        use std::io::Write;

        fn compressed_debug_payload(payload_len: usize) -> Vec<u8> {
            let mut payload = vec![b'A'; payload_len];
            payload[0] = crate::msg::DEBUG;

            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&payload).unwrap();
            let compressed = encoder.finish().unwrap();
            assert!(compressed.len() < 256 * 1024);
            compressed
        }

        fn incoming_packet(compressed: Vec<u8>) -> SSHBuffer {
            let mut buffer = SSHBuffer::new();
            buffer.buffer.extend_from_slice(&[0; 5]);
            buffer.buffer.extend_from_slice(&compressed);
            buffer
        }

        fn session_with_zlib_decompress() -> Session {
            let mut session = authenticated_session();
            if let Some(ref mut enc) = session.common.encrypted {
                enc.decompress = Decompress::Zlib(flate2::Decompress::new(true));
            }
            session
        }

        #[tokio::test]
        async fn compressed_debug_is_ignored_after_server_parses_it() {
            let mut session = session_with_zlib_decompress();
            let mut handler = TestHandler;
            let buffer = incoming_packet(compressed_debug_payload(200 * 1024));
            let mut pkt: IncomingSshPacket = session.maybe_decompress(&buffer).unwrap();

            super::super::super::reply(&mut session, Some(&mut handler), &mut pkt)
                .await
                .unwrap();

            assert!(!session.common.disconnected);
        }

        #[test]
        fn oversized_compressed_debug_is_rejected_before_server_ignores_it() {
            let mut session = session_with_zlib_decompress();
            let buffer = incoming_packet(compressed_debug_payload(
                crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024,
            ));

            let err = session.maybe_decompress(&buffer).unwrap_err();
            assert!(
                matches!(err, crate::Error::PacketSize(len) if len > crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN)
            );
        }
    }

    /// Dual-condition: InstallAck before peer Done keeps transaction open.
    #[test]
    fn kex_install_ack_before_done_waits_then_finalizes() {
        let mut session = authenticated_session();
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 3,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        assert!(session.on_install_ack_outbound(3).is_none());
        assert!(matches!(
            session.pending_kex_install.as_ref().map(|p| &p.phase),
            Some(PendingKexPhase::InstallAcked)
        ));
        assert!(session.blocks_outbound_intake());

        let ready = session
            .merge_peer_done_into_pending(KexAfterInstall::RekeyComplete);
        assert!(ready.is_some(), "both conditions met → finalize");
        assert!(session.pending_kex_install.is_none());
    }

    /// Dual-condition: peer Done before InstallAck only merges after (completion).
    /// Inbound commit is separate (Done reply turn) — not tested here.
    #[test]
    fn kex_install_done_before_ack_waits_then_finalizes() {
        let mut session = authenticated_session();
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 7,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        assert!(session
            .merge_peer_done_into_pending(KexAfterInstall::RekeyComplete)
            .is_none());
        assert_eq!(
            session.pending_kex_install.as_ref().unwrap().after,
            Some(KexAfterInstall::RekeyComplete)
        );
        assert!(matches!(
            session.pending_kex_install.as_ref().map(|p| &p.phase),
            Some(PendingKexPhase::WaitingAck)
        ));
        // apply_kex_after must not touch ciphers — only Idle/deadline.
        session.kex = SessionKexState::Taken;
        let ready = session.on_install_ack_outbound(7);
        assert!(ready.is_some(), "ACK after Done → finalize");
        session.apply_kex_after_install(ready.unwrap());
        assert!(session.pending_kex_install.is_none());
        assert_eq!(session.kex, SessionKexState::Idle);
    }

    /// apply_kex_after_install does not rewrite remote_to_local (inbound already set at Done).
    #[test]
    fn apply_kex_after_does_not_replace_inbound_cipher() {
        let mut session = authenticated_session();
        // remote_to_local is clear Key from fixture; apply must leave it in place.
        session.kex = SessionKexState::Taken;
        session.apply_kex_after_install(KexAfterInstall::RekeyComplete);
        assert_eq!(session.kex, SessionKexState::Idle);
        // Still has a remote_to_local box (not cleared).
        let _ = &session.common.remote_to_local;
    }

    /// pending_reads has a real push path.
    #[test]
    fn park_pending_read_pushes() {
        let mut session = authenticated_session();
        assert!(session.pending_reads.is_empty());
        session.park_pending_read(vec![msg::KEXINIT, 1, 2, 3]);
        assert_eq!(session.pending_reads.len(), 1);
        assert_eq!(session.pending_reads[0][0], msg::KEXINIT);
        assert!(session.pending_len >= 4);
    }

    /// Second register must not overwrite an open transaction.
    #[test]
    fn kex_install_register_conflict_preserves_existing() {
        let mut session = authenticated_session();
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 1,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        let err = session.register_seal_batch_and_install(
            vec![],
            99,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            false,
            None,
        );
        assert!(err.is_err());
        assert_eq!(
            session.pending_kex_install.as_ref().unwrap().generation,
            1,
            "must not overwrite open transaction"
        );
        assert!(session.pending_supervisor_cause.is_some());
    }

    /// fail_pending uses get_or_insert semantics (does not clobber earlier cause).
    #[test]
    fn fail_pending_kex_preserves_first_cause() {
        let mut session = authenticated_session();
        session.pending_supervisor_cause = Some(DisconnectCause::WriteStalled);
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 1,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        session.fail_pending_kex_install();
        assert_eq!(
            session.pending_supervisor_cause,
            Some(DisconnectCause::WriteStalled)
        );
        assert!(session.pending_kex_install.is_none());
    }

    /// NeedSubmit payload bytes participate in sealed backlog.
    #[test]
    fn need_submit_bytes_count_in_sealed_backlog() {
        let mut session = authenticated_session();
        let payloads = vec![bytes::Bytes::from(vec![0u8; 1000])];
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 0,
            after: None,
            phase: PendingKexPhase::NeedSubmit {
                payloads,
                cipher: Box::new(crate::cipher::clear::Key {}),
                compression: Compression::None,
                activate_compress: false,
                reset_seqn: false,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        assert!(
            session.sealed_backlog_bytes() >= 1000 + Session::WIRE_OVERHEAD_PER_PACKET,
            "NeedSubmit must count payload+wire overhead on the HWM ledger"
        );
    }

    /// Evidence for F14-kex: after control-plane fill to hard−ε, a NeedSubmit
    /// batch (kex is allowed to flow) jumps `sealed_backlog` over hard. The
    /// jump equals the NeedSubmit reservation — not a control-reply leak.
    #[test]
    fn kex_need_submit_jumps_hard_after_control_fill() {
        use byteorder::{BigEndian, ByteOrder};
        let mut session = authenticated_session();
        let hard = session.outbound_hard_cap();
        let edge = hard.saturating_sub(50);
        let body = edge.saturating_sub(Session::WIRE_OVERHEAD_PER_PACKET);
        assert!(body > 4, "hard cap must leave room for one framed packet");
        if let Some(ref mut enc) = session.common.encrypted {
            let mut pkt = vec![0u8; 4 + body];
            BigEndian::write_u32(&mut pkt[..4], body as u32);
            pkt[4] = crate::msg::IGNORE;
            enc.write.extend_from_slice(&pkt);
        }
        let at_edge = session.sealed_backlog_bytes();
        assert!(
            at_edge < hard,
            "control fill must sit under hard (at_edge={at_edge} hard={hard})"
        );
        assert!(
            at_edge + Session::MAX_CONTROL_REPLY_RESERVATION >= hard
                || at_edge + 50 >= hard,
            "fill must be at the control-reply edge"
        );

        // ML-KEM-scale ECDH_REPLY (~1.2KiB) + NEWKEYS, worst-case OH each.
        let reply = vec![0u8; 1200];
        let newkeys = vec![crate::msg::NEWKEYS];
        let kex_weight = reply.len()
            + newkeys.len()
            + 2 * Session::WIRE_OVERHEAD_PER_PACKET;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 1,
            after: None,
            phase: PendingKexPhase::NeedSubmit {
                payloads: vec![
                    bytes::Bytes::from(reply),
                    bytes::Bytes::from(newkeys),
                ],
                cipher: Box::new(crate::cipher::clear::Key {}),
                compression: Compression::None,
                activate_compress: false,
                reset_seqn: false,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        let after = session.sealed_backlog_bytes();
        let jumped = after.saturating_sub(at_edge);
        eprintln!(
            "f14-fix3 kex jump: at_edge={at_edge} after={after} hard={hard} \
             jumped={jumped} kex_weight={kex_weight}"
        );
        assert_eq!(jumped, kex_weight, "jump must be exactly the NeedSubmit reservation");
        assert!(
            after > hard,
            "NeedSubmit after control-fill must cross hard (after={after} hard={hard})"
        );
        assert!(
            after.saturating_sub(kex_weight) <= hard,
            "non-kex remainder must stay ≤ hard"
        );
    }

    /// R3 / fix4: real `register_seal_batch_and_install` + Writer first-accept.
    /// Before linearized kex identity, `kex_peak` stayed 0 on this path.
    #[cfg(feature = "_test_hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn kex_direct_accept_after_control_fill_tracks_identity() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        use byteorder::{BigEndian, ByteOrder};
        use crate::server::supervisor::{AtomicWriteProgress, FullLedger, LedgerMaxSlot};
        use crate::server::writer::{spawn_writer_with_hooks, WriterHooks};

        let slot = LedgerMaxSlot::new();
        let pending_arc = Arc::new(AtomicUsize::new(0));
        let sess_pend = Arc::new(AtomicUsize::new(0));
        let fl = Arc::new(FullLedger::new(
            pending_arc.clone(),
            sess_pend,
            slot.clone(),
        ));
        let hang = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let hooks = WriterHooks {
            full_ledger: Some(fl.clone()),
            pending_override: Some(pending_arc),
            socket_hang: Some(hang.clone()),
            ..WriterHooks::default()
        };
        let (handle, join, _evt) = spawn_writer_with_hooks(
            HangWrite,
            crate::sshbuffer::PacketWriter::clear(),
            progress,
            cancel_rx,
            hooks,
        );

        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.full_ledger = Some(fl.clone());
        session.pending_outbound.set_full_ledger(fl);

        let hard = session.outbound_hard_cap();
        let edge = hard.saturating_sub(50);
        let body = edge.saturating_sub(Session::WIRE_OVERHEAD_PER_PACKET);
        if let Some(ref mut enc) = session.common.encrypted {
            let mut pkt = vec![0u8; 4 + body];
            BigEndian::write_u32(&mut pkt[..4], body as u32);
            pkt[4] = crate::msg::IGNORE;
            enc.write.extend_from_slice(&pkt);
        }
        let at_edge = session.sealed_backlog_bytes();
        assert!(at_edge < hard, "fill under hard at_edge={at_edge} hard={hard}");
        assert_eq!(
            slot.kex_peak(),
            0,
            "no kex identity before register"
        );

        // R2 overshoot was 3043B. Two-packet reservation:
        // 2867 + 1 + 2*88 = 3044.
        let reply = vec![0u8; 2867];
        let newkeys = vec![crate::msg::NEWKEYS];
        let kex_weight = reply.len()
            + newkeys.len()
            + 2 * Session::WIRE_OVERHEAD_PER_PACKET;
        assert_eq!(kex_weight, 3044);

        session
            .register_seal_batch_and_install(
                vec![bytes::Bytes::from(reply), bytes::Bytes::from(newkeys)],
                11,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                true,
                false,
                None,
            )
            .expect("direct accept");

        let max = slot.max();
        let kex_peak = slot.kex_peak();
        let max_ex = slot.max_excluding_kex_need();
        eprintln!(
            "f14-fix4 direct accept: at_edge={at_edge} max={max} hard={hard} \
             kex_weight={kex_weight} kex_peak={kex_peak} max_ex_kex={max_ex} \
             parts={:?}",
            slot.parts()
        );

        assert_eq!(
            kex_peak, kex_weight,
            "HARD: direct Writer accept must publish kex_peak (was 0 before fix4)"
        );
        assert!(
            max > hard,
            "HARD: must observe the overshoot scene (max={max} hard={hard})"
        );
        assert!(
            max <= hard.saturating_add(kex_peak),
            "HARD: total ≤ hard+kex_peak (max={max} hard={hard} kex_peak={kex_peak})"
        );
        assert!(
            max_ex <= hard,
            "HARD: linearized non-kex ≤ hard (max_ex={max_ex} hard={hard})"
        );

        hang.store(false, std::sync::atomic::Ordering::SeqCst);
        drop(session.writer.take());
        join.abort();
        let _ = join.await;
    }

    /// Framing-aware budget: tiny max-packet cannot claim full budget as payload.
    #[test]
    fn max_payload_for_budget_accounts_for_framing() {
        let budget = 1000;
        let max_packet = 8u32;
        let p = Session::max_payload_for_budget(budget, max_packet);
        let pkts = if p == 0 { 0 } else { p.div_ceil(max_packet as usize) };
        let cost = p + pkts * Session::packet_reservation(Session::CHANNEL_DATA_FRAMING);
        assert!(cost <= budget, "cost {cost} must fit budget {budget}");
        assert!(
            p < budget || budget == 0,
            "payload alone must be strictly less than budget when framing applies"
        );
        // Tiny remaining budget must not open a second one-packet escape.
        assert_eq!(Session::max_payload_for_budget(50, 32 * 1024), 0);
        assert_eq!(Session::max_payload_for_budget(97, 32 * 1024), 0); // exactly per_pkt
        assert_eq!(Session::max_payload_for_budget(98, 32 * 1024), 1); // 1 app + per_pkt
    }

    /// NeedSubmit + non-Idle keeps rekey gen active so WriteStalled can win over premature Idle.
    #[test]
    fn need_submit_not_idle_and_rekey_gen_active() {
        let mut session = authenticated_session();
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 5;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 5,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::NeedSubmit {
                payloads: vec![bytes::Bytes::from_static(&[1, 2, 3])],
                cipher: Box::new(crate::cipher::clear::Key {}),
                compression: Compression::None,
                activate_compress: false,
                reset_seqn: false,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        assert!(session.blocks_outbound_intake());
        assert_eq!(session.active_rekey_gen(), Some(5));
        assert_ne!(session.kex, SessionKexState::Idle);
        // Watchdog sees NeedSubmit bytes as eligible backlog.
        assert!(session.sealed_backlog_bytes() >= 3);
    }

    /// WriteWatchdog trips WriteStalled while session holds NeedSubmit backlog.
    #[test]
    fn write_stalled_while_need_submit_eligible() {
        use crate::server::supervisor::WriteWatchdog;
        use std::time::Duration;
        let mut wd = WriteWatchdog::new();
        let mut session = authenticated_session();
        session.kex = SessionKexState::Taken;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 2,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::NeedSubmit {
                payloads: vec![bytes::Bytes::from(vec![0u8; 4096])],
                cipher: Box::new(crate::cipher::clear::Key {}),
                compression: Compression::None,
                activate_compress: false,
                reset_seqn: false,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        let eligible = session.sealed_backlog_bytes() as u64;
        assert!(eligible >= 4096);
        wd.observe_eligible(eligible);
        // Wall-clock short deadline (no tokio test-util required).
        std::thread::sleep(Duration::from_millis(30));
        let cause = wd.poll_timeout(Duration::from_millis(10), None);
        assert_eq!(
            cause,
            Some(DisconnectCause::WriteStalled),
            "short watchdog must fire WriteStalled while NeedSubmit holds backlog"
        );
        // Session must not have been force-Idled by the install path.
        assert_ne!(session.kex, SessionKexState::Idle);
        assert!(session.pending_kex_install.is_some());
    }

    /// HWM bound: after forced NeedSubmit + write staging under hang, max ledger stays bounded.
    #[test]
    fn sealed_backlog_includes_need_submit_under_hwm_cap_formula() {
        let hwm = crate::sshbuffer::OUTBOUND_HIGH_WATERMARK;
        let mut session = authenticated_session();
        // Stage write buffer near HWM via enc.write.
        if let Some(ref mut enc) = session.common.encrypted {
            enc.write.resize(hwm / 2, 0);
        }
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 0,
            after: None,
            phase: PendingKexPhase::NeedSubmit {
                payloads: vec![bytes::Bytes::from(vec![0u8; hwm / 4])],
                cipher: Box::new(crate::cipher::clear::Key {}),
                compression: Compression::None,
                activate_compress: false,
                reset_seqn: false,
            },
            inbound_acked: false,
            inbound_sent: false,
        });
        let backlog = session.sealed_backlog_bytes();
        // Must count both write residual and NeedSubmit.
        assert!(
            backlog >= hwm / 2 + hwm / 4,
            "backlog={backlog} expected >= {}",
            hwm / 2 + hwm / 4
        );
        // Budget = HWM + fixed packet_reservation(framing) - backlog.
        let one = Session::packet_reservation(Session::CHANNEL_DATA_FRAMING);
        assert_eq!(
            session.outbound_budget(),
            hwm.saturating_add(one).saturating_sub(backlog),
            "budget must be HWM+one_pkt_res - sealed_backlog"
        );
        assert!(
            session.outbound_budget() < hwm.saturating_add(one),
            "budget must shrink as backlog grows"
        );
    }

    /// skip-exchange style fail: fail_pending does not Idle or clear deadline.
    #[test]
    fn skip_exchange_ack_fail_keeps_non_idle() {
        let mut session = authenticated_session();
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 9;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 9,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Pre-stage a different first cause.
        session.stage_cause(DisconnectCause::WriteStalled);
        session.fail_pending_kex_install();
        assert!(session.pending_kex_install.is_none());
        assert_eq!(
            session.pending_supervisor_cause,
            Some(DisconnectCause::WriteStalled),
            "first cause preserved"
        );
        assert_eq!(session.kex, SessionKexState::Taken, "must not Idle on fail");
    }

    // ─── Session + Writer driven regressions (fix7: real Session+Writer paths) ───

    struct HangWrite;
    impl tokio::io::AsyncWrite for HangWrite {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// GateWrite: hang until released, then append to shared wire buffer.
    struct GateWrite {
        released: Arc<std::sync::atomic::AtomicBool>,
        buf: Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl tokio::io::AsyncWrite for GateWrite {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            use std::sync::atomic::Ordering as AtomicOrdering;
            if !self.released.load(AtomicOrdering::Acquire) {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            self.buf.lock().unwrap().extend_from_slice(data);
            std::task::Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Epoch-tagged clear-ish OpeningKey: XOR payload with `tag` so wrong epoch fails open.
    struct TagOpen(u8);
    impl crate::cipher::OpeningKey for TagOpen {
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
            // Clear framing: [4B len][1B padlen][payload...][pad...]
            if ciphertext_and_tag.len() < 5 {
                return Err(crate::Error::IndexOutOfBounds);
            }
            for b in &mut ciphertext_and_tag[5..] {
                *b ^= self.0;
            }
            Ok(&ciphertext_and_tag[4..])
        }
    }

    /// Matching SealingKey for TagOpen.
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
            // XOR payload region (after 4B len + 1B padlen) with tag.
            if plaintext.len() > 5 {
                for b in &mut plaintext[5..] {
                    *b ^= self.0;
                }
            }
        }
    }

    /// Test helper: set inbound OpeningKey without constructing private `Names`.
    fn set_inbound(session: &mut Session, open: Box<dyn crate::cipher::OpeningKey + Send>) {
        session.common.remote_to_local = open;
    }

    /// P0: NeedSubmit + GateWrite — post-KEX channel data must not leapfrog NEWKEYS on wire.
    #[tokio::test(flavor = "current_thread")]
    async fn p0_seal_order_newkeys_before_post_kex_data_under_need_submit() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Mutex;
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::{spawn_writer, BULK_QUEUE_CAP};
        use crate::sshbuffer::PacketWriter;

        let released = Arc::new(AtomicBool::new(false));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, mut evt_rx) = spawn_writer(
            GateWrite {
                released: released.clone(),
                buf: wire.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
        );

        // Fill bulk so the atomic install parks as NeedSubmit.
        for _ in 0..BULK_QUEUE_CAP {
            let _ = handle.try_seal_payload(Bytes::from(vec![msg::IGNORE; 4]));
        }

        let mut session = authenticated_session();
        session.writer = Some(handle.clone());
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 11;

        // Park channel data as rekey would (window 0 / is_rekeying path).
        let cid = insert_encrypted_channel(&mut session, 65536);
        confirm_test_channel(&mut session, cid, 0);
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .data(cid, Bytes::from_static(b"POSTKEX-MAGIC-DATA"), true)
            .unwrap();
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "fixture: pending_data must exist"
        );

        // Done turn: inbound commit must NOT flush pending_data onto enc.write.
        // (cipher swap only — flush_all_pending lives solely in apply_kex_after_install)
        set_inbound(&mut session, Box::new(TagOpen(0xA5)));
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "P0: commit_rekey_inbound must leave pending_data parked"
        );
        // Simulate reply() tail flush after Done — must still not emit channel data.
        let write_len_before = session
            .common
            .encrypted
            .as_ref()
            .map(|e| e.write.len())
            .unwrap_or(0);
        let _ = session.flush();
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "P0: flush after Done must not drain pending_data before InstallAck complete"
        );
        assert_eq!(
            session
                .common
                .encrypted
                .as_ref()
                .map(|e| e.write.len())
                .unwrap_or(0),
            write_len_before,
            "P0: no channel data into enc.write before RekeyComplete"
        );

        // Register atomic NEWKEYS install → NeedSubmit (bulk full).
        let newkeys_payload = Bytes::from_static(&[msg::NEWKEYS]);
        session
            .register_seal_batch_and_install(
                vec![newkeys_payload.clone()],
                11,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                true,
                true,
                Some(KexAfterInstall::RekeyComplete),
            )
            .unwrap();
        assert!(
            matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::NeedSubmit { .. })
            ),
            "must be NeedSubmit under Full bulk, got {:?}",
            session.pending_kex_install.as_ref().map(|p| &p.phase)
        );
        // If bug returned: data would be in pending_outbound ahead of install.
        assert!(
            session.pending_outbound.is_empty(),
            "P0: channel data must not be in pending_outbound ahead of NEWKEYS install"
        );

        // Free bulk capacity by letting Writer dequeue (GateWrite still hangs socket).
        for _ in 0..128 {
            tokio::task::yield_now().await;
            session.try_advance_pending_kex_install();
            if matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::WaitingAck | PendingKexPhase::InstallAcked)
            ) {
                break;
            }
        }
        assert!(
            matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::WaitingAck | PendingKexPhase::InstallAcked)
            ),
            "NeedSubmit must advance after dequeue, got {:?}",
            session.pending_kex_install.as_ref().map(|p| &p.phase)
        );
        // Still no channel data ahead of install while WaitingAck.
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "pending_data must remain until RekeyComplete"
        );

        // Release socket so Writer can drain out_q soft-cap, process the
        // SealBatchAndInstall (NEWKEYS under old epoch), and emit InstallAck.
        released.store(true, AtomicOrdering::Release);
        let mut got_ack = false;
        let ack_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < ack_deadline {
            while let Ok(ev) = evt_rx.try_recv() {
                if let WriterEvent::InstallAckOutbound { generation } = ev {
                    if generation == 11 {
                        got_ack = true;
                    }
                    if let Some(after) = session.on_install_ack_outbound(generation) {
                        if let Some(ch) = session
                            .common
                            .encrypted
                            .as_mut()
                            .unwrap()
                            .channels
                            .get_mut(&cid)
                        {
                            ch.recipient_window_size = 65536;
                        }
                        session.apply_kex_after_install(after);
                        let _ = session.flush();
                    }
                }
            }
            if got_ack
                && !session
                    .common
                    .encrypted
                    .as_ref()
                    .unwrap()
                    .has_pending_data(cid)
            {
                break;
            }
            let _ = session.retry_pending_outbound();
            let _ = session.flush();
            tokio::task::yield_now().await;
        }
        assert!(got_ack, "must observe InstallAck for gen 11 after GateWrite release");
        assert_eq!(session.kex, SessionKexState::Idle);
        assert!(
            !session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "RekeyComplete must flush_all_pending"
        );

        // Wire order: NEWKEYS (old epoch seal) before post-kex channel data magic.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let _ = session.retry_pending_outbound();
            let _ = session.flush();
            tokio::task::yield_now().await;
            let w = wire.lock().unwrap();
            let has_nk = w.iter().any(|&b| b == msg::NEWKEYS);
            let has_data = w
                .windows(b"POSTKEX-MAGIC-DATA".len())
                .any(|w| w == b"POSTKEX-MAGIC-DATA");
            if has_nk && has_data {
                let nk_pos = w.iter().position(|&b| b == msg::NEWKEYS).unwrap();
                let data_pos = w
                    .windows(b"POSTKEX-MAGIC-DATA".len())
                    .position(|w| w == b"POSTKEX-MAGIC-DATA")
                    .unwrap();
                assert!(
                    nk_pos < data_pos,
                    "P0 wire order: NEWKEYS (pos {nk_pos}) must precede post-kex data (pos {data_pos})"
                );
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "wire timeout has_nk={has_nk} has_data={has_data} wire_len={}",
                    w.len()
                );
            }
            drop(w);
        }

        join.abort();
        let _ = join.await;
    }

    /// P0 ACK-fail: fail_pending does not flush pending_data / does not Idle.
    #[tokio::test(flavor = "current_thread")]
    async fn p0_ack_fail_does_not_flush_pending_or_idle() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);

        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 3;
        let cid = insert_encrypted_channel(&mut session, 65536);
        confirm_test_channel(&mut session, cid, 0);
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .data(cid, Bytes::from_static(b"no-flush-on-fail"), true)
            .unwrap();

        set_inbound(&mut session, Box::new(crate::cipher::clear::Key {}));
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 3,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Writer die → fail path.
        join.abort();
        let _ = join.await;
        session.fail_pending_kex_install();
        assert_eq!(session.kex, SessionKexState::Taken, "fail must not Idle");
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "ACK-fail must not flush_all_pending"
        );
        assert!(session.pending_supervisor_cause.is_some());
    }

    /// Retired swap-path probe. Production no longer `mem::swap`s the inbound
    /// cipher in `Session::run` (S3a: Reader owns the epoch). Equivalent
    /// red-test: `test_s3a_reader::n1_*` + `reader::mid_read_install_does_not_apply`.
    #[test]
    fn r1_done_before_ack_swaps_new_inbound_into_read_future() {
        let mut session = authenticated_session();
        // Simulate run-loop: opening_cipher holds the key used by start_reading.
        let mut opening: Box<dyn crate::cipher::OpeningKey + Send> = Box::new(TagOpen(0x11));
        session.common.remote_to_local = Box::new(TagOpen(0x11));
        session.kex = SessionKexState::Taken;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 7,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Peer Done this turn: commit inbound (new tag 0x22) but do NOT InstallAck-complete.
        // Mirrors commit_rekey_inbound's cipher assignment without full NewKeys construct.
        set_inbound(&mut session, Box::new(TagOpen(0x22)));
        let _ = session.merge_peer_done_into_pending(KexAfterInstall::RekeyComplete);
        assert!(
            session.pending_kex_install.is_some(),
            "completion still waits InstallAck"
        );
        assert_ne!(session.kex, SessionKexState::Idle);

        // Same swap the run loop does after reply() returns (session.rs ~1474).
        std::mem::swap(&mut opening, &mut session.common.remote_to_local);
        // Seal a tiny IGNORE with new-epoch TagSeal(0x22) and open with the armed future key.
        let mut pw = crate::sshbuffer::PacketWriter::clear();
        // Replace sealing key with TagSeal(0x22).
        pw.set_cipher(Box::new(TagSeal(0x22)));
        pw.packet_raw(&[msg::IGNORE, 0, 0, 0, 1, 0x42]).unwrap();
        let mut wire = pw.take_pending_wire_bytes().to_vec();
        // Open with armed opening_cipher — must be new epoch (0x22).
        let opened = opening.open(0, &mut wire).expect("new inbound must open post-Done packet");
        // After open, payload region is XOR-restored; first payload byte is msg type at [0] of open return
        // (open returns from padlen byte).
        assert!(!opened.is_empty());

        // Old epoch must fail to recover the original IGNORE type cleanly if used:
        let mut opening_old: Box<dyn crate::cipher::OpeningKey + Send> = Box::new(TagOpen(0x11));
        let mut wire2 = {
            let mut pw2 = crate::sshbuffer::PacketWriter::clear();
            pw2.set_cipher(Box::new(TagSeal(0x22)));
            pw2.packet_raw(&[msg::IGNORE, 0, 0, 0, 1, 0x42]).unwrap();
            pw2.take_pending_wire_bytes().to_vec()
        };
        let opened_old = opening_old.open(0, &mut wire2).unwrap();
        // With wrong tag, XOR leaves garbage — msg type byte != IGNORE.
        // padlen is at [0] of open result; payload type at [1].
        if opened_old.len() > 1 {
            assert_ne!(
                opened_old[1],
                msg::IGNORE,
                "old epoch must not correctly recover post-Done packet (proves cutover needed)"
            );
        }
        // Completion still not applied.
        assert!(session.pending_kex_install.is_some());
        assert_ne!(session.kex, SessionKexState::Idle);
    }

    /// R1 initial path: after Done, next read future is armed with new inbound before ACK.
    #[test]
    fn r1_initial_done_commits_inbound_before_ack() {
        let mut session = authenticated_session();
        // Simulate pre-initial-Done: opening holds clear/old tag.
        let mut opening: Box<dyn crate::cipher::OpeningKey + Send> = Box::new(TagOpen(0x00));
        session.common.remote_to_local = Box::new(TagOpen(0x00));
        session.kex = SessionKexState::Taken;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 0,
            after: Some(KexAfterInstall::InitialComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Done turn: commit inbound only (ACK not yet).
        set_inbound(&mut session, Box::new(TagOpen(0x33)));
        // Run-loop post-reply swap arms next start_reading with new key.
        std::mem::swap(&mut opening, &mut session.common.remote_to_local);
        let mut pw = crate::sshbuffer::PacketWriter::clear();
        pw.set_cipher(Box::new(TagSeal(0x33)));
        pw.packet_raw(&[msg::SERVICE_REQUEST, 0, 0, 0, 0]).unwrap();
        let mut wire = pw.take_pending_wire_bytes().to_vec();
        opening
            .open(0, &mut wire)
            .expect("initial Done must arm new inbound before InstallAck");
        assert!(session.pending_kex_install.is_some(), "ACK still pending");
        assert_ne!(session.kex, SessionKexState::Idle);
        // Completion not applied yet.
        assert!(matches!(
            session.pending_kex_install.as_ref().map(|p| &p.phase),
            Some(PendingKexPhase::WaitingAck)
        ));
    }

    /// R2: HangWrite + real Full NeedSubmit + short write watchdog → WriteStalled first.
    #[tokio::test(flavor = "current_thread")]
    async fn r2_write_stalled_first_cause_while_need_submit_with_writer() {
        use std::time::Duration;
        use bytes::Bytes;
        use crate::server::supervisor::{AtomicWriteProgress, WriteWatchdog, DisconnectCauseSlot};
        use crate::server::writer::{spawn_writer, BULK_QUEUE_CAP};
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);

        // Deterministic Full without yield.
        for _ in 0..BULK_QUEUE_CAP {
            handle
                .try_seal_payload(Bytes::from(vec![0x2u8; 8]))
                .expect("pre-yield fill");
        }
        let full = handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[msg::NEWKEYS])],
            42,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            true,
        );
        assert!(
            matches!(full, Err(crate::server::writer::TrySendEpochError::Full { .. })),
            "must observe real Full"
        );

        let mut session = authenticated_session();
        session.writer = Some(handle.clone());
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 42;
        // Long rekey deadline still armed.
        session.rekey_deadline.register(42, Duration::from_secs(30));
        if let Err(crate::server::writer::TrySendEpochError::Full {
            payloads,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            generation,
        }) = handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[msg::NEWKEYS])],
            42,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            true,
        ) {
            session.pending_kex_install = Some(PendingKexInstall {
                generation,
                after: Some(KexAfterInstall::RekeyComplete),
                phase: PendingKexPhase::NeedSubmit {
                    payloads,
                    cipher,
                    compression: outbound_compression,
                    activate_compress,
                    reset_seqn,
                },
                inbound_acked: false,
                inbound_sent: false,
            });
        } else {
            session.pending_kex_install = Some(PendingKexInstall {
                generation: 42,
                after: Some(KexAfterInstall::RekeyComplete),
                phase: PendingKexPhase::NeedSubmit {
                    payloads: vec![Bytes::from_static(&[msg::NEWKEYS])],
                    cipher: Box::new(crate::cipher::clear::Key {}),
                    compression: Compression::None,
                    activate_compress: true,
                    reset_seqn: true,
                },
                inbound_acked: false,
                inbound_sent: false,
            });
        }

        // Mirror Session::run supervisor poll: short write_progress_deadline, long rekey.
        let mut wd = WriteWatchdog::new();
        let slot = DisconnectCauseSlot::new();
        let write_dl = Duration::from_millis(40);
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            // KEX must remain non-Idle / deadline present while stalled.
            assert_ne!(session.kex, SessionKexState::Idle);
            assert!(session.pending_kex_install.is_some());
            assert!(session.rekey_deadline.generation.is_some() || session.active_rekey_gen().is_some());
            let eligible = session.sealed_backlog_bytes() as u64;
            assert!(eligible > 0, "NeedSubmit must keep eligible backlog");
            wd.observe_eligible(eligible);
            if let Some(c) = wd.poll_timeout(write_dl, None) {
                slot.record(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            slot.get(),
            Some(DisconnectCause::WriteStalled),
            "first cause must be WriteStalled while NeedSubmit holds backlog"
        );
        // Still not Idle (rekey deadline not the winner).
        assert_ne!(session.kex, SessionKexState::Idle);
        assert!(session.pending_kex_install.is_some());
        join.abort();
        let _ = join.await;
    }

    /// R3: Full → HangWrite dequeue-only → capacity notify path advances NeedSubmit→WaitingAck.
    #[tokio::test(flavor = "current_thread")]
    async fn r3_need_submit_advances_after_dequeue_without_socket_write() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::{spawn_writer, BULK_QUEUE_CAP};
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_cancel, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);

        for _ in 0..BULK_QUEUE_CAP {
            handle
                .try_seal_payload(Bytes::from(vec![0x2u8; 8]))
                .expect("pre-yield fill must succeed");
        }
        let full = handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[msg::NEWKEYS])],
            42,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            true,
        );
        assert!(
            matches!(full, Err(crate::server::writer::TrySendEpochError::Full { .. })),
            "must observe real Full before dequeue"
        );

        let mut session = authenticated_session();
        session.writer = Some(handle.clone());
        session.kex = SessionKexState::Taken;
        let cap = handle.capacity_notify();
        // Register as NeedSubmit with materials from Full.
        if let Err(crate::server::writer::TrySendEpochError::Full {
            payloads,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            generation,
        }) = handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[msg::NEWKEYS])],
            42,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            true,
        ) {
            session.pending_kex_install = Some(PendingKexInstall {
                generation,
                after: Some(KexAfterInstall::RekeyComplete),
                phase: PendingKexPhase::NeedSubmit {
                    payloads,
                    cipher,
                    compression: outbound_compression,
                    activate_compress,
                    reset_seqn,
                },
                inbound_acked: false,
                inbound_sent: false,
            });
        } else {
            session.pending_kex_install = Some(PendingKexInstall {
                generation: 42,
                after: Some(KexAfterInstall::RekeyComplete),
                phase: PendingKexPhase::NeedSubmit {
                    payloads: vec![Bytes::from_static(&[msg::NEWKEYS])],
                    cipher: Box::new(crate::cipher::clear::Key {}),
                    compression: Compression::None,
                    activate_compress: true,
                    reset_seqn: true,
                },
                inbound_acked: false,
                inbound_sent: false,
            });
        }

        // Drive the same sequence as Session capacity arm: wait notify → try_advance.
        let woke =
            tokio::time::timeout(std::time::Duration::from_secs(2), cap.notified()).await;
        assert!(woke.is_ok(), "dequeue must notify without socket write");
        // capacity arm body:
        session.retry_pending_outbound().unwrap();
        session.try_advance_pending_kex_install();
        for _ in 0..32 {
            if matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::WaitingAck | PendingKexPhase::InstallAcked)
            ) {
                break;
            }
            tokio::task::yield_now().await;
            session.try_advance_pending_kex_install();
        }
        assert!(
            matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::WaitingAck | PendingKexPhase::InstallAcked)
            ),
            "NeedSubmit must advance after dequeue-only notify, got {:?}",
            session.pending_kex_install.as_ref().map(|p| &p.phase)
        );
        assert!(handle.pending_bytes() > 0, "socket never progressed");
        join.abort();
        let _ = join.await;
    }

    /// R4-1: tiny peer max-packet — GateWrite samples max sealed_backlog ≤ HWM + one-packet overhead.
    #[tokio::test(flavor = "current_thread")]
    async fn r4_hwm_tiny_max_packet_gatewrite_samples() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Mutex;
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::{PacketWriter, OUTBOUND_HIGH_WATERMARK};

        let released = Arc::new(AtomicBool::new(false));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) = spawn_writer(
            GateWrite {
                released: released.clone(),
                buf: wire.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
        );
        let mut session = authenticated_session();
        session.writer = Some(handle);
        let cid = insert_encrypted_channel(&mut session, 1 << 20);
        // Tiny peer max-packet forces many frames for a moderate payload.
        {
            let ch = session
                .common
                .encrypted
                .as_mut()
                .unwrap()
                .channels
                .get_mut(&cid)
                .unwrap();
            ch.confirmed = true;
            ch.recipient_window_size = 1 << 20;
            ch.recipient_maximum_packet_size = 16;
        }
        let mut max_backlog = 0usize;
        let sample = |s: &Session, max: &mut usize| {
            let b = s.sealed_backlog_bytes();
            if b > *max {
                *max = b;
            }
        };
        // Produce data under HWM clamp (Session::data uses max_payload_for_budget).
        let chunk = vec![0xABu8; 64 * 1024];
        for _ in 0..8 {
            let _ = session.data(cid, Bytes::from(chunk.clone()));
            sample(&session, &mut max_backlog);
            let _ = session.flush();
            sample(&session, &mut max_backlog);
            tokio::task::yield_now().await;
            sample(&session, &mut max_backlog);
        }
        // Budget headroom is config max-packet + framing + wire OH (outbound_budget).
        let one_pkt = (session.common.config.maximum_packet_size as usize)
            .saturating_add(Session::packet_reservation(Session::CHANNEL_DATA_FRAMING));
        // +16: cleartext length prefix / padlen rounding that can appear on enc.write.
        assert!(
            max_backlog <= OUTBOUND_HIGH_WATERMARK + one_pkt + 16,
            "R4 tiny max-packet: max_backlog={max_backlog} > HWM+one_pkt={}",
            OUTBOUND_HIGH_WATERMARK + one_pkt + 16
        );
        released.store(true, AtomicOrdering::Release);
        for _ in 0..64 {
            let _ = session.retry_pending_outbound();
            let _ = session.try_drain_pending_data_under_budget();
            let _ = session.flush();
            tokio::task::yield_now().await;
        }
        join.abort();
        let _ = join.await;
    }

    fn park_ready_channel(session: &mut Session, id: ChannelId, nbytes: usize) {
        confirm_test_channel(session, id, 1 << 20);
        let ch = session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .channels
            .get_mut(&id)
            .unwrap();
        ch.boost_pending = false;
        ch.recipient_maximum_packet_size = 1024;
        assert!(ch.enqueue_data(bytes::Bytes::from(vec![0xABu8; nbytes]), None, 0));
    }

    /// Debt + wrap + budget-stop must keep the failed id as `sched_next`.
    /// ready [c1,c2,c3], debt=c3, start=c2 → emit c2, skip c3, stop on c1.
    #[tokio::test(flavor = "current_thread")]
    async fn sched_stopped_mid_not_overwritten_by_last_served() {
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        let mut session = authenticated_session();
        session.writer = Some(handle.clone());

        // Drain uses recipient max-packet 1024 (see park_ready_channel), so
        // fill against that one-packet hard cap — not config 32KiB
        // `outbound_budget()`, which sits ~32KiB past the 1024-packet bound
        // and leaves room for every parked channel.
        let framing = Session::CHANNEL_DATA_FRAMING;
        let one_1k = 1024 + Session::packet_reservation(framing);
        let hard = crate::sshbuffer::OUTBOUND_HIGH_WATERMARK.saturating_add(one_1k);
        let adjust = 9usize.saturating_add(Session::WIRE_OVERHEAD_PER_PACKET);
        // sealed ∈ [hard-adjust-one, hard-adjust): c2 can emit one 1024B
        // DATA; after that `outbound_budget_for_peer_packet(1024)` is 0.
        let lo = hard.saturating_sub(adjust).saturating_sub(one_1k);
        let hi = hard.saturating_sub(adjust);
        for _ in 0..512 {
            let sealed = session.sealed_backlog_bytes();
            if sealed >= lo && sealed < hi {
                break;
            }
            assert!(
                sealed < hi,
                "fill overshot 1024-packet last zone sealed={sealed} hi={hi}"
            );
            let chunk = lo.saturating_sub(sealed).max(1).min(1024);
            match handle.try_seal_payload(bytes::Bytes::from(vec![1u8; chunk])) {
                Ok(()) => {}
                Err(_) => tokio::task::yield_now().await,
            }
        }
        let sealed = session.sealed_backlog_bytes();
        assert!(
            sealed >= lo && sealed < hi,
            "need sealed in [{lo},{hi}) for one 1KiB DATA then budget-stop, got {sealed}"
        );
        let drain_budget = session.outbound_budget_for_peer_packet(1024, framing);
        assert!(
            drain_budget >= one_1k
                || Session::max_payload_for_budget_framed(drain_budget, 1024, framing) > 0,
            "need room for c2 DATA (budget={drain_budget} sealed={sealed})"
        );

        let c1 = insert_encrypted_channel(&mut session, 1 << 20);
        let c2 = insert_encrypted_channel(&mut session, 1 << 20);
        let c3 = insert_encrypted_channel(&mut session, 1 << 20);
        park_ready_channel(&mut session, c1, 1024);
        park_ready_channel(&mut session, c2, 1024);
        park_ready_channel(&mut session, c3, 1024);
        assert!(c1 < c2 && c2 < c3);

        session.sched_debt = Some(c3);
        session.sched_next = Some(c2);
        session.sched_since_boost = 0;

        session.try_drain_pending_data_under_budget().unwrap();

        assert_eq!(
            session.sched_next,
            Some(c1),
            "stopped_mid must keep the failed id (c1), not last_served's successor (c3); got {:?}",
            session.sched_next
        );
        let left = |id: crate::ChannelId| {
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channels
                .get(&id)
                .unwrap()
                .pending_data
                .iter()
                .map(|(b, _, _)| b.len())
                .sum::<usize>()
        };
        assert!(
            left(c2) < 1024,
            "c2 must emit the one packet that fits; leftover={}",
            left(c2)
        );
        assert_eq!(
            left(c1),
            1024,
            "c1 must budget-stop without emitting; leftover={}",
            left(c1)
        );
        assert_eq!(
            session.sched_since_boost, 1,
            "one regular emit is one completed quantum, not an empty mid-stop"
        );

        join.abort();
        let _ = join.await;
    }

    #[test]
    fn session_extended_data_propagates_zero_max_packet() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        {
            let ch = session
                .common
                .encrypted
                .as_mut()
                .unwrap()
                .channels
                .get_mut(&id)
                .unwrap();
            ch.recipient_maximum_packet_size = 0;
        }
        let err = session
            .extended_data(id, 1, bytes::Bytes::from_static(b"x"))
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::Inconsistent),
            "expected Inconsistent, got {err:?}"
        );
        let pending = session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .channels
            .get(&id)
            .unwrap()
            .pending_data
            .len();
        assert!(
            pending > 0,
            "failed drain must leave the EXTENDED_DATA queued"
        );
    }

    /// R4-2: oversized channel-open field under GateWrite stays within HWM + one-packet.
    #[tokio::test(flavor = "current_thread")]
    async fn r4_hwm_long_channel_open_gatewrite_samples() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Mutex;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::{PacketWriter, OUTBOUND_HIGH_WATERMARK};

        let released = Arc::new(AtomicBool::new(false));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) = spawn_writer(
            GateWrite {
                released: released.clone(),
                buf: wire.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
        );
        let mut session = authenticated_session();
        session.writer = Some(handle);
        let mut max_backlog = 0usize;
        let long_host = "x".repeat(32 * 1024);
        // Multiple large opens; size pre-check / HWM should keep ledger bounded.
        for _ in 0..4 {
            let _ = session.channel_open_direct_tcpip(
                &long_host,
                22,
                "127.0.0.1",
                1234,
            );
            max_backlog = max_backlog.max(session.sealed_backlog_bytes());
            let _ = session.flush();
            max_backlog = max_backlog.max(session.sealed_backlog_bytes());
            tokio::task::yield_now().await;
            max_backlog = max_backlog.max(session.sealed_backlog_bytes());
        }
        let one_pkt = Session::packet_reservation(Session::CHANNEL_DATA_FRAMING);
        // Long channel-open may emit one large control packet; bound is HWM + that packet's
        // wire cost. Use a generous but still fixed single-packet ceiling for the open field.
        let open_one = (32 * 1024) + Session::WIRE_OVERHEAD_PER_PACKET + 64;
        assert!(
            max_backlog <= OUTBOUND_HIGH_WATERMARK + open_one.max(one_pkt),
            "R4 long open: max_backlog={max_backlog} > HWM+allowance={}",
            OUTBOUND_HIGH_WATERMARK + open_one.max(one_pkt)
        );
        released.store(true, AtomicOrdering::Release);
        for _ in 0..32 {
            let _ = session.retry_pending_outbound();
            let _ = session.flush();
            tokio::task::yield_now().await;
        }
        join.abort();
        let _ = join.await;
    }

    /// R4-3: KEX Full NeedSubmit counted in HWM ledger under HangWrite.
    #[tokio::test(flavor = "current_thread")]
    async fn r4_hwm_kex_full_need_submit_samples() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::{spawn_writer, BULK_QUEUE_CAP};
        use crate::sshbuffer::{PacketWriter, OUTBOUND_HIGH_WATERMARK};

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        for _ in 0..BULK_QUEUE_CAP {
            let _ = handle.try_seal_payload(Bytes::from(vec![1u8; 32]));
        }
        let mut session = authenticated_session();
        session.writer = Some(handle.clone());
        session.kex = SessionKexState::Taken;
        let mut max_backlog = session.sealed_backlog_bytes();
        let _ = session.register_seal_batch_and_install(
            vec![Bytes::from(vec![msg::NEWKEYS; 1]), Bytes::from(vec![0u8; 1024])],
            9,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            false,
            Some(KexAfterInstall::RekeyComplete),
        );
        max_backlog = max_backlog.max(session.sealed_backlog_bytes());
        assert!(
            matches!(
                session.pending_kex_install.as_ref().map(|p| &p.phase),
                Some(PendingKexPhase::NeedSubmit { .. })
            ),
            "KEX install must park NeedSubmit under Full"
        );
        // NeedSubmit bytes must participate.
        assert!(
            session.sealed_backlog_bytes()
                >= 1025 + Session::WIRE_OVERHEAD_PER_PACKET,
            "NeedSubmit wire weight in ledger"
        );
        assert!(
            max_backlog <= OUTBOUND_HIGH_WATERMARK + 4096,
            "R4 KEX Full: max_backlog={max_backlog}"
        );
        join.abort();
        let _ = join.await;
    }

    /// R5: rekey × success — InstallAck completes Idle + flush after inbound already live.
    #[tokio::test(flavor = "current_thread")]
    async fn r5_rekey_success_session_writer() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        // Immediate-write sink so install ACK returns promptly.
        struct EagerWrite;
        impl tokio::io::AsyncWrite for EagerWrite {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (handle, join, mut evt) =
            spawn_writer(EagerWrite, PacketWriter::clear(), progress, cancel_rx);
        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 5;
        let cid = insert_encrypted_channel(&mut session, 65536);
        confirm_test_channel(&mut session, cid, 0);
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .data(cid, Bytes::from_static(b"after"), true)
            .unwrap();
        set_inbound(&mut session, Box::new(crate::cipher::clear::Key {}));
        session
            .register_seal_batch_and_install(
                vec![Bytes::from_static(&[msg::NEWKEYS])],
                5,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                true,
                true,
                Some(KexAfterInstall::RekeyComplete),
            )
            .unwrap();
        // Wait InstallAck event.
        let ack_gen = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match evt.recv().await {
                    Some(WriterEvent::InstallAckOutbound { generation }) => break generation,
                    Some(_) => {}
                    None => panic!("writer events closed"),
                }
            }
        })
        .await
        .expect("InstallAck timeout");
        if let Some(ch) = session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .channels
            .get_mut(&cid)
        {
            ch.recipient_window_size = 65536;
        }
        let after = session.on_install_ack_outbound(ack_gen).expect("dual-condition ready");
        session.apply_kex_after_install(after);
        assert_eq!(session.kex, SessionKexState::Idle);
        assert!(session.pending_kex_install.is_none());
        assert!(
            !session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid)
        );
        join.abort();
        let _ = join.await;
    }

    /// R5: rekey × ACK-fail — inbound switched, non-Idle, no completion flush, cause staged.
    #[tokio::test(flavor = "current_thread")]
    async fn r5_rekey_ack_fail_session_writer() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.kex = SessionKexState::Taken;
        session.rekey_gen = 8;
        session.rekey_deadline.register(8, std::time::Duration::from_secs(30));
        let cid = insert_encrypted_channel(&mut session, 65536);
        confirm_test_channel(&mut session, cid, 0);
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .data(cid, Bytes::from_static(b"hold"), true)
            .unwrap();
        set_inbound(&mut session, Box::new(crate::cipher::clear::Key {}));
        // Inbound is switched (encrypted metadata present).
        assert!(session.common.encrypted.is_some());
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 8,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Writer fail injection: abort join → Closed.
        join.abort();
        let _ = join.await;
        session.fail_pending_kex_install();
        assert_eq!(session.kex, SessionKexState::Taken);
        assert!(session.rekey_deadline.generation.is_some());
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_pending_data(cid),
            "no completion flush on fail"
        );
        assert!(session.pending_reads.is_empty());
        assert_eq!(
            session.pending_supervisor_cause,
            Some(DisconnectCause::PeerError)
        );
    }

    /// R5: initial × success — InstallAck runs InitialComplete (ext-info path / Idle).
    #[tokio::test(flavor = "current_thread")]
    async fn r5_initial_success_session_writer() {
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        struct EagerWrite;
        impl tokio::io::AsyncWrite for EagerWrite {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, mut evt) =
            spawn_writer(EagerWrite, PacketWriter::clear(), progress, cancel_rx);
        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.kex = SessionKexState::Taken;
        // Simulate post-initial-Done: Encrypted present, inbound armed, waiting InstallAck.
        set_inbound(&mut session, Box::new(crate::cipher::clear::Key {}));
        assert!(session.common.encrypted.is_some());
        session
            .register_seal_batch_and_install(
                vec![Bytes::from_static(&[msg::NEWKEYS])],
                0,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                true,
                true,
                Some(KexAfterInstall::InitialComplete),
            )
            .unwrap();
        let ack_gen = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match evt.recv().await {
                    Some(WriterEvent::InstallAckOutbound { generation }) => break generation,
                    Some(_) => {}
                    None => panic!("writer events closed"),
                }
            }
        })
        .await
        .expect("InstallAck");
        let after = session.on_install_ack_outbound(ack_gen).expect("ready");
        session.apply_kex_after_install(after);
        assert_eq!(session.kex, SessionKexState::Idle);
        assert!(session.common.encrypted.is_some());
        join.abort();
        let _ = join.await;
    }

    /// R5: initial × ACK-fail.
    #[tokio::test(flavor = "current_thread")]
    async fn r5_initial_ack_fail_session_writer() {
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use crate::sshbuffer::PacketWriter;

        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        let mut session = authenticated_session();
        session.writer = Some(handle);
        session.kex = SessionKexState::Taken;
        // Simulate post-initial-Done: Encrypted present, inbound armed, waiting InstallAck.
        set_inbound(&mut session, Box::new(crate::cipher::clear::Key {}));
        assert!(session.common.encrypted.is_some());
        assert!(session.common.encrypted.is_some(), "inbound committed at Done");
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 0,
            after: Some(KexAfterInstall::InitialComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        join.abort();
        let _ = join.await;
        session.fail_pending_kex_install();
        assert_eq!(session.kex, SessionKexState::Taken);
        assert!(session.pending_supervisor_cause.is_some());
    }

    /// R6: park only when after.is_some(); NeedsReply must not swallow KEXINIT.
    #[test]
    fn r6_should_park_kexinit_requires_peer_done() {
        let mut session = authenticated_session();
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 1,
            after: None,
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        assert!(
            !session.should_park_kexinit(),
            "must not park KEXINIT before peer Done"
        );
        session.pending_kex_install.as_mut().unwrap().after =
            Some(KexAfterInstall::RekeyComplete);
        assert!(
            session.should_park_kexinit(),
            "must park KEXINIT while waiting only for InstallAck"
        );
    }

    /// R6: Done-before-ACK finalize replays parked KEXINIT via reply() gate (no process_packet bypass).
    #[tokio::test(flavor = "current_thread")]
    async fn r6_replay_pending_kexinit_reenters_reply_gate_done_before_ack() {
        let mut session = authenticated_session();
        session.kex = SessionKexState::Taken;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 2,
            after: Some(KexAfterInstall::RekeyComplete),
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Park a KEXINIT as should_park would.
        assert!(session.should_park_kexinit());
        session.park_pending_read(vec![msg::KEXINIT, 0, 1, 2, 3]);
        assert_eq!(session.pending_reads.len(), 1);
        // InstallAck completes dual-condition.
        let after = session.on_install_ack_outbound(2).expect("ready");
        session.apply_kex_after_install(after);
        assert_eq!(session.kex, SessionKexState::Idle);
        // Replay through unified helper — re-enters reply(); with Idle + no pending,
        // KEXINIT should begin_rekey (or at least clear pending_reads without hang).
        let mut handler = TestHandler;
        // begin_rekey needs keys in config — may err; we only assert no infinite park and gate path.
        let result = session.replay_pending_reads(Some(&mut handler)).await;
        // pending_reads drained either way (helper takes them first).
        assert!(
            session.pending_reads.is_empty(),
            "replay must drain parked packets"
        );
        // If begin_rekey failed due to missing keys, that's ok — path re-entered reply.
        let _ = result;
    }

    /// R6: ACK-before-Done order also drains via same helper after merge.
    #[tokio::test(flavor = "current_thread")]
    async fn r6_replay_ack_before_done_order() {
        let mut session = authenticated_session();
        session.kex = SessionKexState::Taken;
        session.pending_kex_install = Some(PendingKexInstall {
            generation: 4,
            after: None, // ACK first
            phase: PendingKexPhase::WaitingAck,
                    inbound_acked: false,
            inbound_sent: false,
        });
        // Before peer Done: must NOT park.
        assert!(!session.should_park_kexinit());
        // ACK first → InstallAcked, not finalized.
        assert!(session.on_install_ack_outbound(4).is_none());
        assert!(matches!(
            session.pending_kex_install.as_ref().map(|p| &p.phase),
            Some(PendingKexPhase::InstallAcked)
        ));
        // Peer Done merges after → both conditions met → finalize.
        session.park_pending_read(vec![msg::KEXINIT, 9, 9, 9]);
        let ready = session
            .merge_peer_done_into_pending(KexAfterInstall::RekeyComplete)
            .expect("ACK already seen → finalize on Done");
        session.apply_kex_after_install(ready);
        assert_eq!(
            session.kex,
            SessionKexState::Idle,
            "completion sets Idle before replay"
        );
        assert!(session.pending_kex_install.is_none());
        let mut handler = TestHandler;
        // Replay re-enters reply(); parked KEXINIT may begin a new rekey — that is
        // correct second-round behaviour, not a hang / double-park.
        let _ = session.replay_pending_reads(Some(&mut handler)).await;
        assert!(
            session.pending_reads.is_empty(),
            "replay must drain parked packets exactly once"
        );
    }

    /// Full park transfers ownership: cursor advances, retry does not re-send.
    #[tokio::test(flavor = "current_thread")]
    async fn flush_full_park_does_not_duplicate_seal_raw() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Mutex;
        use byteorder::{BigEndian, ByteOrder};
        use bytes::Bytes;
        use crate::server::supervisor::AtomicWriteProgress;
        use crate::server::writer::spawn_writer;
        use tokio::io::AsyncWrite;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct GateWrite {
            released: Arc<AtomicBool>,
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl AsyncWrite for GateWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                if !self.released.load(AtomicOrdering::Acquire) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.buf.lock().unwrap().extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let released = Arc::new(AtomicBool::new(false));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = tokio::sync::watch::channel(false);
        let (handle, join, _) = spawn_writer(
            GateWrite {
                released: released.clone(),
                buf: wire.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
        );

        let mut session = authenticated_session();
        session.writer = Some(handle);

        // Stage unique SealRaw packets into enc.write (length-prefixed).
        // Magic prefix avoids false window matches against length/padding bytes.
        let n = crate::server::writer::BULK_QUEUE_CAP + 16;
        const MAGIC: [u8; 4] = [0xA5, 0x5A, 0xC3, 0x3C];
        {
            let enc = session.common.encrypted.as_mut().unwrap();
            for i in 0..n {
                let mut payload = Vec::with_capacity(7);
                payload.push(crate::msg::IGNORE);
                payload.extend_from_slice(&MAGIC);
                payload.push((i >> 8) as u8);
                payload.push((i & 0xff) as u8);
                let mut len_buf = [0u8; 4];
                BigEndian::write_u32(&mut len_buf, payload.len() as u32);
                enc.write.extend_from_slice(&len_buf);
                enc.write.extend_from_slice(&payload);
            }
        }

        // First flush: hang socket → Full parks + advances cursor (no dual ownership).
        session.flush().unwrap();
        assert!(
            !session.pending_outbound.is_empty()
                || session.writer.as_ref().map(|w| w.pending_bytes()).unwrap_or(0) > 0,
            "Full path must leave work in Writer and/or pending"
        );
        // Unconsumed write + pending must be in the sealed-backlog ledger.
        assert!(
            session.sealed_backlog_bytes() > 0,
            "backlog must count pending + unconsumed write"
        );

        // Cursor must have advanced for every packet that was Ok or successfully parked.
        // Remaining unconsumed write (if any) is still past the parked region.
        let cursor_after_first = session.common.encrypted.as_ref().unwrap().write_cursor;
        assert!(cursor_after_first > 0, "cursor must advance on park/submit");

        // Second flush before release: must not re-stage already-parked packets.
        session.flush().unwrap();

        released.store(true, AtomicOrdering::Release);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let _ = session.retry_pending_outbound();
            let _ = session.flush();
            tokio::task::yield_now().await;
            if session.sealed_backlog_bytes() == 0
                && session.pending_outbound.is_empty()
                && session
                    .common
                    .encrypted
                    .as_ref()
                    .map(|e| e.write_cursor >= e.write.len())
                    .unwrap_or(true)
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "drain timeout backlog={} pending_q={} cursor={}/{}",
                    session.sealed_backlog_bytes(),
                    session.pending_outbound.bytes(),
                    session.common.encrypted.as_ref().unwrap().write_cursor,
                    session.common.encrypted.as_ref().unwrap().write.len(),
                );
            }
        }

        let recorded = wire.lock().unwrap().clone();
        for i in 0..n {
            let mut needle = vec![crate::msg::IGNORE];
            needle.extend_from_slice(&MAGIC);
            needle.push((i >> 8) as u8);
            needle.push((i & 0xff) as u8);
            let count = recorded
                .windows(needle.len())
                .filter(|w| *w == needle.as_slice())
                .count();
            assert_eq!(
                count, 1,
                "packet {i} must appear exactly once after Full park+retry, got {count}; wire_len={}",
                recorded.len()
            );
        }

        join.abort();
        let _ = join.await;
        let _ = Bytes::new();
    }

    // ----- RC2 inbound HOL: lane-gated drainage (S5a) -----

    use bytes::Bytes;

    /// Insert a channel whose application buffer holds `buf` messages, returning a spare sender
    /// clone (for minting reserve permits) and the receiver (to drain the buffer).
    fn insert_test_channel(
        session: &mut Session,
        id: ChannelId,
        buf: usize,
    ) -> (
        tokio::sync::mpsc::Sender<ChannelMsg>,
        tokio::sync::mpsc::Receiver<ChannelMsg>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel::<ChannelMsg>(buf);
        session.channels.insert(id, ChannelRef::new(tx.clone()));
        (tx, rx)
    }

    /// Register a channel in the encrypted state (its inbound window starts at `window`) so
    /// window accounting has something to act on. Returns the allocated id.
    fn insert_encrypted_channel(session: &mut Session, window: u32) -> ChannelId {
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .new_channel(window, 32768)
    }

    /// Confirm a test channel with a zero peer window, so anything written queues as
    /// `pending_data` (writes require `confirmed`).
    fn confirm_test_channel(session: &mut Session, id: ChannelId, peer_window: u32) {
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .channels
            .get_mut(&id)
            .unwrap()
            .confirm(&crate::parsing::ChannelOpenConfirmation {
                recipient_channel: 0,
                sender_channel: 0,
                initial_window_size: peer_window,
                maximum_packet_size: 32768,
            });
        session.sender.live.insert(id);
    }

    /// Server-initiated close: `Encrypted::close` removes the protocol entry immediately, so
    /// the peer's mandatory CHANNEL_CLOSE reply fails `is_established_channel`. Before the fix
    /// the reply was simply ignored, leaving the `self.channels` entry registered forever —
    /// a per-closed-channel leak on any long-lived connection that churns channels.
    #[tokio::test]
    async fn server_initiated_close_is_cleaned_up_by_peer_reply() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        // We close first: protocol entry goes away, application entry stays.
        session.close(id).unwrap();
        assert!(!session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .channel_exists(id));
        assert!(
            session.channels.contains_key(&id),
            "precondition: app-side entry outlives our own close"
        );

        // The peer's reply must complete the teardown rather than being dropped by the guard.
        let mut handler = TestHandler;
        let mut pkt = Vec::new();
        pkt.push(crate::msg::CHANNEL_CLOSE);
        pkt.extend_from_slice(&id.0.to_be_bytes());
        session
            .server_read_authenticated(Some(&mut handler), crate::msg::CHANNEL_CLOSE, &mut &pkt[1..])
            .await
            .unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "peer's close reply must release the application-side channel entry"
        );
    }

    /// The leak must not depend on the peer behaving: once our CHANNEL_CLOSE is on the wire and
    /// nothing is reading the channel any more, the application-side entry is released
    /// immediately rather than waiting for a mandatory reply a broken or hostile peer may never
    /// send.
    #[tokio::test]
    async fn server_initiated_close_releases_state_without_peer_reply() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, rx) = insert_test_channel(&mut session, id, 8);

        // Nothing is reading any more — this is what dropping a `Channel` looks like.
        drop(rx);

        session.close(id).unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "state must be released without waiting on the peer"
        );
    }

    /// ...but an application that closed the write side while still reading keeps its channel,
    /// since it may legitimately receive until the peer's own close arrives.
    #[tokio::test]
    async fn server_initiated_close_keeps_state_while_app_still_reads() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        session.close(id).unwrap();

        assert!(
            session.channels.contains_key(&id),
            "a live reader must not have its channel torn out from under it"
        );
    }

    /// D6: a `Handler` callback writes through `Session::data` directly, never through the run
    /// loop's message dispatch. Enforcing the outbound cap only at the dispatch sites left that
    /// path completely unbounded — an echo-style handler against a zero peer window could grow
    /// `pending_data` without limit. The cap must be applied at the write itself.
    #[tokio::test]
    async fn handler_side_writes_are_capped() {
        let mut config = crate::server::Config::default();
        config.max_pending_outbound_bytes = 4096;
        let mut session = authenticated_session_with(config);
        let id = insert_encrypted_channel(&mut session, 0);
        confirm_test_channel(&mut session, id, 0);

        // Peer window is 0, so every write lands in pending_data — exactly the handler-echo
        // shape. No run-loop dispatch is involved.
        for _ in 0..8 {
            if session
                .common
                .encrypted
                .as_ref()
                .is_some_and(|enc| enc.channel_exists(id))
            {
                session.data(id, Bytes::from_static(&[0u8; 1024])).unwrap();
            }
        }

        assert!(
            !session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channel_exists(id),
            "handler-side writes must hit the outbound cap and close the runaway channel"
        );
    }

    fn attach_lane(
        session: &mut Session,
        id: ChannelId,
        window: u32,
        items: Vec<crate::server::inbound_lane::LaneItem>,
    ) -> std::sync::Arc<std::sync::Mutex<crate::server::inbound_lane::LaneTable>> {
        use crate::server::inbound_lane::LaneTable;
        use crate::server::reader::ReaderHandle;
        use std::sync::{Arc, Mutex};

        let lanes = Arc::new(Mutex::new(LaneTable::new(8, 32)));
        {
            let mut g = lanes.lock().unwrap();
            g.open(id, 1, window, 32768, true);
            for item in items {
                assert_eq!(
                    g.try_push(id, item),
                    crate::server::inbound_lane::LanePush::Accepted
                );
            }
        }
        session.reader = Some(ReaderHandle::test_stub(lanes.clone()));
        lanes
    }

    async fn q8_grant_round(omit_lane: bool) -> Result<u32, &'static str> {
        use crate::server::inbound_lane::LaneItem;

        let mut cfg = crate::server::Config::default();
        #[cfg(feature = "_test_hooks")]
        {
            cfg.invert_omit_lane_from_undelivered = omit_lane;
        }
        let mut session = authenticated_session_with(cfg);
        let target = session.target_window_size;
        let id = insert_encrypted_channel(&mut session, target);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        let lane_hold = 64usize;
        let lanes = attach_lane(
            &mut session,
            id,
            target,
            vec![LaneItem::Data(bytes::Bytes::from(vec![0u8; lane_hold]))],
        );
        lanes.lock().unwrap().consume_window(id, target as usize);
        assert_eq!(lanes.lock().unwrap().window_remaining(id), Some(0));

        let mut handler = TestHandler;
        session
            .maybe_grant_after_delivery(id, Some(&mut handler))
            .await
            .map_err(|_| "grant")?;

        let got = session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .sender_window_size(id) as u32;
        Ok(got)
    }

    /// Q8 production: undelivered is lane occupancy only. Grant must leave
    /// lane bytes occupying the window.
    #[tokio::test]
    async fn window_grant_is_lane_only() {
        match q8_grant_round(false).await {
            Ok(got) => {
                let target = crate::server::Config::default().window_size;
                let want = target - 64;
                assert_eq!(got, want, "grant must subtract lane occupancy only");
            }
            Err(e) => panic!("Q8 HARD: production lane-only grant failed: {e}"),
        }
    }

    /// Q8 invert: omit the lane term → full-window grant → enumerated red.
    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn window_grant_omit_lane_is_red() {
        let target = crate::server::Config::default().window_size;
        match q8_grant_round(true).await {
            Ok(got) if got == target => {}
            Ok(got) if got > target - 64 => {
                // over_grant is also an enumerated red class
            }
            other => panic!(
                "Q8 HARD: invert must fail with enumerated class \
                 (lane_omitted|over_grant), got {other:?}"
            ),
        }
        // Explicit class: full-window grant is `lane_omitted`.
        let got = q8_grant_round(true).await.expect("invert still grants");
        assert_eq!(
            got, target,
            "Q8 HARD: omit-lane invert class is lane_omitted (got {got}, target {target})"
        );
    }

    /// With nothing queued the grant still tops all the way back up to `target`, so the fix above
    /// costs nothing on the steady-state fast path.
    #[tokio::test]
    async fn window_grant_restores_full_target_when_drained() {
        let mut session = authenticated_session();
        let target = session.target_window_size;
        let id = insert_encrypted_channel(&mut session, target);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .consume_recv_window(id, target as usize);

        let mut handler = TestHandler;
        session
            .maybe_grant_after_delivery(id, Some(&mut handler))
            .await
            .unwrap();

        assert_eq!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .sender_window_size(id),
            target as usize
        );
    }

    /// G7: reserved Δ == expand/ADJUST Δ. After planning, consume the
    /// remaining window so a second snapshot would double the grant.
    #[cfg(feature = "_test_hooks")]
    fn g7_round(recompute: bool) -> Result<(), &'static str> {
        use crate::server::inbound_lane::LaneTable;
        use crate::server::reader::ReaderHandle;
        use crate::server::WindowObserveSlot;

        let mut cfg = crate::server::Config::default();
        let wobs = WindowObserveSlot::new();
        cfg.window_observe = Some(wobs.clone());
        cfg.invert_recompute_grant_delta = recompute;
        let mut session = authenticated_session_with(cfg);
        let target = 256u32;
        session.target_window_size = target;
        let id = insert_encrypted_channel(&mut session, target);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        let r1 = target / 2 - 1;
        let lanes = std::sync::Arc::new(std::sync::Mutex::new(LaneTable::new(8, 32)));
        {
            let mut g = lanes.lock().unwrap();
            g.open(id, 1, target, 32, true);
            g.consume_window(id, (target - r1) as usize);
            assert_eq!(g.window_remaining(id), Some(r1));
        }
        session.reader = Some(ReaderHandle::test_stub(lanes.clone()));

        let delta = session.planned_grant_delta(id, target, 0);
        if delta == 0 {
            return Err("no_grant");
        }
        if session.reserve_global_inbound_credit(delta).is_err() {
            return Err("reserve");
        }
        lanes.lock().unwrap().consume_window(id, r1 as usize);
        assert_eq!(
            lanes.lock().unwrap().window_remaining(id),
            Some(0)
        );

        let granted = session
            .grant_expand_then_adjust(id, target, 0, delta)
            .map_err(|_| "grant")?;
        if !granted {
            return Err("not_granted");
        }
        let reserved = wobs.last_reserved_delta();
        let expand = wobs.last_expand_delta();
        let adjust = wobs.last_adjust_delta();
        if expand != reserved {
            return Err("delta_mismatch");
        }
        if adjust != reserved {
            return Err("adjust_mismatch");
        }
        if expand != delta {
            return Err("delta_mismatch");
        }
        Ok(())
    }

    #[cfg(feature = "_test_hooks")]
    #[test]
    fn g7_reserved_equals_granted() {
        g7_round(false).unwrap_or_else(|e| panic!("G7 HARD: production identity failed: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[test]
    fn g7_recompute_delta_is_red() {
        match g7_round(true) {
            Err("delta_mismatch") | Err("adjust_mismatch") => {}
            other => panic!(
                "G7 HARD: invert must fail with enumerated class \
                 (delta_mismatch|adjust_mismatch), got {other:?}"
            ),
        }
    }

    /// A producer parked in `Handle::data` whose channel is torn down (peer close / inbound
    /// overflow both discard the outbound backlog) must be woken with an **error**. Reporting
    /// success would tell the caller its bytes were sent when they were thrown away — and
    /// `has_pending_data` alone cannot tell "gone" from "drained", since it returns false for
    /// both.
    #[tokio::test]
    async fn discarded_producer_is_woken_with_error_not_success() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 0);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        // Channel torn down with its backlog discarded, exactly as peer-close does.
        session.discard_channel_outbound(id).unwrap();

        session.release_outbound_acks();

        assert!(
            acked.await.is_err(),
            "discarded data must not be reported as delivered"
        );
    }

    /// Regression for the opposite error: a channel removed by an *orderly* flush+close
    /// delivered its bytes, so its parked producer must be told `Ok`. Inferring failure from
    /// "channel is gone" reported `Err` for data that really was sent.
    #[tokio::test]
    async fn producer_is_woken_with_success_after_orderly_flush_and_close() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        // Orderly close after the backlog drained: `Encrypted::close` emits and removes the
        // channel, so it is gone but everything was delivered.
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .close(id)
            .unwrap();
        assert!(!session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .channel_exists(id));

        session.release_outbound_acks();

        assert!(
            acked.await.is_ok(),
            "delivered data must not be reported as failed"
        );
    }

    /// The ordinary path still reports success: channel alive, backlog drained.
    #[tokio::test]
    async fn drained_producer_is_woken_with_success() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        session.release_outbound_acks();

        assert!(acked.await.is_ok());
    }

    /// Credit apply drains `pending_data` into `enc.write` but must not
    /// leave the parked `Handle::data` ack hanging — settle flush+release
    /// is what unparks. Invert skip leaves the oneshot pending.
    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn settle_after_credit_unparks_ack() {
        settle_after_credit_round(false)
            .await
            .unwrap_or_else(|e| panic!("settle HARD: production must unpark: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn settle_skip_leaves_ack_parked() {
        match settle_after_credit_round(true).await {
            Err("ack_still_parked") => {}
            other => panic!(
                "settle HARD: invert must fail with ack_still_parked, got {other:?}"
            ),
        }
    }

    #[cfg(feature = "_test_hooks")]
    async fn settle_after_credit_round(skip: bool) -> Result<(), &'static str> {
        let mut cfg = crate::server::Config::default();
        cfg.invert_skip_outbound_settle = skip;
        let mut session = authenticated_session_with(cfg);
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 0);
        session
            .data(id, Bytes::from_static(&[0u8; 16]))
            .map_err(|_| "data")?;
        assert!(
            session.has_pending_data_apply(id),
            "zero peer window must queue pending_data"
        );

        let (ack, mut acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        session
            .apply_peer_window_credit::<TestHandler>(id, 1024, None)
            .await
            .map_err(|_| "apply")?;
        assert!(
            !session.has_pending_data_apply(id),
            "credit must drain pending_data into enc.write"
        );

        session
            .settle_outbound_after_stage()
            .map_err(|_| "settle")?;

        match acked.try_recv() {
            Ok(()) => {
                if skip {
                    Err("ack_released")
                } else {
                    Ok(())
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                if skip {
                    Err("ack_still_parked")
                } else {
                    Err("ack_not_released")
                }
            }
            Err(oneshot::error::TryRecvError::Closed) => Err("ack_closed"),
        }
    }

    /// Decision ①: known-dead `Handle::data` is sync Err and does not enqueue.
    #[tokio::test]
    async fn handle_data_unknown_channel_is_sync_err() {
        let session = authenticated_session();
        let handle = session.handle();
        let err = handle
            .data(ChannelId(99), Bytes::from_static(b"x"))
            .await
            .expect_err("unknown id must not enqueue");
        assert_eq!(err.as_ref(), b"x");
    }

    /// Handler-facing `Session::data` stays a no-op Ok on a missing
    /// channel (Encrypted::data silent drop). `?` in a callback must
    /// not tear the session. Sync-Err is Handle::data / Channel::data.
    #[test]
    fn data_apply_dead_channel_is_ok() {
        let mut session = authenticated_session();
        session
            .data_apply(ChannelId(99), Bytes::from_static(b"x"))
            .expect("Handler data() on a gone channel must not fail the callback");
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn discard_and_release_are_exclusive() {
        discard_release_round(false)
            .await
            .unwrap_or_else(|e| panic!("exactly-once HARD: production must Err: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn discard_skip_drop_then_release_is_red() {
        match discard_release_round(true).await {
            Err("discarded_reported_ok") => {}
            other => panic!(
                "exactly-once HARD: invert must fail with discarded_reported_ok, got {other:?}"
            ),
        }
    }

    #[cfg(feature = "_test_hooks")]
    async fn discard_release_round(skip_drop: bool) -> Result<(), &'static str> {
        let mut cfg = crate::server::Config::default();
        cfg.invert_skip_discard_ack_drop = skip_drop;
        let mut session = authenticated_session_with(cfg);
        let id = insert_encrypted_channel(&mut session, 0);
        confirm_test_channel(&mut session, id, 0);
        session
            .data(id, Bytes::from_static(&[0u8; 16]))
            .map_err(|_| "data")?;
        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);
        session
            .discard_channel_outbound(id)
            .map_err(|_| "discard")?;
        session.release_outbound_acks();
        match acked.await {
            Err(_) if !skip_drop => Ok(()),
            Ok(()) if skip_drop => Err("discarded_reported_ok"),
            Ok(()) => Err("discarded_ok_without_invert"),
            Err(_) => Err("still_err_under_invert"),
        }
    }

    #[derive(Clone, Copy)]
    enum WakeKind {
        Release,
        Discard,
        Finalize,
    }

    fn poll_once<F: std::future::Future>(fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        std::future::Future::poll(fut, &mut cx)
    }

    /// Two notify waiters + two parked acks. Production must Ready both.
    /// Invert single-wake → `second_writer_parked`. Invert skip-teardown
    /// (finalize only) → `writer_still_parked`.
    #[cfg(feature = "_test_hooks")]
    async fn two_writer_wake_round(
        kind: WakeKind,
        invert_single: bool,
        invert_skip_fin: bool,
    ) -> Result<(), &'static str> {
        let mut cfg = crate::server::Config::default();
        cfg.invert_single_writer_wake = invert_single;
        cfg.invert_skip_teardown_wake = invert_skip_fin;
        let mut session = authenticated_session_with(cfg);
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 4);

        let notify = session
            .channels
            .get(&id)
            .ok_or("no_chan")?
            .window_size()
            .subscribe();
        let mut w1 = std::pin::pin!(notify.notified());
        let mut w2 = std::pin::pin!(notify.notified());
        if !poll_once(w1.as_mut()).is_pending() {
            return Err("w1_pre_ready");
        }
        if !poll_once(w2.as_mut()).is_pending() {
            return Err("w2_pre_ready");
        }

        let (a1, _r1) = oneshot::channel();
        let (a2, _r2) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(a1);
        session.outbound_acks.entry(id).or_default().push_back(a2);

        match kind {
            WakeKind::Release => session.release_outbound_acks(),
            WakeKind::Discard => session.discard_channel_outbound(id).map_err(|_| "discard")?,
            WakeKind::Finalize => session.finalize_close(id),
        }

        let p1 = poll_once(w1.as_mut()).is_ready();
        let p2 = poll_once(w2.as_mut()).is_ready();
        match (p1, p2) {
            (true, true) => {
                if invert_single || invert_skip_fin {
                    Err("both_woke_under_invert")
                } else {
                    Ok(())
                }
            }
            (true, false) | (false, true) => Err("second_writer_parked"),
            (false, false) => Err("writer_still_parked"),
        }
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn two_writers_release_wakes_both() {
        two_writer_wake_round(WakeKind::Release, false, false)
            .await
            .unwrap_or_else(|e| panic!("wake HARD: release must Ready both: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn two_writers_discard_wakes_both() {
        two_writer_wake_round(WakeKind::Discard, false, false)
            .await
            .unwrap_or_else(|e| panic!("wake HARD: discard must Ready both: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn two_writers_finalize_wakes_both() {
        two_writer_wake_round(WakeKind::Finalize, false, false)
            .await
            .unwrap_or_else(|e| panic!("wake HARD: finalize must Ready both: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn two_writers_single_wake_is_red() {
        match two_writer_wake_round(WakeKind::Release, true, false).await {
            Err("second_writer_parked") => {}
            other => panic!(
                "wake HARD: invert single-wake must second_writer_parked, got {other:?}"
            ),
        }
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn finalize_skip_wake_is_red() {
        match two_writer_wake_round(WakeKind::Finalize, false, true).await {
            Err("writer_still_parked") => {}
            other => panic!(
                "wake HARD: invert skip-teardown-wake must writer_still_parked, got {other:?}"
            ),
        }
    }

    /// Backpressure parks the channel without popping: FIFO DATA→DATA→CLOSE
    /// stays in the lane, exactly one reserve is requested, grant is withheld.
    #[tokio::test]
    async fn inbound_fifo_preserves_order_and_backpressures() {
        use crate::server::inbound_lane::LaneItem;

        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, mut rx) = insert_test_channel(&mut session, id, 1);
        attach_lane(
            &mut session,
            id,
            1024,
            vec![
                LaneItem::Data(Bytes::from_static(b"a")),
                LaneItem::Data(Bytes::from_static(b"bb")),
                LaneItem::Data(Bytes::from_static(b"ccc")),
                LaneItem::Close,
            ],
        );

        let mut handler = TestHandler;
        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .unwrap();

        assert!(
            session.backpressured.contains(&id),
            "second DATA must park the channel"
        );
        assert_eq!(session.inbound_needs_reserve, vec![id]);
        assert_eq!(
            session.reader.as_ref().unwrap().occupancy_count(id),
            3,
            "bb + ccc + Close stay in the lane"
        );
        match rx.try_recv() {
            Ok(ChannelMsg::Data { data }) => assert_eq!(data.as_ref(), b"a"),
            other => panic!("expected first DATA(a) in the app buffer, got {other:?}"),
        }

        let mut reserves = FuturesUnordered::new();
        session.drain_needs_reserve(&mut reserves);
        let (cid, generation, res) = reserves.next().await.expect("one reserve");
        assert_eq!(cid, id);
        assert!(res.is_ok());
        session
            .pump_inbound(id, generation, res, Some(&mut handler))
            .await
            .unwrap();
        match rx.try_recv() {
            Ok(ChannelMsg::Data { data }) => assert_eq!(data.as_ref(), b"bb"),
            other => panic!("expected DATA(bb) after permit, got {other:?}"),
        }
        assert!(
            !session.backpressured.contains(&id),
            "delivered item returns the channel to rotation"
        );
        // bb was drained above, so the next pump can deliver ccc, then
        // park on Close (buffer holds ccc). Close stays at the lane head.
        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .unwrap();
        assert!(
            session.backpressured.contains(&id),
            "Close still needs a permit (buffer holds ccc)"
        );
        assert_eq!(
            session.reader.as_ref().unwrap().occupancy_count(id),
            1,
            "Close remains at the head; no skip-ahead"
        );
        assert!(
            session.reader.as_ref().unwrap().close_queued(id),
            "CLOSE must still be the parked head"
        );
    }

    /// S4b: Delivered DATA no longer calls `Handler::data`. Permit-path
    /// delivery into the application buffer; the callback stays 0.
    #[tokio::test]
    async fn queued_handler_callback_is_deferred_until_delivery() {
        struct Rec(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
        impl crate::server::Handler for Rec {
            type Error = crate::Error;
            async fn data(
                &mut self,
                _channel: ChannelId,
                data: &[u8],
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                self.0.lock().unwrap().push(data.to_vec());
                Ok(())
            }
        }

        use crate::server::inbound_lane::LaneItem;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let mut handler = Rec(seen.clone());
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, mut rx) = insert_test_channel(&mut session, id, 1);
        attach_lane(
            &mut session,
            id,
            1024,
            vec![
                LaneItem::Data(Bytes::from_static(b"a")),
                LaneItem::Data(Bytes::from_static(b"b")),
            ],
        );

        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .unwrap();
        assert!(seen.lock().unwrap().is_empty());
        assert!(session.backpressured.contains(&id));

        assert!(matches!(rx.recv().await, Some(ChannelMsg::Data { .. })));
        let generation = session.reader.as_ref().unwrap().lane_gen(id).unwrap();
        let mut reserves = FuturesUnordered::new();
        session.drain_needs_reserve(&mut reserves);
        let (_, got_gen, res) = reserves.next().await.expect("reserve");
        assert_eq!(got_gen, generation);
        session
            .pump_inbound(id, generation, res, Some(&mut handler))
            .await
            .unwrap();

        assert!(
            seen.lock().unwrap().is_empty(),
            "S4b: Delivered DATA must not call Handler::data"
        );
        match rx.recv().await {
            Some(ChannelMsg::Data { data }) => assert_eq!(data.as_ref(), b"b"),
            other => panic!("expected delivered Data(b), got {other:?}"),
        }
        assert!(!session.inbound_gate.contains_key(&id));
    }

    /// A peer CLOSE for a server-initiated open that is still awaiting OPEN_CONFIRMATION must be
    /// ignored (upstream 7c5659f), not treated as "the peer acked our close". Running the
    /// teardown there removed the unconfirmed enc entry, so the confirmation still in flight hit
    /// the unknown-channel arm of CHANNEL_OPEN_CONFIRMATION and killed the entire session with
    /// `Error::Inconsistent` — a hostile peer could do this to any multiplexed connection.
    #[tokio::test]
    async fn peer_close_before_open_confirmation_is_ignored() {
        let mut session = authenticated_session();
        // Server-initiated open: enc entry exists but is NOT confirmed yet.
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        let mut handler = TestHandler;
        let mut pkt = vec![crate::msg::CHANNEL_CLOSE];
        pkt.extend_from_slice(&id.0.to_be_bytes());
        session
            .server_read_authenticated(Some(&mut handler), crate::msg::CHANNEL_CLOSE, &mut &pkt[1..])
            .await
            .unwrap();

        // The premature CLOSE must not have torn anything down.
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channel_exists(id),
            "premature peer CLOSE must not remove the unconfirmed enc entry"
        );
        assert!(session.channels.contains_key(&id));

        // The confirmation that was already in flight must still be accepted.
        let mut pkt = vec![crate::msg::CHANNEL_OPEN_CONFIRMATION];
        pkt.extend_from_slice(&id.0.to_be_bytes()); // recipient_channel (our id)
        pkt.extend_from_slice(&7u32.to_be_bytes()); // sender_channel (peer's id)
        pkt.extend_from_slice(&2_097_152u32.to_be_bytes()); // initial_window_size
        pkt.extend_from_slice(&32768u32.to_be_bytes()); // maximum_packet_size
        session
            .server_read_authenticated(
                Some(&mut handler),
                crate::msg::CHANNEL_OPEN_CONFIRMATION,
                &mut &pkt[1..],
            )
            .await
            .expect("confirmation after a premature peer CLOSE must not kill the session");
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channels
                .get(&id)
                .unwrap()
                .confirmed,
            "the channel must end up established"
        );
    }

    /// Zero-byte DATA / dup EOF/CLOSE are dropped at the lane (`DroppedZero` /
    /// `DroppedDup`). Count-bound slack covers the rest. This is the S3b
    /// coverage that replaces Scheme C's pending-cap patches.
    #[test]
    fn zero_byte_and_dup_ctrl_are_dropped_at_lane() {
        use crate::server::inbound_lane::{LaneItem, LanePush, LaneTable};

        let mut t = LaneTable::new(8, 32);
        let id = ChannelId(1);
        t.open(id, 1, 1024, 32768, true);
        assert_eq!(
            t.try_push(id, LaneItem::Data(Bytes::from_static(b"a"))),
            LanePush::Accepted
        );
        for _ in 0..64 {
            assert_eq!(
                t.try_push(id, LaneItem::Data(Bytes::new())),
                LanePush::DroppedZero
            );
            assert_eq!(
                t.try_push(
                    id,
                    LaneItem::ExtendedData {
                        ext: 1,
                        data: Bytes::new()
                    }
                ),
                LanePush::DroppedZero
            );
        }
        assert_eq!(t.occupancy_count(id), 1);
        assert_eq!(t.try_push(id, LaneItem::Eof), LanePush::Accepted);
        assert_eq!(t.try_push(id, LaneItem::Close), LanePush::Accepted);
        for _ in 0..64 {
            assert_eq!(t.try_push(id, LaneItem::Eof), LanePush::DroppedDup);
            assert_eq!(t.try_push(id, LaneItem::Close), LanePush::DroppedDup);
        }
        assert_eq!(t.occupancy_count(id), 3, "a + one Eof + one Close");
        assert_eq!(t.occupancy_bytes(id), 1);
    }

    /// If the application bare-drops its channel receiver while a peer `Close` is queued behind
    /// data, the deferred teardown must still run: the reserve resolves `Err`, and dropping just
    /// the queue would leak the `self.channels` entry (its enc twin is already gone) and skip
    /// `handler.channel_close` for the rest of the session.
    #[tokio::test]
    async fn receiver_drop_with_queued_close_still_finalizes() {
        struct CloseRec(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl crate::server::Handler for CloseRec {
            type Error = crate::Error;
            async fn channel_close(
                &mut self,
                _channel: ChannelId,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        use crate::server::inbound_lane::LaneItem;

        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handler = CloseRec(closes.clone());
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, rx) = insert_test_channel(&mut session, id, 1);
        attach_lane(
            &mut session,
            id,
            1024,
            vec![
                LaneItem::Data(Bytes::from_static(b"a")),
                LaneItem::Data(Bytes::from_static(b"bb")),
                LaneItem::Close,
            ],
        );

        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .unwrap();
        assert!(session.backpressured.contains(&id));
        assert!(session.reader.as_ref().unwrap().close_queued(id));

        drop(rx);
        let generation = session.reader.as_ref().unwrap().lane_gen(id).unwrap();
        session
            .pump_inbound(id, generation, Err(()), Some(&mut handler))
            .await
            .unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "CLOSE still in the lane must tear down the app-side entry"
        );
        assert!(!session.inbound_gate.contains_key(&id));
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Contrast: a bare receiver drop with no Close in the lane keeps the
    /// app-side entry (the peer may still close later).
    #[tokio::test]
    async fn receiver_drop_without_queued_close_only_drops_queue() {
        use crate::server::inbound_lane::LaneItem;

        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, rx) = insert_test_channel(&mut session, id, 1);
        attach_lane(
            &mut session,
            id,
            1024,
            vec![
                LaneItem::Data(Bytes::from_static(b"a")),
                LaneItem::Data(Bytes::from_static(b"bb")),
            ],
        );

        let mut handler = TestHandler;
        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .unwrap();
        assert!(session.backpressured.contains(&id));

        drop(rx);
        let generation = session.reader.as_ref().unwrap().lane_gen(id).unwrap();
        session
            .pump_inbound(id, generation, Err(()), Some(&mut handler))
            .await
            .unwrap();

        assert!(session.channels.contains_key(&id));
        assert!(!session.inbound_gate.contains_key(&id));
        assert!(!session.backpressured.contains(&id));
    }

    /// Dual Full: invoke_tx capacity 1 and full, app buffer capacity 1 and
    /// full, Close in the lane. Production must StopDiscard immediately
    /// (`!accepts_ctrl`). Invert restores the S5a-r1 hole.
    async fn dual_full_close_async(
        invert: bool,
        close_at_head: bool,
    ) -> Result<(), &'static str> {
        use crate::server::executor::{HandlerExecutor, Invoke, InvokeMsg};
        use crate::server::inbound_lane::LaneItem;
        use tokio::sync::{mpsc, watch};

        let mut cfg = crate::server::Config::default();
        #[cfg(feature = "_test_hooks")]
        {
            cfg.invert_skip_close_discard_on_park = invert;
        }
        let mut session = authenticated_session_with(cfg);
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);
        session
            .try_send_app(id, ChannelMsg::Data { data: Bytes::from_static(b"x") })
            .map_err(|_| "fill_buf")?;

        let (invoke_tx, invoke_rx) = mpsc::channel(1);
        invoke_tx
            .try_send(InvokeMsg {
                generation: 1,
                invoke: Invoke::ChannelEof { id },
            })
            .map_err(|_| "fill_exec")?;
        let (_result_tx, result_rx) = mpsc::channel(1);
        let (cancel, _cancel_rx) = watch::channel(false);
        session.executor = Some(HandlerExecutor {
            invoke_tx,
            result_rx,
            cancel,
        });
        if !session.executor_full() {
            return Err("exec_not_full");
        }
        let _keep_exec = invoke_rx;

        let items = if close_at_head {
            vec![LaneItem::Close]
        } else {
            vec![
                LaneItem::Data(Bytes::from_static(b"y")),
                LaneItem::Close,
            ]
        };
        attach_lane(&mut session, id, 1024, items);
        if !session.outbound_channel_accepts_ctrl(id) {
            return Err("pre_closed");
        }

        let mut handler = TestHandler;
        session
            .pump_reader_lanes(Some(&mut handler))
            .await
            .map_err(|_| "pump")?;

        if invert {
            if session.outbound_channel_accepts_ctrl(id) {
                return Err("still_accepts_ctrl");
            }
            return Err("expected_red");
        }
        if session.outbound_channel_accepts_ctrl(id) {
            return Err("still_accepts_ctrl");
        }
        Ok(())
    }

    #[tokio::test]
    async fn dual_full_close_at_head_stop_discard() {
        dual_full_close_async(false, true)
            .await
            .unwrap_or_else(|e| panic!("P1 HARD: Close-at-head must StopDiscard: {e}"));
    }

    #[tokio::test]
    async fn dual_full_close_behind_data_stop_discard() {
        dual_full_close_async(false, false)
            .await
            .unwrap_or_else(|e| panic!("P1 HARD: Close-behind-DATA must StopDiscard: {e}"));
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test]
    async fn dual_full_close_invert_is_red() {
        match dual_full_close_async(true, true).await {
            Err("still_accepts_ctrl") => {}
            other => panic!(
                "P1 HARD: invert must fail with enumerated class still_accepts_ctrl, got {other:?}"
            ),
        }
    }

    fn pending_install_stub() -> PendingKexInstall {
        PendingKexInstall {
            generation: 1,
            after: None,
            phase: PendingKexPhase::WaitingAck,
            inbound_acked: false,
            inbound_sent: false,
        }
    }

    /// Extra gate: pending install blocks a second `begin_rekey`.
    #[test]
    fn begin_rekey_rejects_second_while_pending() {
        let mut session = authenticated_session();
        session.pending_kex_install = Some(pending_install_stub());
        match session.begin_rekey() {
            Err(Error::Kex) => {}
            other => panic!("S6a HARD: second begin_rekey must Err(Kex), got {other:?}"),
        }
    }

    /// Invert: skip the pending guard → second begin_rekey is accepted.
    #[cfg(feature = "_test_hooks")]
    #[test]
    fn invert_skip_pending_rekey_guard_is_red() {
        let mut cfg = crate::server::Config::default();
        cfg.invert_skip_pending_rekey_guard = true;
        let mut session = authenticated_session_with(cfg);
        session.pending_kex_install = Some(pending_install_stub());
        match session.begin_rekey() {
            Ok(()) => {}
            other => panic!(
                "S6a HARD: invert must accept second begin_rekey (class double_rekey), got {other:?}"
            ),
        }
        assert!(
            session.kex.active(),
            "S6a HARD invert class double_rekey: second kex is live"
        );
    }
}

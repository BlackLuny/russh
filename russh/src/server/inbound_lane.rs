//! S3b per-channel inbound lane: dual-bound FIFO of decrypted channel messages.
//!
//! After S5a this is the only server inbound backlog: Session does not pop a
//! channel's head until the app buffer has a permit (`try_reserve`). Grant
//! `undelivered` is lane occupancy only (`bytes`, not control payload).
//! Invariant: `bytes ≤ byte_cap ∧ ctrl_bytes ≤ max(byte_cap, INBOUND_LANE_CTRL_FLOOR) ∧ items ≤ count_cap`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use log::warn;
use tokio::sync::Notify;

use crate::ChannelId;

/// Extra zero-byte / REQUEST slots beyond `window / min_packet`.
pub const INBOUND_LANE_COUNT_SLACK: usize = 32;
/// Default smallest packet used for the count bound.
pub const INBOUND_LANE_MIN_PACKET: usize = 8;
/// Ctrl byte budget (kex / OPEN / GLOBAL / ADJUST / unknown). Full → Cancelling.
pub const INBOUND_CTRL_BUDGET: usize = 2 * 1024 * 1024;
/// One transport-legal packet always fits an empty control ledger.
/// Per-lane bound is `max(window + maxpkt, this)`.
pub const INBOUND_LANE_CTRL_FLOOR: usize = crate::cipher::MAXIMUM_PACKET_LEN;

#[derive(Debug, Clone)]
pub enum LaneItem {
    Data(Bytes),
    ExtendedData { ext: u32, data: Bytes },
    Eof,
    Close,
    /// Bytes after the `CHANNEL_REQUEST` type byte (includes channel id).
    Request { payload: Bytes },
    Success { payload: Bytes },
    Failure { payload: Bytes },
}

impl LaneItem {
    pub fn byte_len(&self) -> usize {
        match self {
            LaneItem::Data(d) => d.len(),
            LaneItem::ExtendedData { data, .. } => data.len(),
            LaneItem::Eof
            | LaneItem::Close
            | LaneItem::Request { .. }
            | LaneItem::Success { .. }
            | LaneItem::Failure { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanePush {
    Accepted,
    DroppedZero,
    DroppedDup,
    /// DATA/EXT exceeded `window_remaining`. Ignored per RFC 4254 §5.2
    /// instead of occupying the DoS cap (which would Overflow-close a
    /// slightly over-window peer such as OpenSSH with in-flight packets).
    DroppedOverWindow,
    /// No lane (channel not opened). Caller counts `unknown_drops`.
    NoLane,
    Overflow,
}

/// Result of `try_expand_inbound_cap`. Never awaits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandCap {
    Expanded,
    NoLane,
    GenMismatch,
}

/// Occupancy DoS bound for a committed inbound window.
/// `byte = window + maxpkt`, `count = window / min(8, min_packet) + slack`.
pub fn occupancy_caps(
    window: u32,
    max_packet: u32,
    min_packet: usize,
    slack: usize,
) -> (usize, usize) {
    let min_p = min_packet.min(8).max(1);
    let byte_cap = (window as usize).saturating_add(max_packet as usize);
    let count_cap = (window as usize / min_p).saturating_add(slack).max(1);
    (byte_cap, count_cap)
}

#[derive(Debug)]
pub struct ChannelLane {
    pub generation: u64,
    items: VecDeque<LaneItem>,
    bytes: usize,
    /// Control payload (`Request`/`Success`/`Failure`) ledger. Checked
    /// against `max(byte_cap, INBOUND_LANE_CTRL_FLOOR)`, kept separate
    /// from `bytes` so window-grant `undelivered` stays data-only.
    ctrl_bytes: usize,
    byte_cap: usize,
    count_cap: usize,
    /// Single inbound-window ledger (`sender_window_size`). Reader
    /// consumes on receive; Session expands on grant. No second `-=`.
    window_remaining: u32,
    eof_queued: bool,
    close_queued: bool,
    data_items: usize,
    /// Peer-open: true at insert. Server-open: false until
    /// `CHANNEL_OPEN_CONFIRMATION` (`LaneTable::confirm`).
    confirmed: bool,
}

impl ChannelLane {
    pub fn new(
        generation: u64,
        granted_window: u32,
        max_packet: u32,
        min_packet: usize,
        slack: usize,
        confirmed: bool,
    ) -> Self {
        // Occupancy DoS bound, not granted-window authority (S3c).
        // Extra data beyond the advertised window is ignored per
        // RFC 4254 §5.2; this cap only stops Reader RAM from growing
        // without bound. Raised when the committed target grows
        // (`raise_occupancy_to`); never raised on refill grants.
        let (byte_cap, count_cap) =
            occupancy_caps(granted_window, max_packet, min_packet, slack);
        Self {
            generation,
            items: VecDeque::new(),
            bytes: 0,
            ctrl_bytes: 0,
            byte_cap,
            count_cap,
            window_remaining: granted_window,
            eof_queued: false,
            close_queued: false,
            data_items: 0,
            confirmed,
        }
    }

    pub fn occupancy_bytes(&self) -> usize {
        self.bytes
    }

    pub fn occupancy_count(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn head_is_payload_data(&self) -> bool {
        matches!(
            self.items.front(),
            Some(LaneItem::Data(_)) | Some(LaneItem::ExtendedData { .. })
        )
    }

    pub fn window_remaining(&self) -> u32 {
        self.window_remaining
    }

    /// I1: bytes are off the wire. Extra data past the advertised window
    /// is not deducted (RFC 4254 §5.2). Callers must not queue that extra
    /// payload — see [`LaneTable::ingest`].
    fn consume_window(&mut self, len: usize) {
        let n = len as u32;
        if n <= self.window_remaining {
            self.window_remaining -= n;
        }
    }

    /// Grant only tops up the inbound-window ledger. Occupancy bounds
    /// stay put on refill: a compliant peer satisfies
    /// `lane_bytes + window_remaining ≤ committed_target`, so raising
    /// the DoS cap on each ADJUST Δ would let RAM grow without bound
    /// (S3c). When `Handler::adjust_window` commits a *larger* target,
    /// `raise_occupancy_to` lifts the bound to the new target + maxpkt.
    fn expand(&mut self, add: u32) {
        self.window_remaining = self.window_remaining.saturating_add(add);
    }

    /// Lift occupancy DoS bounds to cover `window` (never shrink).
    fn raise_occupancy_to(
        &mut self,
        window: u32,
        max_packet: u32,
        min_packet: usize,
        slack: usize,
    ) {
        let (byte_cap, count_cap) = occupancy_caps(window, max_packet, min_packet, slack);
        self.byte_cap = self.byte_cap.max(byte_cap);
        self.count_cap = self.count_cap.max(count_cap);
    }

    #[cfg(feature = "_test_hooks")]
    pub fn byte_cap(&self) -> usize {
        self.byte_cap
    }

    #[cfg(feature = "_test_hooks")]
    pub fn count_cap(&self) -> usize {
        self.count_cap
    }

    #[cfg(feature = "_test_hooks")]
    pub fn ctrl_bytes(&self) -> usize {
        self.ctrl_bytes
    }

    #[cfg(feature = "_test_hooks")]
    pub fn ctrl_cap(&self) -> usize {
        self.byte_cap.max(INBOUND_LANE_CTRL_FLOOR)
    }

    fn try_push(&mut self, item: LaneItem) -> LanePush {
        match &item {
            LaneItem::Data(d) if d.is_empty() => return LanePush::DroppedZero,
            LaneItem::ExtendedData { data, .. } if data.is_empty() => {
                return LanePush::DroppedZero
            }
            LaneItem::Eof if self.eof_queued => return LanePush::DroppedDup,
            LaneItem::Close if self.close_queued => return LanePush::DroppedDup,
            _ => {}
        }
        // Brief §4.2 / §0-A: `bytes ≤ byte_cap ∧ ctrl_bytes ≤
        // max(byte_cap, INBOUND_LANE_CTRL_FLOOR) ∧ items ≤ count_cap`.
        // Control payload is a separate ledger; it does not fold into
        // `bytes` (window `undelivered`). The floor keeps a single
        // transport-legal packet from overflowing a small-window lane.
        if self.items.len() >= self.count_cap {
            return LanePush::Overflow;
        }
        let control = matches!(
            item,
            LaneItem::Request { .. } | LaneItem::Success { .. } | LaneItem::Failure { .. }
        );
        if !control {
            let add = item.byte_len();
            if self.bytes.saturating_add(add) > self.byte_cap {
                return LanePush::Overflow;
            }
            self.bytes = self.bytes.saturating_add(add);
            self.data_items = self.data_items.saturating_add(1);
        } else {
            let add = match &item {
                LaneItem::Request { payload }
                | LaneItem::Success { payload }
                | LaneItem::Failure { payload } => payload.len(),
                _ => 0,
            };
            if self.ctrl_bytes.saturating_add(add) > self.byte_cap.max(INBOUND_LANE_CTRL_FLOOR) {
                return LanePush::Overflow;
            }
            self.ctrl_bytes += add;
        }
        self.eof_queued |= matches!(item, LaneItem::Eof);
        self.close_queued |= matches!(item, LaneItem::Close);
        self.items.push_back(item);
        LanePush::Accepted
    }

    fn pop(&mut self) -> Option<LaneItem> {
        let item = self.items.pop_front()?;
        let control = matches!(
            item,
            LaneItem::Request { .. } | LaneItem::Success { .. } | LaneItem::Failure { .. }
        );
        if !control {
            self.bytes = self.bytes.saturating_sub(item.byte_len());
            self.data_items = self.data_items.saturating_sub(1);
        } else {
            let add = match &item {
                LaneItem::Request { payload }
                | LaneItem::Success { payload }
                | LaneItem::Failure { payload } => payload.len(),
                _ => 0,
            };
            self.ctrl_bytes = self.ctrl_bytes.saturating_sub(add);
        }
        match &item {
            LaneItem::Eof => self.eof_queued = false,
            LaneItem::Close => self.close_queued = false,
            _ => {}
        }
        Some(item)
    }
}

#[derive(Debug, Default)]
pub struct LaneTable {
    lanes: HashMap<ChannelId, ChannelLane>,
    min_packet: usize,
    slack: usize,
    next_gen: u64,
    #[cfg(feature = "_test_hooks")]
    observe: Option<Arc<LaneObserveSlot>>,
}

impl LaneTable {
    pub fn new(min_packet: usize, slack: usize) -> Self {
        Self {
            lanes: HashMap::new(),
            min_packet: min_packet.max(1),
            slack,
            next_gen: 1,
            #[cfg(feature = "_test_hooks")]
            observe: None,
        }
    }

    #[cfg(feature = "_test_hooks")]
    pub fn set_observe(&mut self, slot: Arc<LaneObserveSlot>) {
        self.observe = Some(slot);
    }

    /// Unified pop exit: every `pop_any*` / `pop_channel` path goes here
    /// so `_test_hooks` occupancy and `lane_pops` see the pop, not delivery.
    fn take_pop(&mut self, id: ChannelId) -> Option<LaneItem> {
        let item = self.lanes.get_mut(&id)?.pop()?;
        #[cfg(feature = "_test_hooks")]
        if let Some(o) = &self.observe {
            o.note_lane_pop();
            o.set_occ(self.total_occupancy_bytes(), self.total_occupancy_count());
        }
        Some(item)
    }

    pub fn open(
        &mut self,
        id: ChannelId,
        _generation: u64,
        window: u32,
        max_packet: u32,
        confirmed: bool,
    ) {
        let generation = self.next_gen;
        self.next_gen = self.next_gen.saturating_add(1);
        self.lanes.insert(
            id,
            ChannelLane::new(
                generation,
                window,
                max_packet,
                self.min_packet,
                self.slack,
                confirmed,
            ),
        );
    }

    /// Mark a live lane established. No-op if the lane is gone.
    pub fn confirm(&mut self, id: ChannelId) {
        if let Some(lane) = self.lanes.get_mut(&id) {
            lane.confirmed = true;
        }
    }

    /// `None` = no lane. `Some(false)` = server-open, not yet confirmed.
    pub fn is_confirmed(&self, id: ChannelId) -> Option<bool> {
        self.lanes.get(&id).map(|l| l.confirmed)
    }

    pub fn close(&mut self, id: ChannelId, generation: u64) {
        if self.lanes.get(&id).is_some_and(|l| l.generation == generation || generation == 0) {
            self.lanes.remove(&id);
        }
    }

    pub fn try_push(&mut self, id: ChannelId, item: LaneItem) -> LanePush {
        let Some(lane) = self.lanes.get_mut(&id) else {
            return LanePush::NoLane;
        };
        let add = item.byte_len();
        let occ = lane.bytes;
        let cap = lane.byte_cap;
        let cnt = lane.items.len();
        let ccap = lane.count_cap;
        let win = lane.window_remaining;
        let ctrl = lane.ctrl_bytes;
        let r = lane.try_push(item);
        if r == LanePush::Overflow {
            let why = if cnt >= ccap {
                "count_cap"
            } else if occ.saturating_add(add) > cap {
                "byte_cap"
            } else {
                "ctrl_cap"
            };
            warn!(
                "inbound lane overflow id={id:?} why={why} add={add} occ_bytes={occ}/{cap} occ_count={cnt}/{ccap} window_remaining={win} ctrl_bytes={ctrl}"
            );
        }
        r
    }

    /// Reader ingest: consume the inbound window, then queue.
    ///
    /// DATA/EXT that exceeds `window_remaining` is ignored (RFC 4254 §5.2)
    /// and must not be queued. Queuing it let occupancy grow past
    /// `window + maxpkt` and StopDiscarded a live channel (OpenSSH soak
    /// upload close). Occupancy Overflow remains the DoS gate for a
    /// window-ignoring flood that is injected without going through here.
    pub fn ingest(&mut self, id: ChannelId, item: LaneItem) -> LanePush {
        match &item {
            LaneItem::Data(d) => {
                let n = d.len();
                let over = self
                    .window_remaining(id)
                    .is_some_and(|w| (n as u32) > w);
                if over {
                    warn!(
                        "inbound DATA exceeds remaining window id={id:?} len={n} remaining={} (ignored, not queued)",
                        self.window_remaining(id).unwrap_or(0)
                    );
                }
                self.consume_window(id, n);
                if over {
                    return LanePush::DroppedOverWindow;
                }
            }
            LaneItem::ExtendedData { data, .. } => {
                let n = data.len();
                let over = self
                    .window_remaining(id)
                    .is_some_and(|w| (n as u32) > w);
                if over {
                    warn!(
                        "inbound EXTDATA exceeds remaining window id={id:?} len={n} remaining={} (ignored, not queued)",
                        self.window_remaining(id).unwrap_or(0)
                    );
                }
                self.consume_window(id, n);
                if over {
                    return LanePush::DroppedOverWindow;
                }
            }
            _ => {}
        }
        self.try_push(id, item)
    }

    pub fn pop_any(&mut self) -> Option<(ChannelId, LaneItem)> {
        self.pop_any_except(&HashSet::new())
    }

    /// Like [`pop_any`], but do not pop **DATA/EXT** from `hold` lanes
    /// (OPEN callback still holds `Channel`). REQUEST/EOF/CLOSE stay
    /// FIFO-poppable: a data head on a held lane blocks that lane only.
    pub fn pop_any_except(&mut self, hold: &HashSet<ChannelId>) -> Option<(ChannelId, LaneItem)> {
        let id = self
            .lanes
            .iter()
            .find(|(id, l)| {
                !l.is_empty() && !(hold.contains(id) && l.head_is_payload_data())
            })
            .map(|(id, _)| *id)?;
        let item = self.take_pop(id)?;
        Some((id, item))
    }

    /// Pop REQUEST/EOF/CLOSE/SUCCESS/FAILURE only. Used when the
    /// Executor is full so want-reply can still be decided (Full →
    /// FAILURE) without taking DATA off the lane.
    pub fn pop_any_non_payload_except(
        &mut self,
        hold: &HashSet<ChannelId>,
    ) -> Option<(ChannelId, LaneItem)> {
        let id = self
            .lanes
            .iter()
            .find(|(id, l)| {
                !l.is_empty()
                    && !l.head_is_payload_data()
                    && !(hold.contains(id) && l.head_is_payload_data())
            })
            .map(|(id, _)| *id)?;
        let item = self.take_pop(id)?;
        Some((id, item))
    }

    /// Select a lane without popping.
    ///
    /// * `hold_data` — skip DATA/EXT when that is the head (OPEN callback
    ///   still holds `Channel`; REQUEST/EOF/CLOSE stay FIFO-poppable).
    /// * `hold_all` — skip the entire channel (app-buffer backpressure:
    ///   DATA/EXT/EOF/CLOSE stay in the lane until a permit arrives).
    /// * `non_payload_only` — Executor full: only REQUEST/EOF/CLOSE/SUCCESS/FAILURE.
    ///
    /// Union: a channel in both sets is skipped for every app-bound head
    /// (`hold_all`) and for DATA/EXT (`hold_data`). REQUEST on a
    /// `hold_all` channel is also skipped so we never pop past a parked
    /// backpressure wait.
    pub fn peek_gated(
        &self,
        hold_data: &HashSet<ChannelId>,
        hold_all: &HashSet<ChannelId>,
        non_payload_only: bool,
    ) -> Option<ChannelId> {
        self.lanes
            .iter()
            .find(|(id, l)| {
                if l.is_empty() {
                    return false;
                }
                if hold_all.contains(id) {
                    return false;
                }
                if non_payload_only && l.head_is_payload_data() {
                    return false;
                }
                !(hold_data.contains(id) && l.head_is_payload_data())
            })
            .map(|(id, _)| *id)
    }

    pub fn pop_channel(&mut self, id: ChannelId) -> Option<LaneItem> {
        self.take_pop(id)
    }

    pub fn close_queued(&self, id: ChannelId) -> bool {
        self.lanes.get(&id).is_some_and(|l| l.close_queued)
    }

    /// Channels whose lane already holds a peer CLOSE. Full-table filter
    /// each pump (O(live lanes), same order as `peek_gated`). An incremental
    /// close-queued set is P3 debt — not worth the extra state unless a
    /// profile shows a huge lane table.
    pub fn close_queued_ids(&self) -> Vec<ChannelId> {
        self.lanes
            .iter()
            .filter(|(_, l)| l.close_queued)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn head_needs_app(&self, id: ChannelId) -> bool {
        self.lanes.get(&id).is_some_and(|l| {
            matches!(
                l.items.front(),
                Some(LaneItem::Data(_))
                    | Some(LaneItem::ExtendedData { .. })
                    | Some(LaneItem::Eof)
                    | Some(LaneItem::Close)
            )
        })
    }

    pub fn occupancy_bytes(&self, id: ChannelId) -> usize {
        self.lanes.get(&id).map(|l| l.occupancy_bytes()).unwrap_or(0)
    }

    pub fn occupancy_count(&self, id: ChannelId) -> usize {
        self.lanes.get(&id).map(|l| l.occupancy_count()).unwrap_or(0)
    }

    pub fn total_occupancy_bytes(&self) -> usize {
        self.lanes.values().map(|l| l.occupancy_bytes()).sum()
    }

    pub fn total_occupancy_count(&self) -> usize {
        self.lanes.values().map(|l| l.occupancy_count()).sum()
    }

    pub fn has_ready(&self) -> bool {
        self.lanes.values().any(|l| !l.is_empty())
    }

    pub fn generation(&self, id: ChannelId) -> Option<u64> {
        self.lanes.get(&id).map(|l| l.generation)
    }

    pub fn window_remaining(&self, id: ChannelId) -> Option<u32> {
        self.lanes.get(&id).map(|l| l.window_remaining())
    }

    #[cfg(feature = "_test_hooks")]
    pub fn byte_cap(&self, id: ChannelId) -> Option<usize> {
        self.lanes.get(&id).map(|l| l.byte_cap())
    }

    #[cfg(feature = "_test_hooks")]
    pub fn count_cap(&self, id: ChannelId) -> Option<usize> {
        self.lanes.get(&id).map(|l| l.count_cap())
    }

    #[cfg(feature = "_test_hooks")]
    pub fn ctrl_occupancy_bytes(&self, id: ChannelId) -> usize {
        self.lanes.get(&id).map(|l| l.ctrl_bytes()).unwrap_or(0)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn ctrl_cap(&self, id: ChannelId) -> Option<usize> {
        self.lanes.get(&id).map(|l| l.ctrl_cap())
    }

    #[cfg(feature = "_test_hooks")]
    pub fn len(&self) -> usize {
        self.lanes.len()
    }

    /// I1 consume. No-op if the lane is gone (ghost channel).
    pub fn consume_window(&mut self, id: ChannelId, len: usize) {
        if let Some(lane) = self.lanes.get_mut(&id) {
            lane.consume_window(len);
        }
    }

    /// try_push ExpandInboundCap: lock-and-mutate, never await.
    /// Full cannot happen (shared table, not a queue).
    pub fn try_expand(&mut self, id: ChannelId, generation: u64, add: u32) -> ExpandCap {
        let Some(lane) = self.lanes.get_mut(&id) else {
            return ExpandCap::NoLane;
        };
        if generation != 0 && lane.generation != generation {
            return ExpandCap::GenMismatch;
        }
        lane.expand(add);
        ExpandCap::Expanded
    }

    /// Raise occupancy DoS bounds to cover `window`. Never shrinks.
    /// Never awaits.
    pub fn try_raise_occupancy(
        &mut self,
        id: ChannelId,
        generation: u64,
        window: u32,
        max_packet: u32,
    ) -> ExpandCap {
        let Some(lane) = self.lanes.get_mut(&id) else {
            return ExpandCap::NoLane;
        };
        if generation != 0 && lane.generation != generation {
            return ExpandCap::GenMismatch;
        }
        lane.raise_occupancy_to(window, max_packet, self.min_packet, self.slack);
        ExpandCap::Expanded
    }
}

/// In-flight ADJUST credit staging (merge of the old unbounded credit
/// queue). **Not** a third window book — never use this for window
/// decisions. Authority stays `ChannelLane::window_remaining` /
/// `recipient_window_size`. Memory is O(live channels + in-flight
/// teardowns). Reader filters unknown ids before `post`; a TOCTOU
/// (lane closed after the membership check, before `post`) can leave
/// at most O(in-flight teardowns) stale entries, which the next
/// loop-top `take_all` + established gate drops.
pub struct PeerCreditBoard {
    pending: Mutex<HashMap<ChannelId, u64>>,
    notify: Notify,
}

impl std::fmt::Debug for PeerCreditBoard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self
            .pending
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);
        f.debug_struct("PeerCreditBoard")
            .field("pending_len", &n)
            .finish()
    }
}

impl PeerCreditBoard {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        })
    }

    /// Merge `amount` for `id`. No await. HashMap growth under the
    /// lock is only for live channels + in-flight teardowns (unknown
    /// ids are filtered before `post`).
    pub fn post(&self, id: ChannelId, amount: u32) {
        if let Ok(mut g) = self.pending.lock() {
            g.entry(id)
                .and_modify(|v| *v = v.saturating_add(amount as u64))
                .or_insert(amount as u64);
        }
        self.notify.notify_one();
    }

    /// Drain the whole table (`std::mem::take`). Session applies at loop-top.
    pub fn take_all(&self) -> HashMap<ChannelId, u64> {
        self.pending
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    pub fn notify(&self) -> &Notify {
        &self.notify
    }

    #[cfg(feature = "_test_hooks")]
    pub fn len(&self) -> usize {
        self.pending.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Test counters for lane drops / overflow (`_test_hooks`).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct LaneObserveSlot {
    zero_byte_drops: AtomicU64,
    dup_drops: AtomicU64,
    unknown_drops: AtomicU64,
    overflows: AtomicU64,
    close_dropped: AtomicU64,
    last_bytes: std::sync::atomic::AtomicUsize,
    last_count: std::sync::atomic::AtomicUsize,
    last_byte_cap: std::sync::atomic::AtomicUsize,
    last_count_cap: std::sync::atomic::AtomicUsize,
    last_scheme: std::sync::atomic::AtomicUsize,
    /// Legacy Q8 overlap counter (Scheme C is gone; stays 0).
    overlap: AtomicU64,
    /// Q2: a DATA pop happened before a REQUEST pop (same Session pump era).
    data_pops: AtomicU64,
    /// Every lane pop (any `LaneItem`), counted at the table pop exit.
    lane_pops: AtomicU64,
    request_pops: AtomicU64,
    data_before_request: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl LaneObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn note_zero(&self) {
        self.zero_byte_drops.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_dup(&self) {
        self.dup_drops.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_unknown(&self) {
        self.unknown_drops.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_overflow(&self) {
        self.overflows.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_close_dropped(&self) {
        self.close_dropped.fetch_add(1, Ordering::SeqCst);
    }
    pub fn zero_byte_drops(&self) -> u64 {
        self.zero_byte_drops.load(Ordering::SeqCst)
    }
    pub fn dup_drops(&self) -> u64 {
        self.dup_drops.load(Ordering::SeqCst)
    }
    pub fn unknown_drops(&self) -> u64 {
        self.unknown_drops.load(Ordering::SeqCst)
    }
    pub fn overflows(&self) -> u64 {
        self.overflows.load(Ordering::SeqCst)
    }
    pub fn close_dropped(&self) -> u64 {
        self.close_dropped.load(Ordering::SeqCst)
    }
    pub fn set_occ(&self, bytes: usize, count: usize) {
        self.last_bytes.store(bytes, Ordering::SeqCst);
        self.last_count.store(count, Ordering::SeqCst);
    }
    pub fn set_caps(&self, byte_cap: usize, count_cap: usize) {
        self.last_byte_cap.store(byte_cap, Ordering::SeqCst);
        self.last_count_cap.store(count_cap, Ordering::SeqCst);
    }
    pub fn last_byte_cap(&self) -> usize {
        self.last_byte_cap.load(Ordering::SeqCst)
    }
    pub fn last_count_cap(&self) -> usize {
        self.last_count_cap.load(Ordering::SeqCst)
    }
    pub fn last_bytes(&self) -> usize {
        self.last_bytes.load(Ordering::SeqCst)
    }
    pub fn last_count(&self) -> usize {
        self.last_count.load(Ordering::SeqCst)
    }
    pub fn note_overlap(&self) {
        self.overlap.fetch_add(1, Ordering::SeqCst);
    }
    pub fn note_pop_data(&self) {
        self.data_pops.fetch_add(1, Ordering::SeqCst);
        if self.request_pops.load(Ordering::SeqCst) == 0 {
            self.data_before_request.store(1, Ordering::SeqCst);
        }
    }
    pub fn note_pop_request(&self) {
        self.request_pops.fetch_add(1, Ordering::SeqCst);
    }
    pub fn data_pops(&self) -> u64 {
        self.data_pops.load(Ordering::SeqCst)
    }
    pub fn note_lane_pop(&self) {
        self.lane_pops.fetch_add(1, Ordering::SeqCst);
    }
    pub fn lane_pops(&self) -> u64 {
        self.lane_pops.load(Ordering::SeqCst)
    }
    pub fn data_before_request(&self) -> bool {
        self.data_before_request.load(Ordering::SeqCst) != 0
    }
    pub fn overlap(&self) -> u64 {
        self.overlap.load(Ordering::SeqCst)
    }
    pub fn last_scheme(&self) -> usize {
        self.last_scheme.load(Ordering::SeqCst)
    }
    pub fn set_scheme(&self, n: usize) {
        self.last_scheme.store(n, Ordering::SeqCst);
    }
    /// Pump-hold snapshot: Scheme C is gone, so `scheme_c` is always 0.
    pub fn note_split(&self, lane: usize, scheme_c: usize) {
        self.last_scheme.store(scheme_c, Ordering::SeqCst);
        if lane > 0 && scheme_c > 0 {
            self.note_overlap();
        }
    }
}

/// S3c grant-order / ADJUST-bypass observation (`_test_hooks`).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct WindowObserveSlot {
    adjust_bypass: AtomicU64,
    /// Well-formed ADJUST whose id is not in the lane table (dropped
    /// at Reader before `PeerCreditBoard::post`).
    unknown_adjust: AtomicU64,
    /// Well-formed ADJUST for a live but unconfirmed (server-open)
    /// lane. Routed to ctrl so it stays behind `OPEN_CONFIRMATION`.
    unconfirmed_adjust: AtomicU64,
    /// Last id passed to `register_inbound_lane` / `open_lane`.
    last_lane_open: AtomicU32,
    /// Shadow of live lane ids → confirmed *at open time*. Updated on
    /// open/close only; production `confirm_lane` does NOT flip this
    /// shadow. Tests needing the real confirmed state must read
    /// `ReaderHandle::is_confirmed` (real `LaneTable`), not this.
    live: Mutex<HashMap<u32, bool>>,
    /// Last snapshot of `ReaderHandle::lane_count()`.
    lane_count: AtomicU64,
    expand_ok: AtomicU64,
    expand_fail: AtomicU64,
    /// Monotonic ticket taken at cap expand.
    cap_expanded_seq: AtomicU64,
    /// Monotonic ticket taken when ADJUST is written into `enc.write`.
    adjust_emitted_seq: AtomicU64,
    /// Monotonic ticket taken when global inbound credit is reserved
    /// on the grant path (S4d G4). Same `seq` space as expand/ADJUST.
    global_reserve_seq: AtomicU64,
    last_reserved_delta: AtomicU32,
    last_expand_delta: AtomicU32,
    last_adjust_delta: AtomicU32,
    seq: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl WindowObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn note_adjust_bypass(&self) {
        self.adjust_bypass.fetch_add(1, Ordering::SeqCst);
    }
    pub fn adjust_bypass(&self) -> u64 {
        self.adjust_bypass.load(Ordering::SeqCst)
    }
    pub fn note_unknown_adjust(&self) {
        self.unknown_adjust.fetch_add(1, Ordering::SeqCst);
    }
    pub fn unknown_adjust(&self) -> u64 {
        self.unknown_adjust.load(Ordering::SeqCst)
    }
    pub fn note_unconfirmed_adjust(&self) {
        self.unconfirmed_adjust.fetch_add(1, Ordering::SeqCst);
    }
    pub fn unconfirmed_adjust(&self) -> u64 {
        self.unconfirmed_adjust.load(Ordering::SeqCst)
    }
    pub fn note_lane_open(&self, id: u32, confirmed: bool) {
        self.last_lane_open.store(id, Ordering::SeqCst);
        if let Ok(mut g) = self.live.lock() {
            g.insert(id, confirmed);
        }
    }
    pub fn last_lane_open(&self) -> u32 {
        self.last_lane_open.load(Ordering::SeqCst)
    }
    pub fn note_lane_close(&self, id: u32) {
        if let Ok(mut g) = self.live.lock() {
            g.remove(&id);
        }
    }
    /// `None` = not a member. `Some(false)` = unconfirmed server-open.
    pub fn is_confirmed(&self, id: u32) -> Option<bool> {
        self.live.lock().ok().and_then(|g| g.get(&id).copied())
    }
    pub fn lane_has(&self, id: u32) -> bool {
        self.is_confirmed(id).is_some()
    }
    pub fn set_lane_count(&self, n: usize) {
        self.lane_count.store(n as u64, Ordering::SeqCst);
    }
    pub fn lane_count(&self) -> usize {
        self.lane_count.load(Ordering::SeqCst) as usize
    }
    pub fn note_expand_ok(&self) {
        self.expand_ok.fetch_add(1, Ordering::SeqCst);
        let n = self.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.cap_expanded_seq.store(n, Ordering::SeqCst);
    }
    pub fn note_expand_fail(&self) {
        self.expand_fail.fetch_add(1, Ordering::SeqCst);
    }
    pub fn expand_ok(&self) -> u64 {
        self.expand_ok.load(Ordering::SeqCst)
    }
    pub fn expand_fail(&self) -> u64 {
        self.expand_fail.load(Ordering::SeqCst)
    }
    pub fn note_adjust_emitted(&self) {
        let n = self.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.adjust_emitted_seq.store(n, Ordering::SeqCst);
    }
    pub fn note_global_reserve(&self) {
        let n = self.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.global_reserve_seq.store(n, Ordering::SeqCst);
    }
    pub fn cap_expanded_seq(&self) -> u64 {
        self.cap_expanded_seq.load(Ordering::SeqCst)
    }
    pub fn adjust_emitted_seq(&self) -> u64 {
        self.adjust_emitted_seq.load(Ordering::SeqCst)
    }
    pub fn global_reserve_seq(&self) -> u64 {
        self.global_reserve_seq.load(Ordering::SeqCst)
    }
    pub fn note_reserved_delta(&self, n: u32) {
        self.last_reserved_delta.store(n, Ordering::SeqCst);
    }
    pub fn note_expand_delta(&self, n: u32) {
        self.last_expand_delta.store(n, Ordering::SeqCst);
    }
    pub fn note_adjust_delta(&self, n: u32) {
        self.last_adjust_delta.store(n, Ordering::SeqCst);
    }
    pub fn last_reserved_delta(&self) -> u32 {
        self.last_reserved_delta.load(Ordering::SeqCst)
    }
    pub fn last_expand_delta(&self) -> u32 {
        self.last_expand_delta.load(Ordering::SeqCst)
    }
    pub fn last_adjust_delta(&self) -> u32 {
        self.last_adjust_delta.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelId;

    #[test]
    fn f1_control_payload_bounded_by_byte_cap() {
        let mut t = LaneTable::new(8, 32);
        let id = ChannelId(1);
        t.open(id, 0, 2 * 1024 * 1024, 32768, true);

        let large = || LaneItem::Request {
            payload: Bytes::from(vec![0u8; 256 * 1024]),
        };
        let mut overflow_at = None;
        for i in 0..300 {
            match t.try_push(id, large()) {
                LanePush::Accepted => {}
                LanePush::Overflow => {
                    overflow_at = Some(i);
                    break;
                }
                other => panic!("unexpected push result {other:?} at {i}"),
            }
        }
        let idx = overflow_at.expect("loop of 300 must Overflow before count_cap");
        assert!(
            idx <= 9,
            "first Overflow at index {idx}, want ≤ 9 (byte_cap = 2 MiB + 32 KiB)"
        );
        let accepted = idx;
        assert_eq!(t.occupancy_bytes(id), 0);
        assert_eq!(t.occupancy_count(id), accepted);
        #[cfg(feature = "_test_hooks")]
        assert_eq!(t.ctrl_occupancy_bytes(id), accepted * 256 * 1024);

        // Count vs byte independence: 4-byte (id-only) Request still
        // fits the leftover 32 KiB; another 256 KiB does not.
        let tiny = LaneItem::Request {
            payload: Bytes::from(vec![0u8; 4]),
        };
        assert_eq!(t.try_push(id, tiny), LanePush::Accepted);
        assert_eq!(t.try_push(id, large()), LanePush::Overflow);

        while t.pop_channel(id).is_some() {}
        assert_eq!(t.try_push(id, large()), LanePush::Accepted);
    }

    #[test]
    fn f1b_control_floor_independent_of_small_window() {
        let mut t = LaneTable::new(8, 32);
        let id = ChannelId(1);
        t.open(id, 0, 1024, 1024, true);

        let first = LaneItem::Request {
            payload: Bytes::from(vec![0u8; 200 * 1024]),
        };
        assert_eq!(t.try_push(id, first), LanePush::Accepted);
        assert_eq!(t.occupancy_bytes(id), 0);

        let chunk = 32 * 1024;
        let mut accepted = 200 * 1024;
        let mut overflowed = false;
        for i in 0..32 {
            match t.try_push(
                id,
                LaneItem::Request {
                    payload: Bytes::from(vec![0u8; chunk]),
                },
            ) {
                LanePush::Accepted => {
                    accepted += chunk;
                    assert_eq!(t.occupancy_bytes(id), 0, "data occupancy leaked at {i}");
                }
                LanePush::Overflow => {
                    overflowed = true;
                    break;
                }
                other => panic!("unexpected push result {other:?} at {i}"),
            }
        }
        assert!(overflowed, "32 KiB Requests must Overflow at the control floor");
        assert!(
            accepted <= INBOUND_LANE_CTRL_FLOOR,
            "accepted control bytes {accepted} exceed floor {INBOUND_LANE_CTRL_FLOOR}"
        );
        assert!(
            INBOUND_LANE_CTRL_FLOOR - accepted < chunk,
            "leftover {} ≥ 32 KiB — Overflow too late",
            INBOUND_LANE_CTRL_FLOOR - accepted
        );
        assert_eq!(t.occupancy_bytes(id), 0);

        #[cfg(feature = "_test_hooks")]
        {
            assert_eq!(t.ctrl_cap(id), Some(INBOUND_LANE_CTRL_FLOOR));
            assert_eq!(t.ctrl_occupancy_bytes(id), accepted);
        }

        // Data bound is still byte_cap = 2 KiB; the floor does not leak.
        let data = LaneItem::Data(Bytes::from(vec![0u8; 4 * 1024]));
        assert_eq!(t.try_push(id, data), LanePush::Overflow);
    }

    /// Over-window DATA must not be queued. The old path consumed nothing
    /// (len > remaining) then still `try_push`ed, so occupancy grew past
    /// `window + maxpkt` and Overflow-closed a live channel.
    #[test]
    fn over_window_data_is_ignored_not_queued() {
        let mut t = LaneTable::new(8, 32);
        let id = ChannelId(1);
        t.open(id, 0, 100, 50, true);

        assert_eq!(
            t.ingest(id, LaneItem::Data(Bytes::from(vec![0u8; 100]))),
            LanePush::Accepted
        );
        assert_eq!(t.window_remaining(id), Some(0));
        assert_eq!(t.occupancy_bytes(id), 100);

        assert_eq!(
            t.ingest(id, LaneItem::Data(Bytes::from(vec![0u8; 50]))),
            LanePush::DroppedOverWindow
        );
        assert_eq!(t.window_remaining(id), Some(0));
        assert_eq!(t.occupancy_bytes(id), 100);
        assert_eq!(t.occupancy_count(id), 1);

        // Direct try_push (Q5 inject, no ingest) still Overflows at the cap.
        assert_eq!(
            t.try_push(id, LaneItem::Data(Bytes::from(vec![0u8; 51]))),
            LanePush::Overflow
        );
    }
}

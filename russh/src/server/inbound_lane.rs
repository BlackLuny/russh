//! S3b per-channel inbound lane: dual-bound FIFO of decrypted channel messages.
//!
//! This is **not** Scheme C (`pending_inbound`). Occupancy here and Scheme C
//! `pending_bytes` are mutually exclusive: Session pops an item, then
//! `deliver_inbound`. Grant `undelivered` must sum both.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Notify;

use crate::ChannelId;

/// Extra zero-byte / REQUEST slots beyond `window / min_packet`.
pub const INBOUND_LANE_COUNT_SLACK: usize = 32;
/// Default smallest packet used for the count bound.
pub const INBOUND_LANE_MIN_PACKET: usize = 8;
/// Ctrl byte budget (kex / OPEN / GLOBAL / ADJUST / unknown). Full → Cancelling.
pub const INBOUND_CTRL_BUDGET: usize = 2 * 1024 * 1024;

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

#[derive(Debug)]
pub struct ChannelLane {
    pub generation: u64,
    items: VecDeque<LaneItem>,
    bytes: usize,
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
        // Config contract: denominator is `min(8, configured).max(1)`.
        let min_p = min_packet.min(8).max(1);
        // Occupancy DoS bound (this slice), not granted-window authority
        // (S3c). Extra data beyond the advertised window is ignored per
        // RFC 4254 §5.2 / `consume_recv_window`; this cap only stops
        // Reader RAM from growing without bound.
        let byte_cap = (granted_window as usize).saturating_add(max_packet as usize);
        let count_cap = (granted_window as usize / min_p).saturating_add(slack);
        Self {
            generation,
            items: VecDeque::new(),
            bytes: 0,
            byte_cap,
            count_cap: count_cap.max(1),
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
    /// is ignored (RFC 4254 §5.2) — occupancy Overflow is a different gate.
    fn consume_window(&mut self, len: usize) {
        let n = len as u32;
        if n <= self.window_remaining {
            self.window_remaining -= n;
        }
    }

    /// Grant only tops up the inbound-window ledger. Occupancy bounds
    /// (`byte_cap` / `count_cap`) are construction-time constants
    /// (`granted_window + maxpkt`, `window/min(8)+K`) — a compliant
    /// peer satisfies `lane_bytes + window_remaining ≤ target`, so
    /// raising the DoS cap on each grant would let RAM grow without bound.
    fn expand(&mut self, add: u32) {
        self.window_remaining = self.window_remaining.saturating_add(add);
    }

    #[cfg(feature = "_test_hooks")]
    pub fn byte_cap(&self) -> usize {
        self.byte_cap
    }

    #[cfg(feature = "_test_hooks")]
    pub fn count_cap(&self) -> usize {
        self.count_cap
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
        // Brief §4.2: count_cap covers DATA/EXT/EOF/CLOSE/REQUEST (and
        // SUCCESS/FAILURE). 0-byte control still skips the byte cap.
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
}

impl LaneTable {
    pub fn new(min_packet: usize, slack: usize) -> Self {
        Self {
            lanes: HashMap::new(),
            min_packet: min_packet.max(1),
            slack,
            next_gen: 1,
        }
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
        lane.try_push(item)
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
        let item = self.lanes.get_mut(&id)?.pop()?;
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
        let item = self.lanes.get_mut(&id)?.pop()?;
        Some((id, item))
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
    /// Seen both lane and Scheme C occupancy for the same snapshot (Q8).
    overlap: AtomicU64,
    /// Q2: a DATA pop happened before a REQUEST pop (same Session pump era).
    data_pops: AtomicU64,
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
    /// Pump-hold snapshot: the same payload must not sit in both
    /// the Reader lane and Scheme C.
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
    pub fn cap_expanded_seq(&self) -> u64 {
        self.cap_expanded_seq.load(Ordering::SeqCst)
    }
    pub fn adjust_emitted_seq(&self) -> u64 {
        self.adjust_emitted_seq.load(Ordering::SeqCst)
    }
}

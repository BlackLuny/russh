//! S3b per-channel inbound lane: dual-bound FIFO of decrypted channel messages.
//!
//! This is **not** Scheme C (`pending_inbound`). Occupancy here and Scheme C
//! `pending_bytes` are mutually exclusive: Session pops an item, then
//! `deliver_inbound`. Grant `undelivered` must sum both.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "_test_hooks")]
use std::sync::Arc;

use bytes::Bytes;

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

#[derive(Debug)]
pub struct ChannelLane {
    pub generation: u64,
    items: VecDeque<LaneItem>,
    bytes: usize,
    byte_cap: usize,
    count_cap: usize,
    eof_queued: bool,
    close_queued: bool,
    data_items: usize,
}

impl ChannelLane {
    pub fn new(generation: u64, granted_window: u32, max_packet: u32, min_packet: usize, slack: usize) -> Self {
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
            eof_queued: false,
            close_queued: false,
            data_items: 0,
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

    pub fn open(&mut self, id: ChannelId, _generation: u64, window: u32, max_packet: u32) {
        let generation = self.next_gen;
        self.next_gen = self.next_gen.saturating_add(1);
        self.lanes.insert(
            id,
            ChannelLane::new(generation, window, max_packet, self.min_packet, self.slack),
        );
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
        let id = self.lanes.iter().find(|(_, l)| !l.is_empty()).map(|(id, _)| *id)?;
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
    last_scheme: std::sync::atomic::AtomicUsize,
    /// Seen both lane and Scheme C occupancy for the same snapshot (Q8).
    overlap: AtomicU64,
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
    pub fn last_bytes(&self) -> usize {
        self.last_bytes.load(Ordering::SeqCst)
    }
    pub fn last_count(&self) -> usize {
        self.last_count.load(Ordering::SeqCst)
    }
    pub fn note_overlap(&self) {
        self.overlap.fetch_add(1, Ordering::SeqCst);
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

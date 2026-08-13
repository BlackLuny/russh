//! ConnSupervisor (S1): write-progress watchdog + rekey/handshake deadlines
//! integrated into the existing single-task server session loop.
//!
//! Spec: rewrite plan §4.2. Full Reader/Session/Writer task split is S2/S3 —
//! this module only supplies the supervision state machine and timers that the
//! current `select!` loop polls.

use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh_util::time::Instant;

/// Why the supervisor tore down a connection. First cause wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectCause {
    /// Write path armed with wire-eligible bytes made no progress in time
    /// (activity layer or write_min_drain strategy layer).
    WriteStalled = 1,
    /// Rekey (InKex) did not complete before rekey_deadline.
    RekeyTimeout = 2,
    /// Banner / initial kex / auth did not finish before handshake_deadline.
    HandshakeTimeout = 3,
    /// Underlying peer/session error (not a supervisor deadline).
    PeerError = 4,
    /// Explicit local disconnect / clean shutdown.
    LocalShutdown = 5,
}

impl DisconnectCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::WriteStalled),
            2 => Some(Self::RekeyTimeout),
            3 => Some(Self::HandshakeTimeout),
            4 => Some(Self::PeerError),
            5 => Some(Self::LocalShutdown),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Test/harness slot: first cause is stored once (compare-and-swap style).
#[derive(Debug, Default)]
pub struct DisconnectCauseSlot {
    raw: AtomicU8,
}

impl DisconnectCauseSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            raw: AtomicU8::new(0),
        })
    }

    /// Record first cause; later calls are ignored.
    pub fn record(&self, cause: DisconnectCause) {
        let _ = self
            .raw
            .compare_exchange(0, cause.as_u8(), Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn get(&self) -> Option<DisconnectCause> {
        DisconnectCause::from_u8(self.raw.load(Ordering::SeqCst))
    }

    pub fn clear(&self) {
        self.raw.store(0, Ordering::SeqCst);
    }
}

/// Test-only gate: hold Session processing of Writer `InstallAckOutbound` events
/// until [`InstallAckHoldGate::release`]. Used by S2b-1 Done-before-ACK regressions
/// so inbound cutover at peer NEWKEYS is observable while completion still waits.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct InstallAckHoldGate {
    held: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

#[cfg(feature = "_test_hooks")]
impl InstallAckHoldGate {
    pub fn new_held() -> Arc<Self> {
        Arc::new(Self {
            held: std::sync::atomic::AtomicBool::new(true),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub fn is_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Re-arm the hold after a prior [`release`] (e.g. hold only across rekey).
    pub fn hold_again(&self) {
        self.held.store(true, Ordering::SeqCst);
    }

    /// Wait until the gate is released (cancel-safe).
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

/// Test-only: counts how many times Session entered `NeedSubmit` for KEX install.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct NeedSubmitSeenSlot {
    count: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl NeedSubmitSeenSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn mark(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

/// Test-only: observe pending KEX install phase + non-Idle flag (Session run-loop).
///
/// Phase codes: 0=none, 1=NeedSubmit, 2=WaitingAck, 3=InstallAcked.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct KexInstallObserveSlot {
    phase: AtomicU8,
    non_idle: std::sync::atomic::AtomicBool,
    /// Peer Done merged into the open transaction (`after.is_some()`).
    after_known: std::sync::atomic::AtomicBool,
    data_while_pending: AtomicU64,
    /// Inbound packets successfully handled by `reply()` while an install
    /// transaction was still open (R1 aggregated-write proof).
    packets_while_pending: AtomicU64,
    /// Inbound cipher commits at peer Done (`commit_rekey_inbound` /
    /// `commit_initial_encrypted`).
    inbound_commits: AtomicU64,
    /// Completion effects applied (`apply_kex_after_install`: Idle/deadline/
    /// flush_all_pending/ext-info).
    completions: AtomicU64,
    /// Packets re-entered through `replay_pending_reads`.
    replays: AtomicU64,
    /// `clear_rekey_deadline` calls.
    deadline_clears: AtomicU64,
    /// Peer KEXINITs parked via `park_pending_read`.
    parks: AtomicU64,
    /// S3a: inbound InstallAck received for the open transaction.
    inbound_acked: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "_test_hooks")]
impl KexInstallObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_phase(&self, phase: u8) {
        self.phase.store(phase, Ordering::SeqCst);
    }

    pub fn phase(&self) -> u8 {
        self.phase.load(Ordering::SeqCst)
    }

    pub fn set_non_idle(&self, v: bool) {
        self.non_idle.store(v, Ordering::SeqCst);
    }

    pub fn non_idle(&self) -> bool {
        self.non_idle.load(Ordering::SeqCst)
    }

    pub fn set_after_known(&self, v: bool) {
        self.after_known.store(v, Ordering::SeqCst);
    }

    pub fn after_known(&self) -> bool {
        self.after_known.load(Ordering::SeqCst)
    }

    pub fn mark_data_while_pending(&self, n: u64) {
        if self.phase.load(Ordering::SeqCst) != 0 {
            self.data_while_pending.fetch_add(n, Ordering::SeqCst);
        }
    }

    pub fn data_while_pending(&self) -> u64 {
        self.data_while_pending.load(Ordering::SeqCst)
    }

    pub fn mark_packet_while_pending(&self) {
        self.packets_while_pending.fetch_add(1, Ordering::SeqCst);
    }

    pub fn packets_while_pending(&self) -> u64 {
        self.packets_while_pending.load(Ordering::SeqCst)
    }

    pub fn mark_inbound_commit(&self) {
        self.inbound_commits.fetch_add(1, Ordering::SeqCst);
    }

    pub fn inbound_commits(&self) -> u64 {
        self.inbound_commits.load(Ordering::SeqCst)
    }

    pub fn mark_completion(&self) {
        self.completions.fetch_add(1, Ordering::SeqCst);
    }

    pub fn completions(&self) -> u64 {
        self.completions.load(Ordering::SeqCst)
    }

    pub fn mark_replay(&self) {
        self.replays.fetch_add(1, Ordering::SeqCst);
    }

    pub fn replays(&self) -> u64 {
        self.replays.load(Ordering::SeqCst)
    }

    pub fn mark_deadline_clear(&self) {
        self.deadline_clears.fetch_add(1, Ordering::SeqCst);
    }

    pub fn deadline_clears(&self) -> u64 {
        self.deadline_clears.load(Ordering::SeqCst)
    }

    pub fn mark_park(&self) {
        self.parks.fetch_add(1, Ordering::SeqCst);
    }

    pub fn parks(&self) -> u64 {
        self.parks.load(Ordering::SeqCst)
    }

    pub fn set_inbound_acked(&self, v: bool) {
        self.inbound_acked.store(v, Ordering::SeqCst);
    }

    pub fn inbound_acked(&self) -> bool {
        self.inbound_acked.load(Ordering::SeqCst)
    }
}

/// Test-only: R3 liveness chain counters — dequeue notify → real Session
/// capacity select arm → pending KEX install advance (phase 1→2/3).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct CapacityChainSlot {
    dequeue_notifies: AtomicU64,
    arm_runs: AtomicU64,
    install_advances: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl CapacityChainSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Writer dequeued a bulk cmd (mpsc slot freed) and fired `notify_one`.
    pub fn mark_dequeue_notify(&self) {
        self.dequeue_notifies.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dequeue_notifies(&self) -> u64 {
        self.dequeue_notifies.load(Ordering::SeqCst)
    }

    /// Session capacity select arm (`session.rs` capacity_notify arm) ran.
    pub fn mark_arm_run(&self) {
        self.arm_runs.fetch_add(1, Ordering::SeqCst);
    }

    pub fn arm_runs(&self) -> u64 {
        self.arm_runs.load(Ordering::SeqCst)
    }

    /// The capacity arm moved the pending install out of NeedSubmit.
    pub fn mark_install_advance(&self) {
        self.install_advances.fetch_add(1, Ordering::SeqCst);
    }

    pub fn install_advances(&self) -> u64 {
        self.install_advances.load(Ordering::SeqCst)
    }
}

/// Test-only: linearized full-pipeline reservation ledger.
///
/// A **single** `total` atomic is the source of truth for the process-wide
/// max. The four component atomics stay as diagnostics. Cross-stage transfers
/// (`enc.write` → Writer, KEX NeedSubmit → Writer, Writer Full → Session
/// pending) adjust components in opposite directions and leave `total`
/// unchanged, so a torn 4-way load can no longer invent a peak.
///
/// The F1 `HWM+allow+97` failures were exactly that torn load: Writer already
/// held a newly accepted packet while the `enc_write` mirror still included
/// its per-packet reservation (`CHANNEL_DATA` framing 9 + WIRE_OH 88 = 97).
#[cfg(feature = "_test_hooks")]
#[derive(Debug)]
pub struct FullLedger {
    pub writer_pending: Arc<std::sync::atomic::AtomicUsize>,
    pub session_pending: Arc<std::sync::atomic::AtomicUsize>,
    pub kex_need: Arc<std::sync::atomic::AtomicUsize>,
    pub enc_write: Arc<std::sync::atomic::AtomicUsize>,
    /// Linearized reservation sum. `fetch_max` / observe go through this.
    total: std::sync::atomic::AtomicUsize,
    /// Linearized kex identity: parked NeedSubmit **or** Writer-accepted
    /// SealBatch reservation not yet drained. Updated at the same call
    /// sites as `total`, never reconstructed from racy component loads.
    ///
    /// Premise: at most one kex batch in flight (`pending_kex_install` is
    /// unique). Transfer `set_kex_need(0)` then `credit_kex` is a debit+credit
    /// of the same weight, so `kex_live` and non-kex stay conserved. Direct
    /// accept (NeedSubmit never published) only hits `credit_kex`.
    ///
    /// Conservation direction (so `total - kex_live` never overestimates
    /// non-kex except at instruction-width tear): credit kex → bump
    /// `kex_live` first, then `total`; debit kex → drop `total` first,
    /// then `kex_live`. Concurrent samples can only *under*-count non-kex.
    /// Drain identity is **not** inferred from those atomics: the Writer
    /// task owns a sealed-segment FIFO `(wire_len, is_kex)`, so a physical
    /// `[A][K][B]` partial drain of `A+K` retires K and leaves B as
    /// non-kex for the rest of B's lifetime.
    kex_live: std::sync::atomic::AtomicUsize,
    /// Remaining kex reservation/wire inside Writer. Position lives in the
    /// Writer-task segment queue, not here.
    kex_in_writer: std::sync::atomic::AtomicUsize,
    pub slot: Arc<LedgerMaxSlot>,
}

#[cfg(feature = "_test_hooks")]
impl FullLedger {
    pub fn new(
        writer_pending: Arc<std::sync::atomic::AtomicUsize>,
        session_pending: Arc<std::sync::atomic::AtomicUsize>,
        slot: Arc<LedgerMaxSlot>,
    ) -> Self {
        Self {
            writer_pending,
            session_pending,
            kex_need: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            enc_write: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            total: std::sync::atomic::AtomicUsize::new(0),
            kex_live: std::sync::atomic::AtomicUsize::new(0),
            kex_in_writer: std::sync::atomic::AtomicUsize::new(0),
            slot,
        }
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// Credit newly accepted **non-kex** reservation (DATA / control / enc.write).
    pub fn credit(&self, n: usize) {
        if n == 0 {
            return;
        }
        let now = self.total.fetch_add(n, Ordering::AcqRel).saturating_add(n);
        let kex = self.kex_live.load(Ordering::Acquire);
        self.observe_now(now, kex);
    }

    /// Debit **non-kex** reservation that left the pipeline.
    pub fn debit(&self, n: usize) {
        if n == 0 {
            return;
        }
        match self.sub_total(n) {
            Some(now) => {
                let kex = self.kex_live.load(Ordering::Acquire);
                self.observe_now(now, kex);
            }
            None => self.observe_now(0, 0),
        }
    }

    /// Credit a kex batch (parked NeedSubmit growth **or** Writer SealBatch
    /// accept). Pushes `kex_peak`. Non-kex is unchanged.
    pub fn credit_kex(&self, n: usize) {
        if n == 0 {
            return;
        }
        // kex_live first so a torn concurrent sample cannot treat the new
        // bytes as non-kex (`total` still old → non-kex underestimates).
        let kex = self.kex_live.fetch_add(n, Ordering::AcqRel).saturating_add(n);
        let now = self.total.fetch_add(n, Ordering::AcqRel).saturating_add(n);
        self.slot.note_kex_need(kex);
        self.observe_now(now, kex);
    }

    /// Debit a kex batch (NeedSubmit transfer-out, SealBatch rollback, kex
    /// seal shrink, or FIFO drain of kex writer bytes).
    pub fn debit_kex(&self, n: usize) {
        if n == 0 {
            return;
        }
        let now = self.sub_total(n);
        let kex = match self.kex_live.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |cur| cur.checked_sub(n),
        ) {
            Ok(old) => old.saturating_sub(n),
            Err(_) => {
                self.slot.note_mismatch();
                self.kex_live.store(0, Ordering::Release);
                0
            }
        };
        self.observe_now(now.unwrap_or(0), kex);
    }

    /// Writer accepted a SealBatch: kex identity enters `pending_bytes`.
    pub fn credit_kex_to_writer(&self, n: usize) {
        if n == 0 {
            return;
        }
        self.kex_in_writer.fetch_add(n, Ordering::AcqRel);
        self.credit_kex(n);
    }

    /// Kex reservation left Writer (rollback / seal shrink / FIFO drain).
    pub fn debit_kex_from_writer(&self, n: usize) {
        if n == 0 {
            return;
        }
        if self
            .kex_in_writer
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| cur.checked_sub(n))
            .is_err()
        {
            self.slot.note_mismatch();
            self.kex_in_writer.store(0, Ordering::Release);
        }
        self.debit_kex(n);
    }

    pub fn kex_in_writer(&self) -> usize {
        self.kex_in_writer.load(Ordering::Acquire)
    }

    fn sub_total(&self, n: usize) -> Option<usize> {
        match self.total.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |cur| cur.checked_sub(n),
        ) {
            Ok(old) => Some(old.saturating_sub(n)),
            Err(_) => {
                self.slot.note_mismatch();
                self.total.store(0, Ordering::Release);
                None
            }
        }
    }

    /// `enc.write` reservation. Growth is intake; shrink + Writer accept
    /// (after cursor advance) is a conservation transfer.
    pub fn set_enc_write(&self, new: usize) {
        let old = self.enc_write.swap(new, Ordering::AcqRel);
        if new > old {
            self.credit(new - old);
        } else if old > new {
            self.debit(old - new);
        }
    }

    /// Parked NeedSubmit mirror. Growth is kex intake; shrink is a transfer
    /// out of the NeedSubmit component (Writer `credit_kex_to_writer` follows
    /// on the success path). Direct accept never publishes a non-zero value
    /// here — that path only hits `credit_kex_to_writer`.
    pub fn set_kex_need(&self, new: usize) {
        let old = self.kex_need.swap(new, Ordering::AcqRel);
        if new > old {
            self.credit_kex(new - old);
        } else if old > new {
            self.debit_kex(old - new);
        }
    }

    /// Sample `total` and linearized `kex_live` after both atomics have been
    /// updated. Parts remain diagnostic (racy 4-way load). Peaks use the
    /// values computed in this call, not `total - parts[2]`.
    fn observe_now(&self, total: usize, kex_live: usize) {
        let parts = [
            self.writer_pending.load(Ordering::Acquire),
            self.session_pending.load(Ordering::Acquire),
            self.kex_need.load(Ordering::Acquire),
            self.enc_write.load(Ordering::Acquire),
        ];
        self.slot.observe_parts(total, parts);
        self.slot.observe_linearized(total, kex_live);
    }

    pub fn kex_live(&self) -> usize {
        self.kex_live.load(Ordering::Acquire)
    }

    /// Diagnostic only — do **not** use for max. Prefer [`Self::credit`]/
    /// [`Self::debit`] / [`Self::set_enc_write`] / [`Self::set_kex_need`].
    pub fn sample(&self) {
        self.observe_now(self.total(), self.kex_live());
    }
}

/// Test-only: process-wide max of `sealed_backlog_bytes` (atomic watermark).
///
/// Also carries the ledger-integrity counters: `mismatch` counts every failed
/// checked subtraction (must stay 0 — a non-zero value is an observable ledger
/// bug), `full_hits` counts **real** bulk-queue Full events (R4 proof that the
/// flood really pressed the Writer queue to Full).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct LedgerMaxSlot {
    max: std::sync::atomic::AtomicUsize,
    /// Component snapshot `[writer, session_pending, kex_need, enc_write]` taken
    /// by the sample that set `max` — diagnostic for upper-bound violations.
    parts: [std::sync::atomic::AtomicUsize; 4],
    mismatch: AtomicU64,
    full_hits: AtomicU64,
    intake_blocks: AtomicU64,
    /// Peak linearized `kex_live` (NeedSubmit **or** Writer-accepted batch).
    kex_peak: std::sync::atomic::AtomicUsize,
    /// Peak of linearized `total - kex_live` (control/data only). Survives
    /// NeedSubmit → Writer pending. Never derived from racy `parts[2]`.
    max_excluding_kex: std::sync::atomic::AtomicUsize,
    /// Last `kex_live` growth (bytes). Evidence for a kex-identity jump.
    last_kex_jump: std::sync::atomic::AtomicUsize,
    /// Session-thread live `sealed_backlog` has been >= HWM (tiny packets may
    /// sit in `enc.write` and never enter the linearized Writer total).
    live_hwm: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl LedgerMaxSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn observe(&self, n: usize) {
        let mut cur = self.max.load(Ordering::Relaxed);
        while n > cur {
            match self.max.compare_exchange_weak(
                cur,
                n,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    /// Like [`Self::observe`], plus records the four ledger components that
    /// produced the new max (diagnostic only — racy on concurrent max updates).
    ///
    /// `parts` = `[writer_pending, session_pending, kex_need, enc_write]`.
    pub fn observe_parts(&self, n: usize, parts: [usize; 4]) {
        let mut cur = self.max.load(Ordering::Relaxed);
        while n > cur {
            match self.max.compare_exchange_weak(
                cur,
                n,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    for (i, p) in parts.iter().enumerate() {
                        self.parts[i].store(*p, Ordering::SeqCst);
                    }
                    break;
                }
                Err(c) => cur = c,
            }
        }
    }

    /// Peaks from linearized `total` / `kex_live` (same call as the mutation).
    /// `max_excluding_kex` is **not** `total - racy parts[2]`.
    pub fn observe_linearized(&self, total: usize, kex_live: usize) {
        self.observe(total);
        self.note_kex_need(kex_live);
        let non_kex = total.saturating_sub(kex_live);
        let mut nk = self.max_excluding_kex.load(Ordering::Relaxed);
        while non_kex > nk {
            match self.max_excluding_kex.compare_exchange_weak(
                nk,
                non_kex,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => nk = c,
            }
        }
    }

    /// Components of the sample that set the current max:
    /// `[writer_pending, session_pending, kex_need, enc_write]`.
    pub fn parts(&self) -> [usize; 4] {
        [
            self.parts[0].load(Ordering::SeqCst),
            self.parts[1].load(Ordering::SeqCst),
            self.parts[2].load(Ordering::SeqCst),
            self.parts[3].load(Ordering::SeqCst),
        ]
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }

    /// A checked ledger subtraction underflowed — observable accounting error.
    pub fn note_mismatch(&self) {
        self.mismatch.fetch_add(1, Ordering::SeqCst);
        log::error!("ledger mismatch: checked subtraction underflowed");
    }

    pub fn mismatch(&self) -> u64 {
        self.mismatch.load(Ordering::SeqCst)
    }

    /// A real (non-synthetic) bulk-queue Full backpressure event.
    pub fn note_full_hit(&self) {
        self.full_hits.fetch_add(1, Ordering::SeqCst);
    }

    pub fn full_hits(&self) -> u64 {
        self.full_hits.load(Ordering::SeqCst)
    }

    /// Session intake refused new outbound because sealed backlog reached the
    /// HWM budget (the HWM-boundary hit for large-packet floods, where the
    /// budget trips long before the mpsc count limit).
    pub fn note_intake_block(&self) {
        self.intake_blocks.fetch_add(1, Ordering::SeqCst);
    }

    pub fn intake_blocks(&self) -> u64 {
        self.intake_blocks.load(Ordering::SeqCst)
    }

    pub fn note_kex_need(&self, n: usize) {
        let prev_peak = self.kex_peak.load(Ordering::Relaxed);
        if n > prev_peak {
            self.last_kex_jump.store(n.saturating_sub(prev_peak), Ordering::SeqCst);
        }
        let mut cur = prev_peak;
        while n > cur {
            match self.kex_peak.compare_exchange_weak(
                cur,
                n,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    pub fn kex_peak(&self) -> usize {
        self.kex_peak.load(Ordering::SeqCst)
    }

    /// Peak of linearized non-kex (`total - kex_live`) sampled at each
    /// credit/debit. Survives NeedSubmit → Writer pending transfer.
    pub fn max_excluding_kex_need(&self) -> usize {
        self.max_excluding_kex.load(Ordering::SeqCst)
    }

    pub fn last_kex_jump(&self) -> usize {
        self.last_kex_jump.load(Ordering::SeqCst)
    }

    pub fn note_live_hwm(&self, n: usize) {
        if n >= crate::sshbuffer::OUTBOUND_HIGH_WATERMARK {
            self.live_hwm.store(1, Ordering::SeqCst);
        }
    }

    pub fn live_hwm(&self) -> bool {
        self.live_hwm.load(Ordering::SeqCst) != 0
    }

    pub fn clear(&self) {
        self.max.store(0, Ordering::SeqCst);
        self.mismatch.store(0, Ordering::SeqCst);
        self.full_hits.store(0, Ordering::SeqCst);
        self.intake_blocks.store(0, Ordering::SeqCst);
        self.kex_peak.store(0, Ordering::SeqCst);
        self.max_excluding_kex.store(0, Ordering::SeqCst);
        self.last_kex_jump.store(0, Ordering::SeqCst);
        self.live_hwm.store(0, Ordering::SeqCst);
    }
}

/// Test-only: wake the Session run-loop to emit one `IGNORE` (R3 one-bulk-cmd).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct InjectIgnoreGate {
    req: tokio::sync::Notify,
    done: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl InjectIgnoreGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Arm one IGNORE and wake the Session select.
    pub fn request(&self) {
        self.done.store(0, Ordering::SeqCst);
        self.req.notify_one();
    }

    pub async fn wait_requested(&self) {
        self.req.notified().await;
    }

    pub fn mark_done(&self) {
        self.done.store(1, Ordering::SeqCst);
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst) != 0
    }
}

/// Test-only: deferred WINDOW_ADJUST insert / replay / emitted counters.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct DeferredGrantSlot {
    inserts: AtomicU64,
    replays: AtomicU64,
    emitted: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl DeferredGrantSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn note_insert(&self) {
        self.inserts.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_replay(&self) {
        self.replays.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_emitted(&self) {
        self.emitted.fetch_add(1, Ordering::SeqCst);
    }

    pub fn inserts(&self) -> u64 {
        self.inserts.load(Ordering::SeqCst)
    }

    pub fn replays(&self) -> u64 {
        self.replays.load(Ordering::SeqCst)
    }

    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::SeqCst)
    }
}

/// Test-only: StopDiscard discard / grant-clear counters.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct StopDiscardSlot {
    discarded_items: AtomicU64,
    discarded_bytes: AtomicU64,
    grant_clears: AtomicU64,
    /// (recipient, msg) of plaintext seal cmds accepted into Writer bulk.
    queued_unsealed: std::sync::Mutex<Vec<(u32, u8)>>,
    seal_drops: AtomicU64,
    /// Last `Session::close` left `pending_close` set (CLOSE still in lane).
    pending_close: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl StopDiscardSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn note_discard(&self, items: usize, bytes: usize) {
        self.discarded_items
            .fetch_add(items as u64, Ordering::SeqCst);
        self.discarded_bytes
            .fetch_add(bytes as u64, Ordering::SeqCst);
    }

    pub fn note_grant_clear(&self) {
        self.grant_clears.fetch_add(1, Ordering::SeqCst);
    }

    pub fn discarded_items(&self) -> u64 {
        self.discarded_items.load(Ordering::SeqCst)
    }

    pub fn discarded_bytes(&self) -> u64 {
        self.discarded_bytes.load(Ordering::SeqCst)
    }

    pub fn grant_clears(&self) -> u64 {
        self.grant_clears.load(Ordering::SeqCst)
    }

    pub fn note_queued_unsealed(&self, recipient: u32, msg: u8) {
        if let Ok(mut g) = self.queued_unsealed.lock() {
            g.push((recipient, msg));
        }
    }

    pub fn queued_unsealed(&self) -> Vec<(u32, u8)> {
        self.queued_unsealed
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn queued_unsealed_data(&self, recipient: u32) -> usize {
        self.queued_unsealed()
            .into_iter()
            .filter(|(r, m)| *r == recipient && *m == crate::msg::CHANNEL_DATA)
            .count()
    }

    pub fn note_seal_drop(&self) {
        self.seal_drops.fetch_add(1, Ordering::SeqCst);
    }

    pub fn seal_drops(&self) -> u64 {
        self.seal_drops.load(Ordering::SeqCst)
    }

    pub fn set_pending_close(&self, pending: bool) {
        self.pending_close
            .store(u64::from(pending), Ordering::SeqCst);
    }

    pub fn pending_close(&self) -> bool {
        self.pending_close.load(Ordering::SeqCst) != 0
    }
}

/// Test-only: outbound channel-message order as packets enter `enc.write`
/// (the Writer seal FIFO). Used by S2c wire-order assertions.
/// Third field is the CHANNEL_DATA / EXTENDED_DATA payload length (0 otherwise).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct OutboundOrderSlot {
    msgs: std::sync::Mutex<Vec<(u32, u8, u32)>>,
}

#[cfg(feature = "_test_hooks")]
impl OutboundOrderSlot {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    pub fn push(&self, channel: u32, msg: u8, payload_len: u32) {
        if let Ok(mut g) = self.msgs.lock() {
            g.push((channel, msg, payload_len));
        }
    }

    pub fn snapshot(&self) -> Vec<(u32, u8, u32)> {
        self.msgs.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Message types for `channel` in emit order.
    pub fn types_for(&self, channel: u32) -> Vec<u8> {
        self.snapshot()
            .into_iter()
            .filter(|(c, _, _)| *c == channel)
            .map(|(_, m, _)| m)
            .collect()
    }
}

/// Test-only: peer-driven SUCCESS/FAILURE still queued in lanes.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct ReplyQueueSlot {
    current: AtomicUsize,
    max: AtomicUsize,
}

#[cfg(feature = "_test_hooks")]
impl ReplyQueueSlot {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    pub fn observe(&self, n: usize) {
        self.current.store(n, Ordering::SeqCst);
        let _ = self.max.fetch_max(n, Ordering::SeqCst);
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

/// Test-only: S2d scheduler counters (regular quanta + boosts).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct SchedSlot {
    regular_quanta: AtomicU64,
    boosts: AtomicU64,
    /// (recipient_channel, is_boost, ready_set_len at emit)
    emits: std::sync::Mutex<Vec<(u32, bool, u32)>>,
    /// `regular_quanta` snapshot at each boost (for adjacent-gap asserts).
    boost_at: std::sync::Mutex<Vec<u64>>,
}

#[cfg(feature = "_test_hooks")]
impl SchedSlot {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    pub fn note_quantum(&self) {
        self.regular_quanta.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_boost(&self) {
        let q = self.regular_quanta.load(Ordering::SeqCst);
        self.boosts.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut g) = self.boost_at.lock() {
            g.push(q);
        }
    }

    pub fn note_emit(&self, channel: u32, boost: bool, ready_len: u32) {
        if let Ok(mut g) = self.emits.lock() {
            g.push((channel, boost, ready_len));
        }
    }

    pub fn regular_quanta(&self) -> u64 {
        self.regular_quanta.load(Ordering::SeqCst)
    }

    pub fn boosts(&self) -> u64 {
        self.boosts.load(Ordering::SeqCst)
    }

    pub fn emits(&self) -> Vec<(u32, bool, u32)> {
        self.emits.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn boost_at_quanta(&self) -> Vec<u64> {
        self.boost_at.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// Test-only: write-watchdog armed / eligible / rekey-generation edges.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct WatchdogObserveSlot {
    ever_armed: AtomicU64,
    armed_now: AtomicU64,
    last_eligible: AtomicU64,
    disarmed_after_arm: AtomicU64,
    last_rekey_gen: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl WatchdogObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn observe(&self, armed: bool, eligible: u64, rekey_gen: u64) {
        self.last_eligible.store(eligible, Ordering::SeqCst);
        self.last_rekey_gen.store(rekey_gen, Ordering::SeqCst);
        if armed {
            self.ever_armed.store(1, Ordering::SeqCst);
            self.armed_now.store(1, Ordering::SeqCst);
        } else {
            if self.ever_armed.load(Ordering::SeqCst) != 0
                && self.armed_now.swap(0, Ordering::SeqCst) != 0
            {
                self.disarmed_after_arm.store(1, Ordering::SeqCst);
            }
        }
    }

    pub fn ever_armed(&self) -> bool {
        self.ever_armed.load(Ordering::SeqCst) != 0
    }

    pub fn is_armed(&self) -> bool {
        self.armed_now.load(Ordering::SeqCst) != 0
    }

    pub fn last_eligible(&self) -> u64 {
        self.last_eligible.load(Ordering::SeqCst)
    }

    pub fn disarmed_after_arm(&self) -> bool {
        self.disarmed_after_arm.load(Ordering::SeqCst) != 0
    }

    pub fn last_rekey_gen(&self) -> u64 {
        self.last_rekey_gen.load(Ordering::SeqCst)
    }
}

/// Single-structure write-progress snapshot (§4.2).
/// Always read/written as a whole — never field-by-field across tasks.
#[derive(Debug, Clone, Copy)]
pub struct WriteProgress {
    pub generation: u64,
    /// Monotonic millis since an arbitrary epoch (session start).
    pub last_write_ok_ms: u64,
    pub wire_eligible_bytes: u64,
    pub drained_bytes_epoch: u64,
}

impl WriteProgress {
    pub fn new() -> Self {
        Self {
            generation: 0,
            last_write_ok_ms: 0,
            wire_eligible_bytes: 0,
            drained_bytes_epoch: 0,
        }
    }
}

/// Cross-task atomic snapshot of [`WriteProgress`] (§4.2).
///
/// Writer stores with a single mutex replace (release); supervisor/session
/// loads a full copy under the same mutex (acquire). No torn field reads.
#[derive(Debug)]
pub struct AtomicWriteProgress {
    inner: std::sync::Mutex<WriteProgress>,
    base: Instant,
}

impl AtomicWriteProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(WriteProgress::new()),
            base: Instant::now(),
        })
    }

    /// Acquire-load of the full snapshot.
    pub fn load(&self) -> WriteProgress {
        *self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Release-store of the full snapshot (replaces all fields atomically).
    pub fn store(&self, snap: WriteProgress) {
        *self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = snap;
    }

    /// Writer helper: record `Ok(n>0)` socket progress.
    /// Also decrements `wire_eligible_bytes` so cross-task HWM observers see
    /// drain during a long `drain_writes` (not only at the next loop store).
    pub fn note_write(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.generation = g.generation.wrapping_add(1);
        g.last_write_ok_ms = self.base.elapsed().as_millis() as u64;
        g.drained_bytes_epoch = g.drained_bytes_epoch.saturating_add(n as u64);
        g.wire_eligible_bytes = g.wire_eligible_bytes.saturating_sub(n as u64);
    }

    /// Writer helper: publish current wire-eligible byte count.
    pub fn store_eligible(&self, wire_eligible_bytes: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.wire_eligible_bytes = wire_eligible_bytes;
        g.generation = g.generation.wrapping_add(1);
    }
}

impl Default for AtomicWriteProgress {
    fn default() -> Self {
        Self {
            inner: std::sync::Mutex::new(WriteProgress::new()),
            base: Instant::now(),
        }
    }
}

/// Two-layer write watchdog state (activity + optional min-drain policy).
#[derive(Debug)]
pub struct WriteWatchdog {
    /// When wire_eligible became > 0 (idle→eligible edge). None = disarmed.
    armed_at: Option<Instant>,
    last_progress_at: Option<Instant>,
    /// Strategy window: bytes drained since window_start while armed.
    drain_window_start: Option<Instant>,
    drained_in_window: u64,
    /// Session-relative clock base.
    base: Instant,
    /// Cached snapshot (single structure for external observers).
    snapshot: WriteProgress,
    snapshot_gen: u64,
}

impl WriteWatchdog {
    pub fn new() -> Self {
        Self {
            armed_at: None,
            last_progress_at: None,
            drain_window_start: None,
            drained_in_window: 0,
            base: Instant::now(),
            snapshot: WriteProgress::new(),
            snapshot_gen: 0,
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    pub fn snapshot(&self) -> WriteProgress {
        self.snapshot
    }

    pub fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// Map current sealed-but-unflushed bytes into wire_eligible and arm/disarm.
    ///
    /// S1 seam: `wire_eligible = packet_writer.pending_bytes()` (already-sealed
    /// ciphertext). Excludes peer-window=0 pending_data (never sealed) and
    /// kex-gated bulk still in app queues — so pure InKex with empty staging
    /// does **not** arm the write watchdog (case1 → RekeyTimeout only).
    pub fn observe_eligible(&mut self, wire_eligible_bytes: u64) {
        let now = Instant::now();
        self.snapshot.wire_eligible_bytes = wire_eligible_bytes;
        self.snapshot.generation = self.snapshot_gen;

        if wire_eligible_bytes == 0 {
            // Disarm: idle. Next eligible edge re-arms with fresh clock.
            self.armed_at = None;
            self.last_progress_at = None;
            self.drain_window_start = None;
            self.drained_in_window = 0;
            return;
        }

        if self.armed_at.is_none() {
            // idle → eligible edge
            self.armed_at = Some(now);
            self.last_progress_at = Some(now);
            self.drain_window_start = Some(now);
            self.drained_in_window = 0;
            self.snapshot.last_write_ok_ms = self.now_ms();
        }
    }

    /// Socket write returned `Ok(n>0)` (including partial).
    pub fn note_write_ok(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let now = Instant::now();
        self.last_progress_at = Some(now);
        self.drained_in_window = self.drained_in_window.saturating_add(n as u64);
        self.snapshot.drained_bytes_epoch =
            self.snapshot.drained_bytes_epoch.saturating_add(n as u64);
        self.snapshot.last_write_ok_ms = self.now_ms();
        self.snapshot_gen = self.snapshot_gen.wrapping_add(1);
        self.snapshot.generation = self.snapshot_gen;
    }

    /// Returns `WriteStalled` if armed and either activity or strategy layer trips.
    pub fn poll_timeout(
        &mut self,
        write_progress_deadline: Duration,
        write_min_drain: Option<(usize, Duration)>,
    ) -> Option<DisconnectCause> {
        let armed_at = self.armed_at?;
        let now = Instant::now();
        let last = self.last_progress_at.unwrap_or(armed_at);

        // Activity layer: no Ok(n>0) for deadline while armed.
        if now.duration_since(last) >= write_progress_deadline {
            return Some(DisconnectCause::WriteStalled);
        }

        // Strategy layer (write_min_drain): low cumulative drain over window.
        if let Some((min_bytes, window)) = write_min_drain {
            let win_start = self.drain_window_start.unwrap_or(armed_at);
            if now.duration_since(win_start) >= window {
                if self.drained_in_window < min_bytes as u64 {
                    return Some(DisconnectCause::WriteStalled);
                }
                // Slide window after a healthy period.
                self.drain_window_start = Some(now);
                self.drained_in_window = 0;
            }
        }
        None
    }

    /// How long until the next possible activity-layer fire (for select! sleep).
    pub fn next_activity_deadline(
        &self,
        write_progress_deadline: Duration,
    ) -> Option<Duration> {
        let armed_at = self.armed_at?;
        let last = self.last_progress_at.unwrap_or(armed_at);
        let elapsed = Instant::now().duration_since(last);
        Some(write_progress_deadline.saturating_sub(elapsed).max(Duration::from_millis(1)))
    }

    /// How long until the next possible min-drain strategy fire (for select! sleep).
    /// `None` if disarmed or strategy disabled.
    pub fn next_min_drain_deadline(
        &self,
        write_min_drain: Option<(usize, Duration)>,
    ) -> Option<Duration> {
        let (_, window) = write_min_drain?;
        let armed_at = self.armed_at?;
        let win_start = self.drain_window_start.unwrap_or(armed_at);
        let elapsed = Instant::now().duration_since(win_start);
        Some(window.saturating_sub(elapsed).max(Duration::from_millis(1)))
    }
}

impl Default for WriteWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn min_drain_trips_while_activity_resets() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(4096);
        // Small writes keep activity layer happy (deadline 30s).
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(30));
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(100));
        // Strategy: need 4 KiB in 100ms — we only wrote 2 bytes over >100ms.
        let cause = wd.poll_timeout(
            Duration::from_secs(30),
            Some((4096, Duration::from_millis(100))),
        );
        assert_eq!(cause, Some(DisconnectCause::WriteStalled));
    }

    #[test]
    fn min_drain_off_does_not_trip_on_trickle() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(4096);
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(50));
        wd.note_write_ok(1);
        let cause = wd.poll_timeout(Duration::from_secs(30), None);
        assert_eq!(cause, None);
    }

    #[test]
    fn zero_eligible_disarms() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(1024);
        wd.observe_eligible(0);
        thread::sleep(Duration::from_millis(20));
        let cause =
            wd.poll_timeout(Duration::from_millis(10), Some((1, Duration::from_millis(10))));
        assert_eq!(cause, None);
    }

    #[test]
    fn atomic_write_progress_no_tear() {
        let p = AtomicWriteProgress::new();
        p.store_eligible(100);
        p.note_write(50);
        let snap = p.load();
        assert_eq!(snap.wire_eligible_bytes, 50);
        assert_eq!(snap.drained_bytes_epoch, 50);
        assert!(snap.generation >= 2);
    }
}

/// Tracks rekey deadline registration (watch-style generation on the session).
#[derive(Debug, Default, Clone)]
pub struct RekeyDeadline {
    /// Generation currently in InKex with an armed deadline.
    pub generation: Option<u64>,
    pub deadline_at: Option<Instant>,
}

impl RekeyDeadline {
    pub fn register(&mut self, generation: u64, deadline: Duration) {
        self.generation = Some(generation);
        self.deadline_at = Some(Instant::now() + deadline);
    }

    pub fn clear_if_generation(&mut self, generation: u64) {
        if self.generation == Some(generation) {
            self.generation = None;
            self.deadline_at = None;
        }
    }

    pub fn clear(&mut self) {
        self.generation = None;
        self.deadline_at = None;
    }

    /// Fire only if still the same generation and past deadline.
    pub fn poll(&self, current_active_generation: Option<u64>) -> Option<u64> {
        let generation = self.generation?;
        let at = self.deadline_at?;
        if current_active_generation != Some(generation) {
            return None;
        }
        if Instant::now() >= at {
            Some(generation)
        } else {
            None
        }
    }

    pub fn remaining(&self) -> Option<Duration> {
        let at = self.deadline_at?;
        let now = Instant::now();
        if now >= at {
            Some(Duration::ZERO)
        } else {
            Some(at.duration_since(now))
        }
    }
}

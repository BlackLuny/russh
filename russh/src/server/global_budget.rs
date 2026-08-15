//! Process-level byte + connection ledger (S4d).
//!
//! One `used` counter covers three categories on the same book:
//! 1. inbound grant credit (each ADJUST Δ; the initial window is reserved
//!    with the opening estimate)
//! 2. opening reservation (`window_size + OUTBOUND_CAP_ESTIMATE`)
//! 3. per-connection fixed protocol (`inbound_ctrl_budget + WRITER_KEX_BUDGET`)
//!
//! Floor: each accepted connection exclusively holds
//! `floor = min(declared_need, budget / max_connections)` so a later
//! connection still gets that exclusive slice. Bytes above floor come
//! from the shared remainder. Unused connection slots keep their
//! `floor_unit` reserved — a large connection cannot take another
//! connection's floor (G5). Excess already granted is not reclaimed;
//! future grants above floor fail once the shared remainder is gone.
//!
//! Acquire order is always this ledger first, then per-channel state.
//! Release is exactly-once: close / Expired / teardown / expand fail
//! decrement `held`; `ConnAccount` drop refunds whatever remains
//! (S3b #7: Scheme C bytes are part of the channel reservation and
//! are not refunded a second time on delivery).
//!
//! Occupancy is the committed reservation, not a running sum of every
//! historical grant after close. Single-packet rounding: reservations
//! are whole `u32` grant deltas and whole opening estimates. The hook
//! compares `used <= budget` with no extra slack.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::Config;

/// Writer / kex dedicated-queue byte estimate. Hard-coded, aligned
/// with S3b `INBOUND_CTRL_BUDGET` (2 MiB). Not a real allocation.
pub const WRITER_KEX_BUDGET: usize = 2 * 1024 * 1024;

/// Per-channel outbound estimate used at opening (spec `channel_out_cap`).
/// Distinct from `Config::max_pending_outbound_bytes` (the 16 MiB safety
/// cap). S5 will replace this with the real out-cap.
pub const OUTBOUND_CAP_ESTIMATE: u64 = 2 * 1024 * 1024;

/// Default process-level byte budget. This is a counter ceiling, not an
/// allocation. Sized so a fully loaded default connection
/// (`max_channels × (window_size + OUTBOUND_CAP_ESTIMATE) + protocol`)
/// still fits in its floor (`budget / max_connections`). Deployments
/// that want a real host cap must set `Config::global_byte_budget`.
pub const DEFAULT_GLOBAL_BYTE_BUDGET: u64 = 4 * 1024 * 1024 * 1024 * 1024; // 4 TiB

/// Default connection cap. Large enough that existing single-connection
/// tests are unaffected. Deployments that want a real cap must set
/// `Config::max_connections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Why `try_acquire` refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitErr {
    ConnectionsFull,
    Budget,
}

/// Test-only: recreate the r1 two-phase admission (slot++ then floor)
/// so G6 invert can pin the stolen-floor interleaving. Production
/// never installs this gate; `try_acquire` publishes slot+floor under
/// one mutex.
#[cfg(feature = "_test_hooks")]
#[derive(Default)]
pub struct AdmitSplitGate {
    after_slot: AtomicBool,
    go_floor: AtomicBool,
}

#[cfg(feature = "_test_hooks")]
impl AdmitSplitGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn wait_after_slot(&self) {
        while !self.after_slot.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
    pub fn proceed_floor(&self) {
        self.go_floor.store(true, Ordering::SeqCst);
    }
}

/// used + connections published together. Admission and try_reserve
/// are infrequent (grant cadence, not per-packet); a mutex keeps
/// slot+floor atomic so a half-admitted connection cannot raise the
/// shared cap (S4d r1 P1-2). Hook counters stay atomic.
struct LedgerInner {
    used: u64,
    connections: usize,
}

/// Process-level ledger shared by `run_on_socket` / `run_stream`.
pub struct GlobalBudget {
    budget: u64,
    max_connections: usize,
    /// Exclusive per-connection slice (`budget / max_connections`, or
    /// a config override capped at that).
    floor_unit: u64,
    inner: Mutex<LedgerInner>,
    #[cfg(feature = "_test_hooks")]
    admit_split: Mutex<Option<Arc<AdmitSplitGate>>>,
    #[cfg(feature = "_test_hooks")]
    max_used: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    reserve_ok: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    reserve_fail: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    release_count: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    conn_reject: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    grant_reserve_fail: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    expand_before_global: AtomicU64,
    #[cfg(feature = "_test_hooks")]
    global_before_expand: AtomicU64,
}

impl fmt::Debug for GlobalBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalBudget")
            .field("budget", &self.budget)
            .field("max_connections", &self.max_connections)
            .field("floor_unit", &self.floor_unit)
            .field("used", &self.inner.lock().map(|g| g.used).unwrap_or(0))
            .field(
                "connections",
                &self.inner.lock().map(|g| g.connections).unwrap_or(0),
            )
            .finish()
    }
}

impl GlobalBudget {
    pub fn new(budget: u64, max_connections: usize, per_connection_floor: Option<u64>) -> Self {
        let max_c = max_connections.max(1);
        let natural = budget / max_c as u64;
        let floor_unit = match per_connection_floor {
            Some(f) => f.min(natural),
            None => natural,
        };
        Self {
            budget,
            max_connections: max_c,
            floor_unit,
            inner: Mutex::new(LedgerInner {
                used: 0,
                connections: 0,
            }),
            #[cfg(feature = "_test_hooks")]
            admit_split: Mutex::new(None),
            #[cfg(feature = "_test_hooks")]
            max_used: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            reserve_ok: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            reserve_fail: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            release_count: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            conn_reject: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            grant_reserve_fail: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            expand_before_global: AtomicU64::new(0),
            #[cfg(feature = "_test_hooks")]
            global_before_expand: AtomicU64::new(0),
        }
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn floor_unit(&self) -> u64 {
        self.floor_unit
    }

    pub fn used(&self) -> u64 {
        self.inner.lock().map(|g| g.used).unwrap_or(0)
    }

    pub fn connections(&self) -> usize {
        self.inner.lock().map(|g| g.connections).unwrap_or(0)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn set_admit_split(&self, gate: Arc<AdmitSplitGate>) {
        *self.admit_split.lock().expect("admit_split") = Some(gate);
    }

    #[cfg(feature = "_test_hooks")]
    pub fn max_used(&self) -> u64 {
        self.max_used.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn reserve_ok(&self) -> u64 {
        self.reserve_ok.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn reserve_fail(&self) -> u64 {
        self.reserve_fail.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn release_count(&self) -> u64 {
        self.release_count.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn conn_reject(&self) -> u64 {
        self.conn_reject.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn grant_reserve_fail(&self) -> u64 {
        self.grant_reserve_fail.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn expand_before_global(&self) -> u64 {
        self.expand_before_global.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub fn global_before_expand(&self) -> u64 {
        self.global_before_expand.load(Ordering::SeqCst)
    }

    #[cfg(feature = "_test_hooks")]
    pub(crate) fn note_grant_reserve_fail(&self) {
        self.grant_reserve_fail.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(feature = "_test_hooks")]
    pub(crate) fn note_expand_before_global(&self) {
        self.expand_before_global.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(feature = "_test_hooks")]
    pub(crate) fn note_global_before_expand(&self) {
        self.global_before_expand.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(feature = "_test_hooks")]
    fn note_max_used(&self, used: u64) {
        let mut cur = self.max_used.load(Ordering::Relaxed);
        while used > cur {
            match self.max_used.compare_exchange_weak(
                cur,
                used,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    /// Take a connection slot and reserve this connection's exclusive
    /// floor (which includes the fixed protocol budget).
    ///
    /// Slot increment and floor debit are one mutex critical section
    /// (S4d r1 P1-2). `try_reserve` cannot observe a half-admitted
    /// connection.
    pub fn try_acquire(self: &Arc<Self>, config: &Config) -> Result<ConnAccount, AdmitErr> {
        let declared = declared_need(config);
        let floor = declared.min(self.floor_unit);
        let fixed = fixed_protocol_budget(config);

        #[cfg(feature = "_test_hooks")]
        if let Some(gate) = self.admit_split.lock().ok().and_then(|g| g.clone()) {
            return self.try_acquire_split(config, floor, fixed, gate);
        }

        {
            let mut g = self.inner.lock().expect("global budget");
            if g.connections >= self.max_connections {
                #[cfg(feature = "_test_hooks")]
                self.conn_reject.fetch_add(1, Ordering::SeqCst);
                return Err(AdmitErr::ConnectionsFull);
            }
            let future = (self.max_connections.saturating_sub(g.connections + 1) as u64)
                .saturating_mul(self.floor_unit);
            let cap = self.budget.saturating_sub(future);
            if g.used.saturating_add(floor) > cap {
                #[cfg(feature = "_test_hooks")]
                self.conn_reject.fetch_add(1, Ordering::SeqCst);
                return Err(AdmitErr::Budget);
            }
            g.connections += 1;
            g.used += floor;
            #[cfg(feature = "_test_hooks")]
            self.note_max_used(g.used);
        }
        let acc = ConnAccount {
            budget: Arc::clone(self),
            floor,
            held: AtomicU64::new(0),
            live: AtomicBool::new(true),
        };
        if acc.try_reserve(fixed).is_err() {
            drop(acc);
            return Err(AdmitErr::Budget);
        }
        Ok(acc)
    }

    /// r1 two-phase admission: publish live, then floor. Only used when
    /// a test installs `AdmitSplitGate`. Production never calls this.
    #[cfg(feature = "_test_hooks")]
    fn try_acquire_split(
        self: &Arc<Self>,
        _config: &Config,
        floor: u64,
        fixed: u64,
        gate: Arc<AdmitSplitGate>,
    ) -> Result<ConnAccount, AdmitErr> {
        {
            let mut g = self.inner.lock().expect("global budget");
            if g.connections >= self.max_connections {
                self.conn_reject.fetch_add(1, Ordering::SeqCst);
                return Err(AdmitErr::ConnectionsFull);
            }
            g.connections += 1;
        }
        gate.after_slot.store(true, Ordering::SeqCst);
        while !gate.go_floor.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        {
            let mut g = self.inner.lock().expect("global budget");
            let future = (self.max_connections.saturating_sub(g.connections) as u64)
                .saturating_mul(self.floor_unit);
            let cap = self.budget.saturating_sub(future);
            if g.used.saturating_add(floor) > cap {
                g.connections = g.connections.saturating_sub(1);
                self.conn_reject.fetch_add(1, Ordering::SeqCst);
                return Err(AdmitErr::Budget);
            }
            g.used += floor;
            self.note_max_used(g.used);
        }
        let acc = ConnAccount {
            budget: Arc::clone(self),
            floor,
            held: AtomicU64::new(0),
            live: AtomicBool::new(true),
        };
        if acc.try_reserve(fixed).is_err() {
            drop(acc);
            return Err(AdmitErr::Budget);
        }
        Ok(acc)
    }
}

/// One accepted connection's reservation state. Drop refunds leftover
/// held + the exclusive floor + the connection slot.
pub struct ConnAccount {
    budget: Arc<GlobalBudget>,
    floor: u64,
    held: AtomicU64,
    live: AtomicBool,
}

impl fmt::Debug for ConnAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnAccount")
            .field("floor", &self.floor)
            .field("held", &self.held.load(Ordering::Relaxed))
            .finish()
    }
}

impl ConnAccount {
    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn held(&self) -> u64 {
        self.held.load(Ordering::SeqCst)
    }

    pub fn budget(&self) -> &Arc<GlobalBudget> {
        &self.budget
    }

    /// Reserve `n` bytes for this connection. Within the exclusive
    /// floor this only updates `held` (`used` already includes the
    /// floor). Above floor, `used` grows from the shared remainder
    /// and must not eat other connections' unused floors.
    pub fn try_reserve(&self, n: u64) -> Result<(), ()> {
        if n == 0 {
            return Ok(());
        }
        let mut g = self.budget.inner.lock().expect("global budget");
        let h = self.held.load(Ordering::SeqCst);
        let new_h = h.saturating_add(n);
        if new_h <= self.floor {
            self.held.store(new_h, Ordering::SeqCst);
            #[cfg(feature = "_test_hooks")]
            self.budget.reserve_ok.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        let add_used = new_h.saturating_sub(h.max(self.floor));
        let future = (self.budget.max_connections.saturating_sub(g.connections) as u64)
            .saturating_mul(self.budget.floor_unit);
        let cap = self.budget.budget.saturating_sub(future);
        if g.used.saturating_add(add_used) > cap {
            #[cfg(feature = "_test_hooks")]
            self.budget.reserve_fail.fetch_add(1, Ordering::SeqCst);
            return Err(());
        }
        g.used += add_used;
        self.held.store(new_h, Ordering::SeqCst);
        #[cfg(feature = "_test_hooks")]
        {
            self.budget.reserve_ok.fetch_add(1, Ordering::SeqCst);
            self.budget.note_max_used(g.used);
        }
        Ok(())
    }

    pub fn release(&self, n: u64) {
        if n == 0 {
            return;
        }
        let mut g = self.budget.inner.lock().expect("global budget");
        let h = self.held.load(Ordering::SeqCst);
        if h == 0 {
            return;
        }
        let n = n.min(h);
        let new_h = h - n;
        let used_delta = h.saturating_sub(self.floor) - new_h.saturating_sub(self.floor);
        if used_delta > 0 {
            g.used = g.used.saturating_sub(used_delta);
        }
        self.held.store(new_h, Ordering::SeqCst);
        #[cfg(feature = "_test_hooks")]
        self.budget.release_count.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for ConnAccount {
    fn drop(&mut self) {
        if !self.live.swap(false, Ordering::SeqCst) {
            return;
        }
        let mut g = self.budget.inner.lock().expect("global budget");
        let h = self.held.load(Ordering::SeqCst);
        let excess = h.saturating_sub(self.floor);
        let used_release = self.floor.saturating_add(excess);
        if used_release > 0 {
            g.used = g.used.saturating_sub(used_release);
        }
        g.connections = g.connections.saturating_sub(1);
        #[cfg(feature = "_test_hooks")]
        self.budget.release_count.fetch_add(1, Ordering::SeqCst);
    }
}

pub fn fixed_protocol_budget(config: &Config) -> u64 {
    (config.inbound_ctrl_budget as u64).saturating_add(WRITER_KEX_BUDGET as u64)
}

pub fn opening_estimate(config: &Config) -> u64 {
    (config.window_size as u64).saturating_add(OUTBOUND_CAP_ESTIMATE)
}

/// Declared demand for the floor formula: protocol + every slot this
/// connection is allowed to open. A connection that never uses that
/// many channels still *claims* them, so `floor = min(declared,
/// budget/max_connections)` keeps a later connection's slice intact.
pub fn declared_need(config: &Config) -> u64 {
    let per = opening_estimate(config);
    let slots = (config.max_channels.max(1) as u64).saturating_mul(per);
    fixed_protocol_budget(config).saturating_add(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Config;

    fn cfg(budget: u64, max_c: usize, window: u32, max_ch: usize) -> Config {
        let mut c = Config::default();
        c.global_byte_budget = budget;
        c.max_connections = max_c;
        c.window_size = window;
        c.max_channels = max_ch;
        c
    }

    #[test]
    fn acquire_rejects_past_max_connections() {
        let c = cfg(64 * 1024 * 1024, 2, 1024, 1);
        let gb = Arc::new(GlobalBudget::new(
            c.global_byte_budget,
            c.max_connections,
            None,
        ));
        let a = gb.try_acquire(&c).unwrap();
        let b = gb.try_acquire(&c).unwrap();
        assert!(matches!(gb.try_acquire(&c), Err(AdmitErr::ConnectionsFull)));
        drop(a);
        drop(b);
        assert_eq!(gb.connections(), 0);
        assert_eq!(gb.used(), 0);
    }

    #[test]
    fn floor_blocks_one_conn_from_eating_the_other() {
        let c = cfg(32 * 1024 * 1024, 2, 1024, 1);
        let gb = Arc::new(GlobalBudget::new(
            c.global_byte_budget,
            c.max_connections,
            None,
        ));
        let a = gb.try_acquire(&c).unwrap();
        // Eating the whole budget would steal conn B's reserved floor.
        assert!(a.try_reserve(c.global_byte_budget).is_err());
        let b = gb.try_acquire(&c).unwrap();
        assert!(b.try_reserve(1024).is_ok());
        drop(a);
        drop(b);
        assert_eq!(gb.used(), 0);
    }

    #[test]
    fn release_is_exactly_once() {
        let c = cfg(64 * 1024 * 1024, 2, 1024, 2);
        let gb = Arc::new(GlobalBudget::new(
            c.global_byte_budget,
            c.max_connections,
            None,
        ));
        let a = gb.try_acquire(&c).unwrap();
        let need = opening_estimate(&c);
        a.try_reserve(need).unwrap();
        let used_mid = gb.used();
        a.release(need);
        a.release(need); // second release is a no-op on held
        assert!(gb.used() <= used_mid);
        drop(a);
        assert_eq!(gb.used(), 0);
        assert_eq!(gb.connections(), 0);
    }

    /// G6 green: Mutex publish means A cannot take 1 byte of B's
    /// uncommitted floor. B still admits.
    #[cfg(feature = "_test_hooks")]
    #[test]
    fn g6_admission_floor_atomic() {
        // budget = 2×declared so floor_unit == declared; 1 extra byte
        // would have to come from the other slot's floor.
        let declared = declared_need(&cfg(1, 2, 1024, 1));
        let c = cfg(declared * 2, 2, 1024, 1);
        let gb = Arc::new(GlobalBudget::new(
            c.global_byte_budget,
            c.max_connections,
            None,
        ));
        let a = gb.try_acquire(&c).unwrap();
        a.try_reserve(a.floor().saturating_sub(a.held()))
            .expect("fill A to exclusive floor");
        assert_eq!(a.held(), a.floor(), "A starts at exclusive floor");
        match a.try_reserve(1) {
            Err(()) => {}
            Ok(()) => panic!("G6 HARD: A must not take future-slot floor (stolen_floor)"),
        }
        let b = match gb.try_acquire(&c) {
            Ok(b) => b,
            Err(e) => panic!("G6 HARD: B must still admit after A's failed excess, got {e:?}"),
        };
        assert_eq!(gb.connections(), 2);
        assert!(gb.used() <= gb.budget());
        drop(a);
        drop(b);
    }

    /// G6 invert: two-phase admission (slot then floor) lets A steal
    /// 1 byte; B is then stably rejected. Enumerated class, not is_err().
    #[cfg(feature = "_test_hooks")]
    #[test]
    fn g6_split_admit_is_red() {
        match g6_split_round() {
            Err("stolen_floor") | Err("b_rejected") | Err("used_over_cap") => {}
            other => panic!(
                "G6 HARD: split admit must fail with enumerated class \
                 (stolen_floor|b_rejected|used_over_cap), got {other:?}"
            ),
        }
    }

    #[cfg(feature = "_test_hooks")]
    fn g6_split_round() -> Result<(), &'static str> {
        let declared = declared_need(&cfg(1, 2, 1024, 1));
        let c = cfg(declared * 2, 2, 1024, 1);
        let gb = Arc::new(GlobalBudget::new(
            c.global_byte_budget,
            c.max_connections,
            None,
        ));
        let a = gb.try_acquire(&c).map_err(|_| "open")?;
        a.try_reserve(a.floor().saturating_sub(a.held()))
            .map_err(|_| "open")?;
        let gate = AdmitSplitGate::new();
        gb.set_admit_split(gate.clone());
        let gb_b = Arc::clone(&gb);
        let c_b = cfg(declared * 2, 2, 1024, 1);
        let join = std::thread::spawn(move || gb_b.try_acquire(&c_b));
        gate.wait_after_slot();
        let stole = a.try_reserve(1).is_ok();
        gate.proceed_floor();
        let b = join.join().map_err(|_| "join")?;
        if stole {
            return Err("stolen_floor");
        }
        if b.is_err() {
            return Err("b_rejected");
        }
        if gb.used() > gb.budget().saturating_sub(gb.floor_unit())
            && gb.connections() < gb.max_connections()
        {
            return Err("used_over_cap");
        }
        Ok(())
    }
}

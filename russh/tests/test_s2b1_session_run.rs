//! S2b-1 fix10: R1–R6 integration regressions — **zero soft fallbacks**.
//!
//! Hard rule: if the target interleaving is not observed, the test **must fail**.
//! Requires `--features _test_hooks`.
//!
//! fix10 (kimi) closes r9's six must-fix items with deterministic hooks:
//! - client `dh_init_sent` + FaultInjectStream auto-freeze: deterministic client
//!   NEWKEYS delay (freeze engages after DH-init is on the wire, before the
//!   server reply can be read — no race).
//! - FaultInjectStream coalesce gate: client NEWKEYS + first new-key packet are
//!   buffered, then delivered in ONE inner socket write (R1 aggregation proof).
//! - `need_submit_timer_disable` + frozen client reads + capacity-chain counters:
//!   R3's advance can only come from dequeue-notify → capacity select arm.
//! - `fail_next_socket_write`: real initial/rekey Writer-fail injection at
//!   phase 2 with inbound already committed (R5 failure contract).
//! - `inject_kexinit`: illegal nested KEXINIT used only as a resilience probe
//!   during ACK-before-Done (RFC 4253 §7.1 forbids this on a legal peer).
//!   Legal R6 park/replay is the Done-before-ACK integration.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::*;
use russh::server::{
    CapacityChainSlot, DeferredGrantSlot, DisconnectCause, InjectIgnoreGate, InstallAckHoldGate,
    KexInstallObserveSlot, LedgerMaxSlot, NeedSubmitSeenSlot, WatchdogObserveSlot,
};
use tokio::time::sleep;

const GRACE: Duration = Duration::from_secs(1);
const HWM: usize = 128 * 1024;
/// One peer packet total: app max_packet + CHANNEL_DATA framing(9) + wire OH(88).
fn one_packet_total(peer_max_packet: usize) -> usize {
    peer_max_packet + 9 + 4 + 1 + 19 + 64
}

/// Generic hard wait: polls `f` until true or fails after `timeout`.
async fn wait_for<F: FnMut() -> bool>(
    what: &str,
    timeout: Duration,
    mut f: F,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if f() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("HARD: timeout waiting {what}")
}

async fn wait_phase_eq(
    observe: &KexInstallObserveSlot,
    want: u8,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if observe.phase() == want {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!(
        "timeout waiting phase=={want} (got {} non_idle={})",
        observe.phase(),
        observe.non_idle()
    )
}

async fn wait_phase_clear(
    observe: &KexInstallObserveSlot,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if observe.phase() == 0 && !observe.non_idle() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!(
        "timeout waiting phase clear (phase={} non_idle={})",
        observe.phase(),
        observe.non_idle()
    )
}

async fn wait_need_submit(
    need: &NeedSubmitSeenSlot,
    observe: &KexInstallObserveSlot,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if need.count() > 0 && observe.phase() == 1 && observe.non_idle() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!(
        "timeout waiting NeedSubmit (need={} phase={} non_idle={})",
        need.count(),
        observe.phase(),
        observe.non_idle()
    )
}

// ─── R1 ───────────────────────────────────────────────────────────────────────

/// Rekey Done-before-ACK: client NEWKEYS + first new-key CHANNEL_DATA go out in
/// ONE socket write; server decrypts the data while the install is still
/// pending (hold); release completes exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_rekey_done_before_ack_decrypts_under_hold() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let hold = InstallAckHoldGate::new_held();
    hold.release(); // initial handshake free
    let observe = KexInstallObserveSlot::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let dh_flag = Arc::new(AtomicBool::new(false));

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: 32 * 1024,
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            install_ack_hold: Some(hold.clone()),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.dh_init_sent = Some(dh_flag.clone());
    // Keepalive gives the client a periodic poll_write so the coalesce release
    // has a deterministic trigger even when nothing else is being sent.
    client_cfg.keepalive_interval = Some(Duration::from_millis(200));
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let mut channel = session.channel_open_session().await?;

    // Arm deterministic freeze-at-rekey-DH-init.
    ctrl.attach_auto_freeze(dh_flag.clone());
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();

    hold.hold_again();
    let commits0 = observe.inbound_commits(); // initial handshake commit baseline
    let completions0 = observe.completions(); // initial completion baseline
    session.rekey_soon().await?;
    // HARD: server must park in WaitingAck (phase 2) with no peer Done — the
    // client is frozen after its DH-init, so the batch is sealed, the InstallAck
    // is held, and no NEWKEYS can arrive.
    wait_for("phase==2 && !after_known && non_idle", Duration::from_secs(5), || {
        observe.phase() == 2 && !observe.after_known() && observe.non_idle()
    })
    .await?;
    assert!(hold.is_held(), "R1 HARD: hold must be engaged");

    // Buffer client NEWKEYS + first new-key data, then release as ONE write.
    ctrl.arm_coalesce();
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    const MAGIC: &[u8] = b"R1-DONE-BEFORE-ACK-PAYLOAD";
    channel.data(&MAGIC[..]).await?;
    wait_for(
        "coalesce buffer holds NEWKEYS+CHANNEL_DATA",
        Duration::from_secs(5),
        || {
            ctrl.coalesce_appends() >= 2
                && ctrl.coalesce_bytes() >= MAGIC.len() as u64 + 16
        },
    )
    .await?;
    ctrl.release_coalesce();

    // HARD: aggregation delivered in exactly one inner socket write, data
    // decrypted under pending, connection alive, hold still engaged.
    wait_for(
        "NEWKEYS+data processed under pending",
        Duration::from_secs(5),
        || {
            observe.packets_while_pending() >= 1
                && observe.data_while_pending() >= MAGIC.len() as u64
        },
    )
    .await?;
    assert_eq!(
        ctrl.coalesce_flushes(),
        1,
        "R1 HARD: buffered NEWKEYS+data must be delivered in ONE socket write \
         (flushes={} partials={})",
        ctrl.coalesce_flushes(),
        ctrl.coalesce_partials()
    );
    assert_eq!(ctrl.coalesce_partials(), 0, "R1 HARD: no partial coalesce drain");
    assert_eq!(
        observe.inbound_commits(),
        commits0 + 1,
        "R1 HARD: exactly one new inbound commit (peer NEWKEYS)"
    );
    assert!(progress.session_alive(), "R1 HARD: session must stay alive");
    assert!(hold.is_held(), "R1 HARD: hold still active after data");

    hold.release();
    wait_phase_clear(&observe, Duration::from_secs(5)).await?;
    assert_eq!(observe.phase(), 0, "R1 HARD: phase=0 after release");
    assert!(!observe.non_idle(), "R1 HARD: Idle after release");
    assert_eq!(
        observe.completions(),
        completions0 + 1,
        "R1 HARD: exactly one new completion flush after release"
    );
    assert!(cause.get().is_none());
    assert!(progress.session_alive());
    Ok(())
}

/// Initial Done-before-ACK: the very first NEWKEYS + a new-keys client packet
/// are aggregated into ONE client socket write; both are decrypted while the
/// initial install is pending under hold. No phase=0 fallback: if the hold
/// window is missed, every wait below hard-fails.
///
/// Construction: the client auto-freezes after its DH-init; the test then arms
/// the coalesce gate and unfreezes, so the client's NEWKEYS (and a subsequent
/// keepalive the test drives through the owned Handle) are buffered instead of
/// written. Releasing the gate + one more keepalive delivers them in a single
/// inner socket write. (Server keepalives cannot trigger the drain here: the
/// server has no outbound cipher before Done, so it cannot write at all.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_initial_done_before_ack_survives_hold() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let hold = InstallAckHoldGate::new_held(); // held from before connect
    let observe = KexInstallObserveSlot::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let dh_flag = Arc::new(AtomicBool::new(false));

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 2 * 1024 * 1024,
            maximum_packet_size: 32 * 1024,
            first_channel_mode: ServerMode::Idle,
            handshake_deadline: Duration::from_secs(20),
            disconnect_cause_slot: Some(cause.clone()),
            install_ack_hold: Some(hold.clone()),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (stream, ctrl) = FaultInjectStream::connect(addr).await?;
    ctrl.attach_auto_freeze(dh_flag.clone());
    let mut client_cfg = default_client_config();
    client_cfg.window_size = 2 * 1024 * 1024;
    client_cfg.dh_init_sent = Some(dh_flag.clone());
    let connect_task = tokio::spawn({
        let progress = progress.clone();
        async move { connect_on_stream(stream, client_cfg, progress).await }
    });

    // HARD: initial batch sealed, InstallAck held, no client NEWKEYS yet — the
    // client froze itself right after its DH-init hit the wire.
    wait_for(
        "initial phase==2 && !after_known && non_idle",
        Duration::from_secs(10),
        || observe.phase() == 2 && !observe.after_known() && observe.non_idle(),
    )
    .await?;
    assert!(hold.is_held(), "R1 initial HARD: hold must be engaged");

    // Buffer the client NEWKEYS + one new-keys keepalive packet.
    ctrl.arm_coalesce();
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    // Connect completes once the client reads the server reply (its NEWKEYS is
    // buffered by the coalesce gate, not written).
    let mut session = tokio::time::timeout(Duration::from_secs(10), connect_task)
        .await
        .map_err(|_| anyhow::anyhow!("R1 initial HARD: connect did not finish"))???;
    session.send_keepalive(false).await?;
    wait_for(
        "coalesce buffer holds NEWKEYS+keepalive",
        Duration::from_secs(10),
        || ctrl.coalesce_appends() >= 2 && ctrl.coalesce_bytes() >= 60,
    )
    .await?;
    eprintln!(
        "r1 initial: coalesce appends={} bytes={}",
        ctrl.coalesce_appends(),
        ctrl.coalesce_bytes()
    );
    ctrl.release_coalesce();
    // One more client write drives the aggregate out in a single inner write.
    session.send_keepalive(false).await?;

    // HARD: one aggregated socket write; NEWKEYS committed inbound; at least
    // two packets (NEWKEYS + keepalive) decrypted while the initial install is
    // still pending under hold.
    wait_for(
        "initial packets decrypted under pending",
        Duration::from_secs(10),
        || {
            observe.after_known()
                && observe.inbound_commits() == 1
                && observe.packets_while_pending() >= 2
        },
    )
    .await?;
    assert_eq!(
        ctrl.coalesce_flushes(),
        1,
        "R1 initial HARD: buffered NEWKEYS+keepalive in ONE socket write \
         (flushes={} partials={})",
        ctrl.coalesce_flushes(),
        ctrl.coalesce_partials()
    );
    assert_eq!(
        ctrl.coalesce_partials(),
        0,
        "R1 initial HARD: no partial coalesce drain"
    );
    assert!(hold.is_held(), "R1 initial HARD: hold still engaged");
    assert!(progress.session_alive(), "R1 initial HARD: session alive");

    // Auth (SERVICE_REQUEST + USERAUTH_REQUEST) also decrypts under pending.
    auth_publickey(&mut session).await?;
    assert!(
        observe.packets_while_pending() >= 4,
        "R1 initial HARD: auth packets must also land under pending (packets={})",
        observe.packets_while_pending()
    );
    assert!(hold.is_held(), "R1 initial HARD: hold still engaged after auth");

    hold.release();
    wait_phase_clear(&observe, Duration::from_secs(5)).await?;
    assert_eq!(
        observe.completions(),
        1,
        "R1 initial HARD: exactly one completion after release"
    );
    assert!(cause.get().is_none());

    // Data flows post-release.
    let mut channel = session.channel_open_session().await?;
    channel.data(&b"R1-INITIAL-POST"[..]).await?;
    sleep(Duration::from_millis(100)).await;
    assert!(progress.session_alive(), "R1 initial HARD: session alive post-release");
    Ok(())
}

// ─── R2 ───────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_write_stalled_first_cause_under_need_submit() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let need = NeedSubmitSeenSlot::new();
    let observe = KexInstallObserveSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    // One-shot Full inject — must stay false through initial handshake.
    let force_full = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();

    let down_window = 16 * 1024 * 1024u32;
    let pkt = 64u32;
    let wd = Duration::from_secs(2);
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: wd,
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            need_submit_seen: Some(need.clone()),
            kex_install_observe: Some(observe.clone()),
            socket_hang: Some(hang.clone()),
            force_next_bulk_full: Some(force_full.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    flood_gate.release();
    sleep(Duration::from_millis(80)).await;
    // Arm force-Full for NEWKEYS install; keep socket live through the DH exchange.
    force_full.store(true, Ordering::SeqCst);
    session.rekey_soon().await?;

    // HARD: must observe NeedSubmit (Full at install) before watchdog wins.
    wait_need_submit(&need, &observe, Duration::from_secs(8)).await?;
    // Freeze socket progress so watchdog can win while NeedSubmit holds eligible bytes.
    hang.store(true, Ordering::SeqCst);
    let entered = std::time::Instant::now();
    while cause.get().is_none() {
        assert!(
            observe.non_idle() || observe.phase() != 0,
            "R2 HARD: must stay non-Idle while NeedSubmit eligible (phase={})",
            observe.phase()
        );
        if entered.elapsed() > Duration::from_secs(12) {
            break;
        }
        sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(
        cause.get(),
        Some(DisconnectCause::WriteStalled),
        "R2 HARD: first cause WriteStalled, got {:?}",
        cause.get()
    );
    Ok(())
}

// ─── R3 ───────────────────────────────────────────────────────────────────────

/// The NeedSubmit → advance chain must be driven by the Writer dequeue notify
/// → real capacity select arm, with the production 20ms retry timer DISABLED
/// and inbound wakes isolated (client frozen after its DH-init).
///
/// Construction (production FIFO, no KEX leapfrog):
/// 1. force-Full parks the install batch in NeedSubmit; the client auto-freezes
///    after its KEXDH_INIT, so no inbound packet can ever wake the session.
///    No server keepalive — that would pile `pending_outbound` and either
///    starve the batch or require a test-only priority fork.
/// 2. `dequeue_hold` pauses Writer mpsc pull. One IGNORE is injected via a
///    first-class select arm so a **single** real bulk cmd sits in the mpsc
///    and Session pending stays empty.
/// 3. force-Full cleared. Timer off, inbound frozen, loop-top advance off —
///    the ONLY remaining liveness source is a Writer dequeue → capacity
///    notify → capacity select arm.
/// 4. Releasing the hold dequeues that one cmd → notify → arm → production
///    `retry_pending` (empty) → NeedSubmit→WaitingAck. `install_advances`
///    is marked ONLY there, and only when pending is empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_capacity_arm_advances_need_submit_without_socket() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let need = NeedSubmitSeenSlot::new();
    let observe = KexInstallObserveSlot::new();
    let chain = CapacityChainSlot::new();
    let hold = Arc::new(AtomicBool::new(false));
    let force_full = Arc::new(AtomicBool::new(false));
    let inject = InjectIgnoreGate::new();
    let progress = Progress::new();
    let addr = free_addr();
    let dh_flag = Arc::new(AtomicBool::new(false));

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 8 * 1024 * 1024,
            maximum_packet_size: 64,
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            need_submit_seen: Some(need.clone()),
            kex_install_observe: Some(observe.clone()),
            force_next_bulk_full: Some(force_full.clone()),
            need_submit_timer_disable: true,
            capacity_chain: Some(chain.clone()),
            dequeue_hold: Some(hold.clone()),
            inject_ignore: Some(inject.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 8 * 1024 * 1024;
    client_cfg.maximum_packet_size = 64;
    client_cfg.dh_init_sent = Some(dh_flag.clone());
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let _ch = session.channel_open_session().await?;

    // Deterministic client freeze at rekey KEXDH_INIT: no inbound wake possible.
    ctrl.attach_auto_freeze(dh_flag.clone());
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();

    force_full.store(true, Ordering::SeqCst);
    let k0 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    wait_need_submit(&need, &observe, Duration::from_secs(8)).await?;

    // Park one real bulk cmd in the Writer mpsc. Session pending stays empty,
    // so the production FIFO retry-pending-then-KEX path can succeed on the
    // single freed slot.
    hold.store(true, Ordering::SeqCst);
    let bytes_written_marker = ctrl.bytes_written();
    inject.request();
    wait_for("one IGNORE parked in Writer mpsc", Duration::from_secs(5), || {
        inject.is_done()
    })
    .await?;
    assert_eq!(
        chain.install_advances(),
        0,
        "R3 HARD: no advance may happen while force-Full holds (timer disabled)"
    );

    let notifies_before = chain.dequeue_notifies();
    let arms_before = chain.arm_runs();
    force_full.store(false, Ordering::SeqCst);
    hold.store(false, Ordering::SeqCst);

    let t0 = std::time::Instant::now();
    loop {
        if chain.install_advances() >= 1 {
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(8),
            "R3 HARD: capacity chain never advanced NeedSubmit \
             (notifies {}→{} arms {}→{} advances={} phase={}) — \
             with the 20ms timer disabled and inbound frozen, only the \
             dequeue-notify → capacity arm path can advance",
            notifies_before,
            chain.dequeue_notifies(),
            arms_before,
            chain.arm_runs(),
            chain.install_advances(),
            observe.phase()
        );
        assert_eq!(
            ctrl.bytes_written(),
            bytes_written_marker,
            "R3 HARD: no inbound packet may reach the session before the advance"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        chain.dequeue_notifies() > notifies_before,
        "R3 HARD: Writer dequeue notify must fire after hold release ({}→{})",
        notifies_before,
        chain.dequeue_notifies()
    );
    assert!(
        chain.arm_runs() > arms_before,
        "R3 HARD: real capacity select arm must run ({}→{})",
        arms_before,
        chain.arm_runs()
    );
    let p = observe.phase();
    assert!(
        p == 2 || p == 3,
        "R3 HARD: phase must be 2/3 after the arm advance (phase={p})"
    );
    assert_eq!(
        ctrl.bytes_written(),
        bytes_written_marker,
        "R3 HARD: advance must happen with zero inbound traffic"
    );

    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    wait_for(
        "rekey completes after unfreeze",
        Duration::from_secs(8),
        || progress.kex_count.load(Ordering::Relaxed) > k0,
    )
    .await?;
    Ok(())
}

// ─── R4 ───────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_hwm_tiny_max_packet_ledger_max() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let progress = Progress::new();
    let addr = free_addr();
    let peer_max = 16usize;

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: peer_max as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = peer_max as u32;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("tiny flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    ctrl.freeze_read();
    wait_for(
        "tiny linearized total >= HWM && full_hits>0",
        Duration::from_secs(8),
        || ledger.max() >= HWM && ledger.full_hits() > 0,
    )
    .await?;

    let max = ledger.max();
    let allow = one_packet_total(peer_max);
    eprintln!(
        "r4 tiny-max-packet ledger max={max} hwm={HWM} allow={allow} mismatch={} full_hits={} intake_blocks={} parts={:?}",
        ledger.mismatch(),
        ledger.full_hits(),
        ledger.intake_blocks(),
        ledger.parts()
    );
    assert!(
        max >= HWM,
        "R4 tiny HARD: linearized total must cross HWM (max={max} hwm={HWM})"
    );
    assert!(
        max <= HWM + allow,
        "R4 tiny HARD: max {max} > HWM+one_peer_packet {}",
        HWM + allow
    );
    assert!(
        ledger.full_hits() > 0,
        "R4 tiny HARD: tiny packets must press the Writer mpsc to real count-Full \
         (full_hits={})",
        ledger.full_hits()
    );
    assert_eq!(
        ledger.mismatch(),
        0,
        "R4 tiny HARD: no ledger accounting mismatch may be silently swallowed"
    );
    ctrl.unfreeze_read();
    let _ = session;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_hwm_flood_presses_ledger_max() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let progress = Progress::new();
    let addr = free_addr();
    // Peer max-packet matches flood chunk so one-packet allowance is the real bound.
    let peer_max = 16 * 1024usize;

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 8 * 1024 * 1024,
            maximum_packet_size: peer_max as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            ledger_max: Some(ledger.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 8 * 1024 * 1024;
    client_cfg.maximum_packet_size = peer_max as u32;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    ctrl.freeze_read();
    wait_for(
        "flood linearized total >= HWM && intake_blocks>0",
        Duration::from_secs(8),
        || ledger.max() >= HWM && ledger.intake_blocks() > 0,
    )
    .await?;

    let max = ledger.max();
    let allow = one_packet_total(peer_max);
    eprintln!(
        "r4 flood ledger max={max} hwm={HWM} allow={allow} mismatch={} full_hits={} intake_blocks={}",
        ledger.mismatch(),
        ledger.full_hits(),
        ledger.intake_blocks()
    );
    assert!(
        max >= HWM,
        "R4 flood HARD: linearized total must cross HWM (max={max} hwm={HWM})"
    );
    assert!(
        max <= HWM + allow,
        "R4 flood HARD: max {max} > HWM+one_peer_packet {}",
        HWM + allow
    );
    // 16 KiB packets trip the HWM budget at session intake long before the
    // Writer mpsc count limit — the budget refusal is the observable Full hit.
    assert!(
        ledger.intake_blocks() > 0,
        "R4 flood HARD: intake must be refused at the HWM budget at least once \
         (intake_blocks={})",
        ledger.intake_blocks()
    );
    assert_eq!(
        ledger.mismatch(),
        0,
        "R4 flood HARD: no ledger accounting mismatch may be silently swallowed"
    );
    ctrl.unfreeze_read();
    let _ = session;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_hwm_kex_need_submit_in_ledger() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let need = NeedSubmitSeenSlot::new();
    let observe = KexInstallObserveSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    let force_full = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let peer_max = 64usize;

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 8 * 1024 * 1024,
            maximum_packet_size: peer_max as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            rekey_deadline: Duration::from_secs(30),
            need_submit_seen: Some(need.clone()),
            kex_install_observe: Some(observe.clone()),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            force_next_bulk_full: Some(force_full.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 8 * 1024 * 1024;
    client_cfg.maximum_packet_size = peer_max as u32;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    sleep(Duration::from_millis(100)).await;
    // Live socket for DH; force Full on NEWKEYS install → NeedSubmit in ledger.
    force_full.store(true, Ordering::SeqCst);
    session.rekey_soon().await?;
    wait_need_submit(&need, &observe, Duration::from_secs(8)).await?;
    hang.store(true, Ordering::SeqCst); // hold peak for sampling
    sleep(Duration::from_millis(100)).await;

    let max = ledger.max();
    let allow = one_packet_total(peer_max);
    eprintln!(
        "r4 kex ledger max={max} hwm={HWM} allow={allow} need_submit={} mismatch={}",
        need.count(),
        ledger.mismatch()
    );
    assert!(need.count() > 0, "R4 kex HARD: need_submit must be >0");
    assert!(
        ledger.kex_peak() > 0,
        "R4 kex HARD: FullLedger KEX component must enter the linearized total \
         (kex_peak={})",
        ledger.kex_peak()
    );
    assert!(
        max <= HWM + allow,
        "R4 kex HARD: max {max} > HWM+one {}",
        HWM + allow
    );
    assert_eq!(
        ledger.mismatch(),
        0,
        "R4 kex HARD: no ledger accounting mismatch may be silently swallowed"
    );
    let _ = session;
    Ok(())
}

// ─── R5 ───────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_rekey_success_completes() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            disconnect_cause_slot: Some(cause.clone()),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let _ch = session.channel_open_session().await?;
    let k0 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if progress.kex_count.load(Ordering::Relaxed) > k0 {
            break;
        }
        sleep(Duration::from_millis(30)).await;
    }
    assert!(progress.kex_count.load(Ordering::Relaxed) > k0);
    wait_phase_clear(&observe, Duration::from_secs(3)).await?;
    assert!(cause.get().is_none());
    Ok(())
}

/// Rekey Writer-fail: with the install parked at phase 2, inbound ALREADY
/// committed and the peer Done consumed, the next socket write fails. The
/// staged PeerError must be the run-loop's unique first cause; no completion,
/// no replay, no deadline clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_rekey_writer_fail_consumes_peer_error() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let observe = KexInstallObserveSlot::new();
    let hold = InstallAckHoldGate::new_held();
    hold.release(); // initial handshake free
    let fail = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            rekey_deadline: Duration::from_secs(20),
            // Server-initiated keepalives give a deterministic next socket write.
            keepalive_interval: Some(Duration::from_millis(200)),
            keepalive_max: 0,
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            kex_install_observe: Some(observe.clone()),
            install_ack_hold: Some(hold.clone()),
            fail_next_socket_write: Some(fail.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let _ch = session.channel_open_session().await?;

    // Baselines: the INITIAL handshake completion already marked
    // completion/deadline-clear once — the fail contract is "no FURTHER marks".
    let completions0 = observe.completions();
    let replays0 = observe.replays();
    let clears0 = observe.deadline_clears();

    hold.hold_again();
    let commits0 = observe.inbound_commits(); // initial handshake commit baseline
    session.rekey_soon().await?;
    // HARD contract precondition: outbound install parked (phase 2), inbound
    // already switched (peer NEWKEYS committed), KEX non-Idle, deadline armed.
    wait_for(
        "phase==2 && inbound committed && non_idle",
        Duration::from_secs(5),
        || {
            observe.phase() == 2
                && observe.after_known()
                && observe.inbound_commits() == commits0 + 1
                && observe.non_idle()
        },
    )
    .await?;
    assert_eq!(
        observe.deadline_clears(),
        clears0,
        "R5 HARD: deadline must be armed (no clear since baseline)"
    );

    // Inject: the next Writer socket write (server keepalive) fails.
    fail.store(true, Ordering::SeqCst);
    wait_for("PeerError first cause", Duration::from_secs(10), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;

    // HARD failure contract.
    assert!(
        !fail.load(Ordering::SeqCst),
        "R5 HARD: fail injection must be consumed"
    );
    assert_eq!(
        cause.get(),
        Some(DisconnectCause::PeerError),
        "R5 HARD: staged PeerError must be the unique first cause, got {:?}",
        cause.get()
    );
    assert_eq!(
        observe.completions(),
        completions0,
        "R5 HARD: no completion flush may run on the fail path"
    );
    assert_eq!(
        observe.replays(),
        replays0,
        "R5 HARD: no replay may run on the fail path"
    );
    assert_eq!(
        observe.deadline_clears(),
        clears0,
        "R5 HARD: deadline must NOT be cleared by the fail path"
    );
    wait_for("session torn down", Duration::from_secs(5), || {
        !progress.session_alive()
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_initial_success() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            disconnect_cause_slot: Some(cause.clone()),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let _ch = session.channel_open_session().await?;
    wait_phase_clear(&observe, Duration::from_secs(3)).await?;
    assert!(cause.get().is_none());
    Ok(())
}

/// TRUE initial Writer-fail: the initial install is parked at phase 2 with the
/// client's NEWKEYS already committed inbound; the first post-NEWKEYS server
/// socket write (SERVICE_ACCEPT) fails. Same failure contract as the rekey
/// twin — this is no longer a renamed rekey test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_initial_writer_fail_consumes_peer_error() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let observe = KexInstallObserveSlot::new();
    let hold = InstallAckHoldGate::new_held(); // held from before connect
    let fail = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let dh_flag = Arc::new(AtomicBool::new(false));

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            handshake_deadline: Duration::from_secs(20),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            kex_install_observe: Some(observe.clone()),
            install_ack_hold: Some(hold.clone()),
            fail_next_socket_write: Some(fail.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (stream, ctrl) = FaultInjectStream::connect(addr).await?;
    ctrl.attach_auto_freeze(dh_flag.clone());
    let mut client_cfg = default_client_config();
    client_cfg.dh_init_sent = Some(dh_flag.clone());
    let connect_task = tokio::spawn({
        let progress = progress.clone();
        async move {
            let mut h = connect_on_stream(stream, client_cfg, progress).await?;
            auth_publickey(&mut h).await?;
            Ok::<_, anyhow::Error>(h)
        }
    });

    // HARD: initial batch sealed, InstallAck held, client frozen post-DH-init.
    wait_for(
        "initial phase==2 && !after_known && non_idle",
        Duration::from_secs(10),
        || observe.phase() == 2 && !observe.after_known() && observe.non_idle(),
    )
    .await?;

    // Let the client NEWKEYS in: inbound commits, still parked under hold.
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    wait_for(
        "initial inbound committed under hold",
        Duration::from_secs(10),
        || {
            observe.after_known()
                && observe.inbound_commits() == 1
                && observe.phase() == 2
                && observe.non_idle()
        },
    )
    .await?;
    assert_eq!(observe.deadline_clears(), 0, "R5 initial HARD: deadline armed");

    // Inject: the next server socket write (SERVICE_ACCEPT) fails.
    fail.store(true, Ordering::SeqCst);
    wait_for("PeerError first cause", Duration::from_secs(10), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;

    // HARD failure contract (initial).
    assert!(
        !fail.load(Ordering::SeqCst),
        "R5 initial HARD: fail injection must be consumed"
    );
    assert_eq!(
        cause.get(),
        Some(DisconnectCause::PeerError),
        "R5 initial HARD: staged PeerError must be the unique first cause, got {:?}",
        cause.get()
    );
    assert_eq!(
        observe.completions(),
        0,
        "R5 initial HARD: no completion flush on the fail path"
    );
    assert_eq!(
        observe.replays(),
        0,
        "R5 initial HARD: no replay on the fail path"
    );
    assert_eq!(
        observe.deadline_clears(),
        0,
        "R5 initial HARD: deadline must NOT be cleared by the fail path"
    );
    // The connect/auth task must observe the teardown (auth cannot succeed).
    let res = tokio::time::timeout(Duration::from_secs(10), connect_task)
        .await
        .map_err(|_| anyhow::anyhow!("R5 initial HARD: connect task hung"))?;
    assert!(
        res.is_err() || matches!(&res, Ok(Err(_))),
        "R5 initial HARD: auth must not succeed after Writer fail"
    );
    Ok(())
}

// ─── R6 ───────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_second_rekey_completes() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            rekey_deadline: Duration::from_secs(15),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let _ch = session.channel_open_session().await?;

    let k0 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if progress.kex_count.load(Ordering::Relaxed) > k0 {
            break;
        }
        sleep(Duration::from_millis(30)).await;
    }
    assert!(progress.kex_count.load(Ordering::Relaxed) > k0);
    wait_phase_clear(&observe, Duration::from_secs(5)).await?;

    let k1 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if progress.kex_count.load(Ordering::Relaxed) > k1 {
            break;
        }
        sleep(Duration::from_millis(30)).await;
    }
    assert!(
        progress.kex_count.load(Ordering::Relaxed) > k1,
        "R6 HARD: second rekey must complete"
    );
    wait_phase_clear(&observe, Duration::from_secs(5)).await?;
    assert!(progress.session_alive());
    Ok(())
}

/// Done-before-ACK park window: second KEXINIT injected while the first rekey
/// is parked at phase 2 with the peer Done already consumed. Park exactly once,
/// replay exactly once, trigger result consumed, second rekey must complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_second_rekey_during_pending_done_before_ack() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let hold = InstallAckHoldGate::new_held();
    hold.release();
    let observe = KexInstallObserveSlot::new();
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            rekey_deadline: Duration::from_secs(20),
            install_ack_hold: Some(hold.clone()),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let _ch = session.channel_open_session().await?;

    hold.hold_again();
    let k0 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    // HARD: Done-before-ACK window — peer NEWKEYS committed (after known),
    // InstallAck still held (phase 2).
    wait_for(
        "Done-before-ACK window (phase==2 && after_known)",
        Duration::from_secs(5),
        || observe.phase() == 2 && observe.after_known() && observe.non_idle(),
    )
    .await?;
    assert!(hold.is_held(), "R6 HARD: hold engaged");

    // Second rekey while the first is pending — trigger result NOT dropped.
    session.rekey_soon().await?;
    // HARD: server parks the second KEXINIT exactly once (no disconnect).
    wait_for("second KEXINIT parked", Duration::from_secs(5), || {
        observe.parks() == 1
    })
    .await?;
    assert_eq!(observe.replays(), 0, "R6 HARD: no replay before finalize");

    hold.release();
    // HARD: finalize → replay exactly once → BOTH rekeys complete client-side.
    wait_for("both rekeys complete", Duration::from_secs(10), || {
        progress.kex_count.load(Ordering::Relaxed) >= k0 + 2
    })
    .await?;
    assert_eq!(observe.parks(), 1, "R6 HARD: exactly one park");
    assert_eq!(observe.replays(), 1, "R6 HARD: exactly one replay");
    wait_phase_clear(&observe, Duration::from_secs(8)).await?;
    assert!(progress.session_alive());
    Ok(())
}

/// Illegal nested KEXINIT during ACK-before-Done (RFC 4253 §7.1 forbids a
/// second KEXINIT after sending KEXINIT and before NEWKEYS). This is **not**
/// a legal R6 proof — a legitimate peer cannot put KEXINIT#2 on the wire
/// before its own NEWKEYS#1. Kept as a resilience test: the server must park
/// the illegal packet exactly once, replay exactly once, not wedge, and still
/// complete the second rekey. Production does not (yet) disconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_illegal_nested_kexinit_during_ack_before_done() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let dh_flag = Arc::new(AtomicBool::new(false));
    let inject = Arc::new(AtomicBool::new(false));

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            rekey_write_limit: usize::MAX / 4,
            rekey_deadline: Duration::from_secs(20),
            kex_install_observe: Some(observe.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.dh_init_sent = Some(dh_flag.clone());
    client_cfg.inject_kexinit = Some(inject.clone());
    // The client keepalive timer arm is NOT kex-gated (unlike the Msg receiver),
    // so it fires mid-rekey and its flush consumes the inject flag.
    client_cfg.keepalive_interval = Some(Duration::from_millis(50));
    client_cfg.keepalive_max = 0;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let _ch = session.channel_open_session().await?;

    ctrl.attach_auto_freeze(dh_flag.clone());
    dh_flag.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();

    let k0 = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    // HARD: ACK-before-Done window — InstallAck consumed (phase 3), no peer
    // Done (client frozen after DH-init).
    wait_for(
        "ACK-before-Done window (phase==3 && !after_known)",
        Duration::from_secs(5),
        || observe.phase() == 3 && !observe.after_known() && observe.non_idle(),
    )
    .await?;

    // Inject an *illegal* nested KEXINIT (RFC 4253 §7.1). Client kex state
    // is untouched; the keepalive timer arm flushes it (the Msg receiver
    // is kex-gated mid-rekey). This is resilience, not a legal second rekey.
    inject.store(true, Ordering::SeqCst);
    // HARD: server parks it exactly once while the install is pending.
    wait_for("second KEXINIT parked", Duration::from_secs(5), || {
        observe.parks() == 1
    })
    .await?;
    assert_eq!(observe.replays(), 0, "R6 HARD: no replay before Done");
    assert!(
        !inject.load(Ordering::SeqCst),
        "R6 HARD: KEXINIT injection must be consumed"
    );

    // Unfreeze: client finishes rekey #1 → server Done → finalize → replay →
    // second rekey runs to completion. Disarm permanently: the second rekey's
    // DH-init sets `dh_init_sent` again and must NOT re-engage the stall.
    ctrl.disarm_auto_freeze();
    wait_for("both rekeys complete", Duration::from_secs(10), || {
        progress.kex_count.load(Ordering::Relaxed) >= k0 + 2
    })
    .await?;
    assert_eq!(observe.parks(), 1, "R6 HARD: exactly one park");
    assert_eq!(observe.replays(), 1, "R6 HARD: exactly one replay");
    wait_phase_clear(&observe, Duration::from_secs(8)).await?;
    assert!(progress.session_alive());
    Ok(())
}

// ─── F1: real window cliff ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f1_window_adjust_crosses_two_replenishments() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    // 8 MiB window — must cross TWO full replenishments on top of the initial
    // window credit (24 MiB total), with at least two WINDOW_ADJUST packets
    // hard-counted server-side.
    let down_window = 8 * 1024 * 1024u32;
    let pkt = 16 * 1024u32;
    let ledger = LedgerMaxSlot::new();
    let adjust_seen = Arc::new(AtomicU64::new(0));
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            window_adjust_seen: Some(adjust_seen.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    // Strictly beyond initial window + two full replenishments.
    let target = 3 * down_window as u64 + pkt as u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while progress.total() < target {
        if std::time::Instant::now() >= deadline {
            break;
        }
        assert!(progress.session_alive(), "F1: session died mid-growth");
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        progress.total() >= target,
        "F1 HARD: must exceed initial window + two replenishments (need {target}, got {})",
        progress.total()
    );
    assert!(
        adjust_seen.load(Ordering::Relaxed) >= 2,
        "F1 HARD: server must see >=2 WINDOW_ADJUST replenishments (got {})",
        adjust_seen.load(Ordering::Relaxed)
    );
    let max = ledger.max();
    let allow = one_packet_total(pkt as usize);
    eprintln!(
        "f1 window-cliff total={} ledger_max={max} allow={allow} adjusts={} mismatch={}",
        progress.total(),
        adjust_seen.load(Ordering::Relaxed),
        ledger.mismatch()
    );
    assert!(
        max <= HWM + allow,
        "F1 HARD: ledger max {max} > HWM+one_packet {} parts(w/p/k/e)={:?}",
        HWM + allow,
        ledger.parts()
    );
    assert_eq!(
        ledger.mismatch(),
        0,
        "F1 HARD: no ledger accounting mismatch may be silently swallowed"
    );
    let _ = session;
    Ok(())
}

// ─── fix13: deferred WINDOW_ADJUST recovery ─────────────────────────────────

/// Bidirectional pressure: outbound hits HWM (ADJUST skipped), inbound window
/// exhausts, then outbound drain must replay the grant so uplink resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f13_deferred_window_adjust_recovers_after_outbound_drain() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let flood_gate = FloodStartGate::new();
    let grants = DeferredGrantSlot::new();
    let ledger = LedgerMaxSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let deq_hold = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let server_in_window = 64 * 1024u32;
    let hard = HWM + one_packet_total(pkt as usize);

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: server_in_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            secondary_mode: ServerMode::DrainInbound,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            dequeue_hold: Some(deq_hold.clone()),
            deferred_grant: Some(grants.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let down = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(down);
    let up = session.channel_open_session().await?;

    flood_gate.release();
    wait_for("downlink moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    deq_hold.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    // Stop Writer dequeue so new seals Full-park in Session pending
    // and live sealed cannot drain below hard-97.
    sleep(Duration::from_millis(200)).await;
    wait_for("outbound at HWM", Duration::from_secs(8), || {
        ledger.max() >= HWM
    })
    .await?;
    eprintln!(
        "f13 deferred at HWM max={} hard={hard} inserts={} emitted={}",
        ledger.max(),
        grants.inserts(),
        grants.emitted()
    );

    let emitted_before_uplink = grants.emitted();

    let chunk = vec![0x5au8; pkt as usize];
    let mut first = 0usize;
    for _ in 0..16 {
        match tokio::time::timeout(Duration::from_millis(400), up.data_bytes(chunk.clone())).await {
            Ok(Ok(())) => first += chunk.len(),
            _ => break,
        }
    }
    assert!(
        first > 0,
        "F13 HARD: uplink must send something before window exhaust"
    );
    eprintln!(
        "f13 deferred after uplink first={first} inserts={} emitted={} max={}",
        grants.inserts(),
        grants.emitted(),
        ledger.max()
    );
    wait_for("deferred insert", Duration::from_secs(3), || {
        grants.inserts() > 0
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} (first={first} inserts={} emitted={} max={})",
            grants.inserts(),
            grants.emitted(),
            ledger.max()
        )
    })?;
    assert!(
        grants.inserts() > 0,
        "F13 HARD: deferred insert must fire (inserts={} emitted={})",
        grants.inserts(),
        grants.emitted()
    );

    let stalled = tokio::time::timeout(Duration::from_millis(300), up.data_bytes(chunk.clone())).await;
    assert!(
        stalled.is_err(),
        "F13 HARD: peer send window must be 0 while grant is deferred"
    );

    deq_hold.store(false, Ordering::SeqCst);
    hang.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    wait_for("deferred replay+emit", Duration::from_secs(5), || {
        grants.replays() > 0 && grants.emitted() > emitted_before_uplink
    })
    .await?;
    let recovered = tokio::time::timeout(Duration::from_secs(5), up.data_bytes(chunk)).await;
    assert!(
        recovered.is_ok() && recovered.unwrap().is_ok(),
        "F13 HARD: deferred WINDOW_ADJUST must restore uplink after replay \
         (inserts={} replays={} emitted={})",
        grants.inserts(),
        grants.replays(),
        grants.emitted()
    );
    Ok(())
}

// ─── fix13: slow healthy kex must not be WriteStalled ───────────────────────

/// WD < rekey_deadline: armed → drain (eligible=0 / disarm) → slow in-budget
/// kex must not WriteStalled. Missing any of the three edges is a hard fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f13_slow_kex_after_drain_is_not_write_stalled() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let flood_gate = FloodStartGate::new();
    let hold = russh::client::test_hooks::RekeyHoldGate::new();
    let wd_obs = WatchdogObserveSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let wd = Duration::from_secs(2);

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: 16 * 1024,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: wd,
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(10),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            watchdog_observe: Some(wd_obs.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = 16 * 1024;
    client_cfg.rekey_hold = Some(hold.clone());
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    wait_for("watchdog armed", Duration::from_secs(5), || {
        wd_obs.ever_armed()
    })
    .await?;

    hold.arm();
    session.rekey_soon().await?;
    wait_for("rekey hold incomplete", Duration::from_secs(5), || {
        hold.rekey_held_incomplete()
    })
    .await?;
    let kex_gen = wd_obs.last_rekey_gen();
    assert!(
        kex_gen > 0,
        "F13 HARD: slow kex must publish an active rekey generation"
    );

    wait_for("eligible drained / watchdog disarmed", Duration::from_secs(5), || {
        wd_obs.disarmed_after_arm() && !wd_obs.is_armed() && wd_obs.last_eligible() == 0
    })
    .await?;

    sleep(wd + Duration::from_secs(1)).await;
    assert!(
        progress.session_alive(),
        "F13 HARD: healthy slow kex must keep the session alive"
    );
    assert_eq!(
        cause.get(),
        None,
        "F13 HARD: drained staging + in-budget kex must not WriteStalled, got {:?}",
        cause.get()
    );
    assert!(
        hold.rekey_held_incomplete(),
        "F13 HARD: kex must still be incomplete under hold"
    );
    assert_eq!(
        wd_obs.last_rekey_gen(),
        kex_gen,
        "F13 HARD: must stay on the same rekey generation (was {kex_gen})"
    );
    Ok(())
}

// ─── fix13: control-plane replies bounded at hard cap ────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f13_global_request_replies_bounded_at_hwm() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024usize;

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: pkt as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt as u32;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    let allow = one_packet_total(pkt);
    let hard = HWM + allow;
    wait_for("near HWM", Duration::from_secs(8), || {
        ledger.max() >= HWM
    })
    .await?;

    for i in 0..64 {
        let _ = tokio::time::timeout(
            Duration::from_millis(50),
            session.tcpip_forward("127.0.0.1", 18000 + i),
        )
        .await;
    }
    let max = ledger.max();
    eprintln!("f13 control-plane bound max={max} hwm={HWM} allow={allow} hard={hard}");
    assert!(
        max <= hard,
        "F13 HARD: GLOBAL_REQUEST replies must not grow past HWM+one (max={max} hard={hard})"
    );
    Ok(())
}

/// r12 A: live total at hard-control_weight, then want_reply flood, max≤hard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f14_control_reply_stays_at_hard_edge() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024usize;
    let hard = HWM + one_packet_total(pkt);

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: pkt as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt as u32;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    wait_for("hard-control edge", Duration::from_secs(8), || {
        ledger.max() >= HWM
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} (max={} hwm={HWM} hard={hard} parts={:?} intake={})",
            ledger.max(),
            ledger.parts(),
            ledger.intake_blocks()
        )
    })?;
    for i in 0..64 {
        let _ = tokio::time::timeout(
            Duration::from_millis(40),
            session.tcpip_forward("127.0.0.1", 19000 + i),
        )
        .await;
    }
    let max = ledger.max();
    eprintln!("f14 edge control max={max} hard={hard}");
    assert!(
        max <= hard,
        "F14 HARD: control replies at hard-control edge must stay ≤ hard (max={max})"
    );
    Ok(())
}

/// r12 B: same pressure under slow kex; control flood still ≤ hard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f14_control_reply_during_slow_kex_stays_at_hard() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    let hold = russh::client::test_hooks::RekeyHoldGate::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024usize;
    let hard = HWM + one_packet_total(pkt);

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: pkt as u32,
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            rekey_deadline: Duration::from_secs(15),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt as u32;
    client_cfg.rekey_hold = Some(hold.clone());
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    wait_for("HWM before kex", Duration::from_secs(8), || {
        ledger.max() >= HWM
    })
    .await?;
    hang.store(false, Ordering::SeqCst);
    hold.arm();
    let _ = session.rekey_soon().await;
    wait_for("slow kex hold", Duration::from_secs(5), || {
        hold.rekey_held_incomplete()
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    for i in 0..64 {
        let _ = tokio::time::timeout(
            Duration::from_millis(40),
            session.tcpip_forward("127.0.0.1", 20000 + i),
        )
        .await;
    }
    let max = ledger.max();
    let parts = ledger.parts();
    let kex_peak = ledger.kex_peak();
    let max_ex_kex = ledger.max_excluding_kex_need();
    let kex_jump = ledger.last_kex_jump();
    eprintln!(
        "f14 kex-control max={max} hard={hard} parts=[w={} pend={} kex={} enc={}] \
         kex_peak={kex_peak} kex_jump={kex_jump} max_ex_kex={max_ex_kex}",
        parts[0], parts[1], parts[2], parts[3]
    );
    // KEX NeedSubmit is allowed to flow (S2b) and is not an admit_control_reply
    // subject. Control/data stay at hard; the NeedSubmit batch is the only
    // legal overshoot, bounded by the observed kex_peak (0 when no kex landed).
    assert!(
        max <= hard.saturating_add(kex_peak),
        "F14 HARD: total may exceed hard only by the NeedSubmit batch \
         (max={max} hard={hard} kex_peak={kex_peak} max_ex_kex={max_ex_kex} parts={parts:?})"
    );
    assert!(
        max_ex_kex <= hard,
        "F14 HARD: control/data (excluding NeedSubmit) must stay ≤ hard \
         (max_ex_kex={max_ex_kex} hard={hard} parts={parts:?})"
    );
    Ok(())
}

/// r13 residual / fix14b: same hard-edge shape as
/// `f14_control_reply_stays_at_hard_edge`, but the flood is
/// CHANNEL_REQUEST(exec, want_reply) on a second Idle channel.
/// Handler emits CHANNEL_SUCCESS (weight 93). max must stay ≤ hard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f14b_channel_reply_stays_at_hard_edge() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let ledger = LedgerMaxSlot::new();
    let flood_gate = FloodStartGate::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024usize;
    let hard = HWM + one_packet_total(pkt);

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: 4 * 1024 * 1024,
            maximum_packet_size: pkt as u32,
            first_channel_mode: ServerMode::FloodForever,
            secondary_mode: ServerMode::Idle,
            flood_start: Some(flood_gate.clone()),
            rekey_write_limit: usize::MAX / 4,
            write_progress_deadline: Duration::from_secs(30),
            ledger_max: Some(ledger.clone()),
            socket_hang: Some(hang.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt as u32;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let flood_ch = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(flood_ch);
    let idle_ch = session.channel_open_session().await?;
    flood_gate.release();
    wait_for("flood moving", Duration::from_secs(5), || {
        progress.total() > 0
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    wait_for("hard-control edge", Duration::from_secs(8), || {
        ledger.max() >= HWM
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} (max={} hwm={HWM} hard={hard} parts={:?} intake={})",
            ledger.max(),
            ledger.parts(),
            ledger.intake_blocks()
        )
    })?;
    let max_before = ledger.max();
    for i in 0..64 {
        let _ = idle_ch.exec(true, format!("f14b-{i}")).await;
    }
    // `Channel::exec` only queues the request (unlike `tcpip_forward`,
    // which waits for REQUEST_SUCCESS). Give Session time to ingest
    // the want_reply flood and hit admit.
    sleep(Duration::from_millis(400)).await;
    let max = ledger.max();
    eprintln!("f14b channel-reply max_before={max_before} max={max} hard={hard}");
    assert!(
        max <= hard,
        "F14b HARD: channel replies at hard-control edge must stay ≤ hard (max={max})"
    );
    Ok(())
}

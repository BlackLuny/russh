//! S6a: I5 epoch counters + four-direction rekey trigger + seqn-wrap-near.
//!
//! Requires `--features _test_hooks`.
//!
//! cargo test -p russh --features _test_hooks --test test_s6a_rekey -- --nocapture

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::*;
use russh::server::{
    InstallAckHoldGate, KexInstallObserveSlot, ReaderObserveSlot, RekeyI6, WriterObserveSlot,
};
use tokio::time::{sleep, timeout};

const GRACE: Duration = Duration::from_secs(1);
const NEAR: u64 = (1u64 << 31) - 8;
const THRESHOLD: u64 = 1u64 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    RekeyStarted,
    NoRekey,
    TriggeredFromObserve,
    PacketTriggerSkipped,
    SeqnResetOnNonStrict,
    StormDoubleTrigger,
}

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

fn preferred_without_strict() -> russh::Preferred {
    use std::borrow::Cow;
    use russh::kex;
    static KEX: &[kex::Name] = &[
        kex::MLKEM768X25519_SHA256,
        kex::CURVE25519,
        kex::CURVE25519_PRE_RFC_8731,
        kex::DH_G14_SHA256,
        kex::EXTENSION_SUPPORT_AS_CLIENT,
        kex::EXTENSION_SUPPORT_AS_SERVER,
    ];
    russh::Preferred {
        kex: Cow::Borrowed(KEX),
        ..russh::Preferred::default()
    }
}

struct S6aSetup {
    _session: russh::client::Handle<harness::CountingClient>,
    channel: russh::Channel<russh::client::Msg>,
    observe: Arc<KexInstallObserveSlot>,
    i6: Arc<RekeyI6>,
    out_pkts: Arc<AtomicU64>,
    in_pkts: Arc<AtomicU64>,
    out_bytes: Arc<AtomicU64>,
    in_bytes: Arc<AtomicU64>,
    writer_obs: Arc<WriterObserveSlot>,
    reader_obs: Arc<ReaderObserveSlot>,
}

struct S6aOpts {
    invert_observe: bool,
    invert_skip_pkts: bool,
    invert_skip_idle: bool,
    flood: bool,
    flood_start: Option<Arc<FloodStartGate>>,
    nonstrict: bool,
    max_bytes: u64,
    ack_hold: Option<Arc<InstallAckHoldGate>>,
}

impl Default for S6aOpts {
    fn default() -> Self {
        Self {
            invert_observe: false,
            invert_skip_pkts: false,
            invert_skip_idle: false,
            flood: false,
            flood_start: None,
            nonstrict: false,
            max_bytes: u64::MAX / 4,
            ack_hold: None,
        }
    }
}

async fn connect_s6a(opts: S6aOpts) -> Result<S6aSetup, anyhow::Error> {
    let observe = KexInstallObserveSlot::new();
    let i6 = RekeyI6::new();
    let out_pkts = Arc::new(AtomicU64::new(0));
    let in_pkts = Arc::new(AtomicU64::new(0));
    let out_bytes = Arc::new(AtomicU64::new(0));
    let in_bytes = Arc::new(AtomicU64::new(0));
    let writer_obs = WriterObserveSlot::new();
    let reader_obs = ReaderObserveSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: if opts.flood {
                ServerMode::FloodForever
            } else {
                ServerMode::Idle
            },
            flood_start: opts.flood_start,
            max_bytes: opts.max_bytes,
            kex_install_observe: Some(observe.clone()),
            rekey_i6: Some(i6.clone()),
            rekey_out_packets: Some(out_pkts.clone()),
            rekey_in_packets: Some(in_pkts.clone()),
            rekey_out_bytes: Some(out_bytes.clone()),
            rekey_in_bytes: Some(in_bytes.clone()),
            writer_observe: Some(writer_obs.clone()),
            reader_observe: Some(reader_obs.clone()),
            invert_i5_observe_only: opts.invert_observe,
            invert_skip_packet_rekey: opts.invert_skip_pkts,
            invert_skip_idle_gate: opts.invert_skip_idle,
            inbound_ack_hold: opts.ack_hold,
            preferred: if opts.nonstrict {
                Some(preferred_without_strict())
            } else {
                None
            },
            teardown_grace: GRACE,
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    if opts.nonstrict {
        client_cfg.preferred = preferred_without_strict();
    }
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress).await?;
    let channel = session.channel_open_session().await?;
    Ok(S6aSetup {
        _session: session,
        channel,
        observe,
        i6,
        out_pkts,
        in_pkts,
        out_bytes,
        in_bytes,
        writer_obs,
        reader_obs,
    })
}

fn classify(setup: &S6aSetup) -> Class {
    if setup.observe.non_idle() || setup.i6.triggers() > 0 {
        Class::RekeyStarted
    } else {
        Class::NoRekey
    }
}

/// W1: seed production outbound packets near 2^31, then flood k+1 seals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_wrap_near_outbound_triggers() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let gate = FloodStartGate::new();
    let setup = connect_s6a(S6aOpts {
        flood: true,
        flood_start: Some(gate.clone()),
        ..S6aOpts::default()
    })
    .await?;
    // One successful seal must cross the hard bound (flood packets are large).
    setup.out_pkts.store(THRESHOLD - 1, Ordering::SeqCst);
    gate.release();
    wait_for("W1: I5 outbound packets trigger rekey", Duration::from_secs(8), || {
        setup.observe.non_idle() || setup.i6.triggers() > 0
    })
    .await?;
    assert_eq!(classify(&setup), Class::RekeyStarted);
    Ok(())
}

/// W1 invert: seed only the observe slot. Production flush must not fire.
/// invert_i5_observe_only reconstructs the "flush reads observe" bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_observe_only_does_not_trigger() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts::default()).await?;
    setup.writer_obs.set_packets_this_epoch(THRESHOLD);
    setup.channel.data(&b"poke"[..]).await?;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        classify(&setup),
        Class::NoRekey,
        "W1 HARD: seeding observe must not trigger (production reads atomics)"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_i5_observe_only_is_red() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts {
        invert_observe: true,
        ..S6aOpts::default()
    })
    .await?;
    setup.writer_obs.set_packets_this_epoch(THRESHOLD);
    setup.channel.data(&b"poke"[..]).await?;
    wait_for("invert observe-only triggers", Duration::from_secs(8), || {
        setup.observe.non_idle() || setup.i6.triggers() > 0
    })
    .await
    .map_err(|_| anyhow::anyhow!("triggered_from_observe"))?;
    assert_eq!(
        classify(&setup),
        Class::RekeyStarted,
        "W1 HARD invert class {:?}",
        Class::TriggeredFromObserve
    );
    Ok(())
}

/// W1 invert: skip packet predicate even when production count is over the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_skip_packet_rekey_is_red() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts {
        invert_skip_pkts: true,
        ..S6aOpts::default()
    })
    .await?;
    setup.out_pkts.store(THRESHOLD, Ordering::SeqCst);
    setup.channel.data(&b"poke"[..]).await?;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        classify(&setup),
        Class::NoRekey,
        "W1 HARD invert class packet_trigger_skipped"
    );
    let _ = Class::PacketTriggerSkipped;
    Ok(())
}

/// W2: inbound wrap-near.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w2_wrap_near_inbound_triggers() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts::default()).await?;
    setup.in_pkts.store(NEAR, Ordering::SeqCst);
    for i in 0..12u8 {
        setup.channel.data(&[i; 8][..]).await?;
    }
    wait_for("W2: I5 inbound packets trigger rekey", Duration::from_secs(8), || {
        setup.observe.non_idle() || setup.i6.triggers() > 0
    })
    .await?;
    assert_eq!(classify(&setup), Class::RekeyStarted);
    Ok(())
}

/// W3: non-strict install zeros I5 counts but seqn continues (S3a N6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w3_nonstrict_zero_count_seqn_continues() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts {
        nonstrict: true,
        ..S6aOpts::default()
    })
    .await?;
    for i in 0..16u8 {
        setup.channel.data(&[i; 8][..]).await?;
    }
    wait_for("W3: inbound seqn accumulated", Duration::from_secs(3), || {
        setup.reader_obs.seqn() > 8
    })
    .await?;
    let seqn_before = setup.reader_obs.seqn();
    let applied0 = setup.reader_obs.applied_gen();
    setup.in_pkts.store(NEAR, Ordering::SeqCst);
    for i in 0..12u8 {
        setup.channel.data(&[i; 4][..]).await?;
    }
    wait_for("W3: rekey applied", Duration::from_secs(8), || {
        setup.reader_obs.applied_gen() != applied0
            && setup.observe.phase() == 0
            && !setup.observe.non_idle()
    })
    .await?;
    assert_eq!(
        setup.in_pkts.load(Ordering::SeqCst),
        0,
        "W3 HARD: I5 inbound packets must reset at install"
    );
    assert_eq!(
        setup.out_pkts.load(Ordering::SeqCst),
        0,
        "W3 HARD: I5 outbound packets must reset at install"
    );
    assert!(
        !setup.reader_obs.last_reset_seqn(),
        "W3 HARD class seqn_reset_on_nonstrict: must not reset seqn"
    );
    setup.channel.data(&b"w3-post"[..]).await?;
    wait_for("W3: post-rekey seqn observed", Duration::from_secs(3), || {
        setup.reader_obs.seqn() != seqn_before
    })
    .await?;
    assert!(
        setup.reader_obs.seqn() >= seqn_before,
        "W3 HARD: non-strict seqn continues (before={seqn_before} after={})",
        setup.reader_obs.seqn()
    );
    let _ = Class::SeqnResetOnNonStrict;
    Ok(())
}

/// W4: after trigger, more packets do not start a second InKex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4_storm_does_not_double_trigger() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let hold = InstallAckHoldGate::new_held();
    hold.release();
    let setup = connect_s6a(S6aOpts {
        ack_hold: Some(hold.clone()),
        ..S6aOpts::default()
    })
    .await?;
    hold.hold_again();
    setup.in_pkts.store(THRESHOLD, Ordering::SeqCst);
    // Fire-and-forget: a held inbound ACK can stall the client's data() future.
    let _ = timeout(Duration::from_millis(200), setup.channel.data(&b"poke"[..])).await;
    wait_for("W4: first I5 trigger", Duration::from_secs(8), || {
        setup.i6.triggers() > 0 || setup.observe.non_idle()
    })
    .await?;
    let t0 = setup.i6.triggers();
    sleep(Duration::from_millis(400)).await;
    assert!(
        setup.i6.idle_drops() >= 1,
        "W4 HARD: storm must increment idle_drops (got {})",
        setup.i6.idle_drops()
    );
    assert_eq!(
        setup.i6.triggers(),
        t0,
        "W4 HARD class storm_double_trigger: triggers must stay {t0}"
    );
    hold.release();
    let _ = Class::StormDoubleTrigger;
    Ok(())
}

/// W4 invert: skip Idle gate → a second begin_rekey is attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_skip_idle_gate_is_red() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let hold = InstallAckHoldGate::new_held();
    hold.release();
    let setup = connect_s6a(S6aOpts {
        ack_hold: Some(hold.clone()),
        invert_skip_idle: true,
        ..S6aOpts::default()
    })
    .await?;
    hold.hold_again();
    setup.in_pkts.store(THRESHOLD, Ordering::SeqCst);
    let _ = timeout(Duration::from_millis(200), setup.channel.data(&b"poke"[..])).await;
    wait_for("invert idle: first trigger", Duration::from_secs(8), || {
        setup.i6.triggers() > 0
    })
    .await?;
    sleep(Duration::from_millis(400)).await;
    assert!(
        setup.i6.triggers() >= 2,
        "W4 HARD invert class storm_double_trigger: triggers={}",
        setup.i6.triggers()
    );
    hold.release();
    Ok(())
}

/// W5: both directions due in one flush → single begin_rekey + merge count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w5_bidirectional_merges_once() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts::default()).await?;
    setup.out_pkts.store(THRESHOLD, Ordering::SeqCst);
    setup.in_pkts.store(THRESHOLD, Ordering::SeqCst);
    setup.channel.data(&b"poke"[..]).await?;
    wait_for("W5: merged I5 trigger", Duration::from_secs(8), || {
        setup.i6.triggers() > 0
    })
    .await?;
    assert_eq!(setup.i6.triggers(), 1, "W5 HARD: exactly one begin_rekey");
    assert!(
        setup.i6.merges() >= 1,
        "W5 HARD: merge counter must fire (got {})",
        setup.i6.merges()
    );
    Ok(())
}

/// W6: byte second trigger (outbound write_limit).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w6_outbound_bytes_trigger() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let gate = FloodStartGate::new();
    let setup = connect_s6a(S6aOpts {
        flood: true,
        flood_start: Some(gate.clone()),
        max_bytes: 64,
        ..S6aOpts::default()
    })
    .await?;
    setup.out_bytes.store(60, Ordering::SeqCst);
    gate.release();
    wait_for("W6: outbound bytes trigger", Duration::from_secs(8), || {
        setup.i6.triggers() > 0 || setup.observe.non_idle()
    })
    .await?;
    Ok(())
}

/// W6 inbound: seed read bytes near `max_bytes` (P8-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w6_inbound_bytes_trigger() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts {
        max_bytes: 64,
        ..S6aOpts::default()
    })
    .await?;
    setup.in_bytes.store(60, Ordering::SeqCst);
    setup.channel.data(&[0u8; 32][..]).await?;
    wait_for("W6: inbound bytes trigger (P8-1)", Duration::from_secs(8), || {
        setup.i6.triggers() > 0 || setup.observe.non_idle()
    })
    .await?;
    Ok(())
}

/// Extra: invert_skip_packet leaves byte trigger intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w6_bytes_still_fire_when_packets_skipped() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let setup = connect_s6a(S6aOpts {
        invert_skip_pkts: true,
        max_bytes: 32,
        ..S6aOpts::default()
    })
    .await?;
    setup.in_pkts.store(THRESHOLD, Ordering::SeqCst);
    setup.in_bytes.store(8, Ordering::SeqCst);
    setup.channel.data(&[1u8; 40][..]).await?;
    wait_for("W6: bytes fire under packet invert", Duration::from_secs(8), || {
        setup.i6.triggers() > 0
    })
    .await?;
    Ok(())
}

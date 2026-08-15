//! S6b: `Limits` → `RekeyPolicy` + default hard-bound policy.
//!
//! P1/P2/P5 live as lib unit tests (`rekey_policy_api_tests`).
//! P3/P6 are behavioural; P4 is the S0 matrix (harness 256 KiB).
//!
//! cargo test -p russh --features _test_hooks --test test_s6b_rekey_policy -- --nocapture

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::*;
use russh::server::{KexInstallObserveSlot, RekeyI6};
use russh::RekeyPolicy;
use tokio::time::sleep;

const TWO_GIB: u64 = 2 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    DefaultTwoGibTriggered,
    OldOneGibDidNotTrigger,
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

/// P3: Default 1 TiB — injecting 2 GiB must NOT start InKex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_default_two_gib_does_not_rekey() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let i6 = RekeyI6::new();
    let out_bytes = Arc::new(AtomicU64::new(0));
    let progress = Progress::new();
    let addr = free_addr();
    let gate = FloodStartGate::new();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(gate.clone()),
            max_bytes: RekeyPolicy::DEFAULT_MAX_BYTES,
            kex_install_observe: Some(observe.clone()),
            rekey_i6: Some(i6.clone()),
            rekey_out_bytes: Some(out_bytes.clone()),
            teardown_grace: Duration::from_secs(1),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let (session, _ctrl) = connect_faulty(addr, default_client_config(), progress).await?;
    let _channel = session.channel_open_session().await?;
    out_bytes.store(TWO_GIB, Ordering::SeqCst);
    gate.release();
    sleep(Duration::from_millis(400)).await;
    assert!(
        i6.triggers() == 0 && !observe.non_idle(),
        "P3 HARD class {:?}: Default 1 TiB must not rekey at 2 GiB (triggers={} non_idle={})",
        Class::DefaultTwoGibTriggered,
        i6.triggers(),
        observe.non_idle()
    );
    Ok(())
}

/// P3 invert: old 1 GiB threshold at 2 GiB injected MUST rekey.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_p3_one_gib_threshold_is_red() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let i6 = RekeyI6::new();
    let out_bytes = Arc::new(AtomicU64::new(0));
    let progress = Progress::new();
    let addr = free_addr();
    let gate = FloodStartGate::new();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(gate.clone()),
            max_bytes: 1 << 30,
            kex_install_observe: Some(observe.clone()),
            rekey_i6: Some(i6.clone()),
            rekey_out_bytes: Some(out_bytes.clone()),
            teardown_grace: Duration::from_secs(1),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let (session, _ctrl) = connect_faulty(addr, default_client_config(), progress).await?;
    let _channel = session.channel_open_session().await?;
    out_bytes.store(TWO_GIB, Ordering::SeqCst);
    gate.release();
    wait_for("P3 invert: 1 GiB threshold fires at 2 GiB", Duration::from_secs(8), || {
        i6.triggers() > 0 || observe.non_idle()
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "P3 invert class {:?}: 1 GiB threshold did not fire",
            Class::OldOneGibDidNotTrigger
        )
    })?;
    Ok(())
}

/// P6: time trigger is gone — there is no `last_rekey` / `time_limit` left
/// to seed. This test documents the grep door: `RekeyPolicy` has only
/// packets + bytes.
#[test]
fn p6_rekey_policy_has_no_time_field() {
    let p = RekeyPolicy::default();
    let _ = p.max_packets;
    let _ = p.max_bytes;
    // Compile-time: a struct update that only names the two fields.
    let _ = RekeyPolicy {
        max_packets: 1,
        max_bytes: 1,
    };
}

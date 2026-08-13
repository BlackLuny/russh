//! S3a: ReaderTask + inbound epoch + dual-state ACK + unified teardown.
//!
//! Hard rule: target interleaving miss → fail. No soft fallbacks.
//! Requires `--features _test_hooks`.
//!
//! The capacity-1 decoded pipe (Reader waits if Session still holds the
//! previous packet) is a **temporary S3a exception, deleted in S3b**.
//! N* asserts are not relaxed because of that pipe.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::*;
use russh::server::{
    DisconnectCause, InjectIgnoreGate, InstallAckHoldGate, KexInstallObserveSlot, ReadHoldGate,
    ReaderObserveSlot,
};
use tokio::time::sleep;

const GRACE: Duration = Duration::from_secs(1);

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

async fn connect_ready(
    cfg: FloodServerConfig,
) -> Result<
    (
        russh::client::Handle<harness::CountingClient>,
        russh::Channel<russh::client::Msg>,
        Progress,
        std::sync::Arc<russh::server::DisconnectCauseSlot>,
    ),
    anyhow::Error,
> {
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let mut cfg = cfg;
    cfg.disconnect_cause_slot = Some(cause.clone());
    cfg.teardown_grace = GRACE;
    let server = FloodServer::new(progress.clone(), cfg);
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let client_cfg = default_client_config();
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    Ok((session, channel, progress, cause))
}

/// N1: key-first. After NeedsReply the inbound epoch is queued in the
/// capacity-1 channel (not applied). Peer NEWKEYS applies it; the next
/// packet opens with the new epoch. ACK-before-next-read is the r1 swap
/// rewrite (swap path is gone).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_key_first_parks_then_applies_on_peer_newkeys() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let reader = ReaderObserveSlot::new();
    let (session, channel, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        kex_install_observe: Some(observe.clone()),
        reader_observe: Some(reader.clone()),
        rekey_deadline: Duration::from_secs(30),
        write_progress_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;

    let applied0 = reader.applied_gen();
    reader.reset_latches();
    session.rekey_soon().await?;
    wait_for("N1: inbound epoch was queued (key-first park)", Duration::from_secs(8), || {
        reader.queued_ever() || reader.applied_gen() != applied0
    })
    .await?;
    assert!(
        reader.queued_ever(),
        "N1 HARD: NeedsReply must try_push inbound epoch (park in cap-1 channel) \
         before apply; queued_ever={}",
        reader.queued_ever()
    );

    wait_for("N1: rekey completes with new epoch applied", Duration::from_secs(8), || {
        observe.phase() == 0 && !observe.non_idle() && reader.applied_gen() != applied0
    })
    .await?;
    assert!(progress.session_alive(), "N1 HARD: session alive");
    assert!(cause.get().is_none(), "N1 HARD: no disconnect");
    channel.data(&b"n1-post-rekey"[..]).await?;
    sleep(Duration::from_millis(200)).await;
    assert!(progress.session_alive());
    Ok(())
}

/// N2: NEWKEYS-first. NeedsReply inbound send is suppressed so Reader
/// sees peer NEWKEYS with an empty install channel, waits, then Session
/// Done try_pushes. No next read until applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n2_newkeys_first_waits_before_next_read() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let reader = ReaderObserveSlot::new();
    let delay = Arc::new(AtomicBool::new(true));
    let (session, channel, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        kex_install_observe: Some(observe.clone()),
        reader_observe: Some(reader.clone()),
        delay_inbound_epoch: Some(delay.clone()),
        rekey_deadline: Duration::from_secs(30),
        write_progress_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;

    let applied0 = reader.applied_gen();
    reader.reset_latches();
    session.rekey_soon().await?;
    wait_for("N2: Reader hit NEWKEYS-first wait or applied", Duration::from_secs(8), || {
        reader.awaiting_ever() || reader.applied_gen() != applied0
    })
    .await?;
    assert!(
        reader.awaiting_ever(),
        "N2 HARD: with NeedsReply inbound suppressed, Reader must wait on \
         the empty install channel after NEWKEYS (awaiting_ever)"
    );
    delay.store(false, Ordering::SeqCst);

    wait_for("N2: rekey completes after Done push", Duration::from_secs(8), || {
        reader.applied_gen() != applied0 && observe.phase() == 0 && !observe.non_idle()
    })
    .await?;
    assert!(progress.session_alive());
    assert!(cause.get().is_none());
    channel.data(&b"n2-post"[..]).await?;
    Ok(())
}

/// N3: both paths live on a normal rekey. One apply, one completion, no double install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3_simultaneous_single_apply() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let reader = ReaderObserveSlot::new();
    let completions0;
    let (session, _ch, progress, cause) = {
        let c = connect_ready(FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            kex_install_observe: Some(observe.clone()),
            reader_observe: Some(reader.clone()),
            ..FloodServerConfig::default()
        })
        .await?;
        completions0 = observe.completions();
        c
    };
    let applied0 = reader.applied_gen();
    let applies0 = reader.applies();
    session.rekey_soon().await?;
    wait_for("N3: idle after one rekey", Duration::from_secs(8), || {
        observe.phase() == 0 && !observe.non_idle() && reader.applied_gen() != applied0
    })
    .await?;
    assert_eq!(
        observe.completions(),
        completions0 + 1,
        "N3 HARD: exactly one completion"
    );
    assert_eq!(
        reader.applies(),
        applies0 + 1,
        "N3 HARD: exactly one inbound apply (got {} → {})",
        applies0,
        reader.applies()
    );
    assert!(progress.session_alive());
    assert!(cause.get().is_none());
    Ok(())
}

/// N4: outbound ACK + peer Done, inbound ACK held → must not Idle / must not
/// clear deadline; rekey deadline wins with RekeyTimeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n4_incomplete_inbound_ack_does_not_idle() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let inbound_hold = InstallAckHoldGate::new_held();
    inbound_hold.release(); // initial handshake free
    let (session, _ch, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        kex_install_observe: Some(observe.clone()),
        inbound_ack_hold: Some(inbound_hold.clone()),
        rekey_deadline: Duration::from_secs(2),
        write_progress_deadline: Duration::from_secs(30),
        teardown_grace: GRACE,
        ..FloodServerConfig::default()
    })
    .await?;

    inbound_hold.hold_again();
    let clears0 = observe.deadline_clears();
    session.rekey_soon().await?;
    wait_for("N4: peer Done + outbound acked, inbound held", Duration::from_secs(5), || {
        observe.after_known() && observe.phase() == 3 && !observe.inbound_acked()
    })
    .await?;
    assert!(observe.non_idle(), "N4 HARD: must stay non-Idle");
    assert_eq!(
        observe.deadline_clears(),
        clears0,
        "N4 HARD: deadline must stay armed (clears {clears0} → {})",
        observe.deadline_clears()
    );

    wait_for("N4: RekeyTimeout first cause", Duration::from_secs(8), || {
        cause.get() == Some(DisconnectCause::RekeyTimeout)
    })
    .await?;
    assert_eq!(
        cause.get(),
        Some(DisconnectCause::RekeyTimeout),
        "N4 HARD: first cause RekeyTimeout, not PeerError"
    );
    let _ = progress;
    Ok(())
}

/// N5: inbound install must not wait for socket drain (partial write / hang).
/// Apply is held so hang can be proven (`hang_seen`) *before* apply; hang is
/// armed as soon as Reader has opened peer NEWKEYS (bytes the client needed
/// already left the socket) and before apply — not after waiting for queued
/// then discovering apply already ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n5_inbound_install_independent_of_socket_drain() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let reader = ReaderObserveSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let hang_seen = Arc::new(AtomicBool::new(false));
    let apply_hold = ReadHoldGate::new();
    let inject = InjectIgnoreGate::new();
    let (session, channel, _progress, _cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        kex_install_observe: Some(observe.clone()),
        reader_observe: Some(reader.clone()),
        socket_hang: Some(hang.clone()),
        socket_hang_seen: Some(hang_seen.clone()),
        reader_apply_hold: Some(apply_hold.clone()),
        inject_ignore: Some(inject.clone()),
        write_progress_deadline: Duration::from_secs(30),
        rekey_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;

    let applied0 = reader.applied_gen();
    reader.reset_latches();
    apply_hold.hold();
    session.rekey_soon().await?;
    wait_for("N5: Reader opened NEWKEYS (apply held)", Duration::from_secs(8), || {
        reader.awaiting_ever()
    })
    .await?;
    assert_eq!(
        reader.applied_gen(),
        applied0,
        "N5 HARD: apply must still be held when hang is armed"
    );
    hang.store(true, Ordering::SeqCst);
    inject.request();
    let _ = channel.data(&vec![0x5Au8; 16 * 1024][..]).await;
    wait_for("N5: Writer hang path taken with undrained bytes", Duration::from_secs(5), || {
        hang_seen.load(Ordering::SeqCst)
    })
    .await?;
    assert!(
        hang_seen.load(Ordering::SeqCst),
        "N5 HARD: Writer must be stuck on undrained seal before apply assert"
    );
    assert_eq!(
        reader.applied_gen(),
        applied0,
        "N5 HARD: inbound must not apply before hang is proven"
    );
    apply_hold.release();
    wait_for("N5: inbound applied while socket hung", Duration::from_secs(8), || {
        reader.applied_gen() != applied0
    })
    .await?;
    assert!(
        hang_seen.load(Ordering::SeqCst),
        "N5 HARD: Writer still on hang path through apply"
    );
    hang.store(false, Ordering::SeqCst);
    Ok(())
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

async fn n6_rekey_seqn(strict: bool) -> Result<(), anyhow::Error> {
    let reader = ReaderObserveSlot::new();
    let observe = KexInstallObserveSlot::new();
    let pref = if strict {
        None
    } else {
        Some(preferred_without_strict())
    };
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::Idle,
            reader_observe: Some(reader.clone()),
            kex_install_observe: Some(observe.clone()),
            disconnect_cause_slot: Some(cause.clone()),
            preferred: pref.clone(),
            teardown_grace: GRACE,
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    if let Some(p) = pref {
        client_cfg.preferred = p;
    }
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    for i in 0..16 {
        channel.data(&[i as u8; 8][..]).await?;
    }
    wait_for("N6: handshake seqn accumulated", Duration::from_secs(3), || {
        reader.seqn() > 8
    })
    .await?;
    let seqn_before = reader.seqn();
    let applied0 = reader.applied_gen();
    let completions0 = observe.completions();
    session.rekey_soon().await?;
    wait_for("N6: rekey applied then idle", Duration::from_secs(8), || {
        reader.applied_gen() != applied0
            && observe.completions() == completions0 + 1
            && observe.phase() == 0
            && !observe.non_idle()
    })
    .await?;
    channel.data(&b"n6-post-rekey"[..]).await?;
    wait_for("N6: post-rekey packet observed", Duration::from_secs(3), || {
        reader.seqn() != seqn_before
    })
    .await?;
    let seqn_after = reader.seqn();
    if strict {
        assert!(
            reader.last_reset_seqn(),
            "N6 HARD strict: inbound install must request seqn reset"
        );
        assert!(
            seqn_after < seqn_before && seqn_after <= 8,
            "N6 HARD strict: seqn must reset at install (before={seqn_before} after={seqn_after})"
        );
    } else {
        assert!(
            !reader.last_reset_seqn(),
            "N6 HARD non-strict: inbound install must not reset seqn"
        );
        assert!(
            seqn_after >= seqn_before,
            "N6 HARD non-strict: seqn must continue, not reset (before={seqn_before} after={seqn_after})"
        );
    }
    assert!(progress.session_alive());
    assert!(cause.get().is_none());
    Ok(())
}

/// N6 strict-on: install resets inbound seqn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n6_strict_seqn_reset_on_install() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    n6_rekey_seqn(true).await
}

/// N6 strict-off: install must not reset inbound seqn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n6_nonstrict_seqn_continues() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    n6_rekey_seqn(false).await
}

/// N7: capacity-1 install Full → Cancelling (PeerError), no silent drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n7_install_channel_full_cancels() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let force = Arc::new(AtomicBool::new(false));
    let (session, _ch, _progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        force_inbound_install_full: Some(force.clone()),
        write_progress_deadline: Duration::from_secs(30),
        rekey_deadline: Duration::from_secs(30),
        teardown_grace: GRACE,
        ..FloodServerConfig::default()
    })
    .await?;
    force.store(true, Ordering::SeqCst);
    session.rekey_soon().await?;
    wait_for("N7: PeerError from Full install", Duration::from_secs(8), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;
    assert_eq!(cause.get(), Some(DisconnectCause::PeerError));
    Ok(())
}

/// N8: inbound ACK held → completion does not fire; release then Idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n8_inbound_ack_hold_defers_completion() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let observe = KexInstallObserveSlot::new();
    let inbound_hold = InstallAckHoldGate::new_held();
    inbound_hold.release();
    let (session, _ch, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        kex_install_observe: Some(observe.clone()),
        inbound_ack_hold: Some(inbound_hold.clone()),
        rekey_deadline: Duration::from_secs(30),
        write_progress_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;
    let completions0 = observe.completions();
    inbound_hold.hold_again();
    session.rekey_soon().await?;
    wait_for("N8: after_known under inbound hold", Duration::from_secs(5), || {
        observe.after_known() && observe.non_idle() && observe.completions() == completions0
    })
    .await?;
    assert!(observe.non_idle(), "N8 HARD: not Idle while inbound ACK held");
    inbound_hold.release();
    wait_for("N8: Idle after inbound ACK release", Duration::from_secs(5), || {
        observe.phase() == 0 && !observe.non_idle() && observe.completions() == completions0 + 1
    })
    .await?;
    assert!(progress.session_alive());
    assert!(cause.get().is_none());
    Ok(())
}

/// T1: supervisor first cause (WriteStalled) still wins; Reader joins
/// inside the single grace; no Session-side start_reading drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t1_teardown_joins_reader_under_write_stalled() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let reader = ReaderObserveSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::FloodForever,
            socket_hang: Some(hang.clone()),
            reader_observe: Some(reader.clone()),
            write_progress_deadline: Duration::from_millis(400),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            inactivity_timeout: Some(Duration::from_secs(600)),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;
    let (session, _ctrl) =
        connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    // Handshake needs the Writer. Hang only after a channel is live so
    // FloodForever produces eligible backlog.
    hang.store(true, Ordering::SeqCst);

    wait_for("T1: WriteStalled", Duration::from_secs(8), || {
        cause.get() == Some(DisconnectCause::WriteStalled)
    })
    .await?;
    assert_eq!(
        cause.get(),
        Some(DisconnectCause::WriteStalled),
        "T1 HARD: first cause must stay WriteStalled (not Reader PeerError)"
    );
    wait_for("T1: Reader stopped inside grace", GRACE + Duration::from_secs(2), || {
        reader.stopped()
    })
    .await?;
    Ok(())
}

/// Risk 2 (Session::run): key-first park is observable (`queued_ever`) and
/// the connection survives the subsequent NEWKEYS apply. The deterministic
/// "install during held cipher::read" edge lives in
/// `reader::mid_read_tests::mid_read_install_does_not_apply`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mid_read_install_does_not_apply_until_newkeys() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let reader = ReaderObserveSlot::new();
    let observe = KexInstallObserveSlot::new();
    let (session, _ch, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        reader_observe: Some(reader.clone()),
        kex_install_observe: Some(observe.clone()),
        rekey_deadline: Duration::from_secs(30),
        write_progress_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;
    let applied0 = reader.applied_gen();
    reader.reset_latches();
    session.rekey_soon().await?;
    wait_for("mid-read: key-first park", Duration::from_secs(8), || {
        reader.queued_ever() || reader.applied_gen() != applied0
    })
    .await?;
    assert!(
        reader.queued_ever(),
        "HARD mid-read: NeedsReply must park the inbound epoch in the cap-1 \
         channel (not apply it inside cipher::read)"
    );
    wait_for("mid-read: apply after NEWKEYS", Duration::from_secs(8), || {
        reader.applied_gen() != applied0 && observe.phase() == 0 && !observe.non_idle()
    })
    .await?;
    assert!(progress.session_alive());
    assert!(cause.get().is_none());
    Ok(())
}

/// P1: clean client drop must not race into PeerError. Repeat ≥20.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_eof_never_records_peer_error() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    for i in 0..20 {
        let cause = russh::server::DisconnectCauseSlot::new();
        let progress = Progress::new();
        let addr = free_addr();
        let server = FloodServer::new(
            progress.clone(),
            FloodServerConfig {
                first_channel_mode: ServerMode::Idle,
                disconnect_cause_slot: Some(cause.clone()),
                teardown_grace: GRACE,
                inactivity_timeout: Some(Duration::from_secs(600)),
                write_progress_deadline: Duration::from_secs(30),
                ..FloodServerConfig::default()
            },
        );
        let _srv = server.spawn(addr);
        wait_listening(addr).await;
        let (session, _ctrl) =
            connect_faulty(addr, default_client_config(), progress.clone()).await?;
        let ch = session.channel_open_session().await?;
        drop(ch);
        drop(session);
        wait_for(&format!("clean-eof#{i}: session ended"), Duration::from_secs(8), || {
            !progress.session_alive()
        })
        .await?;
        assert_eq!(
            cause.get(),
            None,
            "HARD clean-eof#{i}: cause must stay None, got {:?}",
            cause.get()
        );
    }
    Ok(())
}

/// P1: ReadError still becomes PeerError (must not be swallowed by EOF harvest).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_error_records_peer_error() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let fail = Arc::new(AtomicBool::new(false));
    let (session, channel, progress, cause) = connect_ready(FloodServerConfig {
        first_channel_mode: ServerMode::Idle,
        reader_fail_next_read: Some(fail.clone()),
        write_progress_deadline: Duration::from_secs(30),
        ..FloodServerConfig::default()
    })
    .await?;
    fail.store(true, Ordering::SeqCst);
    let _ = channel.data(&b"trigger-read"[..]).await;
    wait_for("ReadError → PeerError", Duration::from_secs(8), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;
    assert_eq!(cause.get(), Some(DisconnectCause::PeerError));
    let _ = (session, progress);
    Ok(())
}

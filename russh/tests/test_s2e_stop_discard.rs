//! S2e: StopDiscard — peer CLOSE stop edge + lifecycle latch.
//!
//! Hard rule: target interleaving not observed → fail. No soft fallbacks.
//! Requires `--features _test_hooks`.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use harness::*;
use russh::server::{
    self, Auth, DeferredGrantSlot, Handler, Msg, OutboundOrderSlot, Server, Session, StopDiscardSlot,
};
use russh::{Channel, ChannelId, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

const MSG_OPEN_CONFIRM: u8 = 91;
const MSG_WINDOW_ADJUST: u8 = 93;
const MSG_DATA: u8 = 94;
const MSG_EXTENDED: u8 = 95;
const MSG_EOF: u8 = 96;
const MSG_CLOSE: u8 = 97;
const MSG_SUCCESS: u8 = 99;
const MSG_REQUEST: u8 = 98;

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

fn types_for(order: &OutboundOrderSlot, ch: u32) -> Vec<u8> {
    order.types_for(ch)
}

fn server_config(
    order: Arc<OutboundOrderSlot>,
    hang: Option<Arc<AtomicBool>>,
    discard: Option<Arc<StopDiscardSlot>>,
    grants: Option<Arc<DeferredGrantSlot>>,
    window: u32,
    pkt: u32,
) -> russh::server::Config {
    russh::server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        window_size: window,
        maximum_packet_size: pkt,
        outbound_order: Some(order),
        socket_hang: hang,
        stop_discard: discard,
        deferred_grant: grants,
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    }
}

fn post_close_ctrl(ev: &[(u32, u8, u32)], ch: u32) -> Vec<(u8, u32)> {
    let Some(cpos) = ev.iter().position(|(c, m, _)| *c == ch && *m == MSG_CLOSE) else {
        return Vec::new();
    };
    ev[cpos + 1..]
        .iter()
        .filter(|(c, m, _)| {
            *c == ch
                && matches!(
                    *m,
                    MSG_DATA
                        | MSG_EXTENDED
                        | MSG_EOF
                        | MSG_SUCCESS
                        | MSG_REQUEST
                        | MSG_WINDOW_ADJUST
                        | MSG_CLOSE
                )
        })
        .map(|(_, m, n)| (*m, *n))
        .collect()
}

#[derive(Debug, Default)]
struct PeerRecv {
    data_pkts: usize,
    data_bytes: u64,
    closes: usize,
    after_close: usize,
}

/// Drain the client channel until CLOSE or timeout. Decrypt/MAC errors
/// surface as a dead session / missing CLOSE — both hard-fail later.
async fn recv_until_close(
    mut ch: russh::Channel<russh::client::Msg>,
    timeout: Duration,
) -> Result<PeerRecv, anyhow::Error> {
    let mut rec = PeerRecv::default();
    let mut closed = false;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left.min(Duration::from_millis(200)), ch.wait()).await {
            Ok(Some(ChannelMsg::Data { data }))
            | Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                if closed {
                    rec.after_close += 1;
                } else {
                    rec.data_pkts += 1;
                    rec.data_bytes += data.len() as u64;
                }
            }
            Ok(Some(ChannelMsg::Close)) => {
                rec.closes += 1;
                closed = true;
            }
            Ok(Some(ChannelMsg::Eof | ChannelMsg::Success | ChannelMsg::Failure)) => {
                if closed {
                    rec.after_close += 1;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) if closed => break,
            Err(_) => {}
        }
    }
    Ok(rec)
}

/// Peer CLOSE while this channel has framed + unframed backlog.
/// Framed packets stay intact; lane is dropped; nothing after CLOSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_stop_discard_race() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let hang_seen = Arc::new(AtomicBool::new(false));
    let dump_done = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let mut cfg = server_config(
        order.clone(),
        Some(hang.clone()),
        Some(discard.clone()),
        None,
        4 * 1024 * 1024,
        pkt,
    );
    cfg.socket_hang_seen = Some(hang_seen.clone());
    let _srv = spawn_s2e_with(addr, cfg, S2eMode::FloodForever, dump_done.clone());
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let channel = session.channel_open_session().await?;
    wait_for("OPEN_CONFIRM", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
    })
    .await?;

    // Writer hang first (FloodForever is already writing). hang_seen
    // means sealed bytes sit in out_q and cannot drain — HWM will
    // clamp the next 256 KiB dump into pending_data.
    hang.store(true, Ordering::SeqCst);
    wait_for("writer hang seen", Duration::from_secs(5), || {
        hang_seen.load(Ordering::SeqCst)
    })
    .await?;
    wait_for("framed DATA under hang", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_DATA)
            .count()
            >= 4
    })
    .await?;
    channel.exec(true, "park").await?;
    wait_for("256KiB dump in Session", Duration::from_secs(5), || {
        dump_done.load(Ordering::SeqCst)
    })
    .await?;

    let framed_before = order
        .snapshot()
        .iter()
        .filter(|(_, m, _)| *m == MSG_DATA)
        .count();
    let framed_bytes: u64 = order
        .snapshot()
        .iter()
        .filter(|(_, m, _)| *m == MSG_DATA)
        .map(|(_, _, n)| u64::from(*n))
        .sum();
    channel.close().await?;

    wait_for("outbound CLOSE after peer CLOSE", Duration::from_secs(5), || {
        order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} ev={:?}", order.snapshot()))?;

    hang.store(false, Ordering::SeqCst);
    let peer = recv_until_close(channel, Duration::from_secs(5)).await?;

    let ev = order.snapshot();
    let ch = ev
        .iter()
        .find(|(_, m, _)| *m == MSG_DATA)
        .map(|(c, _, _)| *c)
        .expect("DATA channel");
    let closes = ev
        .iter()
        .filter(|(c, m, _)| *c == ch && *m == MSG_CLOSE)
        .count();
    let post = post_close_ctrl(&ev, ch);
    // Reconcile against the full framed prefix (everything before CLOSE),
    // not the earlier snapshot — drain can add packets after the snapshot
    // and before StopDiscard.
    let framed_pkts = ev
        .iter()
        .take_while(|(_, m, _)| *m != MSG_CLOSE)
        .filter(|(_, m, _)| *m == MSG_DATA)
        .count();
    let framed_all_bytes: u64 = ev
        .iter()
        .take_while(|(_, m, _)| *m != MSG_CLOSE)
        .filter(|(_, m, _)| *m == MSG_DATA)
        .map(|(_, _, n)| u64::from(*n))
        .sum();
    eprintln!(
        "s2e stop-discard-race snap={framed_before}/{framed_bytes}B \
         framed={framed_pkts}/{framed_all_bytes}B peer_data={}/{}B \
         peer_close={} after={} discarded_items={} discarded_bytes={} \
         closes={closes} post={post:?} ev_n={}",
        peer.data_pkts,
        peer.data_bytes,
        peer.closes,
        peer.after_close,
        discard.discarded_items(),
        discard.discarded_bytes(),
        ev.len()
    );
    assert!(
        framed_before >= 4,
        "HARD: need framed DATA before peer CLOSE (got {framed_before})"
    );
    assert!(
        discard.discarded_items() > 0,
        "HARD: lane discard must be > 0 (items={} bytes={})",
        discard.discarded_items(),
        discard.discarded_bytes()
    );
    assert_eq!(
        closes, 1,
        "HARD: want exactly one CLOSE, ev={ev:?}"
    );
    assert!(
        post.is_empty(),
        "HARD: packets after CLOSE on {ch}: {post:?} ev={ev:?}"
    );
    assert!(
        progress.session_alive(),
        "HARD: session died (decrypt/MAC failure?)"
    );
    assert!(
        peer.data_pkts > 0 && peer.data_bytes > 0,
        "HARD: peer received no DATA (decrypt path dead) {peer:?}"
    );
    assert!(
        peer.data_pkts <= framed_pkts && peer.data_bytes <= framed_all_bytes,
        "HARD: peer received more DATA than framed (pkts {}/{} bytes {}/{}) — truncated/dup?",
        peer.data_pkts,
        framed_pkts,
        peer.data_bytes,
        framed_all_bytes
    );
    assert_eq!(peer.closes, 1, "HARD: peer must receive exactly one CLOSE {peer:?}");
    assert_eq!(
        peer.after_close, 0,
        "HARD: peer saw packets after CLOSE {peer:?}"
    );
    Ok(())
}

/// Local close() queued at the lane tail races peer CLOSE → one outbound CLOSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_close_arbitration() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2e(
        addr,
        server_config(
            order.clone(),
            Some(hang.clone()),
            Some(discard.clone()),
            None,
            4 * 1024 * 1024,
            pkt,
        ),
        S2eMode::LocalCloseOnExec,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let channel = session.channel_open_session().await?;
    wait_for("confirm", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
    })
    .await?;

    hang.store(true, Ordering::SeqCst);
    channel.exec(true, "local-close").await?;
    wait_for("parked DATA", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_DATA)
    })
    .await?;
    // Local CLOSE is queued behind leftover DATA; must not be on the wire yet.
    assert!(
        !order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE),
        "HARD: local CLOSE escaped before peer CLOSE ev={:?}",
        order.snapshot()
    );

    channel.close().await?;
    wait_for("arbitrated CLOSE", Duration::from_secs(5), || {
        order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await?;
    hang.store(false, Ordering::SeqCst);
    sleep(Duration::from_millis(200)).await;

    let ev = order.snapshot();
    let nclose = ev.iter().filter(|(_, m, _)| *m == MSG_CLOSE).count();
    eprintln!("s2e close-arbitration nclose={nclose} ev={ev:?}");
    assert_eq!(
        nclose, 1,
        "HARD: local close + peer CLOSE must emit exactly one CLOSE ev={ev:?}"
    );
    Ok(())
}

/// After CLOSE is framed: handler success/request/data stay off the wire;
/// deferred WINDOW_ADJUST for that channel is cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_lifecycle_latch() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let grants = DeferredGrantSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2e(
        addr,
        server_config(
            order.clone(),
            Some(hang.clone()),
            Some(discard.clone()),
            Some(grants.clone()),
            4 * 1024 * 1024,
            pkt,
        ),
        S2eMode::LatchOnClose,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let channel = session.channel_open_session().await?;
    wait_for("confirm", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
    })
    .await?;

    hang.store(true, Ordering::SeqCst);
    // Hang first, then park — make_writer is idle in this mode so sealed
    // cannot drain under a late hang. 256 KiB into a hung Writer sits at
    // HWM and keeps the deferred grant registered until CLOSE.
    channel.exec(true, "hold-reply").await?;
    wait_for("HWM filled under hang", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_DATA)
            .map(|(_, _, n)| *n as usize)
            .sum::<usize>()
            >= 128 * 1024
    })
    .await?;
    // Inbound DATA while outbound is at HWM → deferred grant insert.
    channel
        .data_bytes(Bytes::from_static(b"grant-me"))
        .await
        .map_err(|e| anyhow::anyhow!("inbound data: {e:?}"))?;
    wait_for("deferred grant insert", Duration::from_secs(5), || {
        grants.inserts() > 0
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} inserts={}", grants.inserts()))?;

    channel.close().await?;
    wait_for("CLOSE framed", Duration::from_secs(5), || {
        order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await?;
    hang.store(false, Ordering::SeqCst);
    sleep(Duration::from_millis(250)).await;

    let ev = order.snapshot();
    let ch = ev
        .iter()
        .find(|(_, m, _)| *m == MSG_CLOSE)
        .map(|(c, _, _)| *c)
        .expect("CLOSE channel");
    let post = post_close_ctrl(&ev, ch);
    eprintln!(
        "s2e latch inserts={} emitted={} clears={} discarded={} post={post:?} ev={ev:?}",
        grants.inserts(),
        grants.emitted(),
        discard.grant_clears(),
        discard.discarded_items()
    );
    assert!(
        post.is_empty(),
        "HARD: SUCCESS/REQUEST/DATA/ADJUST after CLOSE: {post:?} ev={ev:?}"
    );
    assert!(
        discard.grant_clears() > 0,
        "HARD: deferred grant for closed channel must be cleared (clears={})",
        discard.grant_clears()
    );
    Ok(())
}

/// StopDiscard on one channel must not starve the other (S2d ready-set).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_multi_channel_isolation() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2e(
        addr,
        server_config(
            order.clone(),
            Some(hang.clone()),
            Some(discard.clone()),
            None,
            4 * 1024 * 1024,
            pkt,
        ),
        S2eMode::DualFlood,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let a = session.channel_open_session().await?;
    let b = session.channel_open_session().await?;
    wait_for("two confirms", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
            .count()
            >= 2
    })
    .await?;

    hang.store(true, Ordering::SeqCst);
    a.exec(true, "park").await?;
    b.exec(true, "park").await?;
    wait_for("both DATA", Duration::from_secs(5), || {
        let mut seen = std::collections::HashSet::new();
        for (c, m, _) in order.snapshot() {
            if m == MSG_DATA {
                seen.insert(c);
            }
        }
        seen.len() >= 2
    })
    .await?;

    let ids: Vec<u32> = {
        let mut s = std::collections::HashSet::new();
        for (c, m, _) in order.snapshot() {
            if m == MSG_DATA {
                s.insert(c);
            }
        }
        let mut v: Vec<u32> = s.into_iter().collect();
        v.sort_unstable();
        v
    };
    let victim = ids[0];
    let other = ids[1];
    let other_before = order
        .snapshot()
        .iter()
        .filter(|(c, m, _)| *c == other && *m == MSG_DATA)
        .count();

    a.close().await?;
    wait_for("victim CLOSE", Duration::from_secs(5), || {
        types_for(&order, victim).contains(&MSG_CLOSE)
    })
    .await?;
    hang.store(false, Ordering::SeqCst);
    let _db = spawn_channel_drainer(b);
    wait_for("other still served after victim CLOSE", Duration::from_secs(8), || {
        let ev = order.snapshot();
        let cpos = ev.iter().position(|(c, m, _)| *c == victim && *m == MSG_CLOSE);
        let Some(cpos) = cpos else {
            return false;
        };
        ev[cpos + 1..]
            .iter()
            .any(|(c, m, _)| *c == other && *m == MSG_DATA)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} ev={:?}", order.snapshot()))?;

    let ev = order.snapshot();
    let cpos = ev
        .iter()
        .position(|(c, m, _)| *c == victim && *m == MSG_CLOSE)
        .unwrap();
    let other_after = ev[cpos + 1..]
        .iter()
        .filter(|(c, m, _)| *c == other && *m == MSG_DATA)
        .count();
    let victim_post = post_close_ctrl(&ev, victim);
    eprintln!(
        "s2e isolation victim={victim} other={other} other_before={other_before} \
         other_after={other_after} victim_post={victim_post:?}"
    );
    assert!(
        other_after > 0,
        "HARD: other channel must keep emitting after victim CLOSE ev={ev:?}"
    );
    assert!(
        victim_post.is_empty(),
        "HARD: victim emitted after CLOSE: {victim_post:?}"
    );
    Ok(())
}

/// Writer dequeue hold: plaintext SealRaw sits in bulk FIFO unsealed.
/// Peer CLOSE + release → those items never reach the peer; CLOSE does;
/// the other channel still arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_tombstone_unsealed_fifo() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hold = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let mut cfg = server_config(
        order.clone(),
        None,
        Some(discard.clone()),
        None,
        4 * 1024 * 1024,
        pkt,
    );
    cfg.dequeue_hold = Some(hold.clone());
    let execs = Arc::new(AtomicU32::new(0));
    let _srv = spawn_s2e_counted(addr, cfg, S2eMode::DualPark, execs.clone());
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let a = session.channel_open_session().await?;
    let b = session.channel_open_session().await?;
    wait_for("two confirms", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
            .count()
            >= 2
    })
    .await?;

    hold.store(true, Ordering::SeqCst);
    // Victim is A by construction. After S4b, fire-and-forget execs are
    // posted in lane-pump order, so sending both at once can park B's
    // 256KiB in Writer first and leave A's apply in pending_data (hold
    // never frees mpsc). Sequence A until it owns the unsealed FIFO,
    // then let B apply so isolation is still two live dumps.
    let recip_a = a.id().number();
    a.exec(true, "park").await?;
    wait_for("unsealed FIFO has victim A DATA", Duration::from_secs(5), || {
        discard.queued_unsealed_data(recip_a) >= 1 && execs.load(Ordering::SeqCst) >= 1
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} queued={:?}", discard.queued_unsealed()))?;

    b.exec(true, "park").await?;
    wait_for("other exec DualPark apply returned", Duration::from_secs(5), || {
        execs.load(Ordering::SeqCst) >= 2
    })
    .await?;

    let queued = discard.queued_unsealed();
    let queued_a = discard.queued_unsealed_data(recip_a);
    assert!(
        queued_a >= 1,
        "HARD: need ≥1 unsealed DATA for victim in Writer FIFO queued={queued:?}"
    );

    a.close().await?;
    wait_for("tombstone CLOSE framed", Duration::from_secs(5), || {
        order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await?;
    hold.store(false, Ordering::SeqCst);

    let peer_a = recv_until_close(a, Duration::from_secs(5)).await?;
    let peer_b = recv_until_close(b, Duration::from_secs(5)).await?;
    eprintln!(
        "s2e tombstone queued_a={queued_a} seal_drops={} peer_a={peer_a:?} peer_b={peer_b:?} \
         alive={}",
        discard.seal_drops(),
        progress.session_alive()
    );
    assert!(
        discard.seal_drops() > 0,
        "HARD: Writer must drop unsealed victim payloads at seal (drops={})",
        discard.seal_drops()
    );
    assert_eq!(
        peer_a.closes, 1,
        "HARD: exempt CLOSE must reach peer {peer_a:?}"
    );
    assert_eq!(
        peer_a.after_close, 0,
        "HARD: nothing after CLOSE on victim {peer_a:?}"
    );
    // In-flight seal (at most one) may complete; the rest of the
    // unsealed FIFO must not appear.
    assert!(
        peer_a.data_pkts <= 1,
        "HARD: unsealed victim DATA leaked to peer {peer_a:?} queued_a={queued_a}"
    );
    assert!(
        discard.seal_drops() >= queued_a.saturating_sub(1) as u64,
        "HARD: seal drops {} < queued_a-1 {}",
        discard.seal_drops(),
        queued_a.saturating_sub(1)
    );
    assert!(
        peer_b.data_pkts > 0,
        "HARD: other channel unsealed DATA must still arrive {peer_b:?}"
    );
    assert!(
        progress.session_alive(),
        "HARD: decrypt/MAC failed after tombstone drops"
    );
    Ok(())
}

/// Local CLOSE already framed into enc.write/Writer (socket hung) + peer
/// CLOSE → peer receives exactly one CLOSE (arbitration branch b).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_close_arbitration_already_framed() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let _srv = spawn_s2e(
        addr,
        server_config(
            order.clone(),
            Some(hang.clone()),
            Some(discard.clone()),
            None,
            4 * 1024 * 1024,
            pkt,
        ),
        S2eMode::CloseNow,
    );
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let channel = session.channel_open_session().await?;
    wait_for("confirm", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
    })
    .await?;

    hang.store(true, Ordering::SeqCst);
    channel.exec(true, "close-now").await?;
    wait_for("local CLOSE framed", Duration::from_secs(5), || {
        order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} ev={:?}", order.snapshot()))?;
    assert_eq!(
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_CLOSE)
            .count(),
        1,
        "HARD: one local CLOSE in enc.write before peer CLOSE"
    );

    channel.close().await?;
    hang.store(false, Ordering::SeqCst);
    let peer = recv_until_close(channel, Duration::from_secs(5)).await?;
    let nclose = order
        .snapshot()
        .iter()
        .filter(|(_, m, _)| *m == MSG_CLOSE)
        .count();
    eprintln!(
        "s2e arb-b nclose_order={nclose} peer_close={} after={} alive={}",
        peer.closes,
        peer.after_close,
        progress.session_alive()
    );
    assert_eq!(nclose, 1, "HARD: already_gone must not append a second CLOSE");
    assert_eq!(
        peer.closes, 1,
        "HARD: peer must receive exactly one CLOSE {peer:?}"
    );
    assert_eq!(peer.after_close, 0, "HARD: extra after CLOSE {peer:?}");
    assert!(progress.session_alive(), "HARD: decrypt failed");
    Ok(())
}

/// DATA backlog → local close() parks CLOSE → late SUCCESS/REQUEST
/// injected only after hook proves pending_close && no framed CLOSE.
/// Drain must then emit exactly one CLOSE with zero post-CLOSE ctrl.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2e_local_close_pending_latches_ctrl() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let discard = StopDiscardSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let _srv = spawn_s2e(
        addr,
        server_config(
            order.clone(),
            None,
            Some(discard.clone()),
            None,
            4 * 1024 * 1024,
            pkt,
        ),
        S2eMode::LateCtrlAfterLocalClose,
    );
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    // One peer packet: data() emits that, leftover + CLOSE stay in the lane.
    client_cfg.window_size = pkt;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress).await?;
    let channel = session.channel_open_session().await?;
    wait_for("confirm", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
    })
    .await?;
    ctrl.freeze_read();
    channel.exec(true, "park-close").await?;
    wait_for("CLOSE parked, not framed", Duration::from_secs(5), || {
        discard.pending_close()
            && !order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE)
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} pending_close={} ev={:?}",
            discard.pending_close(),
            order.snapshot()
        )
    })?;
    assert!(
        discard.pending_close(),
        "HARD: close() must leave pending_close"
    );
    assert!(
        !order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE),
        "HARD: CLOSE must still be in the lane ev={:?}",
        order.snapshot()
    );

    channel.exec(true, "late").await?;
    sleep(Duration::from_millis(100)).await;
    assert!(
        !order
            .snapshot()
            .iter()
            .any(|(_, m, _)| *m == MSG_SUCCESS || *m == MSG_REQUEST),
        "HARD: late SUCCESS/REQUEST while CLOSE parked ev={:?}",
        order.snapshot()
    );
    assert!(
        !order.snapshot().iter().any(|(_, m, _)| *m == MSG_CLOSE),
        "HARD: late exec must not have framed CLOSE ev={:?}",
        order.snapshot()
    );

    ctrl.unfreeze_read();
    let peer = recv_until_close(channel, Duration::from_secs(8)).await?;
    wait_for("exactly one framed CLOSE", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_CLOSE)
            .count()
            == 1
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} ev={:?}", order.snapshot()))?;

    let ev = order.snapshot();
    let nclose = ev.iter().filter(|(_, m, _)| *m == MSG_CLOSE).count();
    let cpos = ev
        .iter()
        .position(|(_, m, _)| *m == MSG_CLOSE)
        .expect("HARD: CLOSE missing after drain");
    let ch = ev[cpos].0;
    let post = post_close_ctrl(&ev, ch);
    eprintln!(
        "s2e local-pending-latch pending_close_hook={} nclose={nclose} \
         peer={peer:?} post={post:?} ev={ev:?}",
        discard.pending_close()
    );
    assert_eq!(nclose, 1, "HARD: want exactly one CLOSE ev={ev:?}");
    assert_eq!(peer.closes, 1, "HARD: peer must receive one CLOSE {peer:?}");
    assert_eq!(peer.after_close, 0, "HARD: peer saw post-CLOSE {peer:?}");
    assert!(
        post.is_empty(),
        "HARD: ctrl after CLOSE on wire: {post:?} ev={ev:?}"
    );
    assert!(
        !ev.iter().any(|(_, m, _)| *m == MSG_SUCCESS || *m == MSG_REQUEST),
        "HARD: late SUCCESS/REQUEST must never appear ev={ev:?}"
    );
    Ok(())
}

// ── server ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum S2eMode {
    FloodForever,
    LocalCloseOnExec,
    LatchOnClose,
    DualFlood,
    CloseNow,
    LateCtrlAfterLocalClose,
    DualPark,
}

fn spawn_s2e(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: S2eMode,
) -> tokio::task::JoinHandle<()> {
    spawn_s2e_with(addr, config, mode, Arc::new(AtomicBool::new(false)))
}

fn spawn_s2e_counted(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: S2eMode,
    execs: Arc<AtomicU32>,
) -> tokio::task::JoinHandle<()> {
    spawn_s2e_inner(addr, config, mode, Arc::new(AtomicBool::new(false)), execs)
}

fn spawn_s2e_with(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: S2eMode,
    dump_done: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    spawn_s2e_inner(addr, config, mode, dump_done, Arc::new(AtomicU32::new(0)))
}

fn spawn_s2e_inner(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: S2eMode,
    dump_done: Arc<AtomicBool>,
    execs: Arc<AtomicU32>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sh = S2eSh {
            mode,
            dump_done,
            execs,
        };
        if let Err(e) = sh.run_on_address(Arc::new(config), addr).await {
            eprintln!("s2e server exited: {e:?}");
        }
    })
}

struct S2eSh {
    mode: S2eMode,
    dump_done: Arc<AtomicBool>,
    execs: Arc<AtomicU32>,
}

impl Server for S2eSh {
    type Handler = S2eH;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        S2eH {
            mode: self.mode,
            seq: Arc::new(AtomicU32::new(0)),
            dump_done: self.dump_done.clone(),
            execs: self.execs.clone(),
        }
    }
}

struct S2eH {
    mode: S2eMode,
    seq: Arc<AtomicU32>,
    dump_done: Arc<AtomicBool>,
    execs: Arc<AtomicU32>,
}

impl Handler for S2eH {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let _ = self.seq.fetch_add(1, Ordering::Relaxed);
        let mode = self.mode;
        tokio::spawn(async move {
            match mode {
                S2eMode::FloodForever | S2eMode::DualFlood => {
                    let mut w = channel.make_writer();
                    let chunk = vec![b'x'; 16 * 1024];
                    loop {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
                S2eMode::LocalCloseOnExec
                | S2eMode::LatchOnClose
                | S2eMode::CloseNow
                | S2eMode::LateCtrlAfterLocalClose
                | S2eMode::DualPark => {
                    // Keep the Channel alive so inbound DATA is delivered
                    // (and can trip a deferred WINDOW_ADJUST). Do not write.
                    loop {
                        sleep(Duration::from_secs(60)).await;
                    }
                }
            }
        });
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.mode {
            S2eMode::FloodForever | S2eMode::DualFlood | S2eMode::DualPark => {
                session.data(channel, Bytes::from(vec![b'p'; 256 * 1024]))?;
                self.dump_done.store(true, Ordering::SeqCst);
                self.execs.fetch_add(1, Ordering::SeqCst);
            }
            S2eMode::LocalCloseOnExec => {
                session.data(channel, Bytes::from(vec![b'p'; 256 * 1024]))?;
                session.close(channel)?;
            }
            S2eMode::LatchOnClose => {
                session.data(channel, Bytes::from(vec![b'p'; 256 * 1024]))?;
                // Leave wants_reply set so channel_close can try SUCCESS.
            }
            S2eMode::CloseNow => {
                session.close(channel)?;
            }
            S2eMode::LateCtrlAfterLocalClose => {
                if _data == b"late" {
                    session.channel_success(channel)?;
                    session.exit_status_request(channel, 0)?;
                } else {
                    session.data(channel, Bytes::from(vec![b'p'; 256 * 1024]))?;
                    session.close(channel)?;
                }
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.mode, S2eMode::LatchOnClose) {
            let _ = session.channel_success(channel);
            let _ = session.exit_status_request(channel, 0);
            let _ = session.data(channel, Bytes::from_static(b"late"));
        }
        Ok(())
    }
}

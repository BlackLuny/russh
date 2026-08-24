//! S2d: ready-set 1-packet rotation + gather + quota boost.
//!
//! Hard rule: target scheduling behaviour not observed → fail. No soft fallbacks.
//! Requires `--features _test_hooks`.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use harness::*;
use russh::server::{
    self, Auth, Handler, LedgerMaxSlot, Msg, OutboundOrderSlot, SchedSlot, Server, Session,
};
use russh::{Channel, ChannelId};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

const MSG_OPEN_CONFIRM: u8 = 91;
const MSG_DATA: u8 = 94;
const MSG_EXTENDED: u8 = 95;
const MSG_SUCCESS: u8 = 99;
const HWM: usize = 128 * 1024;

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

fn data_payloads(order: &OutboundOrderSlot) -> Vec<(u32, u32)> {
    order
        .snapshot()
        .into_iter()
        .filter(|(_, m, _)| *m == MSG_DATA)
        .map(|(c, _, n)| (c, n))
        .collect()
}

fn data_bytes_by_channel(order: &OutboundOrderSlot) -> HashMap<u32, u64> {
    let mut m = HashMap::new();
    for (c, n) in data_payloads(order) {
        *m.entry(c).or_insert(0) += u64::from(n);
    }
    m
}

fn data_pkts_by_channel(order: &OutboundOrderSlot) -> HashMap<u32, usize> {
    let mut m = HashMap::new();
    for (c, _) in data_payloads(order) {
        *m.entry(c).or_insert(0) += 1;
    }
    m
}

fn server_config(
    order: Arc<OutboundOrderSlot>,
    hang: Option<Arc<AtomicBool>>,
    sched: Option<Arc<SchedSlot>>,
    window: u32,
    pkt: u32,
) -> russh::server::Config {
    russh::server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        window_size: window,
        maximum_packet_size: pkt,
        outbound_order: Some(order),
        socket_hang: hang,
        sched,
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    }
}

/// Two same-priority flood channels: after both have emitted, further
/// packets in a hung-Writer HWM window must both be > 0 and ratio-bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2d_rotation_fairness() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let start = Arc::new(AtomicBool::new(false));
    let sched = SchedSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2d(
        addr,
        server_config(
            order.clone(),
            Some(hang.clone()),
            Some(sched.clone()),
            4 * 1024 * 1024,
            pkt,
        ),
        S2dMode::DualFlood { start: start.clone() },
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let a = session.channel_open_session().await?;
    let b = session.channel_open_session().await?;
    wait_for("two OPEN_CONFIRM", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .filter(|(_, m, _)| *m == MSG_OPEN_CONFIRM)
            .count()
            >= 2
    })
    .await?;

    // Park 256 KiB on each lane while the Writer is hung so both
    // pending_data queues are occupied, then release. First 16
    // dual-ready scheduler emits must strictly alternate.
    hang.store(true, Ordering::SeqCst);
    a.exec(true, "park").await?;
    b.exec(true, "park").await?;
    sleep(Duration::from_millis(150)).await;
    let mark = data_payloads(&order).len();
    let emit_mark = sched.emits().len();
    hang.store(false, Ordering::SeqCst);
    let _da = spawn_channel_drainer(a);
    let _db = spawn_channel_drainer(b);

    wait_for("32 packets after dual-backlog drain", Duration::from_secs(8), || {
        data_payloads(&order).len() >= mark + 32
    })
    .await?;

    let after = data_payloads(&order);
    let window = &after[mark..mark + 32];
    let mut pkts: HashMap<u32, usize> = HashMap::new();
    for (c, _) in window {
        *pkts.entry(*c).or_insert(0) += 1;
    }
    let dual: Vec<u32> = sched
        .emits()
        .into_iter()
        .skip(emit_mark)
        .filter(|(_, boost, ready)| !*boost && *ready >= 2)
        .map(|(c, _, _)| c)
        .collect();
    let tail = if dual.len() >= 16 { &dual[..16] } else { dual.as_slice() };
    let mut run = 1usize;
    let mut max_run = 1usize;
    for w in tail.windows(2) {
        if w[0] == w[1] {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 1;
        }
    }
    let uniq: HashMap<u32, usize> = {
        let mut m = HashMap::new();
        for c in tail {
            *m.entry(*c).or_insert(0) += 1;
        }
        m
    };
    eprintln!(
        "s2d rotation window pkts={pkts:?} n={} dual_n={} dual_tail={tail:?} max_run={max_run} uniq={uniq:?}",
        window.len(),
        dual.len()
    );
    assert!(
        dual.len() >= 16,
        "HARD: fewer than 16 dual-ready emits after unhang ({}) — ready-set never had both",
        dual.len()
    );
    assert!(
        uniq.len() >= 2,
        "HARD: dual-ready emits must include both channels uniq={uniq:?} tail={tail:?}"
    );
    assert!(
        max_run <= 1,
        "HARD: 1-packet RR broken when ready≥2 (same-channel run {max_run}) tail={tail:?}"
    );
    let mut counts: Vec<usize> = uniq.values().copied().collect();
    counts.sort_unstable();
    let lo = counts[0];
    let hi = *counts.last().unwrap();
    assert!(
        lo > 0 && hi <= lo.saturating_mul(3),
        "HARD: rotation ratio unbounded hi={hi} lo={lo} uniq={uniq:?}"
    );
    Ok(())
}

/// Old bulk stream keeps a strictly positive service rate while new
/// channels are still being opened (churn-active). Open→first-byte→close
/// loop; assert fires before the loop stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2d_old_stream_min_service() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let churn_active = Arc::new(AtomicBool::new(false));
    let sched = SchedSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2d(
        addr,
        server_config(
            order.clone(),
            None,
            Some(sched.clone()),
            4 * 1024 * 1024,
            pkt,
        ),
        S2dMode::LiveChurn,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let old = session
        .channel_open_session()
        .await
        .map_err(|e| anyhow::anyhow!("open old: {e:?}"))?;
    let _d = spawn_channel_drainer(old);

    wait_for("old DATA", Duration::from_secs(5), || {
        !data_payloads(&order).is_empty()
    })
    .await?;
    let old_id = data_payloads(&order)[0].0;
    let old_begin = data_bytes_by_channel(&order)
        .get(&old_id)
        .copied()
        .unwrap_or(0);

    churn_active.store(true, Ordering::SeqCst);
    let mut cycles = 0u64;
    let mut asserted = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline && cycles < 64 {
        live_churn_cycle(&session).await?;
        cycles += 1;
        let old_now = data_bytes_by_channel(&order)
            .get(&old_id)
            .copied()
            .unwrap_or(0);
        if cycles >= 3 && old_now > old_begin {
            assert!(
                churn_active.load(Ordering::SeqCst),
                "HARD: churn already marked stopped at assert"
            );
            let cycles_at_assert = cycles;
            // One more open→first-byte→close so the assert is not at loop end.
            live_churn_cycle(&session).await?;
            cycles += 1;
            assert!(
                cycles > cycles_at_assert && churn_active.load(Ordering::SeqCst),
                "HARD: churn was finished when old-delta was sampled"
            );
            eprintln!(
                "s2d old-min-service old_id={old_id} begin={old_begin} now={old_now} \
                 cycles={cycles} boosts={} quanta={} active=true",
                sched.boosts(),
                sched.regular_quanta()
            );
            asserted = true;
            break;
        }
    }
    churn_active.store(false, Ordering::SeqCst);
    assert!(
        asserted,
        "HARD: never saw old-byte growth while churn was still running \
         (cycles={cycles} begin={old_begin} now={:?})",
        data_bytes_by_channel(&order).get(&old_id)
    );
    Ok(())
}

/// Gathered CHANNEL_DATA payload never exceeds
/// min(peer_maxpacket, 32 KiB); gather does not jump a SUCCESS fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2d_gather_cap() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let cap = pkt.min(32 * 1024);

    let _srv = spawn_s2d(
        addr,
        server_config(order.clone(), Some(hang.clone()), None, 4 * 1024 * 1024, pkt),
        S2dMode::GatherTiny,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| anyhow::anyhow!("open: {e:?}"))?;

    hang.store(true, Ordering::SeqCst);
    channel.exec(true, "gather").await?;
    sleep(Duration::from_millis(400)).await;
    hang.store(false, Ordering::SeqCst);
    let _d = spawn_channel_drainer(channel);

    wait_for("SUCCESS + gathered DATA", Duration::from_secs(8), || {
        let ev = order.snapshot();
        ev.iter().any(|(_, m, _)| *m == MSG_SUCCESS)
            && ev
                .iter()
                .any(|(_, m, n)| *m == MSG_DATA && *n > 1 && *n < cap)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} ev={:?}", order.snapshot()))?;
    sleep(Duration::from_millis(200)).await;

    let ev = order.snapshot();
    eprintln!("s2d gather events={ev:?}");
    let over: Vec<_> = ev
        .iter()
        .filter(|(_, m, n)| *m == MSG_DATA && *n > cap)
        .copied()
        .collect();
    assert!(
        over.is_empty(),
        "HARD: DATA payload exceeds gather cap {cap}: {over:?} ev={ev:?}"
    );
    assert!(
        ev.iter()
            .any(|(_, m, n)| *m == MSG_DATA && *n > 1 && *n < cap),
        "HARD: no gathered packet (want 1 < payload < {cap}) ev={ev:?}"
    );
    let success = ev
        .iter()
        .position(|(_, m, _)| *m == MSG_SUCCESS)
        .ok_or_else(|| anyhow::anyhow!("HARD: no SUCCESS ev={ev:?}"))?;
    assert!(
        ev[..success].iter().any(|(_, m, _)| *m == MSG_DATA),
        "HARD: no DATA before SUCCESS ev={ev:?}"
    );
    assert!(
        ev[success + 1..].iter().any(|(_, m, _)| *m == MSG_DATA),
        "HARD: no DATA after SUCCESS (gather crossed fence?) ev={ev:?}"
    );
    Ok(())
}

/// Adjacent boosts are ≥8 completed regular quanta apart; boost on vs off
/// advances the new channel's first DATA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2d_boost_quota() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let sched = SchedSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_s2d(
        addr,
        server_config(
            order.clone(),
            None,
            Some(sched.clone()),
            4 * 1024 * 1024,
            pkt,
        ),
        S2dMode::LiveChurn,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone())
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e:?}"))?;
    let old = session
        .channel_open_session()
        .await
        .map_err(|e| anyhow::anyhow!("open old: {e:?}"))?;
    let _d = spawn_channel_drainer(old);

    wait_for("old DATA", Duration::from_secs(5), || {
        !data_payloads(&order).is_empty()
    })
    .await?;

    // Space opens so each new Confirmed channel can take a boost slot
    // after ≥8 completed regular quanta.
    let mut extras = Vec::new();
    for i in 0..5 {
        if i > 0 {
            let target = sched.regular_quanta().saturating_add(8);
            wait_for("8 regular quanta before next boost", Duration::from_secs(8), || {
                sched.regular_quanta() >= target
            })
            .await?;
        }
        extras.push(
            session
                .channel_open_session()
                .await
                .map_err(|e| anyhow::anyhow!("open new: {e:?}"))?,
        );
        if extras.len() >= 2 {
            extras.remove(0);
        }
    }
    sleep(Duration::from_millis(200)).await;

    let at = sched.boost_at_quanta();
    let boosts = sched.boosts();
    eprintln!(
        "s2d boost-quota boosts={boosts} quanta={} at={at:?}",
        sched.regular_quanta()
    );
    assert!(
        boosts >= 2,
        "HARD: need ≥2 boosts to check adjacent gap, got {boosts} at={at:?}"
    );
    for w in at.windows(2) {
        let gap = w[1].saturating_sub(w[0]);
        assert!(
            gap >= 8,
            "HARD: adjacent boosts at q={} and q={} gap={gap} < 8",
            w[0],
            w[1]
        );
    }

    let pos_on = first_new_data_index(false).await?;
    let pos_off = first_new_data_index(true).await?;
    eprintln!("s2d boost on/off first-new-data pos_on={pos_on} pos_off={pos_off}");
    assert!(
        pos_on < pos_off,
        "HARD: boost on must place new-channel first DATA earlier than boost off \
         (on={pos_on} off={pos_off})"
    );
    Ok(())
}

/// Hang, park the old stream to HWM, then park the new stream. Return the
/// index of the new channel's first DATA after the old-stream mark.
/// `disable_boost` turns the first-packet jump off.
async fn first_new_data_index(disable_boost: bool) -> Result<usize, anyhow::Error> {
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let sched = SchedSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;
    let mut cfg = server_config(
        order.clone(),
        Some(hang.clone()),
        Some(sched),
        4 * 1024 * 1024,
        pkt,
    );
    cfg.disable_sched_boost = disable_boost;
    let _srv = spawn_s2d(addr, cfg, S2dMode::DualFlood { start: Arc::new(AtomicBool::new(false)) });
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress).await?;
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
    sleep(Duration::from_millis(150)).await;
    let mark = data_payloads(&order).len();
    assert!(
        mark > 0,
        "HARD: old stream must have sealed DATA before the new park"
    );
    b.exec(true, "park").await?;
    sleep(Duration::from_millis(80)).await;
    hang.store(false, Ordering::SeqCst);
    let _da = spawn_channel_drainer(a);
    let _db = spawn_channel_drainer(b);
    wait_for("new-channel DATA after old mark", Duration::from_secs(8), || {
        data_payloads(&order)
            .iter()
            .skip(mark)
            .any(|(c, _)| *c != data_payloads(&order)[0].0)
            && data_payloads(&order).len() >= mark + 2
    })
    .await?;
    let after = data_payloads(&order);
    let window = &after[mark..];
    let ids: Vec<u32> = window.iter().map(|(c, _)| *c).collect();
    let old_id = after[0].0;
    ids.iter()
        .position(|c| *c != old_id)
        .ok_or_else(|| anyhow::anyhow!("HARD: no new-channel DATA after old mark ids={ids:?}"))
}

/// Open a session, wait for the first application byte, then close.
async fn live_churn_cycle(
    session: &russh::client::Handle<CountingClient>,
) -> Result<(), anyhow::Error> {
    let mut ch = session
        .channel_open_session()
        .await
        .map_err(|e| anyhow::anyhow!("churn open: {e:?}"))?;
    {
        let mut reader = ch.make_reader();
        let mut buf = [0u8; 8];
        match tokio::time::timeout(Duration::from_secs(2), reader.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            other => anyhow::bail!("HARD: churn channel produced no first byte: {other:?}"),
        }
    }
    ch.close()
        .await
        .map_err(|e| anyhow::anyhow!("churn close: {e:?}"))?;
    Ok(())
}

/// Tiny EXTENDED_DATA flood stays within HWM + one EXT packet (16+13+88).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2d_ext_tiny_hwm() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let ledger = LedgerMaxSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let peer_max = 16u32;
    let mut cfg = server_config(order.clone(), None, None, 4 * 1024 * 1024, peer_max);
    cfg.ledger_max = Some(ledger.clone());
    let _srv = spawn_s2d(addr, cfg, S2dMode::ExtTiny);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = peer_max;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _d = spawn_channel_drainer(channel);
    wait_for("ext moving", Duration::from_secs(5), || {
        order
            .snapshot()
            .iter()
            .any(|(_, m, n)| *m == MSG_EXTENDED && *n > 0)
    })
    .await?;
    ctrl.freeze_read();
    wait_for("ext ledger >= HWM", Duration::from_secs(8), || {
        ledger.max() >= HWM && ledger.full_hits() > 0
    })
    .await?;
    let max = ledger.max();
    let allow_ext = peer_max as usize + 13 + 4 + 1 + 19 + 64; // framing 13 + wire 88
    eprintln!(
        "s2d ext-tiny ledger max={max} hwm={HWM} allow_ext={allow_ext} full_hits={}",
        ledger.full_hits()
    );
    assert!(max >= HWM, "HARD: EXT flood must cross HWM (max={max})");
    assert!(
        max <= HWM + allow_ext,
        "HARD: EXT flood max {max} > HWM+one_ext {}",
        HWM + allow_ext
    );
    ctrl.unfreeze_read();
    Ok(())
}

// ── server ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum S2dMode {
    DualFlood { start: Arc<AtomicBool> },
    Churn { write_gate: Arc<AtomicBool> },
    LiveChurn,
    GatherTiny,
    ExtTiny,
}

fn spawn_s2d(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: S2dMode,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sh = S2dSh { mode };
        if let Err(e) = sh.run_on_address(Arc::new(config), addr).await {
            eprintln!("s2d server exited: {e:?}");
        }
    })
}

struct S2dSh {
    mode: S2dMode,
}

impl Server for S2dSh {
    type Handler = S2dH;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        S2dH {
            mode: self.mode.clone(),
            seq: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct S2dH {
    mode: S2dMode,
    seq: Arc<AtomicUsize>,
}

impl Handler for S2dH {
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
        let idx = self.seq.fetch_add(1, Ordering::Relaxed);
        let mode = self.mode.clone();
        tokio::spawn(async move {
            match mode {
                S2dMode::DualFlood { start } => {
                    while !start.load(Ordering::SeqCst) {
                        sleep(Duration::from_millis(10)).await;
                    }
                    let mut w = channel.make_writer();
                    // Large chunk so both lanes stay non-empty after the
                    // first HWM fill; 16 KiB drains in ~4 packets and the
                    // idle side vanishes from the ready-set.
                    let chunk = vec![b'x'; 256 * 1024];
                    loop {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
                S2dMode::Churn { write_gate } => {
                    if idx == 0 {
                        let mut w = channel.make_writer();
                        let chunk = vec![b'o'; 16 * 1024];
                        loop {
                            if w.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                    } else {
                        while !write_gate.load(Ordering::SeqCst) {
                            sleep(Duration::from_millis(10)).await;
                        }
                        let mut w = channel.make_writer();
                        let _ = w.write_all(&[b'n'; 64]).await;
                    }
                }
                S2dMode::LiveChurn => {
                    if idx == 0 {
                        let mut w = channel.make_writer();
                        let chunk = vec![b'o'; 16 * 1024];
                        loop {
                            if w.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                    } else {
                        let mut w = channel.make_writer();
                        let _ = w.write_all(&[b'n'; 64]).await;
                    }
                }
                S2dMode::ExtTiny => {
                    let mut w = channel.make_writer_ext(Some(1));
                    let chunk = vec![b'e'; 16];
                    loop {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
                S2dMode::GatherTiny => {}
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
        if matches!(self.mode, S2dMode::DualFlood { .. }) {
            session.data(channel, Bytes::from(vec![b'r'; 256 * 1024]))?;
            return Ok(());
        }
        if matches!(self.mode, S2dMode::GatherTiny) {
            // Fill HWM with a few large writes so the subsequent 1-byte
            // entries park and can be gathered on the next drain.
            session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            for _ in 0..80 {
                session.data(channel, Bytes::from_static(b"X"))?;
            }
            session.channel_success(channel)?;
            for _ in 0..80 {
                session.data(channel, Bytes::from_static(b"Y"))?;
            }
        }
        Ok(())
    }
}

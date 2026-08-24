//! S7b scheduler adversarial gates (correctness, not a throughput SLO).
//!
//! α = 0.5: each of N active streams must keep ≥ α/N of a post-warmup
//! byte window. Invert hooks (`invert_sched_greedy`,
//! `invert_sched_boost_starve`) must collapse that floor.
//!
//! cargo test -p russh --features _test_hooks --test test_s7_sched -- --nocapture

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use harness::*;
use russh::server::{
    self, Auth, Handler, Msg, OutboundOrderSlot, Server, Session, SlotObserveSlot,
};
use russh::{Channel, ChannelId};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

const MSG_OPEN_CONFIRM: u8 = 91;
const MSG_DATA: u8 = 94;
const ALPHA: f64 = 0.5;
const WINDOW: u32 = 4 * 1024 * 1024;
const PKT: u32 = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
enum FailClass {
    Ok,
    ShareCollapsed { min_share: f64, floor: f64 },
    OldStarved { old_share: f64, floor: f64 },
}

impl FailClass {
    fn name(self) -> &'static str {
        match self {
            FailClass::Ok => "Ok",
            FailClass::ShareCollapsed { .. } => "ShareCollapsed",
            FailClass::OldStarved { .. } => "OldStarved",
        }
    }
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
        sleep(Duration::from_millis(15)).await;
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

fn confirm_ids(order: &OutboundOrderSlot) -> Vec<u32> {
    let mut ids = Vec::new();
    for (c, m, _) in order.snapshot() {
        if m == MSG_OPEN_CONFIRM && !ids.contains(&c) {
            ids.push(c);
        }
    }
    ids
}

fn share_class(deltas: &[u64], n_active: usize) -> FailClass {
    let total: u64 = deltas.iter().sum();
    let floor = ALPHA / n_active as f64;
    if total == 0 {
        return FailClass::ShareCollapsed {
            min_share: 0.0,
            floor,
        };
    }
    let min_share = deltas
        .iter()
        .map(|d| *d as f64 / total as f64)
        .fold(f64::INFINITY, f64::min);
    if min_share + 1e-9 < floor {
        FailClass::ShareCollapsed { min_share, floor }
    } else {
        FailClass::Ok
    }
}

#[derive(Clone)]
enum Mode {
    DualFlood,
    LiveChurn,
    Gather1k,
    Mix128,
}

fn spawn_srv(addr: SocketAddr, config: russh::server::Config, mode: Mode) {
    tokio::spawn(async move {
        let mut sh = Sh { mode };
        if let Err(e) = sh.run_on_address(Arc::new(config), addr).await {
            eprintln!("s7b server exited: {e:?}");
        }
    });
}

struct Sh {
    mode: Mode,
}

impl Server for Sh {
    type Handler = H;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        H {
            mode: self.mode.clone(),
            seq: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct H {
    mode: Mode,
    seq: Arc<AtomicUsize>,
}

impl Handler for H {
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
        let _ = reply.accept().await;
        let idx = self.seq.fetch_add(1, Ordering::Relaxed);
        let mode = self.mode.clone();
        tokio::spawn(async move {
            match mode {
                Mode::DualFlood => {
                    let mut w = channel.make_writer();
                    let chunk = vec![b'x'; 64 * 1024];
                    loop {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
                Mode::LiveChurn => {
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
                        let _ = w.write_all(&[b'n'; 256]).await;
                    }
                }
                Mode::Gather1k => {}
                Mode::Mix128 => {
                    let n = if idx % 2 == 0 { 8 * 1024 } else { 1024 };
                    let mut w = channel.make_writer();
                    let buf = vec![b'm'; n];
                    let _ = w.write_all(&buf).await;
                    let _ = w.shutdown().await;
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
        if matches!(self.mode, Mode::Gather1k) {
            // Fill HWM so later 1 KiB entries stay in pending_data and
            // can be gathered (socket_hang still seals).
            for _ in 0..5 {
                session.data(channel, Bytes::from(vec![b'P'; 32 * 1024]))?;
            }
            for _ in 0..40 {
                session.data(channel, Bytes::from(vec![b'k'; 1024]))?;
            }
        }
        Ok(())
    }
}

fn base_cfg(
    order: Arc<OutboundOrderSlot>,
    hang: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> russh::server::Config {
    russh::server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        window_size: WINDOW,
        maximum_packet_size: PKT,
        outbound_order: Some(order),
        socket_hang: hang,
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    }
}

async fn dual_flood_shares(invert: bool) -> Result<(FailClass, Vec<u64>), anyhow::Error> {
    let order = OutboundOrderSlot::new();
    let addr = free_addr();
    let mut cfg = base_cfg(order.clone(), None);
    cfg.invert_sched_greedy = invert;
    spawn_srv(addr, cfg, Mode::DualFlood);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = WINDOW;
    client_cfg.maximum_packet_size = PKT;
    let session = connect_plain(addr, client_cfg).await?;
    let a = session.channel_open_session().await?;
    let b = session.channel_open_session().await?;
    let _da = spawn_channel_drainer(a);
    let _db = spawn_channel_drainer(b);

    wait_for("two confirms", Duration::from_secs(5), || {
        confirm_ids(&order).len() >= 2
    })
    .await?;
    let ids = confirm_ids(&order);
    let id0 = ids[0];
    let id1 = ids[1];

    if invert {
        wait_for("greedy filled one stream", Duration::from_secs(6), || {
            data_bytes_by_channel(&order).values().sum::<u64>() >= 128 * 1024
        })
        .await?;
    } else {
        wait_for("both streams warmed", Duration::from_secs(6), || {
            let m = data_bytes_by_channel(&order);
            m.get(&id0).copied().unwrap_or(0) >= 32 * 1024
                && m.get(&id1).copied().unwrap_or(0) >= 32 * 1024
        })
        .await?;
    }

    let snap = data_bytes_by_channel(&order);
    let s0 = snap.get(&id0).copied().unwrap_or(0);
    let s1 = snap.get(&id1).copied().unwrap_or(0);
    wait_for("share window", Duration::from_secs(6), || {
        let m = data_bytes_by_channel(&order);
        let d0 = m.get(&id0).copied().unwrap_or(0).saturating_sub(s0);
        let d1 = m.get(&id1).copied().unwrap_or(0).saturating_sub(s1);
        if invert {
            d0 + d1 >= 64 * 1024
        } else {
            d0 >= 32 * 1024 && d1 >= 32 * 1024
        }
    })
    .await?;
    let now = data_bytes_by_channel(&order);
    let d0 = now.get(&id0).copied().unwrap_or(0).saturating_sub(s0);
    let d1 = now.get(&id1).copied().unwrap_or(0).saturating_sub(s1);
    let class = share_class(&[d0, d1], 2);
    eprintln!(
        "s7b share invert={invert} id0={id0} d0={d0} id1={id1} d1={d1} class={}",
        class.name()
    );
    Ok((class, vec![d0, d1]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_min_share() -> Result<(), anyhow::Error> {
    let (class, _) = dual_flood_shares(false).await?;
    assert_eq!(
        class,
        FailClass::Ok,
        "HARD: two live streams must each keep ≥ α/N = {} class={class:?}",
        ALPHA / 2.0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_min_share_invert_is_red() -> Result<(), anyhow::Error> {
    let (class, deltas) = dual_flood_shares(true).await?;
    match class {
        FailClass::ShareCollapsed { min_share, floor } => {
            eprintln!("s7b invert ShareCollapsed min={min_share:.4} floor={floor:.4} Δ={deltas:?}");
        }
        other => anyhow::bail!("HARD: greedy invert must be ShareCollapsed, got {other:?}"),
    }
    Ok(())
}

async fn churn_old_share(invert: bool) -> Result<(FailClass, u64, u64, u32), anyhow::Error> {
    let order = OutboundOrderSlot::new();
    let addr = free_addr();
    let mut cfg = base_cfg(order.clone(), None);
    cfg.invert_sched_boost_starve = invert;
    spawn_srv(addr, cfg, Mode::LiveChurn);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = WINDOW;
    client_cfg.maximum_packet_size = PKT;
    let session = connect_plain(addr, client_cfg).await?;
    let old = session.channel_open_session().await?;
    let _d = spawn_channel_drainer(old);

    wait_for("old first DATA", Duration::from_secs(6), || {
        !data_payloads(&order).is_empty()
    })
    .await?;
    let old_id = data_payloads(&order)[0].0;
    // Production: wait until the first-packet boost is gone so the
    // window measures regular service. Invert never serves old after
    // that first packet — require only that one DATA exists.
    if !invert {
        wait_for("old boost cleared", Duration::from_secs(6), || {
            data_bytes_by_channel(&order)
                .get(&old_id)
                .copied()
                .unwrap_or(0)
                >= 32 * 1024
        })
        .await?;
    }

    let snap = data_bytes_by_channel(&order);
    let old0 = snap.get(&old_id).copied().unwrap_or(0);
    let others0: u64 = snap
        .iter()
        .filter(|(id, _)| **id != old_id)
        .map(|(_, b)| *b)
        .sum();

    let mut cycles = 0u32;
    for _ in 0..12 {
        let mut ch = session.channel_open_session().await?;
        let mut reader = ch.make_reader();
        let mut buf = [0u8; 8];
        match tokio::time::timeout(Duration::from_secs(3), reader.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            other => {
                if invert {
                    // Invert may deliver the first-byte; if not, still count the open.
                    let _ = other;
                } else {
                    anyhow::bail!("HARD: churn open produced no first byte: {other:?}");
                }
            }
        }
        drop(reader);
        let _ = ch.close().await;
        cycles += 1;
    }

    let now = data_bytes_by_channel(&order);
    let old1 = now.get(&old_id).copied().unwrap_or(0);
    let others1: u64 = now
        .iter()
        .filter(|(id, _)| **id != old_id)
        .map(|(_, b)| *b)
        .sum();
    let old_d = old1.saturating_sub(old0);
    let new_d = others1.saturating_sub(others0);
    let total = old_d + new_d;
    let floor = ALPHA;
    let old_share = if total == 0 {
        0.0
    } else {
        old_d as f64 / total as f64
    };
    let class = if old_share + 1e-9 < floor {
        FailClass::OldStarved { old_share, floor }
    } else {
        FailClass::Ok
    };
    eprintln!(
        "s7b churn invert={invert} old_d={old_d} new_d={new_d} share={old_share:.4} \
         cycles={cycles} class={}",
        class.name()
    );
    Ok((class, old_d, new_d, cycles))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_churn_old_share() -> Result<(), anyhow::Error> {
    let (class, old_d, _, cycles) = churn_old_share(false).await?;
    assert!(cycles >= 8, "HARD: need ≥8 churn cycles, got {cycles}");
    assert!(old_d > 0, "HARD: old stream made no progress during churn");
    assert_eq!(
        class,
        FailClass::Ok,
        "HARD: old stream share must stay ≥ {ALPHA} under churn class={class:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_churn_old_share_invert_is_red() -> Result<(), anyhow::Error> {
    let (class, _, _, _) = churn_old_share(true).await?;
    match class {
        FailClass::OldStarved { old_share, floor } => {
            eprintln!("s7b invert OldStarved share={old_share:.4} floor={floor:.4}");
        }
        other => anyhow::bail!("HARD: boost-starve invert must be OldStarved, got {other:?}"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_gather_rate() -> Result<(), anyhow::Error> {
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let addr = free_addr();
    let mut cfg = base_cfg(order.clone(), Some(hang.clone()));
    cfg.maximum_packet_size = 32 * 1024;
    spawn_srv(addr, cfg, Mode::Gather1k);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = WINDOW;
    client_cfg.maximum_packet_size = 32 * 1024;
    let session = connect_plain(addr, client_cfg).await?;
    let a = session.channel_open_session().await?;
    let b = session.channel_open_session().await?;
    wait_for("two confirms", Duration::from_secs(5), || {
        confirm_ids(&order).len() >= 2
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    a.exec(true, "g").await?;
    b.exec(true, "g").await?;
    sleep(Duration::from_millis(300)).await;
    let mark = data_payloads(&order).len();
    hang.store(false, Ordering::SeqCst);
    let _da = spawn_channel_drainer(a);
    let _db = spawn_channel_drainer(b);
    wait_for("post-hang DATA", Duration::from_secs(6), || {
        data_payloads(&order).len() > mark + 2
    })
    .await?;
    sleep(Duration::from_millis(200)).await;
    let after: Vec<u32> = data_payloads(&order)
        .into_iter()
        .skip(mark)
        .map(|(_, n)| n)
        .collect();
    let n = after.len() as u64;
    let sum: u64 = after.iter().map(|p| u64::from(*p)).sum();
    let mean = if n == 0 { 0.0 } else { sum as f64 / n as f64 };
    eprintln!("s7b gather mark={mark} after={after:?} mean={mean:.1}");
    assert!(
        after.iter().any(|p| *p > 1024),
        "HARD: gather silent-degraded (post-hang payloads all ≤1 KiB) after={after:?}"
    );
    assert!(
        mean >= 2048.0,
        "HARD: post-hang mean {mean:.1} < 2 KiB lock after={after:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7b_max_channels_mix() -> Result<(), anyhow::Error> {
    let order = OutboundOrderSlot::new();
    let slots = SlotObserveSlot::new();
    let addr = free_addr();
    let mut cfg = base_cfg(order.clone(), None);
    cfg.max_channels = 128;
    cfg.slot_observe = Some(slots.clone());
    spawn_srv(addr, cfg, Mode::Mix128);
    wait_listening(addr).await;
    let mut client_cfg = default_client_config();
    client_cfg.window_size = WINDOW;
    client_cfg.maximum_packet_size = PKT;
    client_cfg.channel_buffer_size = 32;
    let session = connect_plain(addr, client_cfg).await?;

    let mut chans = Vec::new();
    for _ in 0..128 {
        chans.push(session.channel_open_session().await?);
    }
    wait_for("128 live slots", Duration::from_secs(6), || {
        slots.used() >= 128 || slots.max_used() >= 128
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} used={} max_used={} opening={} active={}",
            slots.used(),
            slots.max_used(),
            slots.opening(),
            slots.active()
        )
    })?;
    let mut got = Vec::new();
    for (i, mut ch) in chans.into_iter().enumerate() {
        let want = if i % 2 == 0 { 8 * 1024u64 } else { 1024 };
        let mut reader = ch.make_reader();
        let mut buf = vec![0u8; 16 * 1024];
        let mut n = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while n < want && std::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(400), reader.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(k)) => n += k as u64,
                Ok(Err(e)) => anyhow::bail!("HARD: mix128 ch {i} read {e}"),
            }
        }
        drop(reader);
        let _ = ch.close().await;
        got.push(n);
        assert!(n >= want, "HARD: mix128 ch {i} short {n}/{want}");
    }
    wait_for("slots drained", Duration::from_secs(6), || {
        slots.opening() + slots.active() + slots.closing() == 0
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} opening={} active={} closing={} used={}",
            slots.opening(),
            slots.active(),
            slots.closing(),
            slots.used()
        )
    })?;
    assert_eq!(
        slots.rejected_full(),
        0,
        "HARD: mix128 hit slot full rejects"
    );
    eprintln!(
        "s7b mix128 done n={} max_used={} rejected={}",
        got.len(),
        slots.max_used(),
        slots.rejected_full()
    );
    Ok(())
}

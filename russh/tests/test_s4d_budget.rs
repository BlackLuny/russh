//! S4d: process-level GlobalBudget + max_connections + floor.
//!
//! Real `Session::run` + real sockets. G4 invert must be red with an
//! enumerated failure class (not a bare `is_err()`). Zero fallbacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{
    self, AdmitSplitGate, Auth, GlobalBudget, Handler, Msg, Session, WindowObserveSlot,
    DEFAULT_GLOBAL_BYTE_BUDGET,
};
use russh::{client, Channel, ChannelMsg, ChannelOpenFailure, Error};
use ssh_key::PrivateKey;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(8);

fn server_cfg() -> server::Config {
    let mut cfg = server::Config::default();
    cfg.inactivity_timeout = None;
    cfg.auth_rejection_time = Duration::from_secs(0);
    cfg.keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    cfg
}

fn fixed_plus_opening(cfg: &server::Config) -> u64 {
    let fixed = cfg.inbound_ctrl_budget as u64 + server::WRITER_KEX_BUDGET as u64;
    let opening = cfg.window_size as u64 + server::OUTBOUND_CAP_ESTIMATE;
    fixed + opening * cfg.max_channels.max(1) as u64
}

async fn spawn_listener(
    cfg: Arc<server::Config>,
    handler: impl Fn() -> AcceptCount + Send + Sync + 'static,
) -> std::net::SocketAddr {
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = sock.accept().await else {
                break;
            };
            let cfg = cfg.clone();
            let h = handler();
            tokio::spawn(async move {
                match server::run_stream(cfg, s, h).await {
                    Ok(running) => {
                        let _ = running.await;
                    }
                    Err(_) => {}
                }
            });
        }
    });
    addr
}

async fn spawn_one<H: Handler + Send + 'static>(
    cfg: Arc<server::Config>,
    handler: H,
) -> std::net::SocketAddr {
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = sock.accept().await.unwrap();
        if let Ok(running) = server::run_stream(cfg, s, handler).await {
            let _ = running.await;
        }
    });
    addr
}

async fn connect(addr: std::net::SocketAddr) -> Result<client::Handle<NopClient>, russh::Error> {
    let mut ccfg = client::Config::default();
    ccfg.inactivity_timeout = None;
    let mut session = client::connect(Arc::new(ccfg), addr, NopClient).await?;
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let ok = session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, None))
        .await?
        .success();
    if !ok {
        return Err(russh::Error::NotAuthenticated);
    }
    Ok(session)
}

struct NopClient;
impl client::Handler for NopClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct AcceptCount {
    bytes: Arc<AtomicU64>,
}

impl Handler for AcceptCount {
    type Error = russh::Error;
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
        reply.accept().await?;
        let bytes = self.bytes.clone();
        tokio::spawn(async move {
            let mut ch = channel;
            while let Some(msg) = ch.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
                }
            }
        });
        Ok(())
    }
}

/// Enumerated failure classes for S8c ledger gates. No Timeout class —
/// a wait that expires maps onto the invariant it failed to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerFail {
    GrantStarved { round: usize },
    SecondOpenRefused,
    NoResumeAfterRelease,
}

// ── G1 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g1_global_budget_n_connections() {
    const N: usize = 32;
    let mut cfg = server_cfg();
    cfg.window_size = 8192;
    cfg.maximum_packet_size = 4096;
    cfg.max_channels = 1;
    cfg.max_connections = N;
    cfg.global_byte_budget = fixed_plus_opening(&cfg) * N as u64;
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let b2 = bytes.clone();
    let addr = spawn_listener(cfg, move || AcceptCount {
        bytes: b2.clone(),
    })
    .await;

    let mut sessions = Vec::new();
    for i in 0..N {
        let s = timeout(DEADLINE, connect(addr))
            .await
            .unwrap_or_else(|_| panic!("G1 HARD: connect {i} timed out"))
            .unwrap_or_else(|e| panic!("G1 HARD: connect {i} failed: {e:?}"));
        let ch = timeout(DEADLINE, s.channel_open_session())
            .await
            .expect("G1 HARD: open timed out")
            .unwrap_or_else(|e| panic!("G1 HARD: open {i} failed: {e:?}"));
        ch.data_bytes(vec![7u8; 8192])
            .await
            .unwrap_or_else(|e| panic!("G1 HARD: data {i} failed: {e:?}"));
        sessions.push((s, ch));
    }

    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 8192 * N as u64 {
        if std::time::Instant::now() > deadline {
            panic!(
                "G1 HARD: delivered {} want {}",
                bytes.load(Ordering::SeqCst),
                8192 * N
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        gb.used() <= gb.budget(),
        "G1 HARD: used {} > budget {}",
        gb.used(),
        gb.budget()
    );
    assert!(
        gb.max_used() <= gb.budget(),
        "G1 HARD: max_used {} > budget {}",
        gb.max_used(),
        gb.budget()
    );
    assert_eq!(
        gb.connections(),
        N,
        "G1 HARD: live connections {} want {N}",
        gb.connections()
    );

    let extra = timeout(Duration::from_secs(3), connect(addr)).await;
    match extra {
        Ok(Err(_)) | Err(_) => {}
        Ok(Ok(_)) => panic!("G1 HARD: connection N+1 must not enter"),
    }

    // Already-admitted connections survive the rejected extra connect
    // and the other connections filling their windows.
    assert_eq!(
        gb.connections(),
        N,
        "G1 HARD: filling / reject must not tear down live connections"
    );
    drop(sessions);
}

// ── G2 ──────────────────────────────────────────────────────────────────────
//
// Old G2 (budget = fixed+opening, first refill Δ must freshly reserve)
// pinned S4d's implementation deviation: each WINDOW_ADJUST Δ consumed
// process budget. That contradicts
//   impl-S4-plan.md L244 — inbound grant credit reserved before grant;
//     refund on consume / close / teardown
//   impl-S4-plan.md L520 — book "granted-not-refunded", not the sum of
//     every ADJUST Δ
//   global_budget.rs header — fully loaded connection =
//     max_channels × (window_size + OUTBOUND_CAP_ESTIMATE)
// After the S8c ledger fix a refill that does not raise the committed
// ceiling reserves 0, so the old construction would go green without
// ever testing true exhaust. Exhaust now comes from ceiling growth
// (handler adjust_window → 2×window) against budget = fixed+opening.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g2_grant_reserve_fail_no_adjust() {
    let mut cfg = server_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 1;
    cfg.max_connections = 1;
    cfg.global_byte_budget = fixed_plus_opening(&cfg);
    let wobs = WindowObserveSlot::new();
    cfg.window_observe = Some(wobs.clone());
    let raise = Arc::new(AtomicU32::new(128));
    cfg.grant_target_override = Some(raise);
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_one(
        cfg,
        AcceptCount {
            bytes: bytes.clone(),
        },
    )
    .await;
    let session = timeout(DEADLINE, connect(addr))
        .await
        .expect("G2 HARD: connect timeout")
        .expect("G2 HARD: connect");
    let mut ch = timeout(DEADLINE, session.channel_open_session())
        .await
        .expect("G2 HARD: open timeout")
        .expect("G2 HARD: open");

    let expand0 = wobs.expand_ok();
    let adj0 = wobs.adjust_emitted_seq();
    timeout(DEADLINE, ch.data_bytes(vec![3u8; 64]))
        .await
        .expect("G2 HARD: data1 timeout")
        .expect("G2 HARD: data1");
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 64 {
        if std::time::Instant::now() > deadline {
            panic!("G2 HARD: DATA1 not delivered");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let deadline = std::time::Instant::now() + DEADLINE;
    while gb.grant_reserve_fail() == 0 {
        if std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        wobs.expand_ok(),
        expand0,
        "G2 HARD: expand must not increase after global exhaust"
    );
    assert_eq!(
        wobs.adjust_emitted_seq(),
        adj0,
        "G2 HARD: must not emit ADJUST after global exhaust"
    );
    assert!(
        gb.grant_reserve_fail() >= 1,
        "G2 HARD: grant reserve must fail (got {})",
        gb.grant_reserve_fail()
    );
    // Channel is still open: a further write within the (now zero)
    // window is the peer's problem; we must not have Overflow-closed.
    let closed = timeout(Duration::from_millis(80), ch.wait()).await;
    assert!(
        closed.is_err(),
        "G2 HARD: channel must stay open (not Overflow-closed)"
    );
}

// ── S8c ledger: refill does not accumulate (must-red on unfixed tree) ────────

async fn wait_delivered(bytes: &AtomicU64, want: u64, round: usize) -> Result<(), LedgerFail> {
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < want {
        if std::time::Instant::now() > deadline {
            return Err(LedgerFail::GrantStarved { round });
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

async fn grant_refill_does_not_accumulate_round() -> Result<(), LedgerFail> {
    let mut cfg = server_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 2;
    cfg.max_connections = 1;
    cfg.global_byte_budget = fixed_plus_opening(&cfg);
    let wobs = WindowObserveSlot::new();
    cfg.window_observe = Some(wobs.clone());
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_one(
        cfg,
        AcceptCount {
            bytes: bytes.clone(),
        },
    )
    .await;
    let session = timeout(DEADLINE, connect(addr))
        .await
        .map_err(|_| LedgerFail::GrantStarved { round: 0 })?
        .map_err(|_| LedgerFail::GrantStarved { round: 0 })?;
    let ch = timeout(DEADLINE, session.channel_open_session())
        .await
        .map_err(|_| LedgerFail::GrantStarved { round: 0 })?
        .map_err(|_| LedgerFail::GrantStarved { round: 0 })?;

    for round in 1..=8 {
        let adj0 = wobs.adjust_emitted_seq();
        let want = 64u64 * round as u64;
        ch.data_bytes(vec![round as u8; 64])
            .await
            .map_err(|_| LedgerFail::GrantStarved { round })?;
        wait_delivered(bytes.as_ref(), want, round).await?;
        let deadline = std::time::Instant::now() + DEADLINE;
        while wobs.adjust_emitted_seq() == adj0 {
            if gb.grant_reserve_fail() >= 1 {
                return Err(LedgerFail::GrantStarved { round });
            }
            if std::time::Instant::now() > deadline {
                return Err(LedgerFail::GrantStarved { round });
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    if gb.grant_reserve_fail() != 0 {
        return Err(LedgerFail::GrantStarved { round: 8 });
    }
    match timeout(DEADLINE, session.channel_open_session()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(Error::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage)))
        | Ok(Err(Error::ChannelOpenFailure(_))) => Err(LedgerFail::SecondOpenRefused),
        Ok(Err(_)) | Err(_) => Err(LedgerFail::SecondOpenRefused),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8c_grant_refill_does_not_accumulate() {
    match grant_refill_does_not_accumulate_round().await {
        Ok(()) => {}
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

// ── S8c ledger: exhaust then release resumes (must-red on unfixed tree) ──────

async fn grant_resumes_after_release_round() -> Result<(), LedgerFail> {
    let mut cfg = server_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 2;
    cfg.max_connections = 1;
    cfg.global_byte_budget = fixed_plus_opening(&cfg);
    let wobs = WindowObserveSlot::new();
    cfg.window_observe = Some(wobs.clone());
    let raise = Arc::new(AtomicU32::new(128));
    cfg.grant_target_override = Some(raise);
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_one(
        cfg,
        AcceptCount {
            bytes: bytes.clone(),
        },
    )
    .await;
    let session = timeout(DEADLINE, connect(addr))
        .await
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?;
    let ch1 = timeout(DEADLINE, session.channel_open_session())
        .await
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?;
    let ch2 = timeout(DEADLINE, session.channel_open_session())
        .await
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?;

    timeout(DEADLINE, ch1.data_bytes(vec![1u8; 64]))
        .await
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?;
    wait_delivered(bytes.as_ref(), 64, 1)
        .await
        .map_err(|_| LedgerFail::NoResumeAfterRelease)?;

    // Ceiling already 2×window via grant_target_override. The first
    // grant after delivery is a growth reserve and must fail while
    // ch2 occupies the rest of the floor.
    let drive = std::time::Instant::now() + DEADLINE;
    while gb.grant_reserve_fail() == 0 {
        if std::time::Instant::now() > drive {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if gb.grant_reserve_fail() == 0 {
        return Err(LedgerFail::NoResumeAfterRelease);
    }

    let adj0 = wobs.adjust_emitted_seq();
    let _ = ch2.close().await;
    drop(ch2);

    let deadline = std::time::Instant::now() + DEADLINE;
    while wobs.adjust_emitted_seq() == adj0 {
        if std::time::Instant::now() > deadline {
            return Err(LedgerFail::NoResumeAfterRelease);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let _ = ch1;
    let _ = session;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8c_grant_resumes_after_release() {
    match grant_resumes_after_release_round().await {
        Ok(()) => {}
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

// ── G3 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g3_disconnect_refunds_floor() {
    let mut cfg = server_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 1;
    cfg.max_connections = 1;
    cfg.global_byte_budget = fixed_plus_opening(&cfg);
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_listener(cfg.clone(), {
        let bytes = bytes.clone();
        move || AcceptCount {
            bytes: bytes.clone(),
        }
    })
    .await;

    let s1 = timeout(DEADLINE, connect(addr))
        .await
        .expect("G3 HARD: c1 connect timeout")
        .expect("G3 HARD: c1 connect");
    let ch1 = timeout(DEADLINE, s1.channel_open_session())
        .await
        .expect("G3 HARD: c1 open timeout")
        .expect("G3 HARD: c1 open");
    ch1.data_bytes(vec![1u8; 64]).await.expect("G3 HARD: c1 data");
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 64 {
        if std::time::Instant::now() > deadline {
            panic!("G3 HARD: c1 DATA not delivered");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(gb.connections(), 1, "G3 HARD: c1 must occupy the only slot");
    drop(s1);
    drop(ch1);

    let deadline = std::time::Instant::now() + DEADLINE;
    while gb.connections() != 0 || gb.used() != 0 {
        if std::time::Instant::now() > deadline {
            panic!(
                "G3 HARD: refund incomplete used={} conns={}",
                gb.used(),
                gb.connections()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let s2 = timeout(DEADLINE, connect(addr))
        .await
        .expect("G3 HARD: c2 connect timeout")
        .expect("G3 HARD: c2 connect after refund");
    let ch2 = timeout(DEADLINE, s2.channel_open_session())
        .await
        .expect("G3 HARD: c2 open timeout")
        .expect("G3 HARD: c2 must reopen after refund");
    ch2.data_bytes(vec![2u8; 64]).await.expect("G3 HARD: c2 data");
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 128 {
        if std::time::Instant::now() > deadline {
            panic!("G3 HARD: c2 did not deliver a full window after refund");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ── G4 ──────────────────────────────────────────────────────────────────────

fn g4_round(invert: bool) -> Result<(), &'static str> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    rt.block_on(async move { g4_round_async(invert).await })
}

async fn g4_round_async(invert: bool) -> Result<(), &'static str> {
    let mut cfg = server_cfg();
    // Large enough that reserve succeeds; we are testing order, not exhaust.
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 4;
    cfg.max_connections = 8;
    cfg.global_byte_budget = DEFAULT_GLOBAL_BYTE_BUDGET;
    cfg.invert_global_before_expand = invert;
    let wobs = WindowObserveSlot::new();
    cfg.window_observe = Some(wobs.clone());
    let cfg_arc = Arc::new(cfg);
    let gb = cfg_arc.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_one(
        cfg_arc,
        AcceptCount {
            bytes: bytes.clone(),
        },
    )
    .await;
    let session = timeout(DEADLINE, connect(addr))
        .await
        .map_err(|_| "open")?
        .map_err(|_| "open")?;
    let ch = timeout(DEADLINE, session.channel_open_session())
        .await
        .map_err(|_| "open")?
        .map_err(|_| "open")?;
    ch.data_bytes(vec![9u8; 64]).await.map_err(|_| "data")?;

    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 64 {
        if std::time::Instant::now() > deadline {
            return Err("timeout");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Wait for a grant attempt (or the invert path to fire).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while wobs.expand_ok() == 0
        && gb.grant_reserve_fail() == 0
        && gb.expand_before_global() == 0
        && gb.global_before_expand() == 0
    {
        if std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(40)).await;

    let reserve_seq = wobs.global_reserve_seq();
    let expand_seq = wobs.cap_expanded_seq();
    let adj_seq = wobs.adjust_emitted_seq();

    if invert {
        if expand_seq > 0 && reserve_seq == 0 {
            return Err("expand_without_reserve");
        }
        if adj_seq > 0 && reserve_seq == 0 {
            return Err("adjust_without_reserve");
        }
        if expand_seq > 0 && reserve_seq > 0 && expand_seq < reserve_seq {
            return Err("order");
        }
        if gb.expand_before_global() > 0 {
            return Err("order");
        }
        return Err("expected_invert_red");
    }

    if reserve_seq == 0 || expand_seq == 0 {
        return Err("order");
    }
    if !(reserve_seq < expand_seq) {
        return Err("order");
    }
    if gb.expand_before_global() > 0 {
        return Err("order");
    }
    if gb.global_before_expand() == 0 {
        return Err("order");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g4_order_is_global_then_expand() {
    g4_round_async(false)
        .await
        .unwrap_or_else(|e| panic!("G4 HARD: production order failed: {e}"));
}

#[test]
fn g4_invert_global_before_expand_is_red() {
    let r = g4_round(true);
    match r {
        Err("order") | Err("expand_without_reserve") | Err("adjust_without_reserve") => {}
        other => panic!(
            "G4 HARD: invert must fail with enumerated class \
             (order|expand_without_reserve|adjust_without_reserve), got {other:?}"
        ),
    }
}

// ── G5 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g5_floor_not_starved() {
    let mut cfg = server_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.max_channels = 1;
    cfg.max_connections = 2;
    cfg.global_byte_budget = fixed_plus_opening(&cfg) * 2;
    let cfg = Arc::new(cfg);
    let gb = cfg.shared_budget();
    let bytes = Arc::new(AtomicU64::new(0));
    let addr = spawn_listener(cfg.clone(), {
        let bytes = bytes.clone();
        move || AcceptCount {
            bytes: bytes.clone(),
        }
    })
    .await;

    let s1 = timeout(DEADLINE, connect(addr))
        .await
        .expect("G5 HARD: c1 connect timeout")
        .expect("G5 HARD: c1 connect");
    let ch1 = timeout(DEADLINE, s1.channel_open_session())
        .await
        .expect("G5 HARD: c1 open timeout")
        .expect("G5 HARD: c1 open");
    ch1.data_bytes(vec![1u8; 64]).await.expect("G5 HARD: c1 fill");
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 64 {
        if std::time::Instant::now() > deadline {
            panic!("G5 HARD: c1 did not fill its window");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // c1 sits on its floor (and any leftover remainder). c2 must still
    // get its exclusive floor and deliver one window.
    let s2 = timeout(DEADLINE, connect(addr))
        .await
        .expect("G5 HARD: c2 connect timeout")
        .expect("G5 HARD: c2 must enter on its floor");
    let ch2 = timeout(DEADLINE, s2.channel_open_session())
        .await
        .expect("G5 HARD: c2 open timeout")
        .expect("G5 HARD: c2 must open on its floor");
    ch2.data_bytes(vec![2u8; 64])
        .await
        .expect("G5 HARD: c2 data");
    let deadline = std::time::Instant::now() + DEADLINE;
    while bytes.load(Ordering::SeqCst) < 128 {
        if std::time::Instant::now() > deadline {
            panic!("G5 HARD: c2 did not deliver a floor window");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(gb.connections(), 2, "G5 HARD: both connections live");
    assert!(
        gb.used() <= gb.budget(),
        "G5 HARD: used {} > budget {}",
        gb.used(),
        gb.budget()
    );
}

// ── G6 admission slot+floor atomic ──────────────────────────────────────────

fn g6_cfg() -> server::Config {
    let mut c = server::Config::default();
    c.window_size = 1024;
    c.max_channels = 1;
    c.max_connections = 2;
    // 2×declared so floor_unit == declared; 1 extra byte would steal
    // the other slot's floor (r1 P1-2 shape).
    let per = c.window_size as u64 + server::OUTBOUND_CAP_ESTIMATE;
    let fixed = c.inbound_ctrl_budget as u64 + server::WRITER_KEX_BUDGET as u64;
    c.global_byte_budget = (fixed + per) * 2;
    c
}

#[test]
fn g6_admission_floor_atomic() {
    let c = g6_cfg();
    let gb = Arc::new(GlobalBudget::new(
        c.global_byte_budget,
        c.max_connections,
        None,
    ));
    let a = gb.try_acquire(&c).expect("G6 HARD: A admit");
    a.try_reserve(a.floor().saturating_sub(a.held()))
        .expect("G6 HARD: fill A to floor");
    assert_eq!(a.held(), a.floor());
    match a.try_reserve(1) {
        Err(()) => {}
        Ok(()) => panic!("G6 HARD: A must not take future-slot floor (stolen_floor)"),
    }
    let b = match gb.try_acquire(&c) {
        Ok(b) => b,
        Err(e) => panic!("G6 HARD: B must still admit, got {e:?}"),
    };
    assert_eq!(gb.connections(), 2);
    assert!(gb.used() <= gb.budget());
    drop(a);
    drop(b);
}

fn g6_split_round() -> Result<(), &'static str> {
    let c = g6_cfg();
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
    let c_b = g6_cfg();
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

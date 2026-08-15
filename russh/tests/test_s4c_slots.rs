//! S4c: channel slot(gen) + open_decision_deadline + late-disposition.
//!
//! Real `Session::run` + real sockets. L4 invert must be red when
//! `invert_open_confirm_before_lane` is on. Zero fallbacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{
    self, Auth, Handler, HandlerObserveSlot, Msg, OutboundOrderSlot, Session, SlotObserveSlot,
    WindowObserveSlot,
};
use russh::{client, Channel, ChannelMsg, ChannelOpenFailure, Error};
use ssh_key::PrivateKey;
use tokio::sync::Notify;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(5);

fn server_cfg() -> server::Config {
    let mut cfg = server::Config::default();
    cfg.inactivity_timeout = None;
    cfg.auth_rejection_time = Duration::from_secs(0);
    cfg.keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    cfg
}

async fn spawn_one<H: Handler + Send + 'static>(
    cfg: server::Config,
    handler: H,
) -> std::net::SocketAddr {
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let cfg = Arc::new(cfg);
    tokio::spawn(async move {
        let (s, _) = sock.accept().await.unwrap();
        if let Ok(running) = server::run_stream(cfg, s, handler).await {
            let _ = running.await;
        }
    });
    addr
}

async fn connect(addr: std::net::SocketAddr) -> client::Handle<NopClient> {
    let mut ccfg = client::Config::default();
    ccfg.inactivity_timeout = None;
    let mut session = client::connect(Arc::new(ccfg), addr, NopClient)
        .await
        .unwrap();
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let ok = session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, None))
        .await
        .unwrap()
        .success();
    assert!(ok, "auth failed");
    session
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

// ── handlers ────────────────────────────────────────────────────────────────

struct HoldAccept {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    accept_result: Arc<Mutex<Option<Result<(), russh::Error>>>>,
    echo: bool,
}

impl Handler for HoldAccept {
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.entered.notify_waiters();
        self.release.notified().await;
        let r = reply.accept().await;
        *self.accept_result.lock().unwrap() = Some(r);
        if self.echo {
            let _ = session.data(channel.id(), Bytes::from_static(b"s4c-echo"));
        }
        Ok(())
    }
}

struct AcceptEcho;
impl Handler for AcceptEcho {
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await?;
        let _ = session.data(channel.id(), Bytes::from_static(b"s4c-l4"));
        Ok(())
    }
}



// ── L1 late-disposition ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l1_late_accept_after_deadline_is_expired() {
    let mut cfg = server_cfg();
    cfg.open_decision_deadline = Duration::from_millis(80);
    let slots = SlotObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let order = OutboundOrderSlot::new();
    cfg.slot_observe = Some(slots.clone());
    cfg.window_observe = Some(wobs.clone());
    cfg.outbound_order = Some(order.clone());

    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let accept_result = Arc::new(Mutex::new(None));
    let addr = spawn_one(
        cfg,
        HoldAccept {
            entered: entered.clone(),
            release: release.clone(),
            accept_result: accept_result.clone(),
            echo: false,
        },
    )
    .await;
    let session = connect(addr).await;

    let open = tokio::spawn(async move { session.channel_open_session().await });
    timeout(DEADLINE, entered.notified())
        .await
        .expect("L1 HARD: handler never saw CHANNEL_OPEN");

    let open_res = timeout(DEADLINE, open)
        .await
        .expect("L1 HARD: client open did not finish after deadline")
        .expect("join");
    match open_res {
        Err(Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => {}
        other => panic!("L1 HARD: peer must see OPEN_FAILURE first, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(30)).await;
    let fails = order
        .snapshot()
        .into_iter()
        .filter(|(_, m, _)| *m == 92)
        .count();
    assert_eq!(fails, 1, "L1 HARD: exactly one OPEN_FAILURE on the wire");
    assert_eq!(
        wobs.lane_count(),
        0,
        "L1 HARD: no lane leak after deadline FAILURE"
    );

    release.notify_waiters();
    let deadline = std::time::Instant::now() + DEADLINE;
    let got = loop {
        if let Some(r) = accept_result.lock().unwrap().take() {
            break r;
        }
        if std::time::Instant::now() > deadline {
            panic!("L1 HARD: accept() never returned after release");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert!(
        matches!(got, Err(Error::ChannelOpenExpired)),
        "L1 HARD: late accept must be ChannelOpenExpired, got {got:?}"
    );

    tokio::time::sleep(Duration::from_millis(40)).await;
    let fails2 = order
        .snapshot()
        .into_iter()
        .filter(|(_, m, _)| *m == 92)
        .count();
    let confirms = order
        .snapshot()
        .into_iter()
        .filter(|(_, m, _)| *m == 91)
        .count();
    assert_eq!(fails2, 1, "L1 HARD: no second FAILURE");
    assert_eq!(confirms, 0, "L1 HARD: no CONFIRMATION after expire");
    assert_eq!(wobs.lane_count(), 0, "L1 HARD: still no lane");
    assert!(
        slots.expired() >= 1,
        "L1 HARD: expire counter must move, got {}",
        slots.expired()
    );
}

// ── L2 open-flood ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l2_open_flood_rejects_past_max() {
    const MAX: usize = 8;
    let mut cfg = server_cfg();
    cfg.max_channels = MAX;
    let slots = SlotObserveSlot::new();
    let hob = HandlerObserveSlot::new();
    cfg.slot_observe = Some(slots.clone());
    cfg.handler_observe = Some(hob.clone());

    let addr = spawn_one(cfg, AcceptEcho).await;
    let session = connect(addr).await;

    let mut live = Vec::new();
    for i in 0..MAX {
        let ch = timeout(DEADLINE, session.channel_open_session())
            .await
            .unwrap_or_else(|_| panic!("L2 HARD: open #{i} timed out"))
            .unwrap_or_else(|e| panic!("L2 HARD: open #{i} failed: {e:?}"));
        live.push(ch);
    }

    let mut rejected = 0usize;
    for i in 0..32 {
        match timeout(DEADLINE, session.channel_open_session()).await {
            Ok(Err(Error::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage))) => {
                rejected += 1;
            }
            Ok(Err(Error::ChannelOpenFailure(_))) => rejected += 1,
            Ok(Ok(_)) => panic!("L2 HARD: open past max must FAILURE, got Ok (extra #{i})"),
            Ok(Err(e)) => panic!("L2 HARD: unexpected err on extra #{i}: {e:?}"),
            Err(_) => panic!("L2 HARD: extra open #{i} timed out (must be immediate FAILURE)"),
        }
    }
    assert_eq!(rejected, 32, "L2 HARD: all extras must fail");
    assert!(
        slots.max_used() <= MAX,
        "L2 HARD: used {} > max {MAX}",
        slots.max_used()
    );
    assert!(
        slots.max_opening() <= MAX,
        "L2 HARD: pending opening {} > max {MAX}",
        slots.max_opening()
    );
    assert!(
        slots.rejected_full() >= 1,
        "L2 HARD: full-reject counter silent"
    );

    let ch = &mut live[0];
    let _ = ch.data(&b"ping"[..]).await;
    let got = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return Vec::new(),
            }
        }
    })
    .await
    .expect("L2 HARD: live channel went silent");
    assert_eq!(got, b"s4c-l4", "L2 HARD: already-open channel must still work");
}

// ── L3 isolation ────────────────────────────────────────────────────────────

struct LiveThenHold {
    live_ready: Arc<Notify>,
    hold_second: Arc<Notify>,
    opens: AtomicU32,
}

impl Handler for LiveThenHold {
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let n = self.opens.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            reply.accept().await?;
            let handle = session.handle();
            let id = channel.id();
            let mut stream = channel.into_stream();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = handle
                                .data(id, Bytes::copy_from_slice(&buf[..n]))
                                .await;
                        }
                    }
                }
            });
            self.live_ready.notify_waiters();
        } else {
            self.hold_second.notified().await;
            let _ = reply.accept().await;
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l3_held_opening_does_not_stall_other_channel() {
    let mut cfg = server_cfg();
    cfg.open_decision_deadline = Duration::from_millis(80);
    let live_ready = Arc::new(Notify::new());
    let hold = Arc::new(Notify::new());
    let addr = spawn_one(
        cfg,
        LiveThenHold {
            live_ready: live_ready.clone(),
            hold_second: hold.clone(),
            opens: AtomicU32::new(0),
        },
    )
    .await;
    let session = connect(addr).await;

    let mut live = timeout(DEADLINE, session.channel_open_session())
        .await
        .expect("L3 HARD: live open timed out")
        .expect("L3 HARD: live open failed");
    let _ = live_ready;

    live.data(&b"pre"[..]).await.expect("L3 pre send");
    let pre = timeout(DEADLINE, async {
        loop {
            match live.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return Vec::new(),
            }
        }
    })
    .await
    .expect("L3 HARD: live echo before hold failed");
    assert_eq!(pre, b"pre");

    let held = session.channel_open_session();
    tokio::pin!(held);
    tokio::time::sleep(Duration::from_millis(30)).await;

    live.data(&b"mid"[..]).await.expect("L3 mid send");
    let mid = timeout(DEADLINE, async {
        loop {
            match live.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return Vec::new(),
            }
        }
    })
    .await
    .expect("L3 HARD: live DATA stalled while another opening is held");
    assert_eq!(mid, b"mid", "L3 HARD: other channel DATA must still flow");

    let held_res = timeout(DEADLINE, &mut held)
        .await
        .expect("L3 HARD: held open did not fail after deadline");
    assert!(
        matches!(held_res, Err(Error::ChannelOpenFailure(_))),
        "L3 HARD: held opening must expire, got {held_res:?}"
    );
    hold.notify_waiters();
}

// ── L4 accept-then-data / invert ────────────────────────────────────────────

async fn l4_round(invert: bool) -> Result<Vec<u8>, &'static str> {
    let mut cfg = server_cfg();
    cfg.invert_open_confirm_before_lane = invert;
    let order = OutboundOrderSlot::new();
    cfg.outbound_order = Some(order.clone());
    let addr = spawn_one(cfg, AcceptEcho).await;
    let session = connect(addr).await;
    let mut ch = session
        .channel_open_session()
        .await
        .map_err(|_| "open")?;
    let got = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return Vec::new(),
            }
        }
    })
    .await
    .map_err(|_| "timeout")?;
    if got != b"s4c-l4" {
        return Err("data");
    }
    let types: Vec<u8> = order
        .snapshot()
        .into_iter()
        .map(|(_, m, _)| m)
        .filter(|m| *m == 91 || *m == 94)
        .collect();
    let c = types.iter().position(|m| *m == 91);
    let d = types.iter().position(|m| *m == 94);
    match (c, d) {
        (Some(ci), Some(di)) if ci < di => Ok(got),
        _ => Err("order"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_accept_then_data_confirmation_first() {
    l4_round(false)
        .await
        .expect("L4 HARD: CONFIRMATION must precede DATA");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_invert_confirm_before_lane_is_red() {
    let r = l4_round(true).await;
    // "open" (connection/auth flake) must not satisfy this must-red gate:
    // only order violation, wrong data, or lost DATA prove the invert bit.
    assert!(
        matches!(r, Err("order" | "data" | "timeout")),
        "L4 invert HARD: S3c #13 invert must fail with order/data/timeout (got {r:?})"
    );
}

// ── L5 full slot never enters Executor ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l5_full_does_not_call_handler() {
    const MAX: usize = 4;
    let mut cfg = server_cfg();
    cfg.max_channels = MAX;
    let hob = HandlerObserveSlot::new();
    let slots = SlotObserveSlot::new();
    cfg.handler_observe = Some(hob.clone());
    cfg.slot_observe = Some(slots.clone());

    let addr = spawn_one(cfg, AcceptEcho).await;
    let session = connect(addr).await;
    let mut opened = 0usize;
    for _ in 0..MAX {
        if timeout(DEADLINE, session.channel_open_session())
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
        {
            opened += 1;
        }
    }
    assert_eq!(opened, MAX, "L5 setup: fill slots");
    let calls_at_full = hob.open_calls();
    assert!(
        calls_at_full >= MAX as u64,
        "L5 setup: handler must have seen the fills, got {calls_at_full}"
    );

    for _ in 0..16 {
        let r = timeout(DEADLINE, session.channel_open_session()).await;
        match r {
            Ok(Err(Error::ChannelOpenFailure(_))) => {}
            other => panic!("L5 HARD: extra open must FAILURE, got {other:?}"),
        }
    }
    assert_eq!(
        hob.open_calls(),
        calls_at_full,
        "L5 HARD: full-slot OPEN must not increment channel_open_* calls (was {calls_at_full}, now {})",
        hob.open_calls()
    );
}



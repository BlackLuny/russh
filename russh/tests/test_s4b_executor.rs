//! S4b: HandlerExecutor + command-ized facade.
//!
//! Real `Session::run` + real sockets. H1/H4 invert must be red when the
//! production invert hook is on. Zero fallbacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{
    self, Auth, DisconnectCause, DisconnectCauseSlot, HandleObserveSlot, Handler,
    HandlerObserveSlot, Msg, OutboundOrderSlot, ReplyQueueSlot, Session,
};
use russh::{client, Channel, ChannelId, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    spawn_one_done(cfg, handler).await.0
}

async fn spawn_one_done<H: Handler + Send + 'static>(
    cfg: server::Config,
    handler: H,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let cfg = Arc::new(cfg);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (s, _) = sock.accept().await.unwrap();
        match server::run_stream(cfg, s, handler).await {
            Ok(running) => {
                let _ = running.await;
            }
            Err(_) => {}
        }
        let _ = done_tx.send(());
    });
    (addr, done_rx)
}

async fn spawn_accept_loop<H, F>(cfg: server::Config, mut mk: F) -> std::net::SocketAddr
where
    H: Handler + Send + 'static,
    F: FnMut() -> H + Send + 'static,
{
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let cfg = Arc::new(cfg);
    tokio::spawn(async move {
        loop {
            let (s, _) = match sock.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let handler = mk();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(cfg, s, handler).await {
                    let _ = running.await;
                }
            });
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

// ── H1 handler-block DATA (Delivered skip) ──────────────────────────────────

struct HangData {
    hang: Arc<Notify>,
}

impl Handler for HangData {
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
        reply.accept().await;
        let handle = session.handle();
        let id = channel.id();
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
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
        Ok(())
    }
    async fn data(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.hang.notified().await;
        Ok(())
    }
}

async fn h1_echo_round(invert: bool) -> Result<usize, &'static str> {
    let mut cfg = server_cfg();
    cfg.invert_delivered_handler_data = invert;
    let hang = Arc::new(Notify::new());
    let addr = spawn_one(cfg, HangData { hang }).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.map_err(|_| "open")?;
    let payload = b"s4b-h1-echo";
    ch.data(&payload[..]).await.map_err(|_| "send")?;
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
    if got == payload {
        Ok(got.len())
    } else {
        Err("mismatch")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_delivered_skips_handler_data() {
    let n = h1_echo_round(false)
        .await
        .expect("H1 HARD: peer did not keep reading echo while Handler::data hangs");
    assert!(n > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_invert_delivered_calls_data_is_red() {
    let r = h1_echo_round(true).await;
    assert!(
        r.is_err(),
        "H1 invert HARD: restoring Delivered→Handler::data must fail (got {r:?})"
    );
}

// ── H2 handler-block OPEN ───────────────────────────────────────────────────

struct HangOpen {
    hang: Arc<Notify>,
}

impl Handler for HangOpen {
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
        reply.accept().await;
        // Data plane bypasses Handler so a pending OPEN cannot stall it (H2).
        let handle = session.handle();
        let id = channel.id();
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
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
        Ok(())
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        // Hold the OPEN callback; accept stays pending (S4c owns deadline).
        let _reply = reply;
        self.hang.notified().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, Bytes::copy_from_slice(data))?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_open_pending_does_not_stall_other_channel() {
    let hang = Arc::new(Notify::new());
    let addr = spawn_one(server_cfg(), HangOpen { hang }).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    // Start a hanging OPEN on another channel type.
    let open_fut = session.channel_open_direct_tcpip("127.0.0.1", 1, "127.0.0.1", 2);
    tokio::pin!(open_fut);
    let _ = timeout(Duration::from_millis(50), &mut open_fut).await;
    // The established session channel must still echo.
    ch.data(&b"h2-alive"[..]).await.unwrap();
    let got = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => panic!("H2 HARD: session channel died while OPEN pending"),
            }
        }
    })
    .await
    .expect("H2 HARD: other channel stalled for OPEN callback duration");
    assert_eq!(got, b"h2-alive");
}

// ── H3 handler-flood ────────────────────────────────────────────────────────

struct HangExec {
    release: Arc<AtomicBool>,
    seen: Arc<AtomicU32>,
}

impl Handler for HangExec {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            while !self.release.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_handler_flood_ctrl_cancelling() {
    let observe = HandlerObserveSlot::new();
    let cause = DisconnectCauseSlot::new();
    let mut cfg = server_cfg();
    cfg.max_in_flight_handler_queue = 2;
    cfg.inbound_ctrl_budget = 8 * 1024;
    cfg.handler_observe = Some(observe.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let release = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicU32::new(0));
    let addr = spawn_one(
        cfg,
        HangExec {
            release: release.clone(),
            seen: seen.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let ch = session.channel_open_session().await.unwrap();
    for i in 0..64u32 {
        let _ = timeout(Duration::from_millis(100), ch.exec(true, format!("x{i}"))).await;
    }
    timeout(DEADLINE, async {
        loop {
            if observe.invoke_dropped() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H3 HARD: invoke queue never filled on the original connection");
    release.store(true, Ordering::SeqCst);
    let drain = timeout(DEADLINE, async {
        loop {
            let seen_n = seen.load(Ordering::SeqCst) as u64;
            if seen_n + observe.invoke_dropped() >= 64 {
                return;
            }
            if cause.get() == Some(DisconnectCause::PeerError) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        drain.is_ok(),
        "H3 HARD: original connection neither drained 64 execs nor I2'/CtrlFull (seen={} dropped={} cause={:?})",
        seen.load(Ordering::SeqCst),
        observe.invoke_dropped(),
        cause.get()
    );
    assert!(
        observe.invoke_dropped() > 0,
        "H3 HARD: invoke_dropped stayed 0"
    );
    let accounted = seen.load(Ordering::SeqCst) as u64 + observe.invoke_dropped();
    assert!(
        accounted >= 64 || cause.get() == Some(DisconnectCause::PeerError),
        "H3 HARD: original connection not gated (seen={} dropped={} cause={:?})",
        seen.load(Ordering::SeqCst),
        observe.invoke_dropped(),
        cause.get()
    );
}

// ── H4 回调内 session.data ──────────────────────────────────────────────────

struct EchoNoStream;

impl Handler for EchoNoStream {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, Bytes::copy_from_slice(data))?;
        Ok(())
    }
}

async fn h4_echo(invert: bool) -> Result<Vec<u8>, &'static str> {
    let mut cfg = server_cfg();
    cfg.invert_skip_facade_drain = invert;
    let addr = spawn_one(cfg, EchoNoStream).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.map_err(|_| "open")?;
    ch.data(&b"s4b-h4"[..]).await.map_err(|_| "send")?;
    timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return Ok(data.to_vec()),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return Err("closed"),
            }
        }
    })
    .await
    .map_err(|_| "timeout")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h4_callback_session_data_echo() {
    let got = h4_echo(false)
        .await
        .expect("H4 HARD: session.data in handler-mode did not echo");
    assert_eq!(got, b"s4b-h4");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h4_invert_skip_facade_drain_is_red() {
    let r = h4_echo(true).await;
    assert!(
        r.is_err(),
        "H4 invert HARD: skipping facade drain must deadlock (got {r:?})"
    );
}

// ── H5 channel_failure ──────────────────────────────────────────────────────

struct RejectExec;

impl Handler for RejectExec {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h5_callback_channel_failure() {
    let addr = spawn_one(server_cfg(), RejectExec).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    ch.exec(true, "forbidden").await.unwrap();
    let saw = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) => panic!("H5 HARD: SUCCESS, expected FAILURE"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => panic!("H5 HARD: hung waiting for FAILURE"),
            }
        }
    })
    .await
    .expect("H5 HARD: channel_failure did not reach peer");
    assert!(saw);
}

// ── H6 timeout drop + subsequent CLOSE ──────────────────────────────────────

struct HangExecThen {
    hang: Arc<Notify>,
}

impl Handler for HangExecThen {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.hang.notified().await;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h6_timeout_drop_then_close_still_works() {
    let observe = HandlerObserveSlot::new();
    let mut cfg = server_cfg();
    cfg.handler_callback_timeout = Duration::from_millis(50);
    cfg.handler_observe = Some(observe.clone());
    let hang = Arc::new(Notify::new());
    let addr = spawn_one(cfg, HangExecThen { hang }).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    ch.exec(true, "sleep").await.unwrap();
    timeout(DEADLINE, async {
        loop {
            if observe.timeouts() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H6 HARD: TimedOut harvest never observed");
    assert!(
        observe.timeouts() > 0,
        "H6 HARD: Session did not harvest TimedOut (linger={})",
        observe.timeout_linger()
    );
    // Connection still alive: close the channel; peer must see CLOSE (or EOF).
    ch.close().await.unwrap();
    let saw_close = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Close) | None => return true,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::Failure) | Some(ChannelMsg::Success) => {}
                Some(_) => {}
            }
        }
    })
    .await
    .expect("H6 HARD: after timeout drop, CHANNEL_CLOSE did not complete (half-packet?)");
    assert!(saw_close, "H6 HARD: no CLOSE observed");
}

// ── H7 部分变更: success then timeout ───────────────────────────────────────

struct SuccessThenHang {
    hang: Arc<Notify>,
}

impl Handler for SuccessThenHang {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.hang.notified().await;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h7_success_then_timeout_no_second_failure() {
    let mut cfg = server_cfg();
    cfg.handler_callback_timeout = Duration::from_millis(50);
    let hang = Arc::new(Notify::new());
    let addr = spawn_one(cfg, SuccessThenHang { hang }).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    ch.exec(true, "partial").await.unwrap();
    let mut successes = 0u32;
    let mut failures = 0u32;
    let _ = timeout(Duration::from_millis(400), async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => successes += 1,
                Some(ChannelMsg::Failure) => failures += 1,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) | None => break,
            }
        }
    })
    .await;
    assert_eq!(successes, 1, "H7 HARD: expected exactly 1 SUCCESS");
    assert_eq!(failures, 0, "H7 HARD: timeout must not emit FAILURE");
}

// ── H8 Delivered 不经 Handler ───────────────────────────────────────────────

struct StreamOnly;

impl Handler for StreamOnly {
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
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(())
    }
    async fn data(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h8_delivered_does_not_call_handler_data() {
    let observe = HandlerObserveSlot::new();
    let mut cfg = server_cfg();
    cfg.handler_observe = Some(observe.clone());
    let addr = spawn_one(cfg, StreamOnly).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    ch.data(&b"h8-payload-xxxxx"[..]).await.unwrap();
    let echoed = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => panic!("H8 HARD: channel closed before echo"),
            }
        }
    })
    .await
    .expect("H8 HARD: Delivered payload never echoed");
    assert_eq!(echoed, b"h8-payload-xxxxx", "H8 HARD: echo mismatch");
    assert_eq!(
        observe.data_calls(),
        0,
        "H8 HARD: Delivered DATA invoked Handler::data"
    );
}

// ── H9 Handle 队占满观测 + OPEN 仍完成 ──────────────────────────────────────

struct FloodAccept {
    opens: Arc<AtomicU32>,
    flooded: Arc<Notify>,
}

impl Handler for FloodAccept {
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
        reply.accept().await;
        if n == 0 {
            let handle = session.handle();
            let id = channel.id();
            let flooded = self.flooded.clone();
            tokio::spawn(async move {
                flooded.notify_waiters();
                for _ in 0..64u64 {
                    let _ = handle.data(id, Bytes::from_static(&[b'F'; 16])).await;
                }
            });
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h9_handle_queue_full_open_still_completes() {
    let mut cfg = server_cfg();
    cfg.event_buffer_size = 1;
    let obs = HandleObserveSlot::new();
    cfg.handle_observe = Some(obs.clone());
    let opens = Arc::new(AtomicU32::new(0));
    let flooded = Arc::new(Notify::new());
    let addr = spawn_one(
        cfg,
        FloodAccept {
            opens: opens.clone(),
            flooded: flooded.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let flood_wait = flooded.notified();
    tokio::pin!(flood_wait);
    let _ch1 = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, flood_wait)
        .await
        .expect("H9 setup: flood task must start");
    timeout(DEADLINE, async {
        while !obs.full_seen() && obs.parked() == 0 && obs.max_occupancy() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H9 HARD: Handle queue never observed full/parked");
    assert!(
        obs.full_seen() || obs.parked() >= 1 || obs.max_occupancy() >= 1,
        "H9 HARD: occupancy={} parked={} full={}",
        obs.occupancy(),
        obs.parked(),
        obs.full_seen()
    );
    let ch2 = timeout(DEADLINE, session.channel_open_session())
        .await
        .expect("H9 HARD: accept self-deadlocked while Handle queue full")
        .expect("H9 HARD: second OPEN failed");
    assert!(
        opens.load(Ordering::SeqCst) >= 2,
        "H9 HARD: second open callback never ran"
    );
    ch2.data(&b"alive"[..]).await.unwrap();
}

// ── H10 / H11 / H12 want-reply FIFO (RFC 4254) ──────────────────────────────

const MSG_REQUEST_SUCCESS: u8 = 81;
const MSG_REQUEST_FAILURE: u8 = 82;

fn ssh_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn encode_global_tcpip_forward() -> Vec<u8> {
    let mut p = Vec::new();
    p.push(80); // GLOBAL_REQUEST
    ssh_string(&mut p, "tcpip-forward");
    p.push(1);
    ssh_string(&mut p, "127.0.0.1");
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

fn encode_global_unknown() -> Vec<u8> {
    let mut p = Vec::new();
    p.push(80);
    ssh_string(&mut p, "h10-unknown@example");
    p.push(1);
    p
}

fn encode_channel_unknown(recipient: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(98); // CHANNEL_REQUEST
    p.extend_from_slice(&recipient.to_be_bytes());
    ssh_string(&mut p, "h11-unknown@example");
    p.push(1);
    p
}

fn encode_channel_exec(recipient: u32, cmd: &str) -> Vec<u8> {
    encode_channel_exec_reply(recipient, cmd, true)
}

fn encode_channel_exec_reply(recipient: u32, cmd: &str, want_reply: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(98);
    p.extend_from_slice(&recipient.to_be_bytes());
    ssh_string(&mut p, "exec");
    p.push(if want_reply { 1 } else { 0 });
    ssh_string(&mut p, cmd);
    p
}

struct DelayForward;

impl Handler for DelayForward {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn tcpip_forward(
        &mut self,
        _: &str,
        _: &mut u32,
        _: &mut Session,
    ) -> Result<bool, Self::Error> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h10_global_reply_order() {
    let order = OutboundOrderSlot::new();
    let mut cfg = server_cfg();
    cfg.outbound_order = Some(order.clone());
    let addr = spawn_one(cfg, DelayForward).await;
    let session = connect(addr).await;
    session
        .send_raw_packet(Bytes::from(encode_global_tcpip_forward()))
        .await
        .unwrap();
    session
        .send_raw_packet(Bytes::from(encode_global_unknown()))
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            let reps: Vec<u8> = order
                .snapshot()
                .into_iter()
                .filter(|(c, m, _)| *c == u32::MAX && (*m == MSG_REQUEST_SUCCESS || *m == MSG_REQUEST_FAILURE))
                .map(|(_, m, _)| m)
                .collect();
            if reps.len() >= 2 {
                assert_eq!(
                    reps[0], MSG_REQUEST_SUCCESS,
                    "H10 HARD: first global reply must be SUCCESS (got {reps:?})"
                );
                assert_eq!(
                    reps[1], MSG_REQUEST_FAILURE,
                    "H10 HARD: second global reply must be FAILURE (got {reps:?})"
                );
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H10 HARD: timed out waiting for two global replies");
}

struct DelayExec {
    server_id: Arc<AtomicU32>,
}

impl Handler for DelayExec {
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
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_id.store(channel.id().number(), Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.channel_success(channel)?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h11_channel_reply_order() {
    let sid = Arc::new(AtomicU32::new(0));
    let addr = spawn_one(server_cfg(), DelayExec { server_id: sid.clone() }).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H11 setup: server channel id");
    let recip = sid.load(Ordering::SeqCst);
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(recip, "h11")))
        .await
        .unwrap();
    session
        .send_raw_packet(Bytes::from(encode_channel_unknown(recip)))
        .await
        .unwrap();
    let mut got = Vec::new();
    timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => got.push("ok"),
                Some(ChannelMsg::Failure) => got.push("fail"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => break,
            }
            if got.len() >= 2 {
                break;
            }
        }
    })
    .await
    .expect("H11 HARD: timed out waiting for two channel replies");
    assert_eq!(
        got,
        ["ok", "fail"],
        "H11 HARD: per-channel FIFO must be SUCCESS then FAILURE (got {got:?})"
    );
}

struct LateHandleReply {
    server_id: Arc<Mutex<Option<ChannelId>>>,
    handle: Arc<Mutex<Option<server::Handle>>>,
    exec_done: Arc<AtomicBool>,
}

impl Handler for LateHandleReply {
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
        *self.server_id.lock().unwrap() = Some(channel.id());
        *self.handle.lock().unwrap() = Some(session.handle());
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.exec_done.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h12_handle_late_success_keeps_order() {
    let sid = Arc::new(Mutex::new(None));
    let handle = Arc::new(Mutex::new(None));
    let exec_done = Arc::new(AtomicBool::new(false));
    let addr = spawn_one(
        server_cfg(),
        LateHandleReply {
            server_id: sid.clone(),
            handle: handle.clone(),
            exec_done: exec_done.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H12 setup: server channel id");
    let id = sid.lock().unwrap().expect("server ChannelId");
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(id.number(), "h12")))
        .await
        .unwrap();
    session
        .send_raw_packet(Bytes::from(encode_channel_unknown(id.number())))
        .await
        .unwrap();
    timeout(DEADLINE, async {
        while !exec_done.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H12 setup: exec callback returned");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let early: Vec<&str> = timeout(Duration::from_millis(50), async {
        let mut v = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(10), ch.wait()).await {
                Ok(Some(ChannelMsg::Failure)) => v.push("fail"),
                Ok(Some(ChannelMsg::Success)) => v.push("ok"),
                Ok(Some(ChannelMsg::WindowAdjusted { .. })) => {}
                _ => break,
            }
        }
        v
    })
    .await
    .unwrap_or_default();
    assert!(
        !early.contains(&"fail"),
        "H12 HARD: unknown FAILURE must not precede Handle success (got {early:?})"
    );
    let h = handle.lock().unwrap().clone().expect("server Handle");
    h.channel_success(id)
        .await
        .expect("H12 Handle::channel_success");
    let mut got = Vec::new();
    timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => got.push("ok"),
                Some(ChannelMsg::Failure) => got.push("fail"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => break,
            }
            if got.len() >= 2 {
                break;
            }
        }
    })
    .await
    .expect("H12 HARD: timed out waiting SUCCESS then FAILURE");
    assert_eq!(
        got,
        ["ok", "fail"],
        "H12 HARD: Handle success then unknown FAILURE (got {got:?})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h13_handle_late_success_no_auto_failure() {
    let sid = Arc::new(Mutex::new(None));
    let handle = Arc::new(Mutex::new(None));
    let exec_done = Arc::new(AtomicBool::new(false));
    let addr = spawn_one(
        server_cfg(),
        LateHandleReply {
            server_id: sid.clone(),
            handle: handle.clone(),
            exec_done: exec_done.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H13 setup: server id");
    let id = sid.lock().unwrap().expect("server ChannelId");
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(id.number(), "h13")))
        .await
        .unwrap();
    timeout(DEADLINE, async {
        while !exec_done.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H13 setup: exec returned");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let h = handle.lock().unwrap().clone().expect("server Handle");
    h.channel_success(id)
        .await
        .expect("H13 Handle::channel_success");
    let mut successes = 0u32;
    let mut failures = 0u32;
    let _ = timeout(Duration::from_millis(400), async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => successes += 1,
                Some(ChannelMsg::Failure) => failures += 1,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) | None => break,
            }
        }
    })
    .await;
    assert_eq!(successes, 1, "H13 HARD: expected exactly 1 SUCCESS");
    assert_eq!(failures, 0, "H13 HARD: no auto FAILURE, no double reply");
}

struct TwoChanSilent {
    ids: Arc<Mutex<Vec<u32>>>,
}

impl Handler for TwoChanSilent {
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
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ids.lock().unwrap().push(channel.id().number());
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h14_close_clears_obligation_other_channel_isolated() {
    let ids = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_one(server_cfg(), TwoChanSilent { ids: ids.clone() }).await;
    let session = connect(addr).await;
    let mut a = session.channel_open_session().await.unwrap();
    let mut b = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while ids.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H14 setup: two server ids");
    let (ida, idb) = {
        let g = ids.lock().unwrap();
        (g[0], g[1])
    };
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(ida, "h14")))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    a.close().await.unwrap();
    timeout(DEADLINE, async {
        loop {
            match a.wait().await {
                Some(ChannelMsg::Close) | None => return,
                _ => {}
            }
        }
    })
    .await
    .expect("H14 HARD: CLOSE on unreplied channel must complete");
    session
        .send_raw_packet(Bytes::from(encode_channel_unknown(idb)))
        .await
        .unwrap();
    let mut got_fail = false;
    timeout(DEADLINE, async {
        loop {
            match b.wait().await {
                Some(ChannelMsg::Failure) => {
                    got_fail = true;
                    return;
                }
                Some(ChannelMsg::Success) => panic!("H14 HARD: B must not see SUCCESS"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => return,
            }
        }
    })
    .await
    .expect("H14 HARD: unknown FAILURE on other channel blocked");
    assert!(got_fail, "H14 HARD: other channel FAILURE missing");
    b.data(&b"alive"[..]).await.unwrap();
}

// ── H15 unknown-channel obligations must not enqueue ────────────────────────

struct ReplyPing;

impl Handler for ReplyPing {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h15_unknown_channel_does_not_enqueue() {
    let replies = ReplyQueueSlot::new();
    let mut cfg = server_cfg();
    cfg.reply_queue = Some(replies.clone());
    let addr = spawn_one(cfg, ReplyPing).await;
    let session = connect(addr).await;
    let ch = session.channel_open_session().await.unwrap();
    for n in 0..16u32 {
        session
            .send_raw_packet(Bytes::from(encode_channel_exec(10_000 + n, "ghost")))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        replies.obligations(),
        0,
        "H15 HARD: unknown-channel want-reply grew the obligation map ({})",
        replies.obligations()
    );
    let mut ch = ch;
    ch.exec(true, "ping").await.unwrap();
    timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => return,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::Failure) => panic!("H15 HARD: ping FAILURE"),
                Some(_) => {}
                None => panic!("H15 HARD: channel closed before ping reply"),
            }
        }
    })
    .await
    .expect("H15 HARD: peer did not reply after unknown-channel flood");
}

// ── H16 obligation cap tears the abuser, isolates the other conn ────────────

struct SilentExec;

impl Handler for SilentExec {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h16_obligation_cap_disconnects() {
    let cause = DisconnectCauseSlot::new();
    let mut cfg = server_cfg();
    cfg.max_pending_want_replies = 4;
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_accept_loop(cfg, || SilentExec).await;
    let session = connect(addr).await;
    let ch = session.channel_open_session().await.unwrap();
    for i in 0..8u32 {
        let _ = timeout(Duration::from_millis(200), ch.exec(true, format!("cap-{i}"))).await;
    }
    timeout(DEADLINE, async {
        loop {
            if cause.get() == Some(DisconnectCause::ReplyObligationOverflow) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H16 HARD: flood did not trip ReplyObligationOverflow");
    let other = timeout(DEADLINE, connect(addr))
        .await
        .expect("H16 HARD: sibling connection blocked");
    let och = other.channel_open_session().await.unwrap();
    och.exec(true, "ok").await.unwrap();
    och.data(&b"peer"[..]).await.unwrap();
}

// ── H17 Full → ordered FAILURE ──────────────────────────────────────────────

struct HangThenSuccess {
    release: Arc<AtomicBool>,
    seen: Arc<AtomicU32>,
    server_id: Arc<AtomicU32>,
}

impl Handler for HangThenSuccess {
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
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_id.store(channel.id().number(), Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let n = self.seen.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            while !self.release.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h17_full_posts_ordered_failure() {
    let observe = HandlerObserveSlot::new();
    let mut cfg = server_cfg();
    cfg.max_in_flight_handler_queue = 1;
    cfg.handler_observe = Some(observe.clone());
    let release = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicU32::new(0));
    let sid = Arc::new(AtomicU32::new(0));
    let addr = spawn_one(
        cfg,
        HangThenSuccess {
            release: release.clone(),
            seen: seen.clone(),
            server_id: sid.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H17 setup: server channel id");
    let recip = sid.load(Ordering::SeqCst);
    for i in 0..4u32 {
        session
            .send_raw_packet(Bytes::from(encode_channel_exec(recip, &format!("f{i}"))))
            .await
            .unwrap();
    }
    timeout(DEADLINE, async {
        loop {
            if observe.invoke_dropped() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H17 HARD: try_post Full never observed");
    release.store(true, Ordering::SeqCst);
    let mut got = Vec::new();
    timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => got.push("ok"),
                Some(ChannelMsg::Failure) => got.push("fail"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
                None => break,
            }
            if got.iter().filter(|s| **s == "fail").count() >= 1
                && got.iter().filter(|s| **s == "ok").count() >= 1
            {
                return;
            }
        }
    })
    .await
    .expect("H17 HARD: timed out waiting SUCCESS then FAILURE");
    let first_fail = got.iter().position(|s| *s == "fail");
    let last_ok = got.iter().rposition(|s| *s == "ok");
    assert!(
        first_fail.is_some() && last_ok.is_some() && last_ok.unwrap() < first_fail.unwrap(),
        "H17 HARD: FAILURE must follow decided SUCCESS, not overtake (got {got:?})"
    );
}

// ── H18 teardown wakes a facade oneshot wait ────────────────────────────────

struct BlockOnFacade {
    entered: Arc<AtomicBool>,
}

impl Handler for BlockOnFacade {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.entered.store(true, Ordering::SeqCst);
        session.data(channel, Bytes::from_static(b"x"))?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h18_teardown_wakes_facade_wait() {
    let entered = Arc::new(AtomicBool::new(false));
    let mut cfg = server_cfg();
    cfg.invert_skip_facade_drain = true;
    cfg.teardown_grace = Duration::from_millis(400);
    let (addr, done) = spawn_one_done(
        cfg,
        BlockOnFacade {
            entered: entered.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let ch = session.channel_open_session().await.unwrap();
    ch.exec(true, "block").await.unwrap();
    timeout(DEADLINE, async {
        loop {
            if entered.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H18 setup: callback never entered facade wait");
    drop(ch);
    drop(session);
    timeout(Duration::from_secs(2), done)
        .await
        .expect("H18 HARD: Session::run did not return within grace (facade oneshot hang)")
        .expect("H18 HARD: run join dropped");
}

// ── H19 isolated OS thread exits ────────────────────────────────────────────

struct NopOpen;

impl Handler for NopOpen {
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
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
}

#[tokio::test]
async fn h19_isolated_executor_exits() {
    let observe = HandlerObserveSlot::new();
    let mut cfg = server_cfg();
    cfg.handler_observe = Some(observe.clone());
    cfg.teardown_grace = Duration::from_millis(400);
    let (addr, done) = spawn_one_done(cfg, NopOpen).await;
    let session = connect(addr).await;
    let ch = session.channel_open_session().await.unwrap();
    drop(ch);
    drop(session);
    timeout(Duration::from_secs(2), done)
        .await
        .expect("H19 HARD: Session::run did not return")
        .ok();
    timeout(DEADLINE, async {
        loop {
            if observe.executor_exited() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H19 HARD: isolated executor thread did not exit");
}

// ── H20 want=0 Full must not decide an earlier want-reply ───────────────────

struct LateHandleNoReply {
    server_id: Arc<Mutex<Option<ChannelId>>>,
    handle: Arc<Mutex<Option<server::Handle>>>,
    exec_done: Arc<AtomicBool>,
}

impl Handler for LateHandleNoReply {
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
        *self.server_id.lock().unwrap() = Some(channel.id());
        *self.handle.lock().unwrap() = Some(session.handle());
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.exec_done.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h20_nowant_full_does_not_fail_prior_obligation() {
    let observe = HandlerObserveSlot::new();
    let sid = Arc::new(Mutex::new(None));
    let handle = Arc::new(Mutex::new(None));
    let exec_done = Arc::new(AtomicBool::new(false));
    let mut cfg = server_cfg();
    cfg.max_in_flight_handler_queue = 1;
    cfg.handler_observe = Some(observe.clone());
    let addr = spawn_one(
        cfg,
        LateHandleNoReply {
            server_id: sid.clone(),
            handle: handle.clone(),
            exec_done: exec_done.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H20 setup: server channel id");
    let id = sid.lock().unwrap().expect("server ChannelId");
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(id.number(), "A-want")))
        .await
        .unwrap();
    timeout(DEADLINE, async {
        while !exec_done.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H20 setup: A exec in handler");
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(id.number(), "fill")))
        .await
        .unwrap();
    session
        .send_raw_packet(Bytes::from(encode_channel_exec_reply(
            id.number(),
            "B-nowant",
            false,
        )))
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            if observe.invoke_dropped() > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H20 setup: B want=0 never hit Full");
    tokio::time::sleep(Duration::from_millis(40)).await;
    let early: Vec<&str> = timeout(Duration::from_millis(40), async {
        let mut v = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(10), ch.wait()).await {
                Ok(Some(ChannelMsg::Failure)) => v.push("fail"),
                Ok(Some(ChannelMsg::Success)) => v.push("ok"),
                Ok(Some(ChannelMsg::WindowAdjusted { .. })) => {}
                _ => break,
            }
        }
        v
    })
    .await
    .unwrap_or_default();
    assert!(
        !early.contains(&"fail"),
        "H20 HARD: want=0 Full must not emit FAILURE for A (got {early:?})"
    );
    let h = handle.lock().unwrap().clone().expect("server Handle");
    h.channel_success(id)
        .await
        .expect("H20 Handle::channel_success");
    let mut successes = 0u32;
    let mut failures = 0u32;
    let _ = timeout(Duration::from_millis(400), async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Success) => successes += 1,
                Some(ChannelMsg::Failure) => failures += 1,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) | None => break,
            }
        }
    })
    .await;
    assert_eq!(successes, 1, "H20 HARD: expected exactly 1 SUCCESS for A");
    assert_eq!(
        failures, 0,
        "H20 HARD: want=0 Full must not decide A's obligation"
    );
}

// ── H21 pump quantum: want=0 flood must not starve facade ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h21_pump_quantum_drains_facade_under_nowant_flood() {
    let observe = HandlerObserveSlot::new();
    let entered = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let sid = Arc::new(AtomicU32::new(0));
    let sent = Arc::new(AtomicU32::new(0));
    let hold = Arc::new(AtomicBool::new(false));
    let mut cfg = server_cfg();
    cfg.max_in_flight_handler_queue = 1;
    cfg.handler_observe = Some(observe.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    // Each REQUEST pop sleeps so a live producer can keep the lane
    // non-empty. Without quantum the unbounded pump never returns.
    cfg.lane_request_pop_delay = Some(Duration::from_millis(10));
    let addr = spawn_one(
        cfg,
        H21Handler {
            entered: entered.clone(),
            done: done.clone(),
            server_id: sid.clone(),
        },
    )
    .await;
    let session = Arc::new(connect(addr).await);
    let ch = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, async {
        while sid.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H21 setup: server id");
    let recip = sid.load(Ordering::SeqCst);
    hold.store(true, Ordering::SeqCst);
    session
        .send_raw_packet(Bytes::from(encode_channel_exec(recip, "block")))
        .await
        .unwrap();
    let session_prod = session.clone();
    let done_prod = done.clone();
    let sent_prod = sent.clone();
    let producer = tokio::spawn(async move {
        let mut i = 0u32;
        while !done_prod.load(Ordering::SeqCst) {
            let _ = session_prod
                .send_raw_packet(Bytes::from(encode_channel_exec_reply(
                    recip,
                    &format!("n{i}"),
                    false,
                )))
                .await;
            sent_prod.fetch_add(1, Ordering::SeqCst);
            i = i.wrapping_add(1);
        }
    });
    timeout(DEADLINE, async {
        loop {
            if sent.load(Ordering::SeqCst) >= 8 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H21 setup: producer never filled the lane");
    hold.store(false, Ordering::SeqCst);
    let _ = session
        .send_raw_packet(Bytes::from(encode_channel_exec_reply(recip, "wake", false)))
        .await;
    timeout(DEADLINE, async {
        loop {
            if entered.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H21 setup: callback never entered facade wait");
    let sent_at_entered = sent.load(Ordering::SeqCst);
    timeout(DEADLINE, async {
        loop {
            if done.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H21 HARD: want=0 flood starved facade drain (callback never finished)");
    let _ = producer.await;
    let sent_at_done = sent.load(Ordering::SeqCst);
    assert!(
        observe.invoke_dropped() > 0,
        "H21 HARD: Executor never went Full (dropped=0)"
    );
    assert!(
        sent_at_done > sent_at_entered,
        "H21 HARD: producer went idle before facade completed (entered={sent_at_entered} done={sent_at_done})"
    );
    ch.data(&b"alive"[..]).await.unwrap();
}

struct H21Handler {
    entered: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    server_id: Arc<AtomicU32>,
}

impl Handler for H21Handler {
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
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_id.store(channel.id().number(), Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.entered.store(true, Ordering::SeqCst);
        session.data(channel, Bytes::from_static(b"h21"))?;
        self.done.store(true, Ordering::SeqCst);
        Ok(())
    }
}

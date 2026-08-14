//! S4a: G5 facade skin, pass-through, zero behavior.
//!
//! F0 pins every §1.2.1 public `Session` signature at compile time.
//! F1–F3 are real `Session::run` + real sockets. Red = the skin changed
//! completion timing = rollback; do not adapt the tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Handler, Msg, Session};
use russh::{client, Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
use ssh_key::PrivateKey;
use tokio::sync::Notify;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(5);

// ── F0: compile-time G5 surface pin ─────────────────────────────────────────

/// Bind every public `Session` method from impl-S4-plan.md §1.2.1.
/// A signature drift (S4b+) fails to compile here.
#[test]
fn f0_g5_surface_pin() {
    // 纯读
    let _: fn(&Session) -> server::Handle = Session::handle;
    let _: fn(&Session, &ChannelId) -> u32 = Session::writable_packet_size;
    let _: fn(&Session, &ChannelId) -> u32 = Session::window_size;
    let _: fn(&Session, &ChannelId) -> u32 = Session::max_packet_size;
    let _: fn(&Session, ChannelId) -> usize = Session::sender_window_size;
    let _: fn(&Session, ChannelId) -> bool = Session::has_pending_data;
    let _: for<'a> fn(&'a Session) -> &'a server::Config = Session::config;
    let _: for<'a> fn(&'a Session) -> &'a [u8] = Session::remote_sshid;

    // 排包 (generic `impl Into<Bytes>` cannot be coerced to a fn pointer, so
    // pin via return-annotated closures over two distinct Into<Bytes> types.
    // Residual blindspot (P2-1, review-S4a-r1): a bound widening that still
    // admits Bytes and Vec<u8> would compile here; receiver drift is caught by
    // the &mut Session parameter type.
    let _: fn(&mut Session) -> Result<(), russh::Error> = Session::flush;
    let _: fn(&mut Session, ChannelId) -> Result<usize, russh::Error> = Session::flush_pending;
    let _: fn(&mut Session, ChannelId) -> Result<usize, russh::Error> =
        Session::flush_pending_fences;
    let _data = |s: &mut Session, id: ChannelId, data: Bytes| -> Result<(), russh::Error> {
        s.data(id, data)
    };
    let _data_vec = |s: &mut Session, id: ChannelId, data: Vec<u8>| -> Result<(), russh::Error> {
        s.data(id, data)
    };
    let _ext = |s: &mut Session, id: ChannelId, ext: u32, data: Bytes| -> Result<(), russh::Error> {
        s.extended_data(id, ext, data)
    };
    let _ext_vec =
        |s: &mut Session, id: ChannelId, ext: u32, data: Vec<u8>| -> Result<(), russh::Error> {
            s.extended_data(id, ext, data)
        };
    let _: fn(&mut Session, ChannelId) -> Result<(), russh::Error> = Session::channel_success;
    let _: fn(&mut Session, ChannelId) -> Result<(), russh::Error> = Session::channel_failure;
    let _: fn(&mut Session) = Session::request_success;
    let _: fn(&mut Session) = Session::request_failure;
    let _: fn(&mut Session, ChannelId) -> Result<(), russh::Error> = Session::eof;
    let _: fn(&mut Session, ChannelId, bool) -> Result<(), russh::Error> = Session::xon_xoff_request;
    let _: fn(&mut Session, ChannelId, u32) -> Result<(), russh::Error> =
        Session::exit_status_request;
    let _: fn(&mut Session, ChannelId, russh::Sig, bool, &str, &str) -> Result<(), russh::Error> =
        Session::exit_signal_request;
    let _: fn(&mut Session) -> Result<(), russh::Error> = Session::keepalive_request;
    let _: fn(&mut Session, tokio::sync::oneshot::Sender<()>) -> Result<(), russh::Error> =
        Session::send_ping;
    let _: fn(&mut Session, bool, &str, &str) -> Result<(), russh::Error> = Session::debug;

    // 生命周期
    let _: fn(&mut Session, ChannelId) -> Result<(), russh::Error> = Session::close;
    let _: fn(
        &mut Session,
        ChannelId,
        ChannelOpenFailure,
        &str,
        &str,
    ) -> Result<(), russh::Error> = Session::channel_open_failure;
    let _: fn(&mut Session) -> Result<ChannelId, russh::Error> = Session::channel_open_session;
    let _: fn(&mut Session, &str, u32, &str, u32) -> Result<ChannelId, russh::Error> =
        Session::channel_open_direct_tcpip;
    let _: fn(&mut Session, &str) -> Result<ChannelId, russh::Error> =
        Session::channel_open_direct_streamlocal;
    let _: fn(&mut Session, &str, u32, &str, u32) -> Result<ChannelId, russh::Error> =
        Session::channel_open_forwarded_tcpip;
    let _: fn(&mut Session, &str) -> Result<ChannelId, russh::Error> =
        Session::channel_open_forwarded_streamlocal;
    let _: fn(&mut Session, &str, u32) -> Result<ChannelId, russh::Error> = Session::channel_open_x11;
    let _: fn(&mut Session) -> Result<ChannelId, russh::Error> = Session::channel_open_agent;
    let _: fn(
        &mut Session,
        russh::Disconnect,
        &str,
        &str,
    ) -> Result<(), russh::Error> = Session::disconnect;
    let _: fn(
        &mut Session,
        &str,
        u32,
        Option<tokio::sync::oneshot::Sender<Option<u32>>>,
    ) -> Result<(), russh::Error> = Session::tcpip_forward;
    let _: fn(
        &mut Session,
        &str,
        u32,
        Option<tokio::sync::oneshot::Sender<bool>>,
    ) -> Result<(), russh::Error> = Session::cancel_tcpip_forward;
}

// ── live Session::run helpers ───────────────────────────────────────────────

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
        match server::run_stream(cfg, s, handler).await {
            Ok(running) => {
                let _ = running.await;
            }
            Err(_) => {}
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

// ── F1 直通排包 ─────────────────────────────────────────────────────────────

struct EchoH;

impl Handler for EchoH {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f1_passthrough_data_echo() {
    let addr = spawn_one(server_cfg(), EchoH).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    let payload = b"s4a-f1-echo";
    ch.data(&payload[..]).await.unwrap();
    let got = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => return data.to_vec(),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(other) => panic!("F1 unexpected {other:?}"),
                None => panic!("F1 channel closed before echo"),
            }
        }
    })
    .await
    .expect("F1 HARD: session.data returned but peer did not see echo in 5s");
    assert_eq!(got, payload, "F1 HARD: echo mismatch");
}

// ── F2 直通拒请求 (zfc: exec → channel_failure) ────────────────────────────

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
async fn f2_passthrough_channel_failure() {
    let addr = spawn_one(server_cfg(), RejectExec).await;
    let session = connect(addr).await;
    let mut ch = session.channel_open_session().await.unwrap();
    ch.exec(true, "forbidden").await.unwrap();
    let saw_failure = timeout(DEADLINE, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) => panic!("F2 HARD: got SUCCESS, expected FAILURE"),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(other) => panic!("F2 unexpected {other:?}"),
                None => panic!("F2 HARD: hung waiting for CHANNEL_FAILURE"),
            }
        }
    })
    .await
    .expect("F2 HARD: channel_failure returned but peer never saw FAILURE (hung)");
    assert!(saw_failure);
}

// ── F3 accept 免死锁 (Handle 队列灌满时回调内 accept) ───────────────────────

struct FloodAccept {
    opens: Arc<AtomicU32>,
    flooded: Arc<Notify>,
    flood_started: Arc<AtomicU64>,
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
        // Critical: accept must not send on the bounded Handle receiver.
        reply.accept().await;
        if n == 0 {
            let handle = session.handle();
            let id = channel.id();
            let flooded = self.flooded.clone();
            let started = self.flood_started.clone();
            tokio::spawn(async move {
                flooded.notify_waiters();
                for i in 0..64u64 {
                    started.store(i + 1, Ordering::SeqCst);
                    // Parks on the bounded session queue + window ack.
                    // Must not be called from this callback (would deadlock the loop).
                    let _ = handle.data(id, Bytes::from_static(&[b'F'; 16])).await;
                }
            });
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f3_accept_while_handle_queue_full() {
    let mut cfg = server_cfg();
    cfg.event_buffer_size = 1;
    let opens = Arc::new(AtomicU32::new(0));
    let flooded = Arc::new(Notify::new());
    let flood_started = Arc::new(AtomicU64::new(0));
    let addr = spawn_one(
        cfg,
        FloodAccept {
            opens: opens.clone(),
            flooded: flooded.clone(),
            flood_started: flood_started.clone(),
        },
    )
    .await;
    let session = connect(addr).await;
    let flood_wait = flooded.notified();
    tokio::pin!(flood_wait);
    let _ch1 = session.channel_open_session().await.unwrap();
    timeout(DEADLINE, flood_wait)
        .await
        .expect("F3 setup: flood task must start");
    // Give the flood at least one send so event_buffer_size=1 is occupied.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    // P2-2 (review-S4a-r1): prove the flood actually began sending before the
    // second OPEN. This does not hard-prove the queue is full at the OPEN
    // instant — a production-reachable occupancy observation needs a hook this
    // slice may not add (S4a brief); S4b owns that strengthening.
    assert!(
        flood_started.load(Ordering::SeqCst) >= 1,
        "F3 setup: flood task never issued a Handle::data before second OPEN"
    );
    // Second OPEN is processed on the ctrl/reader path while Handle::data
    // senders sit on the bounded event queue (size 1). accept() must return.
    let ch2 = timeout(DEADLINE, session.channel_open_session())
        .await
        .expect("F3 HARD: accept self-deadlocked (CONFIRMATION never arrived)")
        .expect("F3 HARD: second OPEN failed");
    assert!(
        opens.load(Ordering::SeqCst) >= 2,
        "F3 HARD: second open callback never ran"
    );
    // Connection still alive: ch2 can carry data.
    ch2.data(&b"alive"[..]).await.unwrap();
}

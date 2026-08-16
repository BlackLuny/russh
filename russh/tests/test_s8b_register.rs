//! S8b ChannelTx register-before-park (D2).
//!
//! Object gate: two acked writers, manual poll, no tokio scheduling.
//! Production: both Ready(Ok). Invert `invert_park_before_register`:
//! exactly one Ready, one Pending → `LostWake` (names who was lost).
//!
//! E2E reuses the S5b dual-writer shape. Invert E2E is frequency-only;
//! the object gate is the must-red carrier.
//!
//! cargo test -p russh --features _test_hooks --test test_s8b_register -- --nocapture --test-threads=1

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, client};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::{Duration, sleep, timeout};

const PEER_WINDOW: usize = 32;
const PAYLOAD: usize = 256;

#[cfg(feature = "_test_hooks")]
#[test]
fn register_before_park_production() {
    match russh::s8b_object_register_round(false) {
        russh::S8bObjectClass::BothReady => {}
        other => panic!("production must BothReady, got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[test]
fn park_before_register_invert_is_lost_wake() {
    match russh::s8b_object_register_round(true) {
        russh::S8bObjectClass::LostWake { lost, ready } => {
            assert_ne!(lost, ready, "LostWake must name distinct writers");
        }
        other => panic!("invert must LostWake (not Timeout), got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[test]
fn ack_before_register_production() {
    match russh::s8b_object_ack_before_register_round(false) {
        russh::S8bObjectClass::AckReady => {}
        other => panic!("production ack-before-register must AckReady, got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[test]
fn ack_before_register_bound2_is_parked() {
    match russh::s8b_object_ack_before_register_round(true) {
        russh::S8bObjectClass::AckBeforeRegisterParked => {}
        other => panic!("bound-2 invert must AckBeforeRegisterParked (not Timeout), got {other:?}"),
    }
}

/// D2-P2: discard (live.remove then notify) in the pre-accept window
/// must surface BrokenPipe on the early-Ok arm, not a fake Ok.
/// Pre-fix tree is the invert: this test is red on e4cf099.
#[cfg(feature = "_test_hooks")]
#[test]
fn known_dead_after_discard_is_broken_pipe() {
    match russh::s8c_object_known_dead_round(true) {
        russh::S8bObjectClass::DeadBrokenPipe => {}
        russh::S8bObjectClass::DeadReportedOk => {
            panic!("DeadReportedOk: early Ok after discard (known_dead skipped)")
        }
        other => panic!("discard path must DeadBrokenPipe (not Timeout), got {other:?}"),
    }
}

/// Same construction, channel still live: stale-permit early Ok must
/// survive. Proves the check does not break the tolerated permit path.
#[cfg(feature = "_test_hooks")]
#[test]
fn known_dead_check_does_not_break_live_early_ok() {
    match russh::s8c_object_known_dead_round(false) {
        russh::S8bObjectClass::AckReady => {}
        other => panic!("live channel must still early-Ok, got {other:?}"),
    }
}

fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DualClass {
    BothDone,
    SecondWriterParked,
    Timeout,
    Connection,
}

async fn run_dual_writers() -> Result<DualClass, anyhow::Error> {
    let addr = addr();
    let (started_tx, started_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
    let received = Arc::new(AtomicUsize::new(0));

    tokio::spawn(DualServer::run(addr, started_tx, done_tx));

    while TcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        window_size: PEER_WINDOW as u32,
        channel_buffer_size: 8,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut session = match russh::client::connect(config, addr, Client).await {
        Ok(s) => s,
        Err(_) => return Ok(DualClass::Connection),
    };
    let mut channel = match session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await
        .map(|x| x.success())
    {
        Ok(true) => match session.channel_open_session().await {
            Ok(ch) => ch,
            Err(_) => return Ok(DualClass::Connection),
        },
        _ => return Ok(DualClass::Connection),
    };

    let _ = started_rx.await;
    let rec = received.clone();
    let collect = async move {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    rec.fetch_add(data.len(), Ordering::SeqCst);
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(_) => {}
            }
            if rec.load(Ordering::SeqCst) >= PAYLOAD * 2 {
                break;
            }
        }
    };

    let writers = async {
        let mut n = 0;
        while n < 2 {
            match timeout(Duration::from_secs(5), done_rx.recv()).await {
                Ok(Some(_)) => n += 1,
                _ => break,
            }
        }
        n
    };
    let (collect_r, n_done) = tokio::join!(timeout(Duration::from_secs(5), collect), writers);
    let timed_out = collect_r.is_err();
    let got = received.load(Ordering::SeqCst);
    let class = if n_done == 2 {
        DualClass::BothDone
    } else if got >= PAYLOAD * 2 && n_done < 2 {
        DualClass::SecondWriterParked
    } else if n_done == 1 || timed_out {
        DualClass::Timeout
    } else {
        DualClass::Connection
    };
    eprintln!("s8b e2e class={class:?} received={got} writers_done={n_done} timed_out={timed_out}");
    Ok(class)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_dual_writer_production() -> Result<(), anyhow::Error> {
    #[cfg(feature = "_test_hooks")]
    let _g = russh::acquire_invert_park_before_register(false);
    match run_dual_writers().await? {
        DualClass::BothDone => Ok(()),
        other => anyhow::bail!("e2e production must BothDone, got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_dual_writer_invert_frequency() -> Result<(), anyhow::Error> {
    let _g = russh::acquire_invert_park_before_register(true);
    let class = run_dual_writers().await?;
    eprintln!("s8b e2e invert frequency class={class:?} (not a must-red carrier)");
    let _ = class;
    Ok(())
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct DualServer {
    started: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
    done: tokio::sync::mpsc::UnboundedSender<&'static str>,
}

impl DualServer {
    async fn run(
        addr: SocketAddr,
        started: oneshot::Sender<()>,
        done: tokio::sync::mpsc::UnboundedSender<&'static str>,
    ) {
        let config = server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            event_buffer_size: 8,
            ..Default::default()
        };
        let mut server = Self {
            started: Arc::new(std::sync::Mutex::new(Some(started))),
            done,
        };
        server.run_on_address(Arc::new(config), addr).await.unwrap();
    }
}

impl russh::server::Server for DualServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for DualServer {
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
        reply.accept().await?;
        if let Some(tx) = self.started.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let done = self.done.clone();
        tokio::spawn(async move {
            let mut stdout = channel.make_writer();
            let mut stderr = channel.make_writer_ext(Some(1));
            let a = vec![0u8; PAYLOAD];
            let b = vec![1u8; PAYLOAD];
            let (r1, r2) = tokio::join!(stdout.write_all(&a), stderr.write_all(&b));
            let _ = (r1, r2);
            let _ = done.send("stdout");
            let _ = done.send("stderr");
        });
        Ok(())
    }
}

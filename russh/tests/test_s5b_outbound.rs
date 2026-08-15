//! S5b outbound single-ledger gates.
//!
//! `Channel::data` on the server waits on Session `recipient_window_size`
//! (acked permit), not the WindowSizeRef mirror. Invert restores the
//! stale-mirror path (Session no longer updates it).
//!
//! Requires `--features _test_hooks` for the invert half.
//!
//! cargo test -p russh --features _test_hooks --test test_s5b_outbound -- --nocapture

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

fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinClass {
    Progressed,
    Stall,
    Timeout,
    Connection,
}

struct Hooks {
    invert_mirror: bool,
}

async fn run_channel_data(hooks: Hooks) -> Result<WinClass, anyhow::Error> {
    let addr = addr();
    let (started_tx, started_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let received = Arc::new(AtomicUsize::new(0));
    let invert = hooks.invert_mirror;

    tokio::spawn(WinServer::run(addr, hooks, started_tx, done_tx));

    while TcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        window_size: PEER_WINDOW as u32,
        channel_buffer_size: 4,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut session = match russh::client::connect(config, addr, Client).await {
        Ok(s) => s,
        Err(_) => return Ok(WinClass::Connection),
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
            Err(_) => return Ok(WinClass::Connection),
        },
        _ => return Ok(WinClass::Connection),
    };

    let _ = started_rx.await;
    sleep(Duration::from_millis(80)).await;
    let first = received.load(Ordering::SeqCst);
    if first > PEER_WINDOW {
        return Ok(WinClass::Timeout);
    }

    let rec = received.clone();
    let collect = async move {
        while rec.load(Ordering::SeqCst) < PAYLOAD {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    rec.fetch_add(data.len(), Ordering::SeqCst);
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(other) => panic!("unexpected {other:?}"),
            }
        }
    };

    let timed_out = timeout(Duration::from_secs(5), async {
        collect.await;
        let _ = done_rx.await;
    })
    .await
    .is_err();

    let got = received.load(Ordering::SeqCst);
    let class = if !timed_out && got == PAYLOAD {
        WinClass::Progressed
    } else if timed_out && got <= PEER_WINDOW {
        WinClass::Stall
    } else if timed_out {
        WinClass::Timeout
    } else {
        WinClass::Connection
    };
    eprintln!(
        "s5b window class={class:?} received={got} first={first} timed_out={timed_out} invert={}",
        invert
    );
    Ok(class)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_data_waits_for_peer_window() -> Result<(), anyhow::Error> {
    match run_channel_data(Hooks {
        invert_mirror: false,
    })
    .await?
    {
        WinClass::Progressed => Ok(()),
        other => anyhow::bail!("production Channel::data must Progressed, got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_data_stale_mirror_is_red() -> Result<(), anyhow::Error> {
    match run_channel_data(Hooks {
        invert_mirror: true,
    })
    .await?
    {
        WinClass::Stall | WinClass::Timeout => Ok(()),
        other => anyhow::bail!(
            "invert stale-mirror must Stall|Timeout (not connection), got {other:?}"
        ),
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct WinServer {
    hooks: std::sync::Arc<Hooks>,
    started: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
    done: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
}

impl WinServer {
    async fn run(
        addr: SocketAddr,
        hooks: Hooks,
        started: oneshot::Sender<()>,
        done: oneshot::Sender<()>,
    ) {
        let invert = hooks.invert_mirror;
        let mut config = server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            event_buffer_size: 8,
            ..Default::default()
        };
        #[cfg(feature = "_test_hooks")]
        {
            config.invert_channel_window_mirror = invert;
        }
        let mut server = Self {
            hooks: std::sync::Arc::new(hooks),
            started: std::sync::Arc::new(std::sync::Mutex::new(Some(started))),
            done: std::sync::Arc::new(std::sync::Mutex::new(Some(done))),
        };
        let _ = server.hooks;
        server.run_on_address(Arc::new(config), addr).await.unwrap();
    }
}

impl russh::server::Server for WinServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for WinServer {
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
            let payload = vec![0u8; PAYLOAD];
            let _ = channel.data_bytes(payload).await;
            let _ = channel.eof().await;
            if let Some(tx) = done.lock().unwrap().take() {
                let _ = tx.send(());
            }
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DualClass {
    BothDone,
    SecondWriterParked,
    Timeout,
    Connection,
}

#[derive(Clone, Copy)]
struct DualHooks {
    invert_single_wake: bool,
    orderly_close: bool,
}

async fn run_dual_writers(hooks: DualHooks) -> Result<DualClass, anyhow::Error> {
    let addr = addr();
    let (started_tx, started_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
    let received = Arc::new(AtomicUsize::new(0));
    let orderly = hooks.orderly_close;

    tokio::spawn(DualServer::run(addr, hooks, started_tx, done_tx));

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
            if rec.load(Ordering::SeqCst) >= PAYLOAD * 2 && !orderly {
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
    let (collect_r, n_done) = tokio::join!(
        timeout(Duration::from_secs(5), collect),
        writers
    );
    let timed_out = collect_r.is_err();
    let got = received.load(Ordering::SeqCst);
    let class = if n_done == 2 {
        DualClass::BothDone
    } else if got >= PAYLOAD * 2 && n_done < 2 {
        // Bytes reached the peer; a write future is still parked.
        DualClass::SecondWriterParked
    } else if n_done == 1 || timed_out {
        DualClass::Timeout
    } else {
        DualClass::Connection
    };
    eprintln!(
        "s5b dual class={class:?} received={got} writers_done={n_done} timed_out={timed_out} invert={} close={}",
        hooks.invert_single_wake, orderly
    );
    Ok(class)
}

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_writer_both_complete() -> Result<(), anyhow::Error> {
    match run_dual_writers(DualHooks {
        invert_single_wake: false,
        orderly_close: false,
    })
    .await?
    {
        DualClass::BothDone => Ok(()),
        other => anyhow::bail!("dual writers must BothDone, got {other:?}"),
    }
}

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_writer_single_wake_is_red() -> Result<(), anyhow::Error> {
    match run_dual_writers(DualHooks {
        invert_single_wake: true,
        orderly_close: false,
    })
    .await?
    {
        DualClass::SecondWriterParked | DualClass::Timeout => Ok(()),
        other => anyhow::bail!(
            "invert single-wake must SecondWriterParked|Timeout, got {other:?}"
        ),
    }
}

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_writer_orderly_close_unblocks() -> Result<(), anyhow::Error> {
    match run_dual_writers(DualHooks {
        invert_single_wake: false,
        orderly_close: true,
    })
    .await?
    {
        DualClass::BothDone => Ok(()),
        other => anyhow::bail!("orderly close must unblock both writers, got {other:?}"),
    }
}

#[derive(Clone)]
struct DualServer {
    hooks: DualHooks,
    started: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
    done: tokio::sync::mpsc::UnboundedSender<&'static str>,
}

impl DualServer {
    async fn run(
        addr: SocketAddr,
        hooks: DualHooks,
        started: oneshot::Sender<()>,
        done: tokio::sync::mpsc::UnboundedSender<&'static str>,
    ) {
        let mut config = server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            event_buffer_size: 8,
            ..Default::default()
        };
        #[cfg(feature = "_test_hooks")]
        {
            config.invert_single_writer_wake = hooks.invert_single_wake;
        }
        let mut server = Self {
            hooks,
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await?;
        if let Some(tx) = self.started.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let done = self.done.clone();
        let close = self.hooks.orderly_close;
        let handle = session.handle();
        let cid = channel.id();
        tokio::spawn(async move {
            let mut stdout = channel.make_writer();
            let mut stderr = channel.make_writer_ext(Some(1));
            let a = vec![0u8; PAYLOAD];
            let b = vec![1u8; PAYLOAD];
            if close {
                let h = handle.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(80)).await;
                    let _ = h.close(cid).await;
                });
            }
            let (r1, r2) = tokio::join!(stdout.write_all(&a), stderr.write_all(&b));
            let _ = (r1, r2);
            let _ = done.send("stdout");
            let _ = done.send("stderr");
        });
        Ok(())
    }
}

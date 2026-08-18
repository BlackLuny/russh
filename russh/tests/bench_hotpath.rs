//! Ad-hoc hot-path throughput bench (ignored; not a CI gate).
//!
//! Mirrors the S7a P1/P2 shapes but runs exactly one scenario per process so
//! external CPU accounting (`/usr/bin/time -l`) is attributable.
//!
//! ```text
//! BENCH_MIB=512 BENCH_PATH=b cargo test -p russh --release --test bench_hotpath \
//!   -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Preferred, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

const FILL: u8 = 0xA5;
const CHUNK: usize = 32 * 1024;
const WINDOW: u32 = 4 * 1024 * 1024;
const PACKET: u32 = 32 * 1024;
const XFER_TIMEOUT: Duration = Duration::from_secs(600);

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn free_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn wait_listening(addr: SocketAddr) {
    while StdTcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }
}

fn aes256_gcm_only() -> Preferred {
    Preferred {
        cipher: Cow::Borrowed(&[russh::cipher::AES_256_GCM]),
        ..Preferred::default()
    }
}

fn server_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()
}

fn mibps(bytes: u64, dt: Duration) -> f64 {
    (bytes as f64) / (1024.0 * 1024.0) / dt.as_secs_f64()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathKind {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    Down,
    Up,
}

#[derive(Clone)]
struct Cfg {
    path: PathKind,
    dir: Dir,
    bytes_per_channel: u64,
}

struct BenchServer {
    cfg: Cfg,
}

impl server::Server for BenchServer {
    type Handler = BenchHandler;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        BenchHandler {
            cfg: self.cfg.clone(),
        }
    }
}

struct BenchHandler {
    cfg: Cfg,
}

impl server::Handler for BenchHandler {
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
        reply: russh::server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let id = channel.id();
        let cfg = self.cfg.clone();
        let _ = reply.accept().await;
        tokio::spawn(async move {
            match cfg.dir {
                Dir::Down => produce(cfg, channel, handle, id).await,
                Dir::Up => sink(channel).await,
            }
        });
        Ok(())
    }
}

async fn sink(channel: Channel<Msg>) {
    let (mut r, _w) = channel.split();
    let mut reader = r.make_reader();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

async fn produce(cfg: Cfg, channel: Channel<Msg>, handle: server::Handle, id: ChannelId) {
    let n = cfg.bytes_per_channel;
    match cfg.path {
        PathKind::B => {
            let mut stream = channel.into_stream();
            let chunk = vec![FILL; CHUNK];
            let mut left = n;
            while left > 0 {
                let take = (left as usize).min(chunk.len());
                if stream.write_all(&chunk[..take]).await.is_err() {
                    return;
                }
                left -= take as u64;
            }
            let _ = stream.shutdown().await;
        }
        PathKind::A => {
            let _keep = channel;
            let chunk = Bytes::from(vec![FILL; CHUNK]);
            let mut left = n;
            while left > 0 {
                let take = (left as usize).min(chunk.len());
                if handle.data(id, chunk.slice(..take)).await.is_err() {
                    return;
                }
                left -= take as u64;
            }
            let _ = handle.eof(id).await;
        }
    }
}

async fn spawn_server(addr: SocketAddr, cfg: Cfg, evbuf: usize) {
    let config = Arc::new(server::Config {
        keys: vec![server_key()],
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        event_buffer_size: evbuf,
        channel_buffer_size: 100,
        nodelay: true,
        preferred: aes256_gcm_only(),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });
    let mut srv = BenchServer { cfg };
    let _ = srv.run_on_address(config, addr).await;
}

struct QuietClient;

impl client::Handler for QuietClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect(addr: SocketAddr) -> Result<russh::client::Handle<QuietClient>, russh::Error> {
    let config = Arc::new(client::Config {
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        channel_buffer_size: 256,
        nodelay: true,
        preferred: aes256_gcm_only(),
        inactivity_timeout: None,
        ..Default::default()
    });
    let key = Arc::new(server_key());
    let mut session = russh::client::connect(config, addr, QuietClient).await?;
    let ok = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?
        .success();
    if !ok {
        return Err(russh::Error::NotAuthenticated);
    }
    Ok(session)
}

async fn drain_channel(
    channel: &mut russh::Channel<russh::client::Msg>,
    want: u64,
) -> Result<u64, anyhow::Error> {
    let mut reader = channel.make_reader();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0u64;
    while got < want {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        got += n as u64;
    }
    Ok(got)
}

async fn push_channel(
    channel: russh::Channel<russh::client::Msg>,
    want: u64,
) -> Result<u64, anyhow::Error> {
    let mut stream = channel.into_stream();
    let chunk = vec![FILL; CHUNK];
    let mut left = want;
    while left > 0 {
        let take = (left as usize).min(chunk.len());
        stream.write_all(&chunk[..take]).await?;
        left -= take as u64;
    }
    stream.flush().await?;
    Ok(want)
}

async fn run_once(cfg: Cfg, chans: usize, evbuf: usize) -> Result<(u64, Duration), anyhow::Error> {
    let addr = free_addr();
    let per = cfg.bytes_per_channel;
    let dir = cfg.dir;
    tokio::spawn(spawn_server(addr, cfg, evbuf));
    wait_listening(addr).await;
    let session = connect(addr).await?;
    let mut opened = Vec::new();
    for _ in 0..chans {
        opened.push(session.channel_open_session().await?);
    }
    let t0 = Instant::now();
    let mut joins = Vec::new();
    for mut ch in opened {
        joins.push(tokio::spawn(async move {
            match dir {
                Dir::Down => drain_channel(&mut ch, per).await,
                Dir::Up => push_channel(ch, per).await,
            }
        }));
    }
    let mut total = 0u64;
    for j in joins {
        total += timeout(XFER_TIMEOUT, j).await???;
    }
    let dt = t0.elapsed();
    if total != per * chans as u64 {
        anyhow::bail!("short transfer {total}/{}", per * chans as u64);
    }
    Ok((total, dt))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench() -> Result<(), anyhow::Error> {
    let path = if env_str("BENCH_PATH", "b").eq_ignore_ascii_case("a") {
        PathKind::A
    } else {
        PathKind::B
    };
    let dir = if env_str("BENCH_DIR", "down").eq_ignore_ascii_case("up") {
        Dir::Up
    } else {
        Dir::Down
    };
    let chans = env_usize("BENCH_CHANNELS", 1);
    let mib = env_usize("BENCH_MIB", 512) as u64;
    let warm = env_usize("BENCH_WARMUP_MIB", 8) as u64;
    let trials = env_usize("BENCH_TRIALS", 3);
    let evbuf = env_usize("BENCH_EVBUF", 64);
    let per = mib * 1024 * 1024 / chans as u64;

    if warm > 0 {
        let cfg = Cfg {
            path,
            dir,
            bytes_per_channel: warm * 1024 * 1024 / chans as u64,
        };
        let _ = run_once(cfg, chans, evbuf).await?;
    }

    let mut rates = Vec::new();
    for i in 0..trials {
        let cfg = Cfg {
            path,
            dir,
            bytes_per_channel: per,
        };
        let (bytes, dt) = run_once(cfg, chans, evbuf).await?;
        let r = mibps(bytes, dt);
        eprintln!(
            "BENCH trial={i} path={path:?} dir={dir:?} chans={chans} bytes={bytes} \
             wall={:.3}s MiBps={r:.1}",
            dt.as_secs_f64()
        );
        rates.push(r);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    eprintln!(
        "BENCH RESULT path={path:?} dir={dir:?} chans={chans} mib={mib} median_MiBps={:.1} all={rates:?}",
        rates[rates.len() / 2]
    );
    Ok(())
}

//! Loopback SSH proxy / multi-channel bulk bench for this russh fork.
//!
//! Measures throughput, process CPU, RSS, and stall/isolation reliability
//! against a local origin. Usage:
//!
//!   cargo run --release --example proxy_loopback_bench -- --scenario proxy-down-1ch
//!
//! Cipher is locked to chacha20-poly1305 unless `--gcm` is passed.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, Preferred, cipher, client, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const CHUNK: usize = 32 * 1024;
const STALL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scenario {
    /// Origin → SSH server → client, 1 direct-tcpip channel.
    #[value(name = "proxy-down-1ch")]
    ProxyDown1ch,
    /// Same, 4 concurrent direct-tcpip channels.
    #[value(name = "proxy-down-4ch")]
    ProxyDown4ch,
    /// Same, 8 concurrent direct-tcpip channels.
    #[value(name = "proxy-down-8ch")]
    ProxyDown8ch,
    /// Client → SSH server → origin sink, 1 channel.
    #[value(name = "proxy-up-1ch")]
    ProxyUp1ch,
    /// Session-channel flood (apples-to-apples vs sunset).
    #[value(name = "session-down-1ch")]
    SessionDown1ch,
    #[value(name = "session-down-4ch")]
    SessionDown4ch,
    #[value(name = "session-down-8ch")]
    SessionDown8ch,
    /// One frozen reader + one healthy drain. Healthy must finish.
    SlowFast,
    /// Bulk transfer while other channels open/close.
    Churn,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    scenario: Scenario,
    /// Payload per channel (MiB).
    #[arg(long, default_value_t = 256)]
    mib: u64,
    /// Prefer aes256-gcm instead of chacha20-poly1305.
    #[arg(long)]
    gcm: bool,
    /// Channel window (bytes). Default 4 MiB.
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    window: u32,
    #[arg(long, default_value_t = 32768)]
    max_packet: u32,
}

#[derive(Clone)]
struct Shared {
    per_channel: u64,
    flood_slots: Arc<AtomicU64>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let (channels, per_channel, kind) = match args.scenario {
        Scenario::ProxyDown1ch => (1usize, args.mib * 1024 * 1024, Kind::ProxyDown),
        Scenario::ProxyDown4ch => (4, args.mib * 1024 * 1024, Kind::ProxyDown),
        Scenario::ProxyDown8ch => (8, args.mib * 1024 * 1024, Kind::ProxyDown),
        Scenario::ProxyUp1ch => (1, args.mib * 1024 * 1024, Kind::ProxyUp),
        Scenario::SessionDown1ch => (1, args.mib * 1024 * 1024, Kind::SessionDown),
        Scenario::SessionDown4ch => (4, args.mib * 1024 * 1024, Kind::SessionDown),
        Scenario::SessionDown8ch => (8, args.mib * 1024 * 1024, Kind::SessionDown),
        Scenario::SlowFast => (2, args.mib * 1024 * 1024, Kind::SlowFast),
        Scenario::Churn => (1, args.mib * 1024 * 1024, Kind::Churn),
    };

    let origin = if matches!(kind, Kind::ProxyDown | Kind::ProxyUp) {
        Some(spawn_origin(kind, per_channel).await?)
    } else {
        None
    };

    let cipher_name = if args.gcm {
        cipher::AES_256_GCM
    } else {
        cipher::CHACHA20_POLY1305
    };
    let preferred = Preferred {
        cipher: Cow::Owned(vec![cipher_name]),
        kex: Cow::Owned(vec![russh::kex::CURVE25519]),
        ..Preferred::default()
    };

    let host_key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    let server_cfg = Arc::new(server::Config {
        keys: vec![host_key],
        window_size: args.window,
        maximum_packet_size: args.max_packet,
        nodelay: true,
        inactivity_timeout: None,
        keepalive_interval: None,
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        limits: russh::Limits {
            rekey_write_limit: usize::MAX,
            rekey_read_limit: usize::MAX,
            rekey_time_limit: Duration::from_secs(86_400),
        },
        preferred: preferred.clone(),
        ..Default::default()
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ssh_addr = listener.local_addr()?;
    let flood_slots = match kind {
        Kind::SessionDown | Kind::SlowFast => channels as u64,
        Kind::Churn => 1,
        Kind::ProxyDown | Kind::ProxyUp => 0,
    };
    let shared = Shared {
        per_channel,
        flood_slots: Arc::new(AtomicU64::new(flood_slots)),
    };
    let mut sh = HandlerServer {
        shared: shared.clone(),
        kind,
    };
    tokio::spawn(async move {
        let _ = sh.run_on_socket(server_cfg, &listener).await;
    });

    // Wait until the listener is actually accepting.
    for _ in 0..200 {
        if TcpStream::connect(ssh_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let client_cfg = Arc::new(client::Config {
        window_size: args.window,
        maximum_packet_size: args.max_packet,
        nodelay: true,
        inactivity_timeout: None,
        keepalive_interval: None,
        preferred,
        limits: russh::Limits {
            rekey_write_limit: usize::MAX,
            rekey_read_limit: usize::MAX,
            rekey_time_limit: Duration::from_secs(86_400),
        },
        ..Default::default()
    });

    let rss0 = rss_bytes();
    let cpu0 = process_cpu_secs();
    let t0 = Instant::now();

    let result = match kind {
        Kind::ProxyDown => {
            proxy_down_client(client_cfg, ssh_addr, origin.expect("origin"), channels, per_channel)
                .await
        }
        Kind::ProxyUp => {
            proxy_up_client(client_cfg, ssh_addr, origin.expect("origin"), per_channel).await
        }
        Kind::SessionDown => {
            session_down_client(client_cfg, ssh_addr, channels, per_channel).await
        }
        Kind::SlowFast => slow_fast_client(client_cfg, ssh_addr, per_channel).await,
        Kind::Churn => churn_client(client_cfg, ssh_addr, per_channel).await,
    };

    let wall = t0.elapsed().as_secs_f64().max(1e-9);
    let cpu = (process_cpu_secs() - cpu0).max(0.0);
    let rss1 = rss_bytes().max(rss0);
    let (ok, bytes, note) = match result {
        Ok(b) => (true, b, String::new()),
        Err(e) => (false, 0, format!("{e:#}")),
    };
    let mib = bytes as f64 / (1024.0 * 1024.0);
    let mib_s = mib / wall;
    let cpu_s_per_gib = if bytes == 0 {
        0.0
    } else {
        cpu / (bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    };

    println!(
        "impl=russh-fork scenario={:?} channels={channels} bytes={bytes} wall_s={wall:.4} mib_s={mib_s:.1} cpu_s={cpu:.4} cpu_s_per_gib={cpu_s_per_gib:.3} rss_peak_mib={:.2} ok={ok} notes={note}",
        args.scenario,
        rss1 as f64 / (1024.0 * 1024.0),
    );
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    ProxyDown,
    ProxyUp,
    SessionDown,
    SlowFast,
    Churn,
}

async fn spawn_origin(kind: Kind, per_channel: u64) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                match kind {
                    Kind::ProxyDown => {
                        let buf = vec![0xABu8; CHUNK];
                        let mut left = per_channel;
                        while left > 0 {
                            let n = (left as usize).min(buf.len());
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                            left -= n as u64;
                        }
                        let _ = sock.shutdown().await;
                    }
                    Kind::ProxyUp => {
                        let mut sink = tokio::io::sink();
                        let _ = tokio::io::copy(&mut sock, &mut sink).await;
                    }
                    _ => {}
                }
            });
        }
    });
    Ok(addr)
}

async fn connect_client(
    cfg: Arc<client::Config>,
    addr: std::net::SocketAddr,
) -> Result<client::Handle<Cli>> {
    let mut session = client::connect(cfg, addr, Cli).await?;
    let key = Arc::new(PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Ed25519,
    )?);
    let hash = session.best_supported_rsa_hash().await?.flatten();
    let ok = session
        .authenticate_publickey("bench", PrivateKeyWithHashAlg::new(key, hash))
        .await?
        .success();
    if !ok {
        bail!("auth failed");
    }
    Ok(session)
}

async fn proxy_down_client(
    cfg: Arc<client::Config>,
    ssh: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    channels: usize,
    per_channel: u64,
) -> Result<u64> {
    let session = connect_client(cfg, ssh).await?;
    let mut joins = Vec::new();
    for _ in 0..channels {
        let ch = session
            .channel_open_direct_tcpip(
                origin.ip().to_string(),
                origin.port() as u32,
                "127.0.0.1",
                0,
            )
            .await?;
        joins.push(tokio::spawn(async move {
            drain_stream(ch, Some(per_channel)).await
        }));
    }
    let mut total = 0u64;
    for j in joins {
        total += j.await??;
    }
    Ok(total)
}

async fn proxy_up_client(
    cfg: Arc<client::Config>,
    ssh: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    per_channel: u64,
) -> Result<u64> {
    let session = connect_client(cfg, ssh).await?;
    let ch = session
        .channel_open_direct_tcpip(
            origin.ip().to_string(),
            origin.port() as u32,
            "127.0.0.1",
            0,
        )
        .await?;
    let mut w = ch.into_stream();
    let buf = vec![0xCDu8; CHUNK];
    let mut left = per_channel;
    while left > 0 {
        let n = (left as usize).min(buf.len());
        timeout(STALL, w.write_all(&buf[..n]))
            .await
            .context("uplink stall")??;
        left -= n as u64;
    }
    w.shutdown().await?;
    Ok(per_channel)
}

async fn session_down_client(
    cfg: Arc<client::Config>,
    ssh: std::net::SocketAddr,
    channels: usize,
    per_channel: u64,
) -> Result<u64> {
    let session = connect_client(cfg, ssh).await?;
    let mut joins = Vec::new();
    for _ in 0..channels {
        let ch = session.channel_open_session().await?;
        joins.push(tokio::spawn(async move {
            drain_stream(ch, Some(per_channel)).await
        }));
    }
    let mut total = 0u64;
    for j in joins {
        total += j.await??;
    }
    Ok(total)
}

async fn slow_fast_client(
    cfg: Arc<client::Config>,
    ssh: std::net::SocketAddr,
    per_channel: u64,
) -> Result<u64> {
    let session = connect_client(cfg, ssh).await?;
    let frozen = session.channel_open_session().await?;
    let healthy = session.channel_open_session().await?;
    // Hold the frozen channel (do not drain). Its window will exhaust.
    let _hold = tokio::spawn(async move {
        let _ch = frozen;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });
    let got = drain_stream(healthy, Some(per_channel)).await?;
    Ok(got)
}

async fn churn_client(
    cfg: Arc<client::Config>,
    ssh: std::net::SocketAddr,
    per_channel: u64,
) -> Result<u64> {
    let session = connect_client(cfg, ssh).await?;
    let bulk = session.channel_open_session().await?;
    let drain = tokio::spawn(async move { drain_stream(bulk, Some(per_channel)).await });
    for i in 0..80u32 {
        let extra = session.channel_open_session().await?;
        if i % 2 == 0 {
            extra.close().await?;
        } else {
            drop(extra);
        }
    }
    drain.await?
}

async fn drain_stream(ch: Channel<client::Msg>, expect: Option<u64>) -> Result<u64> {
    let mut stream = ch.into_stream();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0u64;
    loop {
        let n = timeout(STALL, stream.read(&mut buf))
            .await
            .context("drain stall (no channel progress for 5s)")??;
        if n == 0 {
            break;
        }
        got += n as u64;
        if let Some(exp) = expect {
            if got >= exp {
                break;
            }
        }
    }
    if let Some(exp) = expect {
        if got < exp {
            bail!("short read: got {got} want {exp}");
        }
    }
    Ok(got)
}

#[derive(Clone)]
struct HandlerServer {
    shared: Shared,
    kind: Kind,
}

impl server::Server for HandlerServer {
    type Handler = Handler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        Handler {
            shared: self.shared.clone(),
            kind: self.kind,
        }
    }
}

struct Handler {
    shared: Shared,
    kind: Kind,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
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
        match self.kind {
            Kind::SessionDown | Kind::SlowFast | Kind::Churn => {
                let should_flood = self
                    .shared
                    .flood_slots
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(1))
                    .is_ok();
                if should_flood {
                    let n = self.shared.per_channel;
                    tokio::spawn(async move {
                        let _ = flood_channel(channel, n).await;
                    });
                } else {
                    tokio::spawn(async move {
                        let _ = channel.close().await;
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let host = host_to_connect.to_string();
        let port = port_to_connect as u16;
        tokio::spawn(async move {
            let Ok(mut tcp) = TcpStream::connect((host.as_str(), port)).await else {
                let _ = channel.close().await;
                return;
            };
            let _ = tcp.set_nodelay(true);
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }
}

async fn flood_channel(channel: Channel<Msg>, bytes: u64) -> Result<(), russh::Error> {
    let mut w = channel.into_stream();
    let buf = vec![0xABu8; CHUNK];
    let mut left = bytes;
    while left > 0 {
        let n = (left as usize).min(buf.len());
        w.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    w.shutdown().await?;
    Ok(())
}

struct Cli;
impl client::Handler for Cli {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn process_cpu_secs() -> f64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
    unsafe extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0.0;
    }
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

fn rss_bytes() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

//! S7a performance baseline (ignored, not a CI gate).
//!
//! Loopback, real `Session::run`. Path B = `Channel::into_stream()`
//! (zfc `ChannelStream` / ChannelTx acked). Path A = `Handle::data`.
//!
//! ```text
//! cargo test -p russh --release --features _test_hooks --test test_s7_perf \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Numbers are only meaningful in `--release` (debug inverts memcpy vs cipher).

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Preferred, RekeyPolicy, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const FILL: u8 = 0xA5;
const CHUNK: usize = 32 * 1024;
const P1_BYTES: u64 = 64 * 1024 * 1024;
const P2_STREAMS: usize = 8;
const P2_BYTES_EACH: u64 = 16 * 1024 * 1024;
const P3_N: usize = 200;
const P4_BYTES: u64 = 128 * 1024 * 1024;
const P4_REKEY_BYTES: u64 = 2 * 1024 * 1024;
const TRIALS: usize = 3;
const WINDOW: u32 = 4 * 1024 * 1024;
const PACKET: u32 = 32 * 1024;
const XFER_TIMEOUT: Duration = Duration::from_secs(90);

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

fn mbps(bytes: u64, dt: Duration) -> f64 {
    let secs = dt.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / (1024.0 * 1024.0) / secs
}

fn median_f64(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[xs.len() / 2]
}

fn spread_pct(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    let med = median_f64(&mut v);
    if med <= 0.0 {
        return 0.0;
    }
    let min = xs.iter().copied().fold(f64::INFINITY, f64::min);
    let max = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (max - min) / med * 100.0
}

fn print_median(tag: &str, xs: &[f64]) {
    let mut v = xs.to_vec();
    let med = median_f64(&mut v);
    let sp = spread_pct(xs);
    let reliable = if sp <= 20.0 { "yes" } else { "no" };
    eprintln!("S7A {tag} median={med:.3} spread_pct={sp:.1} reliable={reliable} trials={xs:?}");
}

#[derive(Clone, Copy, Debug)]
enum PathKind {
    A,
    B,
}

impl PathKind {
    fn label(self) -> &'static str {
        match self {
            PathKind::A => "A",
            PathKind::B => "B",
        }
    }
}

#[derive(Clone)]
struct SrvCfg {
    path: PathKind,
    evbuf: usize,
    nodelay: bool,
    bytes_per_channel: u64,
    first_byte_only: bool,
    rekey_bytes: Option<u64>,
}

struct PerfServer {
    cfg: SrvCfg,
}

impl server::Server for PerfServer {
    type Handler = PerfHandler;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        PerfHandler { cfg: self.cfg.clone() }
    }
}

struct PerfHandler {
    cfg: SrvCfg,
}

impl server::Handler for PerfHandler {
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
            produce(cfg, channel, handle, id).await;
        });
        Ok(())
    }
}

async fn produce(cfg: SrvCfg, channel: Channel<Msg>, handle: server::Handle, id: ChannelId) {
    let n = if cfg.first_byte_only {
        1
    } else {
        cfg.bytes_per_channel
    };
    match cfg.path {
        PathKind::B => {
            let mut stream = channel.into_stream();
            let chunk = vec![FILL; CHUNK];
            let mut left = n;
            while left > 0 {
                let take = (left as usize).min(chunk.len());
                let piece = chunk.get(..take).unwrap_or(&[]);
                if stream.write_all(piece).await.is_err() {
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
                let piece = chunk.slice(..take);
                if handle.data(id, piece).await.is_err() {
                    return;
                }
                left -= take as u64;
            }
            let _ = handle.eof(id).await;
        }
    }
}

async fn spawn_server(addr: SocketAddr, cfg: SrvCfg) {
    let limits = match cfg.rekey_bytes {
        Some(b) => RekeyPolicy {
            max_bytes: b,
            ..RekeyPolicy::default()
        },
        None => RekeyPolicy::default(),
    };
    let config = Arc::new(server::Config {
        keys: vec![server_key()],
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        event_buffer_size: cfg.evbuf,
        channel_buffer_size: 100,
        nodelay: cfg.nodelay,
        preferred: aes256_gcm_only(),
        limits,
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    });
    let mut srv = PerfServer { cfg };
    let _ = srv.run_on_address(config, addr).await;
}

struct CountingClient {
    kex: Arc<AtomicU64>,
}

impl client::Handler for CountingClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.kex.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

async fn connect(
    addr: SocketAddr,
    nodelay: bool,
    kex: Arc<AtomicU64>,
) -> Result<russh::client::Handle<CountingClient>, russh::Error> {
    let config = Arc::new(client::Config {
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        channel_buffer_size: 256,
        nodelay,
        preferred: aes256_gcm_only(),
        inactivity_timeout: None,
        ..Default::default()
    });
    let key = Arc::new(server_key());
    let mut session = russh::client::connect(config, addr, CountingClient { kex }).await?;
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
    progress: Option<Arc<AtomicU64>>,
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
        if let Some(ref p) = progress {
            p.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    Ok(got)
}

async fn p1_once(path: PathKind, evbuf: usize) -> Result<(u64, Duration), anyhow::Error> {
    let addr = free_addr();
    let cfg = SrvCfg {
        path,
        evbuf,
        nodelay: true,
        bytes_per_channel: P1_BYTES,
        first_byte_only: false,
        rekey_bytes: None,
    };
    tokio::spawn(spawn_server(addr, cfg));
    wait_listening(addr).await;
    let kex = Arc::new(AtomicU64::new(0));
    let session = connect(addr, true, kex).await?;
    let mut ch = session.channel_open_session().await?;
    let t0 = Instant::now();
    let got = timeout(XFER_TIMEOUT, drain_channel(&mut ch, P1_BYTES, None)).await??;
    let dt = t0.elapsed();
    if got != P1_BYTES {
        anyhow::bail!("P1 path={} evbuf={evbuf} short read {got}/{P1_BYTES}", path.label());
    }
    Ok((got, dt))
}

async fn p2_once() -> Result<(u64, Duration, Vec<u64>), anyhow::Error> {
    let addr = free_addr();
    let cfg = SrvCfg {
        path: PathKind::B,
        evbuf: 64,
        nodelay: true,
        bytes_per_channel: P2_BYTES_EACH,
        first_byte_only: false,
        rekey_bytes: None,
    };
    tokio::spawn(spawn_server(addr, cfg));
    wait_listening(addr).await;
    let kex = Arc::new(AtomicU64::new(0));
    let session = connect(addr, true, kex).await?;
    let mut chans = Vec::new();
    for _ in 0..P2_STREAMS {
        chans.push(session.channel_open_session().await?);
    }
    let t0 = Instant::now();
    let mut joins = Vec::new();
    for mut ch in chans {
        joins.push(tokio::spawn(async move {
            drain_channel(&mut ch, P2_BYTES_EACH, None).await
        }));
    }
    let mut shares = Vec::new();
    for j in joins {
        let got = timeout(XFER_TIMEOUT, j).await???;
        shares.push(got);
    }
    let dt = t0.elapsed();
    let total: u64 = shares.iter().sum();
    Ok((total, dt, shares))
}

async fn p3_once(nodelay: bool) -> Result<Vec<Duration>, anyhow::Error> {
    let addr = free_addr();
    let cfg = SrvCfg {
        path: PathKind::B,
        evbuf: 64,
        nodelay,
        bytes_per_channel: 1,
        first_byte_only: true,
        rekey_bytes: None,
    };
    tokio::spawn(spawn_server(addr, cfg));
    wait_listening(addr).await;
    let kex = Arc::new(AtomicU64::new(0));
    let session = connect(addr, nodelay, kex).await?;
    let mut samples = Vec::with_capacity(P3_N);
    for _ in 0..P3_N {
        let t0 = Instant::now();
        let mut ch = session.channel_open_session().await?;
        let mut reader = ch.make_reader();
        let mut buf = [0u8; 8];
        let n = timeout(Duration::from_secs(5), reader.read(&mut buf)).await??;
        let dt = t0.elapsed();
        if n == 0 {
            anyhow::bail!("P3 nodelay={nodelay} first read EOF");
        }
        samples.push(dt);
        drop(reader);
        let _ = ch.close().await;
    }
    Ok(samples)
}

fn percentile_us(sorted: &[Duration], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)].as_secs_f64() * 1_000_000.0
}

async fn p4_once() -> Result<P4Stat, anyhow::Error> {
    let addr = free_addr();
    let cfg = SrvCfg {
        path: PathKind::B,
        evbuf: 64,
        nodelay: true,
        bytes_per_channel: P4_BYTES,
        first_byte_only: false,
        rekey_bytes: Some(P4_REKEY_BYTES),
    };
    tokio::spawn(spawn_server(addr, cfg));
    wait_listening(addr).await;
    let kex = Arc::new(AtomicU64::new(0));
    let session = connect(addr, true, kex.clone()).await?;
    let mut ch = session.channel_open_session().await?;
    let progress = Arc::new(AtomicU64::new(0));
    let samples = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let samp_task = {
        let progress = progress.clone();
        let samples = samples.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(2)).await;
                let got = progress.load(Ordering::Relaxed);
                samples.lock().unwrap().push((start.elapsed(), got));
            }
        })
    };
    let t0 = Instant::now();
    let got = timeout(
        Duration::from_secs(180),
        drain_channel(&mut ch, P4_BYTES, Some(progress.clone())),
    )
    .await??;
    let dt = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    let _ = samp_task.await;
    if got != P4_BYTES {
        anyhow::bail!("P4 short read {got}/{P4_BYTES}");
    }
    let pts = samples.lock().unwrap().clone();
    let pit = analyze_pit(&pts);
    Ok(P4Stat {
        bytes: got,
        dt,
        kex: kex.load(Ordering::Relaxed),
        pit,
    })
}

struct P4Stat {
    bytes: u64,
    dt: Duration,
    kex: u64,
    pit: Pit,
}

struct Pit {
    pit_ms: f64,
    pit_depth: f64,
    min_win_mbps: f64,
    med_win_mbps: f64,
}

fn analyze_pit(pts: &[(Duration, u64)]) -> Pit {
    const WIN: Duration = Duration::from_millis(5);
    let mut rates = Vec::new();
    let mut i = 0;
    while i < pts.len() {
        let (t0, b0) = pts[i];
        let mut j = i + 1;
        while j < pts.len() && pts[j].0.saturating_sub(t0) < WIN {
            j += 1;
        }
        if j >= pts.len() {
            break;
        }
        let (t1, b1) = pts[j];
        let dt = t1.saturating_sub(t0);
        if dt.as_secs_f64() > 0.0 && b1 >= b0 {
            rates.push((dt, mbps(b1 - b0, dt)));
        }
        i = j;
    }
    if rates.is_empty() {
        return Pit {
            pit_ms: 0.0,
            pit_depth: 0.0,
            min_win_mbps: 0.0,
            med_win_mbps: 0.0,
        };
    }
    let mut just: Vec<f64> = rates.iter().map(|(_, r)| *r).collect();
    let med = median_f64(&mut just);
    let min = rates.iter().map(|(_, r)| *r).fold(f64::INFINITY, f64::min);
    let thresh = med * 0.5;
    let mut pit = Duration::ZERO;
    for (dt, r) in &rates {
        if *r < thresh {
            pit += *dt;
        }
    }
    let depth = if med > 0.0 { 1.0 - (min / med) } else { 0.0 };
    Pit {
        pit_ms: pit.as_secs_f64() * 1000.0,
        pit_depth: depth,
        min_win_mbps: min,
        med_win_mbps: med,
    }
}

async fn raw_tcp_copy(bytes: u64) -> Result<(u64, Duration), anyhow::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await?;
        sock.set_nodelay(true)?;
        let chunk = vec![FILL; CHUNK];
        let mut left = bytes;
        while left > 0 {
            let take = (left as usize).min(chunk.len());
            let piece = chunk.get(..take).unwrap_or(&[]);
            sock.write_all(piece).await?;
            left -= take as u64;
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut client = TcpStream::connect(addr).await?;
    client.set_nodelay(true)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0u64;
    let t0 = Instant::now();
    while got < bytes {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        got += n as u64;
    }
    let dt = t0.elapsed();
    server.await??;
    if got != bytes {
        anyhow::bail!("raw tcp short {got}/{bytes}");
    }
    Ok((got, dt))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn s7a_baseline_suite() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    eprintln!("S7A start cipher=aes256-gcm@openssh.com chunk={CHUNK} p1={P1_BYTES}");

    let _ = raw_tcp_copy(P1_BYTES).await?;
    let mut raw_rates = Vec::new();
    for trial in 1..=TRIALS {
        let (got, dt) = raw_tcp_copy(P1_BYTES).await?;
        let r = mbps(got, dt);
        eprintln!(
            "S7A_RAW trial={trial} bytes={got} ms={:.2} MBps={r:.3}",
            dt.as_secs_f64() * 1000.0
        );
        raw_rates.push(r);
    }
    print_median("RAW", &raw_rates);

    for evbuf in [10usize, 64, 256] {
        let mut rates = Vec::new();
        for trial in 1..=TRIALS {
            let (got, dt) = p1_once(PathKind::B, evbuf).await?;
            let r = mbps(got, dt);
            eprintln!(
                "S7A_P1 path=B evbuf={evbuf} trial={trial} bytes={got} ms={:.2} MBps={r:.3}",
                dt.as_secs_f64() * 1000.0
            );
            rates.push(r);
        }
        print_median(&format!("P1 path=B evbuf={evbuf}"), &rates);
    }

    {
        let mut rates = Vec::new();
        for trial in 1..=TRIALS {
            let (got, dt) = p1_once(PathKind::A, 64).await?;
            let r = mbps(got, dt);
            eprintln!(
                "S7A_P1 path=A evbuf=64 trial={trial} bytes={got} ms={:.2} MBps={r:.3}",
                dt.as_secs_f64() * 1000.0
            );
            rates.push(r);
        }
        print_median("P1 path=A evbuf=64", &rates);
    }

    {
        let mut rates = Vec::new();
        for trial in 1..=TRIALS {
            let (total, dt, shares) = p2_once().await?;
            let r = mbps(total, dt);
            let min = *shares.iter().min().unwrap_or(&0);
            let max = *shares.iter().max().unwrap_or(&0);
            let hi_lo = if min == 0 {
                0.0
            } else {
                max as f64 / min as f64
            };
            eprintln!(
                "S7A_P2 trial={trial} streams={P2_STREAMS} each={P2_BYTES_EACH} total={total} \
                 ms={:.2} MBps={r:.3} shares={shares:?} hi_lo={hi_lo:.3}",
                dt.as_secs_f64() * 1000.0
            );
            rates.push(r);
        }
        print_median("P2", &rates);
    }

    for nodelay in [false, true] {
        let mut samples = p3_once(nodelay).await?;
        samples.sort();
        let p50 = percentile_us(&samples, 0.50);
        let p95 = percentile_us(&samples, 0.95);
        let p99 = percentile_us(&samples, 0.99);
        let label = if nodelay { "on" } else { "off" };
        eprintln!(
            "S7A_P3 nodelay={label} n={} p50_us={p50:.1} p95_us={p95:.1} p99_us={p99:.1}",
            samples.len()
        );
    }

    {
        let mut rates = Vec::new();
        for trial in 1..=TRIALS {
            let st = p4_once().await?;
            let r = mbps(st.bytes, st.dt);
            eprintln!(
                "S7A_P4 trial={trial} bytes={} ms={:.2} MBps={r:.3} kex={} \
                 pit_ms={:.1} pit_depth={:.3} min_win_MBps={:.3} med_win_MBps={:.3}",
                st.bytes,
                st.dt.as_secs_f64() * 1000.0,
                st.kex,
                st.pit.pit_ms,
                st.pit.pit_depth,
                st.pit.min_win_mbps,
                st.pit.med_win_mbps
            );
            rates.push(r);
        }
        print_median("P4", &rates);
    }

    eprintln!("S7A done");
    Ok(())
}

/// Single P1 path-B evbuf=10 transfer so `/usr/bin/time` can sample one shot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn s7a_p5_p1b10() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let (got, dt) = p1_once(PathKind::B, 10).await?;
    eprintln!(
        "S7A_P5 path=B evbuf=10 bytes={got} ms={:.2} MBps={:.3}",
        dt.as_secs_f64() * 1000.0,
        mbps(got, dt)
    );
    Ok(())
}

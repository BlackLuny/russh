//! Long-running russh client for localhost soak tests.
//!
//! Opens `direct-tcpip` channels against `s8_matrix_server` (host/port
//! encode echo/sink/source) or a real TCP destination via OpenSSH sshd.
//!
//! ```text
//! cargo run -p russh --release --example soak_client -- \
//!   --host 127.0.0.1 --port 2222 --user s8 --password s8pass \
//!   --down 2 --up 2 --echo 1 --seconds 86400 --stats /tmp/soak/russh_client.jsonl
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use russh::client;
use russh::keys::ssh_key;
use russh::{Preferred, RekeyPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{interval, sleep};

const CHUNK: usize = 32 * 1024;
const SOURCE_FILL: u8 = 0xAB;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 2222)]
    port: u16,
    #[arg(long, default_value = "s8")]
    user: String,
    #[arg(long, default_value = "s8pass")]
    password: String,
    /// Download (server→client source) channel count.
    #[arg(long, default_value_t = 2)]
    down: usize,
    /// Upload (client→server sink) channel count.
    #[arg(long, default_value_t = 2)]
    up: usize,
    /// Echo channel count (integrity-checked).
    #[arg(long, default_value_t = 1)]
    echo: usize,
    #[arg(long, default_value_t = 86400)]
    seconds: u64,
    /// Stall if no byte progress for this many seconds.
    #[arg(long, default_value_t = 60)]
    stall_secs: u64,
    /// Override client RekeyPolicy.max_bytes. 0 = default (1 TiB).
    #[arg(long, default_value_t = 0)]
    rekey_bytes: u64,
    /// JSONL stats path.
    #[arg(long)]
    stats: Option<String>,
    /// Source dest used in direct-tcpip (s8 fixture: host `source` port 1).
    #[arg(long, default_value = "source")]
    source_host: String,
    #[arg(long, default_value_t = 1)]
    source_port: u32,
    #[arg(long, default_value = "sink")]
    sink_host: String,
    #[arg(long, default_value_t = 9)]
    sink_port: u32,
    #[arg(long, default_value = "echo")]
    echo_host: String,
    #[arg(long, default_value_t = 7)]
    echo_port: u32,
    /// Open/close an extra 1 MiB echo channel this often (0 = off).
    #[arg(long, default_value_t = 30)]
    churn_secs: u64,
    /// Target bytes/sec per direction-channel (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    rate_bps: u64,
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Counters {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    channels_live: AtomicU64,
    channels_opened: AtomicU64,
    channels_closed: AtomicU64,
    verify_errors: AtomicU64,
    io_errors: AtomicU64,
    stalls: AtomicU64,
    churn_ok: AtomicU64,
    churn_fail: AtomicU64,
}

impl Counters {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            channels_live: AtomicU64::new(0),
            channels_opened: AtomicU64::new(0),
            channels_closed: AtomicU64::new(0),
            verify_errors: AtomicU64::new(0),
            io_errors: AtomicU64::new(0),
            stalls: AtomicU64::new(0),
            churn_ok: AtomicU64::new(0),
            churn_fail: AtomicU64::new(0),
        })
    }
}

fn json_line(c: &Counters, elapsed: f64, stall: bool, session_alive: bool) -> String {
    format!(
        "{{\"t\":{:.3},\"bytes_in\":{},\"bytes_out\":{},\"channels_live\":{},\"channels_opened\":{},\"channels_closed\":{},\"verify_errors\":{},\"io_errors\":{},\"stalls\":{},\"churn_ok\":{},\"churn_fail\":{},\"stall\":{},\"session_alive\":{}}}",
        elapsed,
        c.bytes_in.load(Ordering::Relaxed),
        c.bytes_out.load(Ordering::Relaxed),
        c.channels_live.load(Ordering::Relaxed),
        c.channels_opened.load(Ordering::Relaxed),
        c.channels_closed.load(Ordering::Relaxed),
        c.verify_errors.load(Ordering::Relaxed),
        c.io_errors.load(Ordering::Relaxed),
        c.stalls.load(Ordering::Relaxed),
        c.churn_ok.load(Ordering::Relaxed),
        c.churn_fail.load(Ordering::Relaxed),
        stall,
        session_alive,
    )
}

async fn maybe_rate_limit(started: Instant, sent: u64, rate_bps: u64) {
    if rate_bps == 0 {
        return;
    }
    let expected = Duration::from_secs_f64(sent as f64 / rate_bps as f64);
    let elapsed = started.elapsed();
    if expected > elapsed {
        sleep(expected - elapsed).await;
    }
}

async fn run_down(
    mut stream: russh::ChannelStream<russh::client::Msg>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    rate_bps: u64,
) {
    counters.channels_live.fetch_add(1, Ordering::Relaxed);
    counters.channels_opened.fetch_add(1, Ordering::Relaxed);
    let mut buf = vec![0u8; CHUNK];
    let started = Instant::now();
    let mut got = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match stream.read(&mut buf).await {
            Ok(0) => {
                counters.io_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Ok(n) => {
                if buf[..n].iter().any(|b| *b != SOURCE_FILL) {
                    counters.verify_errors.fetch_add(1, Ordering::Relaxed);
                }
                counters.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                got += n as u64;
                maybe_rate_limit(started, got, rate_bps).await;
            }
            Err(_) => {
                counters.io_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    counters.channels_live.fetch_sub(1, Ordering::Relaxed);
    counters.channels_closed.fetch_add(1, Ordering::Relaxed);
}

async fn run_up(
    mut stream: russh::ChannelStream<russh::client::Msg>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    rate_bps: u64,
) {
    counters.channels_live.fetch_add(1, Ordering::Relaxed);
    counters.channels_opened.fetch_add(1, Ordering::Relaxed);
    let chunk = vec![SOURCE_FILL; CHUNK];
    let started = Instant::now();
    let mut sent = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match stream.write_all(&chunk).await {
            Ok(()) => {
                counters.bytes_out.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                sent += chunk.len() as u64;
                maybe_rate_limit(started, sent, rate_bps).await;
            }
            Err(_) => {
                counters.io_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    let _ = stream.shutdown().await;
    counters.channels_live.fetch_sub(1, Ordering::Relaxed);
    counters.channels_closed.fetch_add(1, Ordering::Relaxed);
}

async fn run_echo(
    mut stream: russh::ChannelStream<russh::client::Msg>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    rate_bps: u64,
) {
    counters.channels_live.fetch_add(1, Ordering::Relaxed);
    counters.channels_opened.fetch_add(1, Ordering::Relaxed);
    let mut seq: u64 = 0;
    let started = Instant::now();
    let mut sent = 0u64;
    let mut out = vec![0u8; 8 + 1024];
    let mut inp = vec![0u8; 8 + 1024];
    while !stop.load(Ordering::Relaxed) {
        out[..8].copy_from_slice(&seq.to_le_bytes());
        out[8] = (seq & 0xff) as u8;
        if stream.write_all(&out).await.is_err() {
            counters.io_errors.fetch_add(1, Ordering::Relaxed);
            break;
        }
        counters.bytes_out.fetch_add(out.len() as u64, Ordering::Relaxed);
        sent += out.len() as u64;
        let mut filled = 0;
        while filled < out.len() {
            match stream.read(&mut inp[filled..]).await {
                Ok(0) | Err(_) => {
                    counters.io_errors.fetch_add(1, Ordering::Relaxed);
                    counters.channels_live.fetch_sub(1, Ordering::Relaxed);
                    counters.channels_closed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Ok(n) => filled += n,
            }
        }
        counters.bytes_in.fetch_add(out.len() as u64, Ordering::Relaxed);
        if inp[..8] != out[..8] || inp[8] != out[8] {
            counters.verify_errors.fetch_add(1, Ordering::Relaxed);
        }
        seq = seq.wrapping_add(1);
        maybe_rate_limit(started, sent, rate_bps).await;
    }
    let _ = stream.shutdown().await;
    counters.channels_live.fetch_sub(1, Ordering::Relaxed);
    counters.channels_closed.fetch_add(1, Ordering::Relaxed);
}

async fn open_stream(
    handle: &russh::client::Handle<ClientHandler>,
    host: &str,
    port: u32,
) -> Result<russh::ChannelStream<russh::client::Msg>, russh::Error> {
    let ch = handle
        .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
        .await?;
    Ok(ch.into_stream())
}

async fn churn_once(
    handle: &russh::client::Handle<ClientHandler>,
    args: &Args,
    counters: &Counters,
) {
    match handle
        .channel_open_direct_tcpip(&args.echo_host, args.echo_port, "127.0.0.1", 0)
        .await
    {
        Ok(ch) => {
            let mut stream = ch.into_stream();
            let payload = vec![0x5A; 1024];
            let mut remaining = 1024 * 1024;
            let mut ok = true;
            while remaining > 0 {
                if stream.write_all(&payload).await.is_err() {
                    ok = false;
                    break;
                }
                let mut got = 0;
                while got < payload.len() {
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf[got..]).await {
                        Ok(0) | Err(_) => {
                            ok = false;
                            break;
                        }
                        Ok(n) => got += n,
                    }
                }
                if !ok {
                    break;
                }
                remaining -= payload.len();
            }
            let _ = stream.shutdown().await;
            if ok {
                counters.churn_ok.fetch_add(1, Ordering::Relaxed);
            } else {
                counters.churn_fail.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(_) => {
            counters.churn_fail.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut limits = RekeyPolicy::default();
    if args.rekey_bytes > 0 {
        limits.max_bytes = args.rekey_bytes;
    }
    let config = Arc::new(client::Config {
        nodelay: true,
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 6,
        limits,
        preferred: Preferred::default(),
        ..Default::default()
    });

    let mut session = client::connect(
        config,
        (args.host.as_str(), args.port),
        ClientHandler,
    )
    .await?;
    let authed = session
        .authenticate_password(&args.user, &args.password)
        .await?
        .success();
    if !authed {
        return Err("password auth failed".into());
    }

    let counters = Counters::new();
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();

    for _ in 0..args.down {
        let stream = open_stream(&session, &args.source_host, args.source_port).await?;
        let c = counters.clone();
        let s = stop.clone();
        let rate = args.rate_bps;
        tasks.push(tokio::spawn(async move {
            run_down(stream, c, s, rate).await;
        }));
    }
    for _ in 0..args.up {
        let stream = open_stream(&session, &args.sink_host, args.sink_port).await?;
        let c = counters.clone();
        let s = stop.clone();
        let rate = args.rate_bps;
        tasks.push(tokio::spawn(async move {
            run_up(stream, c, s, rate).await;
        }));
    }
    for _ in 0..args.echo {
        let stream = open_stream(&session, &args.echo_host, args.echo_port).await?;
        let c = counters.clone();
        let s = stop.clone();
        let rate = args.rate_bps;
        tasks.push(tokio::spawn(async move {
            run_echo(stream, c, s, rate).await;
        }));
    }

    let stats_path = args.stats.clone();
    if let Some(path) = stats_path.as_deref() {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
    }

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(args.seconds);
    let mut tick = interval(Duration::from_secs(1));
    let mut last_in = 0u64;
    let mut last_out = 0u64;
    let mut last_progress = Instant::now();
    let mut saw_stall = false;

    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        tick.tick().await;
        if args.churn_secs > 0 && t0.elapsed().as_secs() > 0 && t0.elapsed().as_secs() % args.churn_secs == 0
        {
            churn_once(&session, &args, &counters).await;
        }
        let bin = counters.bytes_in.load(Ordering::Relaxed);
        let bout = counters.bytes_out.load(Ordering::Relaxed);
        if bin > last_in || bout > last_out {
            last_in = bin;
            last_out = bout;
            last_progress = Instant::now();
        }
        let stall = last_progress.elapsed() >= Duration::from_secs(args.stall_secs);
        if stall && !saw_stall {
            counters.stalls.fetch_add(1, Ordering::Relaxed);
            saw_stall = true;
            eprintln!("SOAK_STALL detected after {:.1}s", t0.elapsed().as_secs_f64());
        }
        if !stall {
            saw_stall = false;
        }
        let live = !session.is_closed();
        let line = json_line(&counters, t0.elapsed().as_secs_f64(), stall, live);
        println!("{line}");
        if let Some(path) = stats_path.as_deref() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
        if stall || !live || counters.verify_errors.load(Ordering::Relaxed) > 0 {
            if !live || counters.verify_errors.load(Ordering::Relaxed) > 0 {
                break;
            }
        }
        let finished = tasks.iter().all(|t| t.is_finished());
        if finished && Instant::now() < deadline {
            eprintln!("SOAK_CHANNELS_DIED before duration elapsed");
            counters.io_errors.fetch_add(1, Ordering::Relaxed);
            break;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "soak done", "en")
        .await;
    for t in tasks {
        let _ = t.await;
    }

    let final_line = json_line(&counters, t0.elapsed().as_secs_f64(), saw_stall, false);
    eprintln!("SOAK_CLIENT_SUMMARY {final_line}");
    let fail = counters.verify_errors.load(Ordering::Relaxed) > 0
        || counters.stalls.load(Ordering::Relaxed) > 0
        || counters.io_errors.load(Ordering::Relaxed) > 0;
    if fail {
        std::process::exit(2);
    }
    Ok(())
}

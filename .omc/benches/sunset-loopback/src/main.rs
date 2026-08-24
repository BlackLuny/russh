//! Sunset loopback multi-channel bulk + reliability bench.
//!
//! Sunset has no TCP forwarding (direct-tcpip is rejected in core), so the
//! data-plane analogue is session-channel bulk. Isolation is tested with one
//! frozen reader + one healthy drain on the same connection.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use embedded_io_async::{Read as ERead, Write as EWrite};
use sunset::{ChanHandle, KeyType, SignKey};
use sunset_async::{ProgressHolder, SSHClient, SSHServer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHUNK: usize = 32 * 1024;
const STALL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scenario {
    SessionDown1ch,
    SessionDown4ch,
    SlowFast,
    Churn,
    DirectTcpipReject,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    scenario: Scenario,
    #[arg(long, default_value_t = 16)]
    mib: u64,
}

#[derive(Clone, Copy)]
enum Kind {
    Down,
    SlowFast,
    Churn,
    RejectTcp,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (channels, kind) = match args.scenario {
        Scenario::SessionDown1ch => (1usize, Kind::Down),
        Scenario::SessionDown4ch => (4, Kind::Down),
        Scenario::SlowFast => (2, Kind::SlowFast),
        Scenario::Churn => (1, Kind::Churn),
        Scenario::DirectTcpipReject => (1, Kind::RejectTcp),
    };
    let per_channel = args.mib * 1024 * 1024;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                if let Err(e) = run_server(sock, kind, per_channel).await {
                    eprintln!("sunset server session: {e:#}");
                }
            });
        }
    });

    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let rss0 = rss_bytes();
    let cpu0 = process_cpu_secs();
    let t0 = Instant::now();
    let result = run_client(addr, kind, channels, per_channel).await;
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
        "impl=sunset scenario={:?} channels={channels} bytes={bytes} wall_s={wall:.4} mib_s={mib_s:.1} cpu_s={cpu:.4} cpu_s_per_gib={cpu_s_per_gib:.3} rss_peak_mib={:.2} ok={ok} notes={note}",
        args.scenario,
        rss1 as f64 / (1024.0 * 1024.0),
    );
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_server(mut sock: TcpStream, kind: Kind, per_channel: u64) -> Result<()> {
    let _ = sock.set_nodelay(true);
    let (mut rsock, mut wsock) = sock.split();
    let hostkey = SignKey::generate(KeyType::Ed25519, None)?;
    let serv: &'static SSHServer = Box::leak(Box::new(SSHServer::new_owned()));
    let (ch_tx, mut ch_rx) = mpsc::unbounded_channel::<ChanHandle>();
    let mut pending: std::collections::HashMap<u32, ChanHandle> =
        std::collections::HashMap::new();

    let run = serv.run_tokio(&mut rsock, &mut wsock);

    let events = async move {
        loop {
            let mut ph = ProgressHolder::new();
            let ev = serv.progress(&mut ph).await?;
            match ev {
                sunset::ServEvent::Hostkeys(h) => {
                    h.hostkeys(&[&hostkey])?;
                }
                sunset::ServEvent::FirstAuth(a) => {
                    a.allow()?;
                }
                sunset::ServEvent::OpenSession(a) => {
                    let ch = a.accept()?;
                    pending.insert(ch.num().0, ch);
                }
                sunset::ServEvent::SessionExec(a) => {
                    let num = a.channel().0;
                    a.succeed()?;
                    if let Some(ch) = pending.remove(&num) {
                        let _ = ch_tx.send(ch);
                    }
                }
                sunset::ServEvent::SessionShell(a) => {
                    let num = a.channel().0;
                    a.succeed()?;
                    if let Some(ch) = pending.remove(&num) {
                        let _ = ch_tx.send(ch);
                    }
                }
                sunset::ServEvent::SessionPty(a) => {
                    a.succeed()?;
                }
                sunset::ServEvent::Defunct => break,
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let io_loop = async move {
        while let Some(ch) = ch_rx.recv().await {
            let mut stdio = serv.stdio(ch).await?;
            tokio::spawn(async move {
                match kind {
                    Kind::RejectTcp => {}
                    Kind::Down | Kind::SlowFast | Kind::Churn => {
                        let _ = flood_stdio(&mut stdio, per_channel).await;
                    }
                }
            });
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = run => { r.context("sunset server run")?; }
        r = events => { r?; }
        r = io_loop => { r?; }
    }
    Ok(())
}

async fn flood_stdio(io: &mut sunset_async::ChanInOut<'_>, bytes: u64) -> Result<()> {
    let buf = vec![0xABu8; CHUNK];
    let mut left = bytes;
    while left > 0 {
        let n = (left as usize).min(buf.len());
        let mut off = 0;
        while off < n {
            let w = timeout(STALL, io.write(&buf[off..n]))
                .await
                .context("sunset server write stall")??;
            if w == 0 {
                bail!("sunset write returned 0");
            }
            off += w;
        }
        left -= n as u64;
    }
    Ok(())
}

async fn run_client(
    addr: std::net::SocketAddr,
    kind: Kind,
    channels: usize,
    per_channel: u64,
) -> Result<u64> {
    if matches!(kind, Kind::RejectTcp) {
        return client_direct_tcpip_expect_reject(addr).await;
    }

    let mut sock = TcpStream::connect(addr).await?;
    let _ = sock.set_nodelay(true);
    let (mut rsock, mut wsock) = sock.split();
    let cli: &'static SSHClient = Box::leak(Box::new(SSHClient::new_owned()));
    let run = cli.run_tokio(&mut rsock, &mut wsock);
    let (io_tx, mut io_rx) = mpsc::unbounded_channel::<sunset_async::ChanInOut<'static>>();

    let events = async move {
        let mut pending_io = std::collections::HashMap::<u32, sunset_async::ChanInOut<'static>>::new();
        loop {
            let mut ph = ProgressHolder::new();
            let ev = cli.progress(&mut ph).await?;
            match ev {
                sunset::CliEvent::Hostkey(h) => h.accept()?,
                sunset::CliEvent::Username(u) => u.username("bench")?,
                sunset::CliEvent::Password(p) => p.skip()?,
                sunset::CliEvent::Pubkey(p) => p.skip()?,
                sunset::CliEvent::Authenticated => {
                    drop(ph);
                    for _ in 0..channels {
                        let (io, stderr) = cli.open_session_nopty().await?;
                        drop(stderr);
                        pending_io.insert(io.num().0, io);
                    }
                }
                sunset::CliEvent::SessionOpened(mut opener) => {
                    let num = opener.channel().0;
                    opener.exec("flood")?;
                    if let Some(io) = pending_io.remove(&num) {
                        let _ = io_tx.send(io);
                    }
                }
                sunset::CliEvent::Defunct => break,
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let work = async move {
        let mut opened = Vec::new();
        while opened.len() < channels {
            match timeout(STALL, io_rx.recv()).await {
                Ok(Some(io)) => opened.push(io),
                Ok(None) => bail!("channel tx closed before all sessions opened"),
                Err(_) => bail!("timeout waiting to open sunset sessions"),
            }
        }
        match kind {
            Kind::Down => {
                let mut joins = Vec::new();
                for mut io in opened {
                    joins.push(tokio::spawn(async move {
                        drain_stdio(&mut io, Some(per_channel)).await
                    }));
                }
                let mut total = 0u64;
                for j in joins {
                    total += j.await??;
                }
                Ok(total)
            }
            Kind::SlowFast => {
                let mut it = opened.into_iter();
                let frozen = it.next().context("no frozen ch")?;
                let mut healthy = it.next().context("no healthy ch")?;
                tokio::spawn(async move {
                    let _f = frozen;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
                drain_stdio(&mut healthy, Some(per_channel)).await
            }
            Kind::Churn => {
                let mut bulk = opened.into_iter().next().context("no bulk ch")?;
                let drain =
                    tokio::spawn(async move { drain_stdio(&mut bulk, Some(per_channel)).await });
                for i in 0..3u32 {
                    let (extra, stderr) = cli.open_session_nopty().await?;
                    drop(stderr);
                    if i % 2 == 0 {
                        drop(extra);
                    } else {
                        let _ = extra.until_closed().await;
                    }
                    let _ = i;
                }
                drain.await?
            }
            Kind::RejectTcp => unreachable!(),
        }
    };

    tokio::select! {
        r = run => {
            r.context("sunset client run")?;
            bail!("sunset client run exited first");
        }
        r = events => {
            r?;
            bail!("sunset client events exited first");
        }
        r = work => r,
    }
}

async fn drain_stdio(
    io: &mut sunset_async::ChanInOut<'_>,
    expect: Option<u64>,
) -> Result<u64> {
    let mut buf = [0u8; 4096];
    let mut got = 0u64;
    loop {
        let n = timeout(STALL, io.read(&mut buf))
            .await
            .context("sunset drain stall (no progress for 5s)")??;
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

async fn client_direct_tcpip_expect_reject(addr: std::net::SocketAddr) -> Result<u64> {
    // Sunset core rejects ChannelOpenType::DirectTcpip before the app sees it.
    // Opening a session and recording that the protocol has no forwarding API
    // is the observable outcome: we fail closed with a documented note.
    let mut sock = TcpStream::connect(addr).await?;
    let _ = sock.set_nodelay(true);
    let (mut rsock, mut wsock) = sock.split();
    let cli = SSHClient::new_owned();
    let run = cli.run_tokio(&mut rsock, &mut wsock);
    let probe = async {
        loop {
            let mut ph = ProgressHolder::new();
            let ev = cli.progress(&mut ph).await?;
            match ev {
                sunset::CliEvent::Hostkey(h) => h.accept()?,
                sunset::CliEvent::Username(u) => u.username("bench")?,
                sunset::CliEvent::Password(p) => p.skip()?,
                sunset::CliEvent::Pubkey(p) => p.skip()?,
                sunset::CliEvent::Authenticated => {
                    drop(ph);
                    // There is no open_direct_tcpip on SSHClient. Treat that as the result.
                    bail!("direct-tcpip API absent (core also rejects ChannelOpenType::DirectTcpip)");
                }
                sunset::CliEvent::Defunct => bail!("defunct"),
                _ => {}
            }
        }
        #[allow(unreachable_code)]
        Ok::<u64, anyhow::Error>(0)
    };
    tokio::select! {
        r = run => {
            r.ok();
            bail!("direct-tcpip API absent (core also rejects ChannelOpenType::DirectTcpip)");
        }
        r = probe => r,
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

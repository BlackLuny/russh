//! 测试夹具,非 API 用法示例.
//!
//! S8a real-client matrix fixture: password auth, session placeholder,
//! `direct-tcpip` echo/sink/source. Mirrors zfc inbound shape (reject
//! exec/shell/sftp). Default `RekeyPolicy` / `Preferred`; knobs via CLI.
//!
//! `required-features=["_test_hooks"]` keeps this binary out of the default
//! `cargo build --examples` surface and marks it as not a user example.
//! The fixture itself uses only ungated public `Config` fields.
//!
//! `tcpip_forward` 接受(与 zfc 拒绝不同)仅为 `-R` 冒烟所需.
//!
//! Build: `cargo run -p russh --example s8_matrix_server --features _test_hooks`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use russh::keys::ssh_key;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, RekeyPolicy, SshId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

const USER_DEFAULT: &str = "s8";
const PASS_DEFAULT: &str = "s8pass";
const SOURCE_FILL: u8 = 0xAB;
const SOURCE_CHUNK: usize = 16 * 1024;

#[derive(Parser, Debug)]
#[command(about = "S8a matrix fixture (not an API usage example)")]
struct Args {
    /// SSH listen address. Port 0 = ephemeral.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// Control HTTP listen address. Port 0 = ephemeral.
    #[arg(long, default_value = "127.0.0.1:0")]
    control: String,
    #[arg(long, default_value = USER_DEFAULT)]
    user: String,
    #[arg(long, default_value = PASS_DEFAULT)]
    password: String,
    /// Override `RekeyPolicy.max_packets` (I5 hard bound). Omit = Default 2^31.
    #[arg(long)]
    max_packets: Option<u64>,
    /// Override `RekeyPolicy.max_bytes`. Omit = Default 1 TiB.
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Enable write_min_drain as `BYTES,SECS` (e.g. 4096,30). Omit = Default None.
    #[arg(long)]
    write_min_drain: Option<String>,
    /// Path written with S8_LISTEN / S8_CONTROL once both sockets are bound.
    #[arg(long)]
    ready_file: Option<String>,
    #[arg(long, default_value_t = false)]
    nodelay: bool,
    /// Override handshake deadline seconds (Default 30).
    #[arg(long)]
    handshake_deadline_secs: Option<u64>,
    /// OpenSSH public key file. When set, only this key is accepted.
    /// When omitted, publickey is rejected (password cells do not use it).
    #[arg(long)]
    authorized_key: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum TcpMode {
    Echo,
    Sink,
    Source,
    SourceRand,
}

fn tcp_mode(host: &str, port: u32) -> TcpMode {
    let h = host.to_ascii_lowercase();
    if h.contains("source-rand") || port == 2 {
        TcpMode::SourceRand
    } else if h.contains("source") || port == 1 {
        TcpMode::Source
    } else if h.contains("sink") || port == 9 {
        TcpMode::Sink
    } else {
        TcpMode::Echo
    }
}

fn fill_xorshift(buf: &mut [u8], state: &mut u64) {
    let mut i = 0;
    while i < buf.len() {
        *state ^= state.wrapping_shl(13);
        *state ^= state.wrapping_shr(7);
        *state ^= state.wrapping_shl(17);
        let bytes = state.to_le_bytes();
        let n = (buf.len() - i).min(8);
        buf[i..i + n].copy_from_slice(&bytes[..n]);
        i += n;
    }
}

fn load_authorized(path: &str) -> Result<ssh_key::PublicKey, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(ssh_key::PublicKey::from_openssh(text.trim())?)
}

fn key_matches(expected: &ssh_key::PublicKey, offered: &ssh_key::PublicKey) -> bool {
    expected.fingerprint(ssh_key::HashAlg::Sha256)
        == offered.fingerprint(ssh_key::HashAlg::Sha256)
}

struct Stats {
    sessions: AtomicUsize,
    channels: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    auth_ok: AtomicU64,
    auth_fail: AtomicU64,
    disconnects: AtomicU64,
    i6: Arc<russh::server::RekeyI6>,
}

impl Stats {
    fn json(&self) -> String {
        format!(
            "{{\"ok\":true,\"sessions\":{},\"channels\":{},\"bytes_in\":{},\"bytes_out\":{},\"auth_ok\":{},\"auth_fail\":{},\"disconnects\":{},\"rekey_triggers\":{},\"rekey_merges\":{},\"rekey_idle_drops\":{}}}",
            self.sessions.load(Ordering::SeqCst),
            self.channels.load(Ordering::SeqCst),
            self.bytes_in.load(Ordering::SeqCst),
            self.bytes_out.load(Ordering::SeqCst),
            self.auth_ok.load(Ordering::SeqCst),
            self.auth_fail.load(Ordering::SeqCst),
            self.disconnects.load(Ordering::SeqCst),
            self.i6.triggers(),
            self.i6.merges(),
            self.i6.idle_drops(),
        )
    }
}

#[derive(Clone)]
struct Shared {
    user: String,
    password: String,
    stats: Arc<Stats>,
    authorized: Option<ssh_key::PublicKey>,
}

#[derive(Clone)]
struct S8Server {
    shared: Shared,
}

struct S8Handler {
    shared: Shared,
    authed: bool,
}

impl russh::server::Server for S8Server {
    type Handler = S8Handler;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Self::Handler {
        self.shared.stats.sessions.fetch_add(1, Ordering::SeqCst);
        S8Handler {
            shared: self.shared.clone(),
            authed: false,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        self.shared.stats.disconnects.fetch_add(1, Ordering::SeqCst);
        eprintln!("S8_SESSION_ERROR {error:?}");
    }
}

impl Drop for S8Handler {
    fn drop(&mut self) {
        self.shared.stats.sessions.fetch_sub(1, Ordering::SeqCst);
    }
}

impl russh::server::Handler for S8Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.shared.user && password == self.shared.password {
            self.authed = true;
            self.shared.stats.auth_ok.fetch_add(1, Ordering::SeqCst);
            Ok(Auth::Accept)
        } else {
            self.shared.stats.auth_fail.fetch_add(1, Ordering::SeqCst);
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if let Some(expected) = self.shared.authorized.as_ref() {
            if key_matches(expected, key) {
                self.authed = true;
                self.shared.stats.auth_ok.fetch_add(1, Ordering::SeqCst);
                return Ok(Auth::Accept);
            }
        }
        self.shared.stats.auth_fail.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await?;
        track_idle(channel, self.shared.stats.clone());
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mode = tcp_mode(host_to_connect, port_to_connect);
        reply.accept().await?;
        spawn_tcpip(channel, mode, self.shared.stats.clone());
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await?;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if *port == 0 {
            *port = 22000;
        }
        let handle = session.handle();
        let address = address.to_string();
        let bound = *port;
        tokio::spawn(async move {
            match handle
                .channel_open_forwarded_tcpip(address, bound, "127.0.0.1", 1)
                .await
            {
                Ok(ch) => {
                    let _ = ch.data_bytes(&b"S8-R-OK\n"[..]).await;
                    let _ = ch.eof().await;
                }
                Err(e) => eprintln!("S8_R_OPEN_FAIL {e:?}"),
            }
        });
        Ok(true)
    }
}

fn track_idle(channel: Channel<Msg>, stats: Arc<Stats>) {
    stats.channels.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let mut ch = channel;
        let mut reader = ch.make_reader();
        let mut buf = [0u8; 256];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        stats.channels.fetch_sub(1, Ordering::SeqCst);
    });
}

fn spawn_tcpip(channel: Channel<Msg>, mode: TcpMode, stats: Arc<Stats>) {
    stats.channels.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        run_tcpip(channel, mode, &stats).await;
        stats.channels.fetch_sub(1, Ordering::SeqCst);
    });
}

async fn run_tcpip(mut channel: Channel<Msg>, mode: TcpMode, stats: &Stats) {
    match mode {
        TcpMode::Echo => {
            let mut writer = channel.make_writer();
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                        if writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }
            let _ = writer.shutdown().await;
        }
        TcpMode::Sink => {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }
        }
        TcpMode::Source => {
            let mut writer = channel.make_writer();
            let chunk = vec![SOURCE_FILL; SOURCE_CHUNK];
            loop {
                if writer.write_all(&chunk).await.is_err() {
                    break;
                }
                stats.bytes_out.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
        }
        TcpMode::SourceRand => {
            let mut writer = channel.make_writer();
            let mut chunk = vec![0u8; SOURCE_CHUNK];
            let mut rng = 0xC0FFEE_u64.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            loop {
                fill_xorshift(&mut chunk, &mut rng);
                if writer.write_all(&chunk).await.is_err() {
                    break;
                }
                stats.bytes_out.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

fn parse_min_drain(s: &str) -> Result<(usize, Duration), String> {
    let (bytes, secs) = s.split_once(',').ok_or_else(|| {
        format!("write_min_drain expected BYTES,SECS (got {s})")
    })?;
    let n: usize = bytes
        .trim()
        .parse()
        .map_err(|_| format!("bad write_min_drain bytes: {bytes}"))?;
    let secs = secs.trim().trim_end_matches('s');
    let sec: u64 = secs
        .parse()
        .map_err(|_| format!("bad write_min_drain secs: {secs}"))?;
    Ok((n, Duration::from_secs(sec)))
}

async fn serve_control(
    listener: TcpListener,
    stats: Arc<Stats>,
    mut stop: broadcast::Receiver<()>,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            acc = listener.accept() => {
                let Ok((mut sock, _)) = acc else { continue };
                let stats = stats.clone();
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().unwrap_or("");
                    if path.contains("/shutdown") {
                        let body = b"bye\n";
                        let hdr = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(hdr.as_bytes()).await;
                        let _ = sock.write_all(body).await;
                        let _ = shutdown_tx.send(()).await;
                        return;
                    }
                    let body = stats.json();
                    let hdr = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(hdr.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if std::env::var_os("RUST_LOG").is_some() {
        env_logger::init();
    }

    let i6 = russh::server::RekeyI6::new();
    let stats = Arc::new(Stats {
        sessions: AtomicUsize::new(0),
        channels: AtomicUsize::new(0),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        auth_ok: AtomicU64::new(0),
        auth_fail: AtomicU64::new(0),
        disconnects: AtomicU64::new(0),
        i6: i6.clone(),
    });

    let mut limits = RekeyPolicy::default();
    if let Some(p) = args.max_packets {
        limits.max_packets = p;
    }
    if let Some(b) = args.max_bytes {
        limits.max_bytes = b;
    }
    let write_min_drain = match args.write_min_drain.as_deref() {
        Some(s) => Some(parse_min_drain(s)?),
        None => None,
    };
    let authorized = match args.authorized_key.as_deref() {
        Some(path) => Some(load_authorized(path)?),
        None => None,
    };

    let config = russh::server::Config {
        server_id: SshId::Standard("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5".into()),
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_millis(200),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )?],
        limits,
        preferred: Preferred::default(),
        inactivity_timeout: None,
        nodelay: args.nodelay,
        write_min_drain,
        handshake_deadline: args
            .handshake_deadline_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30)),
        rekey_i6: i6,
        ..Default::default()
    };

    let ssh_listener = TcpListener::bind(&args.listen).await?;
    let ssh_addr = ssh_listener.local_addr()?;
    let ctrl_listener = TcpListener::bind(&args.control).await?;
    let ctrl_addr = ctrl_listener.local_addr()?;

    println!("S8_LISTEN={ssh_addr}");
    println!("S8_CONTROL={ctrl_addr}");
    println!("S8_READY");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    if let Some(path) = args.ready_file.as_deref() {
        std::fs::write(
            path,
            format!("S8_LISTEN={ssh_addr}\nS8_CONTROL={ctrl_addr}\nS8_READY\n"),
        )?;
    }

    let (stop_tx, stop_rx) = broadcast::channel::<()>(1);
    let (die_tx, mut die_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(serve_control(
        ctrl_listener,
        stats.clone(),
        stop_rx,
        die_tx,
    ));

    let mut server = S8Server {
        shared: Shared {
            user: args.user,
            password: args.password,
            stats: stats.clone(),
            authorized,
        },
    };
    let running = server.run_on_socket(Arc::new(config), &ssh_listener);
    let handle = running.handle();

    tokio::select! {
        _ = die_rx.recv() => {}
        res = running => {
            if let Err(e) = res {
                eprintln!("S8_SERVER_ERR {e}");
            }
        }
    }
    handle.shutdown("s8 fixture stop".into());
    let _ = stop_tx.send(());
    println!("S8_SUMMARY {}", stats.json());
    Ok(())
}

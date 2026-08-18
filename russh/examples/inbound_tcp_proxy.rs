//! Pure SSH inbound TCP proxy for OpenSSH `ssh -L` / `direct-tcpip`.
//!
//! Accepts any public-key auth, then bidi-copies each `direct-tcpip` channel
//! against a real TCP connection to the requested destination (loopback echo
//! in the soak harness). Defaults match `russh::server::Config` except:
//! - a generated host key
//! - `inactivity_timeout = None` so a 2h soak is not killed by the 10-minute
//!   default if the control channel is quiet under `-N`
//! - optional keepalive (OpenSSH `ServerAliveInterval` is also used client-side)
//!
//! Usage:
//!   cargo run -p russh --example inbound_tcp_proxy -- --bind 127.0.0.1:0 --port-file /tmp/proxy.port

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::Parser;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
struct Cli {
    /// Bind address for the SSH proxy (use port 0 to pick a free port).
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    /// Write the bound `host:port` here so the soak script can discover it.
    #[arg(long)]
    port_file: Option<PathBuf>,
    /// TCP nodelay on accepted SSH sockets.
    #[arg(long, default_value_t = true)]
    nodelay: bool,
    /// Server keepalive interval in seconds (0 = disabled).
    #[arg(long, default_value_t = 60)]
    keepalive_secs: u64,
    /// Override channel buffer size (0 = library default).
    #[arg(long, default_value_t = 0)]
    channel_buffer_size: usize,
    /// Override event buffer size (0 = library default of 10).
    #[arg(long, default_value_t = 0)]
    event_buffer_size: usize,
}

#[derive(Clone, Default)]
struct ProxyServer {
    channels_opened: Arc<AtomicU64>,
    bytes_relayed: Arc<AtomicU64>,
}

impl russh::server::Server for ProxyServer {
    type Handler = ProxyHandler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Self::Handler {
        eprintln!("ssh client connected from {peer:?}");
        ProxyHandler {
            channels_opened: self.channels_opened.clone(),
            bytes_relayed: self.bytes_relayed.clone(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("ssh session error: {error:#}");
    }
}

struct ProxyHandler {
    channels_opened: Arc<AtomicU64>,
    bytes_relayed: Arc<AtomicU64>,
}

impl russh::server::Handler for ProxyHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        eprintln!("auth_publickey user={user} -> accept");
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        eprintln!("auth_password user={user} -> accept");
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // OpenSSH `ssh -N` usually skips a session channel; accept anyway.
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let dest = format!("{host_to_connect}:{port_to_connect}");
        let n = self.channels_opened.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!(
            "direct-tcpip #{n} {originator_address}:{originator_port} -> {dest} chan={:?}",
            channel.id()
        );

        match TcpStream::connect((host_to_connect, port_to_connect as u16)).await {
            Ok(tcp) => {
                reply.accept().await;
                let bytes_relayed = self.bytes_relayed.clone();
                tokio::spawn(async move {
                    if let Err(e) = tcp.set_nodelay(true) {
                        eprintln!("upstream nodelay failed: {e}");
                    }
                    let mut ssh = channel.into_stream();
                    let mut tcp = tcp;
                    match tokio::io::copy_bidirectional(&mut ssh, &mut tcp).await {
                        Ok((a, b)) => {
                            bytes_relayed.fetch_add(a.saturating_add(b), Ordering::Relaxed);
                            eprintln!(
                                "direct-tcpip closed dest={dest} ssh->tcp={a} tcp->ssh={b}"
                            );
                        }
                        Err(e) => {
                            eprintln!("direct-tcpip copy error dest={dest}: {e}");
                        }
                    }
                    let _ = tcp.shutdown().await;
                });
            }
            Err(e) => {
                eprintln!("direct-tcpip connect {dest} failed: {e}");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();
    let mut config = russh::server::Config::default();
    config.keys = vec![
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap(),
    ];
    config.inactivity_timeout = None;
    config.auth_rejection_time_initial = Some(Duration::from_secs(0));
    config.nodelay = cli.nodelay;
    if cli.keepalive_secs > 0 {
        config.keepalive_interval = Some(Duration::from_secs(cli.keepalive_secs));
        config.keepalive_max = 3;
    }
    if cli.channel_buffer_size > 0 {
        config.channel_buffer_size = cli.channel_buffer_size;
    }
    if cli.event_buffer_size > 0 {
        config.event_buffer_size = cli.event_buffer_size;
    }
    // Keep library default rekey bounds (1 GiB / 1 h) so the 2h soak exercises
    // at least one time-based rekey on main's production settings.
    let config = Arc::new(config);

    let listener = TcpListener::bind(&cli.bind).await?;
    let bound = listener.local_addr()?;
    eprintln!("inbound_tcp_proxy listening on {bound}");
    if let Some(path) = &cli.port_file {
        std::fs::write(path, bound.to_string())?;
    }

    let mut server = ProxyServer::default();
    server.run_on_socket(config, &listener).await?;
    Ok(())
}

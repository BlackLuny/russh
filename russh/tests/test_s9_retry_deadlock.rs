//! S9 P2 regression gate: `retry_pending_outbound` / `flush_apply` deadlock.
//!
//! `flush_apply` refuses to drain `enc.write` while `pending_outbound` is
//! non-empty (parked commands must reach the Writer first). The retry path
//! used to gate each parked command on `sealed_backlog_bytes()`, which
//! already counts that command's bytes **and** the un-submitted `enc.write`
//! weight that only `flush_apply` can reduce. Once `enc.write` alone reached
//! `OUTBOUND_HIGH_WATERMARK + one packet`, the two blocked each other for
//! good: the session stopped iterating, the Writer went idle with the
//! peer's KEXINIT still sitting in `enc.write`, and the connection wedged
//! until the rekey deadline killed it.
//!
//! Reachable with enough concurrent bulk channels — this is `zfc`'s shape,
//! not a synthetic corner. On `origin/main` (single session loop) the same
//! scenario completes in ~3 s.
//!
//! Production: the transfer completes. Invert `invert_retry_global_hwm`:
//! it wedges (must-red carrier).
//!
//! cargo test -p russh --features _test_hooks --test test_s9_retry_deadlock -- --test-threads=1

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

/// Enough concurrent producers that the aggregate `enc.write` backlog
/// crosses the hard cap while a volume rekey is in flight. Four does not
/// reach it at credit 1; eight does.
const NUM_CHANNELS: usize = 8;
const BYTES_PER_CHANNEL: u64 = 2 * 1024 * 1024;
const FILL: u8 = 0xC3;
const REKEY_WRITE_LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Completed,
    Wedged { got: u64 },
    Connection,
}

async fn run(invert: bool, deadline: Duration) -> Result<Class, anyhow::Error> {
    let server_addr = free_addr();
    tokio::spawn(Server { invert }.serve(server_addr));
    while TcpStream::connect(server_addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        window_size: 64 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 4,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut session = match russh::client::connect(config, server_addr, Client).await {
        Ok(s) => s,
        Err(_) => return Ok(Class::Connection),
    };
    let hash = match session.best_supported_rsa_hash().await {
        Ok(h) => h.flatten(),
        Err(_) => return Ok(Class::Connection),
    };
    match session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, hash))
        .await
        .map(|x| x.success())
    {
        Ok(true) => {}
        _ => return Ok(Class::Connection),
    }

    let received = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for _ in 0..NUM_CHANNELS {
        // A wedged session stops answering CHANNEL_OPEN; that is the wedge
        // showing up early, not a setup failure.
        let mut channel = match session.channel_open_session().await {
            Ok(c) => c,
            Err(_) => {
                return Ok(Class::Wedged {
                    got: received.load(Ordering::Relaxed),
                });
            }
        };
        let received = received.clone();
        readers.push(tokio::spawn(async move {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 16 * 1024];
            let mut got: u64 = 0;
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n as u64;
                        received.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                if got >= BYTES_PER_CHANNEL {
                    break;
                }
            }
            got
        }));
    }

    // Client-forced re-exchanges on top of the server's volume rekeys. The
    // readers are already independent tasks, so the transfer is saturated
    // while these fire.
    for _ in 0..3 {
        sleep(Duration::from_millis(500)).await;
        let _ = session.rekey_soon().await;
    }

    let want = BYTES_PER_CHANNEL * NUM_CHANNELS as u64;
    let all = async {
        let mut total = 0u64;
        for r in readers {
            total += r.await.unwrap_or(0);
        }
        total
    };
    let class = match timeout(deadline, all).await {
        Ok(total) if total == want => Class::Completed,
        Ok(total) => Class::Wedged { got: total },
        Err(_) => Class::Wedged {
            got: received.load(Ordering::Relaxed),
        },
    };
    eprintln!("s9 retry-deadlock invert={invert} class={class:?}");
    Ok(class)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manychannel_rekey_completes() -> Result<(), anyhow::Error> {
    match run(false, Duration::from_secs(40)).await? {
        Class::Completed => Ok(()),
        other => anyhow::bail!("production must complete, got {other:?}"),
    }
}

/// Must-red carrier. The invert wedges permanently; a short deadline keeps
/// the evidence cheap.
#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_hwm_gate_invert_wedges() -> Result<(), anyhow::Error> {
    match run(true, Duration::from_secs(15)).await? {
        Class::Wedged { .. } => Ok(()),
        other => anyhow::bail!("invert must wedge, got {other:?}"),
    }
}

fn free_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct Server {
    invert: bool,
}

impl Server {
    async fn serve(self, addr: SocketAddr) {
        let config = server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: 64 * 1024,
            maximum_packet_size: 32 * 1024,
            channel_buffer_size: 4,
            limits: russh::RekeyPolicy {
                max_bytes: REKEY_WRITE_LIMIT,
                ..Default::default()
            },
            #[cfg(feature = "_test_hooks")]
            invert_retry_global_hwm: self.invert,
            ..Default::default()
        };
        let mut s = self;
        let _ = s.run_on_address(Arc::new(config), addr).await;
    }
}

impl russh::server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
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
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = reply.accept().await;
        tokio::spawn(async move {
            let mut writer = channel.make_writer();
            let chunk = vec![FILL; 32 * 1024];
            let mut left = BYTES_PER_CHANNEL as usize;
            while left > 0 {
                let n = left.min(chunk.len());
                #[allow(clippy::indexing_slicing)]
                if writer.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
            let _ = writer.shutdown().await;
        });
        Ok(())
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

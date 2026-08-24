//! S8c fix2: `Handler::adjust_window` returning a larger (or smaller)
//! target must not stall inbound or Overflow-close the channel.
//!
//! Enumerated failure classes only — a wait that expires maps onto
//! `InboundStalled`, never a bare Timeout.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Handler, Msg, Session};
use russh::{client, Channel, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);
const DEADLINE_CAP: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdjustFail {
    InboundStalled {
        sent: u64,
        received: u64,
        adjust_calls: u32,
        max_target: u32,
    },
    ChannelClosed {
        sent: u64,
        received: u64,
        adjust_calls: u32,
    },
    TargetDidNotGrow {
        max_target: u32,
    },
    NeverInvoked,
}

#[derive(Clone, Copy)]
enum AdjustMode {
    Control,
    Grow { cap: u32 },
    Shrink { floor: u32 },
}

struct NopClient;
impl client::Handler for NopClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct AdjustH {
    bytes: Arc<AtomicU64>,
    calls: Arc<AtomicU32>,
    max_seen: Arc<AtomicU32>,
    mode: AdjustMode,
}

impl Handler for AdjustH {
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
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await?;
        let bytes = self.bytes.clone();
        tokio::spawn(async move {
            let mut ch = channel;
            while let Some(msg) = ch.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    bytes.fetch_add(data.len() as u64, Ordering::SeqCst);
                }
            }
        });
        Ok(())
    }
    fn adjust_window(&mut self, _id: russh::ChannelId, current: u32) -> u32 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = match self.mode {
            AdjustMode::Control => current,
            AdjustMode::Grow { cap } => current.saturating_mul(2).min(cap),
            AdjustMode::Shrink { floor } => (current / 2).max(floor),
        };
        self.max_seen.fetch_max(next, Ordering::SeqCst);
        next
    }
}

async fn run(mode: AdjustMode, total: u64, window: u32, deadline: Duration) -> Result<(u64, u32, u32), AdjustFail> {
    let mut cfg = server::Config::default();
    cfg.inactivity_timeout = None;
    cfg.auth_rejection_time = Duration::from_secs(0);
    cfg.window_size = window;
    cfg.maximum_packet_size = 4096;
    cfg.keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let cfg = Arc::new(cfg);
    let h = AdjustH {
        bytes: Arc::new(AtomicU64::new(0)),
        calls: Arc::new(AtomicU32::new(0)),
        max_seen: Arc::new(AtomicU32::new(0)),
        mode,
    };
    let (bytes, calls, max_seen) = (h.bytes.clone(), h.calls.clone(), h.max_seen.clone());
    let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = sock.accept().await.unwrap();
        if let Ok(running) = server::run_stream(cfg, s, h).await {
            let _ = running.await;
        }
    });
    let mut ccfg = client::Config::default();
    ccfg.inactivity_timeout = None;
    let mut session = client::connect(Arc::new(ccfg), addr, NopClient)
        .await
        .unwrap();
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    assert!(session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, None))
        .await
        .unwrap()
        .success());
    let ch = session.channel_open_session().await.unwrap();
    let chunk = vec![0x5au8; 4096];
    let mut sent = 0u64;
    let send = async {
        while sent < total {
            if let Err(_) = ch.data(&chunk[..]).await {
                return Err(AdjustFail::ChannelClosed {
                    sent,
                    received: bytes.load(Ordering::SeqCst),
                    adjust_calls: calls.load(Ordering::SeqCst),
                });
            }
            sent += chunk.len() as u64;
        }
        while bytes.load(Ordering::SeqCst) < total {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    };
    match timeout(deadline, send).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(AdjustFail::InboundStalled {
                sent,
                received: bytes.load(Ordering::SeqCst),
                adjust_calls: calls.load(Ordering::SeqCst),
                max_target: max_seen.load(Ordering::SeqCst),
            });
        }
    }
    let got = bytes.load(Ordering::SeqCst);
    let ncall = calls.load(Ordering::SeqCst);
    let maxt = max_seen.load(Ordering::SeqCst);
    if ncall == 0 {
        return Err(AdjustFail::NeverInvoked);
    }
    if matches!(mode, AdjustMode::Grow { .. }) && maxt <= window {
        return Err(AdjustFail::TargetDidNotGrow { max_target: maxt });
    }
    Ok((got, ncall, maxt))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_window_returns_current() {
    match run(AdjustMode::Control, 2 * 1024 * 1024, 8192, DEADLINE).await {
        Ok((got, calls, maxt)) => {
            eprintln!("S8c adjust control: got={got} calls={calls} max_target={maxt}");
        }
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_window_returns_larger() {
    match run(
        AdjustMode::Grow { cap: 1 << 20 },
        2 * 1024 * 1024,
        8192,
        DEADLINE,
    )
    .await
    {
        Ok((got, calls, maxt)) => {
            eprintln!("S8c adjust grow: got={got} calls={calls} max_target={maxt}");
        }
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_window_grows_to_cap() {
    match run(
        AdjustMode::Grow { cap: 4 * 1024 * 1024 },
        8 * 1024 * 1024,
        8192,
        DEADLINE_CAP,
    )
    .await
    {
        Ok((got, calls, maxt)) => {
            eprintln!("S8c adjust grow-to-cap: got={got} calls={calls} max_target={maxt}");
            assert!(
                maxt >= 4 * 1024 * 1024,
                "S8c HARD: grow-to-cap max_target {maxt} < 4 MiB"
            );
        }
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_window_returns_smaller() {
    match run(
        AdjustMode::Shrink { floor: 4096 },
        2 * 1024 * 1024,
        8192,
        DEADLINE,
    )
    .await
    {
        Ok((got, calls, maxt)) => {
            eprintln!("S8c adjust shrink: got={got} calls={calls} max_target={maxt}");
        }
        Err(e) => panic!("S8c HARD: {e:?}"),
    }
}

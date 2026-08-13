//! S2c: per-channel outbound lane + causal fence + window-exempt fences.
//!
//! Hard rule: target interleaving not observed → fail. No soft fallbacks.
//! Requires `--features _test_hooks`.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use harness::*;
use russh::server::{
    self, Auth, DisconnectCause, Handler, Msg, OutboundOrderSlot, ReplyQueueSlot, Server, Session,
};
use russh::{Channel, ChannelId};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

const MSG_OPEN_CONFIRM: u8 = 91;
const MSG_DATA: u8 = 94;
const MSG_EXTENDED: u8 = 95;
const MSG_EOF: u8 = 96;
const MSG_CLOSE: u8 = 97;
const MSG_SUCCESS: u8 = 99;

async fn wait_for<F: FnMut() -> bool>(
    what: &str,
    timeout: Duration,
    mut f: F,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if f() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("HARD: timeout waiting {what}")
}

fn types_of(order: &OutboundOrderSlot) -> Vec<u8> {
    order.snapshot().into_iter().map(|(_, m, _)| m).collect()
}

/// RFC 4254 §5.3 / I3: once CHANNEL_EOF is on the wire for a channel,
/// that channel must not emit further DATA / EXTENDED_DATA.
fn assert_no_data_after_eof(ev: &[(u32, u8, u32)]) {
    let eof = ev
        .iter()
        .position(|(_, m, _)| *m == MSG_EOF)
        .unwrap_or_else(|| panic!("HARD: no EOF in {ev:?}"));
    let ch = ev[eof].0;
    let post: Vec<_> = ev[eof + 1..]
        .iter()
        .copied()
        .filter(|(c, m, _)| *c == ch && (*m == MSG_DATA || *m == MSG_EXTENDED))
        .collect();
    assert!(
        post.is_empty(),
        "HARD: DATA/EXTENDED after EOF on channel {ch} (eof@{eof}) post={post:?} ev={ev:?}"
    );
}

fn server_config(
    order: Arc<OutboundOrderSlot>,
    hang: Option<Arc<AtomicBool>>,
    window: u32,
    pkt: u32,
) -> russh::server::Config {
    russh::server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        window_size: window,
        maximum_packet_size: pkt,
        outbound_order: Some(order),
        socket_hang: hang,
        inactivity_timeout: Some(Duration::from_secs(600)),
        ..Default::default()
    }
}

/// Appendix B.5: OPEN_CONFIRMATION is on the wire before DATA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_open_confirm_before_data() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let flood_gate = FloodStartGate::new();
    let progress = Progress::new();
    let addr = free_addr();

    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            first_channel_mode: ServerMode::FloodForever,
            flood_start: Some(flood_gate.clone()),
            outbound_order: Some(order.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let (session, _ctrl) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);
    flood_gate.release();
    wait_for("DATA emitted", Duration::from_secs(5), || {
        types_of(&order).contains(&MSG_DATA)
    })
    .await?;

    let types = types_of(&order);
    eprintln!("s2c open-confirm-race types={types:?}");
    let confirm = types
        .iter()
        .position(|m| *m == MSG_OPEN_CONFIRM)
        .ok_or_else(|| anyhow::anyhow!("HARD: no OPEN_CONFIRMATION in {types:?}"))?;
    let data = types
        .iter()
        .position(|m| *m == MSG_DATA)
        .ok_or_else(|| anyhow::anyhow!("HARD: no CHANNEL_DATA in {types:?}"))?;
    assert!(
        confirm < data,
        "HARD: OPEN_CONFIRMATION must precede DATA (c@{confirm} d@{data} types={types:?})"
    );
    Ok(())
}

/// I3 close-with-backlog: residual DATA precedes EOF then CLOSE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_close_with_backlog_data_before_close() -> Result<(), anyhow::Error> {
    close_with_backlog_run(LaneMode::FloodThenClose, true).await
}

/// Dual: EOF-only tail fence. Channel stays alive; no CLOSE on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_close_with_backlog_eof_keeps_channel() -> Result<(), anyhow::Error> {
    close_with_backlog_run(LaneMode::FloodThenEofOnly, false).await
}

async fn close_with_backlog_run(mode: LaneMode, expect_close: bool) -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_lane_server(
        addr,
        server_config(order.clone(), Some(hang.clone()), 4 * 1024 * 1024, pkt),
        mode,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    wait_for("DATA moving", Duration::from_secs(5), || {
        types_of(&order).contains(&MSG_DATA)
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    wait_for("backlog built", Duration::from_secs(8), || {
        types_of(&order).iter().filter(|m| **m == MSG_DATA).count() >= 4
    })
    .await?;
    hang.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();

    wait_for("EOF emitted", Duration::from_secs(8), || {
        types_of(&order).contains(&MSG_EOF)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} types={:?}", types_of(&order)))?;

    if expect_close {
        wait_for("CLOSE emitted", Duration::from_secs(5), || {
            types_of(&order).contains(&MSG_CLOSE)
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e} types={:?}", types_of(&order)))?;
    } else {
        sleep(Duration::from_millis(400)).await;
    }

    let types = types_of(&order);
    eprintln!("s2c close-with-backlog mode={mode:?} types={types:?}");
    let last_data = types
        .iter()
        .rposition(|m| *m == MSG_DATA)
        .ok_or_else(|| anyhow::anyhow!("HARD: no DATA in {types:?}"))?;
    let eof = types
        .iter()
        .position(|m| *m == MSG_EOF)
        .ok_or_else(|| anyhow::anyhow!("HARD: no EOF in {types:?}"))?;
    assert!(
        last_data < eof,
        "HARD: last DATA must precede EOF (d@{last_data} e@{eof}) types={types:?}"
    );
    if expect_close {
        let close = types
            .iter()
            .position(|m| *m == MSG_CLOSE)
            .ok_or_else(|| anyhow::anyhow!("HARD: no CLOSE in {types:?}"))?;
        assert!(
            eof < close,
            "HARD: EOF must precede CLOSE (e@{eof} c@{close}) types={types:?}"
        );
    } else {
        assert!(
            !types.contains(&MSG_CLOSE),
            "HARD: EOF-only variant must not emit CLOSE types={types:?}"
        );
        // Channel is still open: another exec must be accepted (not torn down).
        let _ = tokio::time::timeout(Duration::from_millis(200), session.channel_open_session())
            .await;
        assert!(
            !types_of(&order).contains(&MSG_CLOSE),
            "HARD: opening another channel after EOF-only must not emit CLOSE"
        );
    }
    Ok(())
}

/// Appendix B.8: after exactly filling the window, EOF/CLOSE still emit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_close_at_zero_window_emits_fences() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    let win = 16u32;

    let _srv = spawn_lane_server(
        addr,
        server_config(order.clone(), None, win, win),
        LaneMode::ExactWindowThenFence,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = win;
    client_cfg.maximum_packet_size = win;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    // Hold the channel without reading so the window stays exhausted.
    let _ch = session.channel_open_session().await?;

    wait_for("zero-window fences", Duration::from_secs(5), || {
        let t = types_of(&order);
        t.contains(&MSG_EOF) && t.contains(&MSG_CLOSE)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} types={:?}", types_of(&order)))?;

    let types = types_of(&order);
    eprintln!("s2c zero-window fence types={types:?}");
    let eof = types.iter().position(|m| *m == MSG_EOF).unwrap();
    let close = types.iter().position(|m| *m == MSG_CLOSE).unwrap();
    assert!(eof < close, "HARD: EOF before CLOSE types={types:?}");
    Ok(())
}

/// Mixed DATA / SUCCESS / EOF stay in submission order (SUCCESS cannot overtake parked DATA).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_submission_order_matrix() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_lane_server(
        addr,
        server_config(order.clone(), Some(hang.clone()), 4 * 1024 * 1024, pkt),
        LaneMode::FloodThenMatrix,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    wait_for("flood DATA", Duration::from_secs(5), || {
        types_of(&order).contains(&MSG_DATA)
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    wait_for("near HWM", Duration::from_secs(8), || {
        types_of(&order).iter().filter(|m| **m == MSG_DATA).count() >= 8
    })
    .await?;

    channel.exec(true, "matrix").await?;
    sleep(Duration::from_millis(300)).await;
    hang.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    let _drainer = spawn_channel_drainer(channel);

    wait_for("matrix complete", Duration::from_secs(8), || {
        let ev = order.snapshot();
        ev.iter().any(|(_, m, _)| *m == MSG_SUCCESS)
            && ev.iter().any(|(_, m, _)| *m == MSG_EOF)
            && ev.iter().any(|(_, m, n)| *m == MSG_DATA && *n == 1)
            && ev.iter().any(|(_, m, n)| *m == MSG_DATA && *n == 2)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} events={:?}", order.snapshot()))?;

    let ev = order.snapshot();
    eprintln!("s2c order-matrix events={ev:?}");
    let x = ev
        .iter()
        .position(|(_, m, n)| *m == MSG_DATA && *n == 1)
        .ok_or_else(|| anyhow::anyhow!("HARD: no 1-byte X DATA in {ev:?}"))?;
    let last_flood = ev[..x]
        .iter()
        .rposition(|(_, m, n)| *m == MSG_DATA && *n >= 1024)
        .ok_or_else(|| anyhow::anyhow!("HARD: no flood-sized DATA before X in {ev:?}"))?;
    let success = ev
        .iter()
        .position(|(_, m, _)| *m == MSG_SUCCESS)
        .ok_or_else(|| anyhow::anyhow!("HARD: no SUCCESS in {ev:?}"))?;
    let y = ev
        .iter()
        .position(|(_, m, n)| *m == MSG_DATA && *n == 2)
        .ok_or_else(|| anyhow::anyhow!("HARD: no 2-byte Y DATA in {ev:?}"))?;
    let eof = ev
        .iter()
        .position(|(_, m, _)| *m == MSG_EOF)
        .ok_or_else(|| anyhow::anyhow!("HARD: no EOF in {ev:?}"))?;
    assert!(
        last_flood < x && x < success && success < y && y < eof,
        "HARD: want flood-tail < X(1) < SUCCESS < Y(2) < EOF \
         (flood@{last_flood} x@{x} s@{success} y@{y} eof@{eof}) ev={ev:?}"
    );
    assert_no_data_after_eof(&ev);
    Ok(())
}

/// RFC 4254 §5.3 / I3 tail fence: flood keeps writing while exec
/// submits EOF. After settle, that channel must have no DATA after EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_no_data_after_eof() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let order = OutboundOrderSlot::new();
    let hang = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    let addr = free_addr();
    let pkt = 4 * 1024u32;

    let _srv = spawn_lane_server(
        addr,
        server_config(order.clone(), Some(hang.clone()), 4 * 1024 * 1024, pkt),
        LaneMode::FloodForeverThenExecEof,
    );
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = 4 * 1024 * 1024;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;

    wait_for("flood DATA", Duration::from_secs(5), || {
        types_of(&order).contains(&MSG_DATA)
    })
    .await?;
    hang.store(true, Ordering::SeqCst);
    ctrl.freeze_read();
    wait_for("backlog built", Duration::from_secs(8), || {
        types_of(&order).iter().filter(|m| **m == MSG_DATA).count() >= 4
    })
    .await?;

    // Exec on the session loop submits EOF while the flood task is
    // still write_all-ing. Hang holds the Writer so later DATA and
    // the EOF fence race at enqueue, not just at emit.
    channel.exec(true, "eof").await?;
    sleep(Duration::from_millis(200)).await;
    hang.store(false, Ordering::SeqCst);
    ctrl.unfreeze_read();
    let _drainer = spawn_channel_drainer(channel);

    wait_for("EOF emitted", Duration::from_secs(8), || {
        types_of(&order).contains(&MSG_EOF)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e} types={:?}", types_of(&order)))?;
    // Flood keeps writing after the fence is on the wire.
    sleep(Duration::from_millis(400)).await;

    let ev = order.snapshot();
    eprintln!("s2c no-data-after-eof events={ev:?}");
    assert_no_data_after_eof(&ev);
    Ok(())
}

/// Invariant #3: parked DATA + want_reply flood must not grow pending_ctrl
/// without bound. Admit at generation → PeerError or a hard-capped queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2c_parked_data_reply_queue_is_bounded() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let replies = ReplyQueueSlot::new();
    let cause = russh::server::DisconnectCauseSlot::new();
    let progress = Progress::new();
    let addr = free_addr();
    // Tiny peer window so Session::data(32KiB) parks a remainder; SUCCESS
    // sits behind it and never reaches emit until the window moves.
    let win = 1024u32;

    let mut cfg = server_config(OutboundOrderSlot::new(), None, win, win);
    cfg.reply_queue = Some(replies.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let _srv = spawn_lane_server(addr, cfg, LaneMode::ReplyFlood);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = win;
    client_cfg.maximum_packet_size = win;
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;

    // More than HWM/93 (~1400) so a missing generation admit cannot hide
    // behind "we just didn't send enough".
    const FLOOD: usize = 2000;
    for i in 0..FLOOD {
        let _ = channel.exec(true, format!("q-{i}")).await;
    }
    sleep(Duration::from_millis(600)).await;

    let qmax = replies.max();
    let qnow = replies.current();
    let hard = 128 * 1024 + win as usize + 9 + 4 + 1 + 19 + 64;
    let max_legal = (hard / 93) + 2;
    eprintln!(
        "s2c reply-queue flood qmax={qmax} qnow={qnow} max_legal={max_legal} \
         cause={:?} alive={}",
        cause.get(),
        progress.session_alive()
    );
    assert!(
        qmax <= max_legal,
        "HARD: pending SUCCESS/FAILURE unbounded \
         (qmax={qmax} > max_legal={max_legal}); generation admit missing"
    );
    assert!(
        qmax < FLOOD,
        "HARD: all {FLOOD} replies queued (qmax={qmax}); admit never fired"
    );
    assert!(
        matches!(cause.get(), Some(DisconnectCause::PeerError)),
        "HARD: expected PeerError after reply-queue cap, got {:?} alive={}",
        cause.get(),
        progress.session_alive()
    );
    Ok(())
}

// ── server ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum LaneMode {
    FloodThenClose,
    FloodThenEofOnly,
    ExactWindowThenFence,
    FloodThenMatrix,
    FloodForeverThenExecEof,
    ReplyFlood,
}

fn spawn_lane_server(
    addr: SocketAddr,
    config: russh::server::Config,
    mode: LaneMode,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sh = LaneSh { mode };
        if let Err(e) = sh.run_on_address(Arc::new(config), addr).await {
            eprintln!("s2c lane server exited: {e:?}");
        }
    })
}

struct LaneSh {
    mode: LaneMode,
}

impl Server for LaneSh {
    type Handler = LaneH;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        LaneH {
            mode: self.mode,
            parked: false,
        }
    }
}

struct LaneH {
    mode: LaneMode,
    parked: bool,
}

impl Handler for LaneH {
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
        reply.accept().await;
        let mode = self.mode;
        tokio::spawn(async move {
            match mode {
                LaneMode::FloodThenClose
                | LaneMode::FloodThenEofOnly
                | LaneMode::FloodThenMatrix => {
                    let mut w = channel.make_writer();
                    let chunk = vec![b'x'; 16 * 1024];
                    let n = if matches!(mode, LaneMode::FloodThenMatrix) {
                        64
                    } else {
                        32
                    };
                    for _ in 0..n {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                    if matches!(mode, LaneMode::FloodThenClose) {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                    } else if matches!(mode, LaneMode::FloodThenEofOnly) {
                        let _ = channel.eof().await;
                    }
                }
                LaneMode::FloodForeverThenExecEof => {
                    let mut w = channel.make_writer();
                    let chunk = vec![b'x'; 16 * 1024];
                    loop {
                        if w.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
                LaneMode::ExactWindowThenFence => {
                    let mut w = channel.make_writer();
                    let _ = w.write_all(&[b'z'; 16]).await;
                    let _ = channel.eof().await;
                    let _ = channel.close().await;
                }
                LaneMode::ReplyFlood => {}
            }
        });
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.mode {
            LaneMode::ReplyFlood => {
                if !self.parked {
                    // One large DATA so the remainder parks at the tiny peer
                    // window; later SUCCESS items sit behind it.
                    session.data(channel, Bytes::from(vec![b'p'; 32 * 1024]))?;
                    self.parked = true;
                }
                session.channel_success(channel)?;
            }
            LaneMode::FloodForeverThenExecEof => {
                session.eof(channel)?;
            }
            _ => {
                session.data(channel, Bytes::from_static(b"X"))?;
                session.channel_success(channel)?;
                session.data(channel, Bytes::from_static(b"YY"))?;
                session.eof(channel)?;
            }
        }
        Ok(())
    }
}

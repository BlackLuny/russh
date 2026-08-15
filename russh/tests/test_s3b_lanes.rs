//! S3b: per-channel inbound lane + dual bounds + CLOSE dual path + Scheme C.
//!
//! Real `Session::run`. Hard rule: miss → fail. Requires `_test_hooks`.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness::*;
use russh::server::{
    Auth, ChannelOpenHandle, DisconnectCause, Handler, LaneObserveSlot, Msg, Server, Session,
    StopDiscardSlot,
};
use russh::{Channel, ChannelId, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::time::sleep;

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
        sleep(Duration::from_millis(15)).await;
    }
    anyhow::bail!("HARD: timeout waiting {what}")
}

#[derive(Clone, Default)]
struct Rec {
    events: Arc<Mutex<Vec<&'static str>>>,
    data_before_pty: Arc<AtomicBool>,
    data_seen: Arc<AtomicBool>,
    pty_seen: Arc<AtomicBool>,
    handler_closes: Arc<Mutex<Vec<u32>>>,
    last_server_id: Arc<AtomicU32>,
}

impl Rec {
    fn push(&self, e: &'static str) {
        self.events.lock().unwrap().push(e);
    }
}

struct RecServer {
    rec: Rec,
}

impl Server for RecServer {
    type Handler = RecHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        RecHandler { rec: self.rec.clone() }
    }
}

struct RecHandler {
    rec: Rec,
}

impl Handler for RecHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.rec
            .last_server_id
            .store(channel.id().number(), Ordering::SeqCst);
        let rec = self.rec.clone();
        tokio::spawn(async move {
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { .. } => {
                        rec.push("data");
                        rec.data_seen.store(true, Ordering::SeqCst);
                        // Delivered DATA no longer calls Handler::data (S4b).
                        // App-buffer arrival is the Q2 observation.
                        if !rec.pty_seen.load(Ordering::SeqCst) {
                            rec.data_before_pty.store(true, Ordering::SeqCst);
                        }
                    }
                    ChannelMsg::Eof => rec.push("eof"),
                    ChannelMsg::Close => rec.push("close"),
                    _ => {}
                }
            }
        });
        Ok(())
    }

    async fn data(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rec.data_seen.store(true, Ordering::SeqCst);
        if !self.rec.pty_seen.load(Ordering::SeqCst) {
            self.rec.data_before_pty.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        id: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rec.handler_closes.lock().unwrap().push(id.number());
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rec.pty_seen.store(true, Ordering::SeqCst);
        self.rec.push("pty");
        Ok(())
    }
}

async fn spawn_rec(
    rec: Rec,
    cfg: russh::server::Config,
) -> std::net::SocketAddr {
    let addr = free_addr();
    let mut srv = RecServer { rec };
    tokio::spawn(async move {
        let _ = srv.run_on_address(Arc::new(cfg), addr).await;
    });
    wait_listening(addr).await;
    addr
}

fn base_cfg() -> russh::server::Config {
    russh::server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    }
}

/// Q1: DATA×N + EOF + CLOSE arrive in FIFO on Channel::wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q1_data_eof_close_fifo() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let addr = spawn_rec(rec.clone(), base_cfg()).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    for i in 0..4u8 {
        ch.data_bytes(vec![i]).await?;
    }
    ch.eof().await?;
    ch.close().await?;
    wait_for("Q1 close", Duration::from_secs(5), || {
        rec.events.lock().unwrap().contains(&"close")
    })
    .await?;
    let ev = rec.events.lock().unwrap().clone();
    eprintln!("q1 events={ev:?}");
    let data_n = ev.iter().filter(|e| **e == "data").count();
    assert!(data_n >= 4, "Q1 HARD: expected ≥4 DATA, got {ev:?}");
    let data_pos: Vec<_> = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| **e == "data")
        .map(|(i, _)| i)
        .collect();
    let eof = ev.iter().position(|e| *e == "eof").expect("Q1 HARD: missing EOF");
    let close = ev.iter().position(|e| *e == "close").expect("Q1 HARD: missing CLOSE");
    assert!(
        data_pos.len() >= 4 && data_pos.iter().take(4).all(|p| *p < eof),
        "Q1 HARD: all 4 DATA must precede EOF: {ev:?}"
    );
    assert!(eof < close, "Q1 HARD: EOF before CLOSE: {ev:?}");
    Ok(())
}

/// Q2: DATA and REQUEST sit in the same lane FIFO (pump held).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q2_request_does_not_overtake_data() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let hold = Arc::new(AtomicBool::new(true));
    let observe = LaneObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.lane_observe = Some(observe.clone());
    let addr = spawn_rec(rec.clone(), cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(&b"hello"[..]).await?;
    ch.request_pty(false, "xterm", 80, 24, 0, 0, &[]).await?;
    wait_for("Q2 both queued", Duration::from_secs(3), || {
        observe.last_count() >= 2
    })
    .await?;
    hold.store(false, Ordering::SeqCst);
    ch.data_bytes(&b"wake"[..]).await?;
    wait_for("Q2 pty", Duration::from_secs(3), || rec.pty_seen.load(Ordering::SeqCst)).await?;
    assert!(
        observe.data_before_request(),
        "Q2 HARD: same-lane FIFO, DATA before pty-req"
    );
    Ok(())
}

/// Q3: 0-byte DATA flood does not grow the lane; counter > 0; session lives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q3_zero_byte_flood_dropped() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let zeros = Arc::new(AtomicU64::new(80));
    let mut cfg = base_cfg();
    cfg.lane_observe = Some(observe.clone());
    cfg.inject_zero_data = Some(zeros);
    cfg.channel_buffer_size = 1;
    let addr = spawn_rec(rec.clone(), cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(&b"x"[..]).await?;
    for _ in 0..200 {
        ch.data_bytes_allow_empty(&[][..]).await?;
    }
    wait_for("Q3 drops", Duration::from_secs(5), || observe.zero_byte_drops() > 0).await?;
    eprintln!(
        "q3 zero_drops={} last_count={}",
        observe.zero_byte_drops(),
        observe.last_count()
    );
    assert!(observe.zero_byte_drops() > 0, "Q3 HARD: zero-byte counter");
    ch.data_bytes(&b"y"[..]).await?;
    wait_for("Q3 still alive", Duration::from_secs(3), || {
        rec.events.lock().unwrap().iter().filter(|e| **e == "data").count() >= 2
    })
    .await?;
    Ok(())
}

/// Q4: repeated EOF/CLOSE delivered once. Extra copies go on the wire
/// via send_raw_packet so Reader actually sees the dups.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q4_dup_eof_close_dedup() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.lane_observe = Some(observe.clone());
    let addr = spawn_rec(rec.clone(), cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(&b"z"[..]).await?;
    wait_for("Q4 id", Duration::from_secs(2), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    let id = rec.last_server_id.load(Ordering::SeqCst);
    ch.send_raw_payload(encode_eof(id, &[])).await?;
    ch.send_raw_payload(encode_eof(id, &[])).await?;
    ch.send_raw_payload(encode_close(id, &[])).await?;
    ch.send_raw_payload(encode_close(id, &[])).await?;
    wait_for("Q4 close", Duration::from_secs(5), || {
        rec.events.lock().unwrap().contains(&"close")
    })
    .await?;
    let ev = rec.events.lock().unwrap().clone();
    let eofs = ev.iter().filter(|e| **e == "eof").count();
    let closes = ev.iter().filter(|e| **e == "close").count();
    eprintln!("q4 events={ev:?} dups={}", observe.dup_drops());
    assert_eq!(eofs, 1, "Q4 HARD: EOF once {ev:?}");
    assert_eq!(closes, 1, "Q4 HARD: CLOSE once {ev:?}");
    assert!(
        observe.dup_drops() > 0,
        "Q4 HARD: Reader must see duplicate EOF/CLOSE (dups={})",
        observe.dup_drops()
    );
    Ok(())
}

/// Q5: occupancy bound (not granted-window authority) under pump hold.
/// Hook fill is required so Session never drains the lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q5_occupancy_bound_closes_only_victim() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let discard = StopDiscardSlot::new();
    let observe = LaneObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.stop_discard = Some(discard.clone());
    cfg.lane_observe = Some(observe.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.inject_until_overflow = Some(Arc::new(AtomicBool::new(true)));
    let addr = spawn_rec(rec.clone(), cfg).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 256;
    ccfg.maximum_packet_size = 64;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut victim = session.channel_open_session().await?;
    let mut other = session.channel_open_session().await?;
    // One legal packet; the window-ignoring flood is injected on the
    // Reader (a compliant russh client will never exceed byte_cap).
    victim.data_bytes(vec![0u8; 64]).await?;
    wait_for("Q5 overflow", Duration::from_secs(5), || {
        observe.overflows() > 0 || discard.discarded_items() > 0
    })
    .await?;
    other.data_bytes(&b"ok"[..]).await?;
    hold.store(false, Ordering::SeqCst);
    // Release is not itself a select event; one more write wakes the pump.
    other.data_bytes(&b"ok2"[..]).await?;
    wait_for("Q5 other lives", Duration::from_secs(3), || {
        rec.events.lock().unwrap().iter().any(|e| *e == "data")
    })
    .await?;
    eprintln!(
        "q5 discarded_items={} overflows={}",
        discard.discarded_items(),
        observe.overflows()
    );
    assert!(
        observe.overflows() > 0 || discard.discarded_items() > 0,
        "Q5 HARD: victim must StopDiscard"
    );
    Ok(())
}

/// Q6a: lane exactly at count_cap (no Overflow yet). CLOSE marker drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q6a_close_on_exactly_full_lane() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let hold = Arc::new(AtomicBool::new(true));
    let observe = LaneObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 16;
    cfg.inbound_min_packet_size = 8;
    cfg.inbound_lane_count_slack = 4;
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.lane_observe = Some(observe.clone());
    cfg.write_progress_deadline = Duration::from_secs(8);
    let addr = spawn_rec(rec.clone(), cfg).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 16;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    // count_cap = 64/8+4 = 12. 12×1B sits under byte_cap=80.
    for _ in 0..12 {
        ch.data_bytes(vec![1u8]).await?;
    }
    wait_for("Q6a lane exactly full", Duration::from_secs(4), || {
        observe.last_count() >= 12 && observe.overflows() == 0
    })
    .await?;
    let base_cd = observe.close_dropped();
    let base_ov = observe.overflows();
    ch.close().await?;
    let mut saw_peer_close = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ch.wait()).await {
            Ok(Some(ChannelMsg::Close)) => {
                saw_peer_close = true;
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    eprintln!(
        "q6a peer_close={saw_peer_close} close_dropped {}→{} overflows {}→{} count={}",
        base_cd,
        observe.close_dropped(),
        base_ov,
        observe.overflows(),
        observe.last_count()
    );
    assert!(
        saw_peer_close,
        "Q6a HARD: client wait() must see peer ChannelMsg::Close"
    );
    wait_for("Q6a close_dropped delta", Duration::from_secs(4), || {
        observe.close_dropped() > base_cd
    })
    .await?;
    assert_eq!(
        observe.close_dropped(),
        base_cd + 1,
        "Q6a HARD: CLOSE marker drop +1 from baseline"
    );
    hold.store(false, Ordering::SeqCst);
    Ok(())
}

/// Q6b: Overflow teardown first, then peer CLOSE → NoLane CloseDropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q6b_close_after_overflow_teardown() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let hold = Arc::new(AtomicBool::new(true));
    let observe = LaneObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 16;
    cfg.inbound_min_packet_size = 8;
    cfg.inbound_lane_count_slack = 4;
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.lane_observe = Some(observe.clone());
    cfg.inject_until_overflow = Some(Arc::new(AtomicBool::new(true)));
    cfg.write_progress_deadline = Duration::from_secs(8);
    let addr = spawn_rec(rec.clone(), cfg).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 16;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8]).await?;
    wait_for("Q6b overflow teardown", Duration::from_secs(4), || {
        observe.overflows() > 0 && !rec.handler_closes.lock().unwrap().is_empty()
    })
    .await?;
    let base_cd = observe.close_dropped();
    let base_unk = observe.unknown_drops();
    let base_hc = rec.handler_closes.lock().unwrap().len();
    let id = rec.last_server_id.load(Ordering::SeqCst);
    // ch.close() is a no-op if Overflow already delivered peer CLOSE.
    let close_ok = tokio::time::timeout(
        Duration::from_secs(3),
        ch.send_raw_payload(encode_close(id, &[])),
    )
    .await;
    assert!(close_ok.is_ok(), "Q6b HARD: raw CLOSE must send");
    wait_for("Q6b post-CLOSE signal", Duration::from_secs(4), || {
        observe.close_dropped() > base_cd || observe.unknown_drops() > base_unk
    })
    .await?;
    let hc = rec.handler_closes.lock().unwrap().len();
    eprintln!(
        "q6b close_dropped {}→{} unknown {}→{} handler_closes {}→{}",
        base_cd,
        observe.close_dropped(),
        base_unk,
        observe.unknown_drops(),
        base_hc,
        hc
    );
    assert!(
        observe.close_dropped() == base_cd + 1 || observe.unknown_drops() == base_unk + 1,
        "Q6b HARD: post-CLOSE NoLane must increment close_dropped or unknown"
    );
    assert_eq!(
        hc, base_hc,
        "Q6b HARD: no second handler.channel_close"
    );
    hold.store(false, Ordering::SeqCst);
    Ok(())
}

/// Q7: ctrl budget exhaust → Cancelling (PeerError), not silent drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q7_ctrl_full_cancels() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let force = Arc::new(AtomicBool::new(false));
    let cause = russh::server::DisconnectCauseSlot::new();
    let mut cfg = base_cfg();
    cfg.force_ctrl_full = Some(force.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_rec(rec, cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let _ch = session.channel_open_session().await?;
    force.store(true, Ordering::SeqCst);
    let _ = session.rekey_soon().await;
    wait_for("Q7 PeerError", Duration::from_secs(8), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;
    assert_eq!(cause.get(), Some(DisconnectCause::PeerError));
    Ok(())
}

/// Q8: a payload is in the lane *or* Scheme C, never memcpy'd into both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q8_no_double_count_handoff() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let hold = Arc::new(AtomicBool::new(true));
    let observe = LaneObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.channel_buffer_size = 1;
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.lane_observe = Some(observe.clone());
    let addr = spawn_rec(rec.clone(), cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(vec![7u8; 32]).await?;
    wait_for("Q8 in lane", Duration::from_secs(3), || observe.last_bytes() >= 32).await?;
    let in_lane = observe.last_bytes();
    assert!(in_lane >= 32, "Q8 HARD: payload must sit in the Reader lane first ({in_lane})");
    assert_eq!(
        observe.last_scheme(),
        0,
        "Q8 HARD: payload still in the lane must not also be in Scheme C"
    );
    assert_eq!(observe.overlap(), 0, "Q8 HARD: same-payload double occupancy");
    hold.store(false, Ordering::SeqCst);
    // Wake Session (pump hold release is not itself a select event).
    ch.data_bytes(vec![8u8]).await?;
    wait_for("Q8 pumped", Duration::from_secs(3), || {
        rec.data_seen.load(Ordering::SeqCst)
    })
    .await?;
    eprintln!("q8 lane_after={} overlap={}", observe.last_bytes(), observe.overlap());
    Ok(())
}

/// P2-3: CLOSE for a never-opened channel must not call Handler::channel_close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ghost_close_does_not_notify_handler() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let ghost = Arc::new(AtomicU32::new(0xFFFF_FFFE));
    let mut cfg = base_cfg();
    cfg.lane_observe = Some(observe.clone());
    cfg.inject_close_for = Some(ghost);
    let addr = spawn_rec(rec.clone(), cfg).await;
    let (session, _) = connect_faulty(addr, default_client_config(), Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    ch.data_bytes(&b"x"[..]).await?;
    wait_for("ghost CLOSE counted", Duration::from_secs(5), || {
        observe.unknown_drops() > 0
    })
    .await?;
    let closes = rec.handler_closes.lock().unwrap().clone();
    assert!(
        !closes.contains(&0xFFFF_FFFE),
        "P2-3 HARD: handler must not see close for a never-opened id {closes:?}"
    );
    ch.data_bytes(&b"y"[..]).await?;
    wait_for("session still alive", Duration::from_secs(3), || {
        rec.events.lock().unwrap().iter().filter(|e| **e == "data").count() >= 2
    })
    .await?;
    eprintln!(
        "ghost_close unknown={} handler_closes={closes:?}",
        observe.unknown_drops()
    );
    Ok(())
}

const MSG_DATA: u8 = 94;
const MSG_EOF: u8 = 96;
const MSG_CLOSE: u8 = 97;

fn encode_data(ch: u32, data: &[u8], trail: &[u8]) -> Vec<u8> {
    let mut p = vec![MSG_DATA];
    p.extend_from_slice(&ch.to_be_bytes());
    p.extend_from_slice(&(data.len() as u32).to_be_bytes());
    p.extend_from_slice(data);
    p.extend_from_slice(trail);
    p
}

fn encode_eof(ch: u32, trail: &[u8]) -> Vec<u8> {
    let mut p = vec![MSG_EOF];
    p.extend_from_slice(&ch.to_be_bytes());
    p.extend_from_slice(trail);
    p
}

fn encode_close(ch: u32, trail: &[u8]) -> Vec<u8> {
    let mut p = vec![MSG_CLOSE];
    p.extend_from_slice(&ch.to_be_bytes());
    p.extend_from_slice(trail);
    p
}

/// P1: trailing bytes on DATA/EOF/CLOSE take the old ensure_end path (ctrl).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trailing_bytes_data_eof_close_rejected() -> Result<(), anyhow::Error> {
    for kind in ["data", "eof", "close"] {
        let rec = Rec::default();
        let cause = russh::server::DisconnectCauseSlot::new();
        let mut cfg = base_cfg();
        cfg.disconnect_cause_slot = Some(cause.clone());
        let addr = spawn_rec(rec.clone(), cfg).await;
        let progress = Progress::new();
        let (session, _) = connect_faulty(addr, default_client_config(), progress.clone()).await?;
        let mut ch = session.channel_open_session().await?;
        ch.data_bytes(&b"ok"[..]).await?;
        wait_for("opened", Duration::from_secs(3), || {
            rec.last_server_id.load(Ordering::SeqCst) != 0
                && rec.events.lock().unwrap().contains(&"data")
        })
        .await?;
        let id = rec.last_server_id.load(Ordering::SeqCst);
        let pkt = match kind {
            "data" => encode_data(id, b"x", &[0xFF]),
            "eof" => encode_eof(id, &[0xFF]),
            _ => encode_close(id, &[0xFF]),
        };
        ch.send_raw_payload(pkt).await?;
        wait_for("trailing convicted", Duration::from_secs(5), || {
            cause.get() == Some(DisconnectCause::PeerError) || !progress.session_alive()
        })
        .await
        .ok();
        sleep(Duration::from_millis(400)).await;
        let ev = rec.events.lock().unwrap().clone();
        let hc = rec.handler_closes.lock().unwrap().clone();
        eprintln!(
            "trailing {kind}: ev={ev:?} hc={hc:?} cause={:?} alive={}",
            cause.get(),
            progress.session_alive()
        );
        match kind {
            "data" => assert_eq!(
                ev.iter().filter(|e| **e == "data").count(),
                1,
                "trailing DATA must not deliver: {ev:?}"
            ),
            "eof" => assert!(
                !ev.contains(&"eof"),
                "trailing EOF must not deliver: {ev:?}"
            ),
            _ => assert!(
                !ev.contains(&"close") && hc.is_empty(),
                "trailing CLOSE must not run lifecycle: ev={ev:?} hc={hc:?}"
            ),
        }
        assert!(
            cause.get() == Some(DisconnectCause::PeerError) || !progress.session_alive(),
            "trailing {kind}: old ensure_end must convict (cause={:?} alive={})",
            cause.get(),
            progress.session_alive()
        );
    }
    Ok(())
}

/// Wire occupancy bound: raw client ignores window, total > window+maxpkt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q5_wire_occupancy_overflow() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let discard = StopDiscardSlot::new();
    let observe = LaneObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.stop_discard = Some(discard.clone());
    cfg.lane_observe = Some(observe.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    let addr = spawn_rec(rec.clone(), cfg).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut victim = session.channel_open_session().await?;
    let mut other = session.channel_open_session().await?;
    wait_for("ids", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    // First open is victim. last_server_id is `other` (second). Victim is other-1
    // if ids are consecutive; send by opening order: victim opened first = 1.
    wait_for("victim opened", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    // Two channels: last_id is `other`. Victim opened first → id 1.
    let victim_id = rec.last_server_id.load(Ordering::SeqCst).saturating_sub(1);
    let victim_id = if victim_id == 0 { 1 } else { victim_id };
    // byte_cap = 64+32 = 96. Four 32B frames = 128 > 96.
    for _ in 0..4 {
        victim
            .send_raw_payload(encode_data(victim_id, &[0u8; 32], &[]))
            .await?;
    }
    wait_for("wire overflow", Duration::from_secs(5), || {
        observe.overflows() > 0 || discard.discarded_items() > 0
    })
    .await?;
    hold.store(false, Ordering::SeqCst);
    other.data_bytes(&b"ok"[..]).await?;
    wait_for("other lives", Duration::from_secs(3), || {
        rec.events.lock().unwrap().iter().any(|e| *e == "data")
    })
    .await?;
    eprintln!(
        "q5_wire overflows={} discarded={}",
        observe.overflows(),
        discard.discarded_items()
    );
    assert!(
        observe.overflows() > 0 || discard.discarded_items() > 0,
        "Q5-wire HARD: occupancy overflow on the real path"
    );
    let _ = victim;
    Ok(())
}

/// min(8, configured=16): 8B packets must not hit count_cap first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn count_cap_uses_min8_not_raw_config() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.inbound_min_packet_size = 16;
    cfg.inbound_lane_count_slack = 0;
    cfg.lane_observe = Some(observe.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    let addr = spawn_rec(rec.clone(), cfg).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    // Wrong denom 16 → count_cap=4; right min(8,16)=8 → count_cap=8.
    // 5×8B = 40 < window 64, so a count-cap of 4 would Overflow.
    for _ in 0..5 {
        ch.data_bytes(vec![0u8; 8]).await?;
    }
    wait_for("5 small packets queued", Duration::from_secs(3), || {
        observe.last_count() >= 5
    })
    .await?;
    eprintln!(
        "min8 sentinel count={} overflows={}",
        observe.last_count(),
        observe.overflows()
    );
    assert_eq!(
        observe.overflows(),
        0,
        "HARD: 8B packets must not hit count_cap when min_packet=16"
    );
    hold.store(false, Ordering::SeqCst);
    Ok(())
}

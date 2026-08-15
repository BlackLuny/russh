//! S3c: inbound window authority + ADJUST bypass + grant order.
//!
//! Real `Session::run`. W1/W3 are must-fail constructions: invert the
//! expand-then-ADJUST order (or skip expand) and these assertions go red.

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod harness;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use harness::*;
use russh::client;
use russh::server::{
    Auth, ChannelOpenHandle, DisconnectCause, DisconnectCauseSlot, Handler, LaneObserveSlot, Msg,
    PeerCreditBoard, ReadHoldGate, ReaderObserveSlot, Server, Session, WindowObserveSlot,
};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
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
    bytes: Arc<AtomicU64>,
    last_server_id: Arc<std::sync::atomic::AtomicU32>,
    /// Bytes the handler pushed outbound (W2/W4).
    outbound_attempted: Arc<AtomicU64>,
    last_window: Arc<std::sync::atomic::AtomicU32>,
    last_writable: Arc<std::sync::atomic::AtomicU32>,
    last_sender: Arc<std::sync::atomic::AtomicU32>,
    closes: Arc<AtomicU64>,
    adjusts: Arc<AtomicU64>,
    /// When true, `data` parks so Session stays inside the handler await.
    data_hold: Arc<AtomicBool>,
    /// Set at the top of `data` so tests can wait until Session is inside it.
    in_data: Arc<AtomicBool>,
    /// W7: first inbound `data` spawns `Handle::channel_open_session`.
    open_on_data: Arc<AtomicBool>,
    /// W7: `Handle::channel_open_session` returned (OPEN_CONFIRMATION).
    server_open_done: Arc<AtomicBool>,
    /// W8: `Handle::channel_open_session` returned `Err` (OPEN_FAILURE).
    server_open_fail: Arc<AtomicBool>,
}

struct RecServer {
    rec: Rec,
    /// How many outbound bytes to dump on each open (0 = none).
    dump: usize,
}

impl Server for RecServer {
    type Handler = RecHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        RecHandler {
            rec: self.rec.clone(),
            dump: self.dump,
        }
    }
}

struct RecHandler {
    rec: Rec,
    dump: usize,
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
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.rec
            .last_server_id
            .store(channel.id().number(), Ordering::SeqCst);
        if self.dump > 0 {
            let n = self.dump;
            let handle = session.handle();
            let id = channel.id();
            let attempted = self.rec.outbound_attempted.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(50)).await;
                attempted.fetch_add(n as u64, Ordering::SeqCst);
                let _ = handle.data(id, Bytes::from(vec![7u8; n])).await;
            });
        }
        Ok(())
    }
    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.rec.open_on_data.swap(false, Ordering::SeqCst) {
            let handle = session.handle();
            let done = self.rec.server_open_done.clone();
            let fail = self.rec.server_open_fail.clone();
            tokio::spawn(async move {
                match handle.channel_open_session().await {
                    Ok(ch) => {
                        done.store(true, Ordering::SeqCst);
                        let _ = handle.data(ch.id(), Bytes::from(vec![7u8; 32])).await;
                    }
                    Err(_) => {
                        fail.store(true, Ordering::SeqCst);
                    }
                }
            });
        }
        self.rec.in_data.store(true, Ordering::SeqCst);
        while self.rec.data_hold.load(Ordering::SeqCst) {
            sleep(Duration::from_millis(5)).await;
        }
        self.rec
            .bytes
            .fetch_add(data.len() as u64, Ordering::SeqCst);
        self.rec
            .last_window
            .store(session.window_size(&id), Ordering::SeqCst);
        self.rec
            .last_writable
            .store(session.writable_packet_size(&id), Ordering::SeqCst);
        self.rec
            .last_sender
            .store(session.sender_window_size(id) as u32, Ordering::SeqCst);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rec.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn window_adjusted(
        &mut self,
        _: ChannelId,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rec.adjusts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn spawn_rec(
    rec: Rec,
    cfg: russh::server::Config,
    dump: usize,
) -> std::net::SocketAddr {
    let addr = free_addr();
    let mut srv = RecServer { rec, dump };
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

fn encode_adjust(recipient: u32, amount: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(9);
    p.push(93u8); // CHANNEL_WINDOW_ADJUST
    p.extend_from_slice(&recipient.to_be_bytes());
    p.extend_from_slice(&amount.to_be_bytes());
    p
}

/// W1: after a full-window send+deliver, the grant tops up
/// `window_remaining` and the peer immediately sends another window.
/// Occupancy bounds stay `64+32`; first window is already out of the
/// lane, so the second 64 sits at occupancy 64 < 96. Zero Overflow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_window_grant_race_zero_overflow() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.inbound_lane_count_slack = 32;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 64]).await?;
    wait_for("first 64 delivered + grant", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 64 && wobs.expand_ok() >= 1 && wobs.adjust_emitted_seq() > 0
    })
    .await?;
    // Peer sees ADJUST (expand already happened) and immediately uses the
    // new window — this is the W1 interleaving.
    ch.data_bytes(vec![2u8; 64]).await?;
    wait_for("second 64 delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 128
    })
    .await?;
    assert_eq!(
        observe.overflows(),
        0,
        "W1 HARD: compliant peer after grant must not Overflow"
    );
    assert_eq!(rec.bytes.load(Ordering::SeqCst), 128, "W1 HARD: all bytes delivered");
    Ok(())
}

/// W3: hook order cap_expanded_seq < adjust_emitted_seq.
///
/// Must-fail: invert (emit ADJUST then expand). Tickets would then
/// satisfy emitted < expanded and this assert goes red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w3_grant_order_cap_before_adjust() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.window_observe = Some(wobs.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 64]).await?;
    wait_for("grant fired", Duration::from_secs(4), || {
        wobs.expand_ok() >= 1 && wobs.adjust_emitted_seq() > 0
    })
    .await?;
    let cap = wobs.cap_expanded_seq();
    let adj = wobs.adjust_emitted_seq();
    eprintln!("w3 order cap={cap} adjust={adj}");
    assert!(
        cap > 0 && adj > 0 && cap < adj,
        "W3 HARD: cap_expanded ({cap}) must be strictly before ADJUST emit ({adj})"
    );
    Ok(())
}

/// W2: fill the inbound lane (pump held) then peer ADJUST. Outbound
/// try_drain must make progress *while the lane is still full*. Hook
/// proves ADJUST used the bypass (not the lane).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w2_adjust_under_full_lane_unblocks_outbound() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    let addr = spawn_rec(rec.clone(), cfg, 16 * 1024).await;

    let mut ccfg = default_client_config();
    // Tiny client receive window so server dump parks after the first packet.
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 64;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut ch = session.channel_open_session().await?;
    wait_for("server id", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    let sid = rec.last_server_id.load(Ordering::SeqCst);

    // First window must already be on the wire (dump parked on client window=64).
    let mut got = 0u64;
    let first_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < first_deadline && got == 0 {
        match tokio::time::timeout(Duration::from_millis(200), ch.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    assert!(
        got > 0,
        "W2 setup: server dump must deliver the first window (got={got} attempted={})",
        rec.outbound_attempted.load(Ordering::SeqCst)
    );
    let b0 = got;

    // Fill inbound lane under pump hold (12 × 1B < count_cap).
    for _ in 0..12 {
        ch.data_bytes(vec![3u8]).await?;
    }
    wait_for("lane full", Duration::from_secs(4), || {
        observe.last_count() >= 12
    })
    .await?;
    let bypass0 = wobs.adjust_bypass();

    // Peer ADJUST while the lane is still held. Must not enter the lane.
    ch.send_raw_payload(Bytes::from(encode_adjust(sid, 16 * 1024)))
        .await?;
    wait_for("ADJUST bypass", Duration::from_secs(4), || {
        wobs.adjust_bypass() > bypass0
    })
    .await?;
    assert_eq!(
        observe.last_count(),
        12,
        "W2 HARD: ADJUST must not sit in the lane (count still 12)"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline && got <= b0 {
        match tokio::time::timeout(Duration::from_millis(200), ch.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    eprintln!(
        "w2 bypass {}→{} lane_count={} b0={b0} got={} attempted={}",
        bypass0,
        wobs.adjust_bypass(),
        observe.last_count(),
        got,
        rec.outbound_attempted.load(Ordering::SeqCst)
    );
    assert!(
        got > b0,
        "W2 HARD: try_drain must produce outbound progress after ADJUST under full lane; b0={b0} got={got}"
    );
    hold.store(false, Ordering::SeqCst);
    Ok(())
}

/// W4: victim inbound full + ADJUST; other channel outbound still flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4_other_channel_outbound_isolated() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64 * 1024;
    ccfg.maximum_packet_size = 64;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let victim = session.channel_open_session().await?;
    let mut other = session.channel_open_session().await?;
    wait_for("both open", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) >= 1
    })
    .await?;
    let victim_id = rec.last_server_id.load(Ordering::SeqCst).saturating_sub(1);

    for _ in 0..12 {
        victim.data_bytes(vec![4u8]).await?;
    }
    wait_for("victim lane full", Duration::from_secs(4), || {
        observe.last_count() >= 12
    })
    .await?;
    victim
        .send_raw_payload(Bytes::from(encode_adjust(victim_id, 1024)))
        .await?;
    wait_for("victim ADJUST bypass", Duration::from_secs(4), || {
        wobs.adjust_bypass() >= 1
    })
    .await?;

    // Other channel: client → server DATA must still deliver after hold release.
    hold.store(false, Ordering::SeqCst);
    other.data_bytes(vec![5u8; 32]).await?;
    // Wake the pump with another byte.
    other.data_bytes(vec![6u8]).await?;
    wait_for("other delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 32
    })
    .await?;
    assert_eq!(
        observe.overflows(),
        0,
        "W4 HARD: other channel must not Overflow"
    );
    Ok(())
}

/// P1-2: production invert (`invert_grant_order`) makes W3's
/// `cap < adj` assertion fail. Same two production calls, swapped —
/// not a hand-built observe slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w3_invert_grant_order_is_red() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.window_observe = Some(wobs.clone());
    cfg.invert_grant_order = true;
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 64]).await?;
    wait_for("inverted grant fired", Duration::from_secs(4), || {
        wobs.expand_ok() >= 1 && wobs.adjust_emitted_seq() > 0
    })
    .await?;
    let cap = wobs.cap_expanded_seq();
    let adj = wobs.adjust_emitted_seq();
    eprintln!("w3 invert production cap={cap} adjust={adj}");
    assert!(
        adj > 0 && cap > 0 && adj < cap,
        "W3 invert HARD: production must emit ADJUST before expand (adj={adj} cap={cap})"
    );
    assert!(
        !(cap < adj),
        "W3 invert HARD: the W3 assertion `cap < adj` must be false under invert"
    );
    Ok(())
}

/// P1-1: ≥4 real grant rounds must not raise occupancy bounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn occupancy_caps_constant_across_grants() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.inbound_lane_count_slack = 32;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    // Four full-window grant rounds. First push also snapshots construction-time caps.
    for i in 0..4 {
        ch.data_bytes(vec![2u8; 64]).await?;
        let need_grants = i as u64 + 1;
        wait_for("grant round", Duration::from_secs(4), || {
            rec.bytes.load(Ordering::SeqCst) >= 64 * need_grants && wobs.expand_ok() >= need_grants
        })
        .await?;
        if i == 0 {
            assert!(observe.last_byte_cap() > 0, "caps snapshotted on first push");
        }
    }
    let byte0 = 64 + 32;
    let count0 = 64 / 8 + 32;
    assert!(
        wobs.expand_ok() >= 4,
        "HARD: need ≥4 real grants, got {}",
        wobs.expand_ok()
    );
    assert_eq!(
        observe.last_byte_cap(),
        byte0,
        "HARD: byte_cap must stay {} after {} grants (got {})",
        byte0,
        wobs.expand_ok(),
        observe.last_byte_cap()
    );
    assert_eq!(
        observe.last_count_cap(),
        count0,
        "HARD: count_cap must stay {} after {} grants (got {})",
        count0,
        wobs.expand_ok(),
        observe.last_count_cap()
    );
    Ok(())
}

/// P2: after a half-window consume that does not grant, getters must
/// report the Reader remaining, not the frozen Encrypted ceiling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getters_read_reader_window_not_mirror() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 32]).await?;
    wait_for("32 delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 32
    })
    .await?;
    let win = rec.last_window.load(Ordering::SeqCst);
    let wr = rec.last_writable.load(Ordering::SeqCst);
    let sender = rec.last_sender.load(Ordering::SeqCst);
    eprintln!("p2 window={win} writable={wr} sender={sender}");
    assert_eq!(
        win, 32,
        "P2 HARD: window_size must be Reader remaining 32, not Encrypted 64"
    );
    assert_eq!(
        wr, 32,
        "P2 HARD: writable_packet_size must be min(32, maxpkt=32)"
    );
    assert_eq!(
        sender, 32,
        "P2 HARD: sender_window_size must be Reader remaining 32, not Encrypted 64"
    );
    Ok(())
}

/// After constant occupancy caps, W1 occupancy overflow is structurally
/// unreachable (construction is the protection). W1 “must-red” is
/// withdrawn. Order is gated by `w3_invert_grant_order_is_red`;
/// occupancy cap by `occupancy_caps_constant_across_grants`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_original_occupancy_mustfail_never_red() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.inbound_lane_count_slack = 32;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    cfg.invert_grant_order = true;
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 64]).await?;
    wait_for("first 64 delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 64 && wobs.adjust_emitted_seq() > 0
    })
    .await?;
    ch.data_bytes(vec![2u8; 64]).await?;
    wait_for("second 64 delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 128
    })
    .await?;
    eprintln!(
        "w1 invert occupancy overflows={} byte_cap={} delivered={}",
        observe.overflows(),
        observe.last_byte_cap(),
        rec.bytes.load(Ordering::SeqCst)
    );
    assert_eq!(observe.last_byte_cap(), 96);
    assert_eq!(
        observe.overflows(),
        0,
        "W1 original occupancy must-fail never fired: delivered first window leaves occupancy 0, 64<96"
    );
    assert_eq!(rec.bytes.load(Ordering::SeqCst), 128);
    Ok(())
}

fn encode_close(recipient: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(5);
    p.push(97u8); // CHANNEL_CLOSE
    p.extend_from_slice(&recipient.to_be_bytes());
    p
}

/// F2-4: trailing extra byte on ADJUST is malformed — does not post,
/// does not drain, no `window_adjusted`, PeerError disconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_trailing_byte_convicts() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let board = PeerCreditBoard::new();
    let cause = DisconnectCauseSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.peer_credit = Some(board.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    wait_for("server id", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    let sid = rec.last_server_id.load(Ordering::SeqCst);
    let mut payload = encode_adjust(sid, 1024);
    payload.push(0xFF);
    ch.send_raw_payload(Bytes::from(payload)).await?;
    wait_for("PeerError disconnect", Duration::from_secs(4), || {
        cause.get() == Some(DisconnectCause::PeerError)
    })
    .await?;
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        board.len(),
        0,
        "F2-4 HARD: malformed ADJUST must not post to the board"
    );
    assert_eq!(
        rec.adjusts.load(Ordering::SeqCst),
        0,
        "F2-4 HARD: no window_adjusted callback"
    );
    Ok(())
}

/// F2-4: well-formed ADJUST for a non-existent channel is ignored
/// (established gate). Session stays up; real channel window unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adjust_unknown_channel_ignored() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let board = PeerCreditBoard::new();
    let cause = DisconnectCauseSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 64;
    cfg.maximum_packet_size = 32;
    cfg.peer_credit = Some(board.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64;
    ccfg.maximum_packet_size = 32;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let ch = session.channel_open_session().await?;
    ch.data_bytes(vec![1u8; 32]).await?;
    wait_for("32 delivered", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 32
    })
    .await?;
    let post_open_win = rec.last_window.load(Ordering::SeqCst);
    let post_open_sender = rec.last_sender.load(Ordering::SeqCst);
    assert_eq!(post_open_win, 32);
    assert_eq!(post_open_sender, 32);
    let unknown = 0xFFFF_FFFEu32;
    ch.send_raw_payload(Bytes::from(encode_adjust(unknown, 4096)))
        .await?;
    sleep(Duration::from_millis(80)).await;
    assert_eq!(
        rec.last_window.load(Ordering::SeqCst),
        post_open_win,
        "F2-4 HARD: unknown ADJUST must not change real-channel window"
    );
    assert_eq!(
        rec.last_sender.load(Ordering::SeqCst),
        post_open_sender,
        "F2-4 HARD: sender_window_size must stay post-open value"
    );
    assert_eq!(
        rec.adjusts.load(Ordering::SeqCst),
        0,
        "F2-4 HARD: no window_adjusted callback for unknown id"
    );
    assert_eq!(
        board.len(),
        0,
        "F2-4 HARD: unknown ADJUST must never enter the board"
    );
    assert!(
        cause.get().is_none(),
        "F2-4 HARD: unknown ADJUST must not disconnect ({:?})",
        cause.get()
    );
    ch.data_bytes(vec![2u8; 8]).await?;
    wait_for("still alive", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 40
    })
    .await?;
    Ok(())
}

/// F2-1: full lane + CLOSE + continuous legal ADJUST flood. CLOSE must
/// complete in bounded time; board occupancy stays O(channels).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w5_close_survives_adjust_flood() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let observe = LaneObserveSlot::new();
    let wobs = WindowObserveSlot::new();
    let hold = Arc::new(AtomicBool::new(true));
    let board = PeerCreditBoard::new();
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.lane_observe = Some(observe.clone());
    cfg.window_observe = Some(wobs.clone());
    cfg.lane_pump_hold = Some(hold.clone());
    cfg.peer_credit = Some(board.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64 * 1024;
    ccfg.maximum_packet_size = 64;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut victim = session.channel_open_session().await?;
    wait_for("victim server id", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    let victim_id = rec.last_server_id.load(Ordering::SeqCst);
    let other = session.channel_open_session().await?;
    wait_for("other open", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != victim_id
    })
    .await?;
    let opened = 2usize;

    for _ in 0..12 {
        victim.data_bytes(vec![3u8]).await?;
    }
    wait_for("victim lane full", Duration::from_secs(4), || {
        observe.last_count() >= 12
    })
    .await?;

    let t0 = std::time::Instant::now();
    victim
        .send_raw_payload(Bytes::from(encode_close(victim_id)))
        .await?;
    // Release the pump so CLOSE can be torn down while ADJUST floods.
    hold.store(false, Ordering::SeqCst);
    for i in 0..2000 {
        victim
            .send_raw_payload(Bytes::from(encode_adjust(victim_id, 1)))
            .await?;
        if i % 250 == 0 {
            assert!(
                board.len() <= opened,
                "w5 HARD: board.len()={} > opened={opened}",
                board.len()
            );
        }
    }

    let mut client_close = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline
        && !(rec.closes.load(Ordering::SeqCst) >= 1 && client_close)
    {
        match tokio::time::timeout(Duration::from_millis(20), victim.wait()).await {
            Ok(Some(ChannelMsg::Close)) => client_close = true,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "w5 close elapsed={}ms board_len={} handler_closes={} client_close={client_close}",
        elapsed.as_millis(),
        board.len(),
        rec.closes.load(Ordering::SeqCst)
    );
    assert!(
        rec.closes.load(Ordering::SeqCst) >= 1 && client_close,
        "w5 HARD: CLOSE teardown must complete (handler_closes={} client_close={client_close})",
        rec.closes.load(Ordering::SeqCst)
    );
    assert!(
        elapsed <= Duration::from_secs(4),
        "w5 HARD: CLOSE took {}ms",
        elapsed.as_millis()
    );

    hold.store(false, Ordering::SeqCst);
    other.data_bytes(vec![5u8; 32]).await?;
    wait_for("other delivered after victim CLOSE", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 32
    })
    .await?;
    sleep(Duration::from_millis(80)).await;
    let live = 1usize;
    assert!(
        board.len() <= live,
        "w5 HARD: after teardown+drain board.len()={} > live={live}",
        board.len()
    );
    eprintln!(
        "w5 close elapsed={}ms final board_len={}",
        elapsed.as_millis(),
        board.len()
    );
    Ok(())
}

/// F3-2: distinct unknown-id ADJUST flood while Session is blocked in
/// `Handler::data`. Board must stay O(live channels); unknown never
/// enters; known credit still applies after release.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w6_unknown_id_flood_board_bounded() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let board = PeerCreditBoard::new();
    let hold_ctrl = Arc::new(AtomicBool::new(false));
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.window_observe = Some(wobs.clone());
    cfg.peer_credit = Some(board.clone());
    cfg.hold_session_ctrl = Some(hold_ctrl.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;
    let mut ccfg = default_client_config();
    ccfg.window_size = 64 * 1024;
    ccfg.maximum_packet_size = 64;
    let (session, _) = connect_faulty(addr, ccfg, Progress::new()).await?;
    let mut victim = session.channel_open_session().await?;
    wait_for("victim server id", Duration::from_secs(3), || {
        rec.last_server_id.load(Ordering::SeqCst) != 0
    })
    .await?;
    let victim_id = rec.last_server_id.load(Ordering::SeqCst);
    let live_channels = 1usize;

    rec.data_hold.store(true, Ordering::SeqCst);
    rec.in_data.store(false, Ordering::SeqCst);
    hold_ctrl.store(true, Ordering::SeqCst);
    victim.data_bytes(vec![9u8; 8]).await?;
    wait_for("session inside Handler::data", Duration::from_secs(4), || {
        rec.in_data.load(Ordering::SeqCst)
    })
    .await?;

    let mut peak = 0usize;
    for i in 0..3000u32 {
        let unknown = 0xFFFF_0000u32.wrapping_add(i);
        assert_ne!(unknown, victim_id, "unknown id collided with victim");
        victim
            .send_raw_payload(Bytes::from(encode_adjust(unknown, 1)))
            .await?;
        victim
            .send_raw_payload(Bytes::from(encode_adjust(victim_id, 1)))
            .await?;
        if i % 50 == 0 {
            let n = board.len();
            peak = peak.max(n);
            assert!(
                n <= live_channels,
                "w6 HARD: during hold board.len()={n} > live={live_channels}"
            );
        }
    }
    for _ in 0..8 {
        let n = board.len();
        peak = peak.max(n);
        assert!(
            n <= live_channels,
            "w6 HARD: hold sample board.len()={n} > live={live_channels}"
        );
        sleep(Duration::from_millis(5)).await;
    }

    wait_for("unknown_adjust==3000", Duration::from_secs(4), || {
        wobs.unknown_adjust() == 3000
    })
    .await?;
    assert_eq!(wobs.unknown_adjust(), 3000);
    rec.data_hold.store(false, Ordering::SeqCst);
    hold_ctrl.store(false, Ordering::SeqCst);
    // Loop-top must apply known credit before CLOSE teardown, otherwise
    // the established gate would drop the board entry without callback.
    wait_for("known credit applied", Duration::from_secs(4), || {
        rec.adjusts.load(Ordering::SeqCst) > 0
    })
    .await?;
    assert!(
        rec.adjusts.load(Ordering::SeqCst) > 0,
        "w6 HARD: known-id ADJUST must apply (window_adjusted/adjusts=0)"
    );

    let t0 = std::time::Instant::now();
    victim
        .send_raw_payload(Bytes::from(encode_close(victim_id)))
        .await?;
    let mut client_close = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline
        && !(rec.closes.load(Ordering::SeqCst) >= 1 && client_close)
    {
        match tokio::time::timeout(Duration::from_millis(20), victim.wait()).await {
            Ok(Some(ChannelMsg::Close)) => client_close = true,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "w6 peak board.len()={peak} close elapsed={}ms handler_closes={} client_close={client_close} unknown_adjust={} adjusts={}",
        elapsed.as_millis(),
        rec.closes.load(Ordering::SeqCst),
        wobs.unknown_adjust(),
        rec.adjusts.load(Ordering::SeqCst)
    );
    assert!(
        rec.closes.load(Ordering::SeqCst) >= 1 && client_close,
        "w6 HARD: CLOSE teardown must complete (handler_closes={} client_close={client_close})",
        rec.closes.load(Ordering::SeqCst)
    );
    assert!(
        elapsed <= Duration::from_secs(4),
        "w6 HARD: CLOSE took {}ms",
        elapsed.as_millis()
    );

    let other = session.channel_open_session().await?;
    other.data_bytes(vec![5u8; 16]).await?;
    wait_for("other delivered after victim CLOSE", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= 24
    })
    .await?;
    sleep(Duration::from_millis(80)).await;
    assert_eq!(
        board.len(),
        0,
        "w6 HARD: final board.len()={} (must be 0)",
        board.len()
    );
    eprintln!(
        "w6 peak board.len()={peak} close elapsed={}ms final board_len={}",
        elapsed.as_millis(),
        board.len()
    );
    Ok(())
}

/// Stash for a server-initiated `CHANNEL_OPEN`. Dropping `reply` without
/// `accept` would send OPEN_FAILURE.
struct W7Pending {
    channel: Channel<client::Msg>,
    reply: client::ChannelOpenHandle,
}

struct W7Client {
    pending: Arc<Mutex<Option<W7Pending>>>,
    opened: Arc<AtomicBool>,
}

impl client::Handler for W7Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_session(
        &mut self,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self.pending.lock().expect("w7 pending lock") = Some(W7Pending { channel, reply });
        self.opened.store(true, Ordering::SeqCst);
        Ok(())
    }
}

async fn connect_w7(
    addr: std::net::SocketAddr,
    mut ccfg: russh::client::Config,
) -> Result<
    (
        client::Handle<W7Client>,
        Arc<Mutex<Option<W7Pending>>>,
        Arc<AtomicBool>,
    ),
    anyhow::Error,
> {
    ccfg.window_size = 0;
    let pending = Arc::new(Mutex::new(None));
    let opened = Arc::new(AtomicBool::new(false));
    let mut session = client::connect(
        Arc::new(ccfg),
        addr,
        W7Client {
            pending: pending.clone(),
            opened: opened.clone(),
        },
    )
    .await?;
    anyhow::ensure!(
        session.authenticate_none("user").await?.success(),
        "w7 auth failed"
    );
    Ok((session, pending, opened))
}

/// F4-2: server-originated OPEN, same-batch CONFIRMATION(window=0) then
/// ADJUST(n). Credit must apply so parked DATA can leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w7_server_open_confirmation_then_adjust_credits() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let robs = ReaderObserveSlot::new();
    let read_hold = ReadHoldGate::new();
    let cause = DisconnectCauseSlot::new();
    let hold_ctrl = Arc::new(AtomicBool::new(false));
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.window_observe = Some(wobs.clone());
    cfg.reader_observe = Some(robs.clone());
    cfg.reader_read_hold = Some(read_hold.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    cfg.hold_session_ctrl = Some(hold_ctrl.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;

    let mut ccfg = default_client_config();
    ccfg.window_size = 0;
    ccfg.maximum_packet_size = 64;
    let (session, pending, opened) = connect_w7(addr, ccfg).await?;
    let dummy = session.channel_open_session().await?;
    rec.open_on_data.store(true, Ordering::SeqCst);
    dummy.data_bytes(vec![1u8; 8]).await?;
    wait_for("server CHANNEL_OPEN", Duration::from_secs(4), || {
        opened.load(Ordering::SeqCst)
    })
    .await?;
    let W7Pending { mut channel, reply } = pending
        .lock()
        .expect("w7 pending lock")
        .take()
        .ok_or_else(|| anyhow::anyhow!("w7: no pending server-open"))?;
    let sid = wobs.last_lane_open();

    // Pin Session inside Handler::data so it cannot consume ctrl while
    // Reader dispatches the same-batch CONFIRMATION + ADJUST. Without
    // that, Session can confirm before Reader sees ADJUST (bypass) and
    // the test would miss the R3-P1-1 board-drop.
    rec.in_data.store(false, Ordering::SeqCst);
    rec.data_hold.store(true, Ordering::SeqCst);
    hold_ctrl.store(true, Ordering::SeqCst);
    dummy.data_bytes(vec![2u8; 1]).await?;
    wait_for("session inside Handler::data", Duration::from_secs(4), || {
        rec.in_data.load(Ordering::SeqCst)
    })
    .await?;

    // Park Reader at the next packet boundary. A dummy wake completes
    // any in-flight cipher::read so hold actually takes effect before
    // CONFIRMATION + ADJUST hit the wire.
    read_hold.hold();
    dummy.data_bytes(vec![3u8; 1]).await?;
    wait_for("reader in read_hold", Duration::from_secs(4), || {
        robs.in_read_hold()
    })
    .await?;

    let t0 = std::time::Instant::now();
    // `accept()` posts on the client's open-reply channel; `send_raw_payload`
    // posts on the per-channel sender. Those are different Session arms, so
    // back-to-back calls can put ADJUST on the wire *before* CONFIRMATION.
    // Reader is held: wait for the client loop to encode CONFIRMATION first.
    reply.accept().await;
    sleep(Duration::from_millis(80)).await;
    channel
        .send_raw_payload(Bytes::from(encode_adjust(sid, 4096)))
        .await?;
    read_hold.release();
    wait_for("unconfirmed ADJUST on ctrl", Duration::from_secs(4), || {
        wobs.unconfirmed_adjust() >= 1
    })
    .await?;
    rec.data_hold.store(false, Ordering::SeqCst);
    hold_ctrl.store(false, Ordering::SeqCst);

    let mut got = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline
        && !(rec.server_open_done.load(Ordering::SeqCst)
            && (rec.adjusts.load(Ordering::SeqCst) >= 1 || got > 0))
    {
        match tokio::time::timeout(Duration::from_millis(30), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    eprintln!(
        "w7 confirm_then_adjust confirm={} adjusts={} data={} unconfirmed={} bypass={} sid={} elapsed={}ms",
        rec.server_open_done.load(Ordering::SeqCst),
        rec.adjusts.load(Ordering::SeqCst),
        got,
        wobs.unconfirmed_adjust(),
        wobs.adjust_bypass(),
        sid,
        t0.elapsed().as_millis(),
    );
    assert!(
        rec.server_open_done.load(Ordering::SeqCst),
        "w7 HARD: Handle::channel_open_session must return"
    );
    assert!(
        rec.adjusts.load(Ordering::SeqCst) >= 1 || got > 0,
        "w7 HARD: credit must apply or DATA must arrive (adjusts={} data={got})",
        rec.adjusts.load(Ordering::SeqCst)
    );
    assert!(
        cause.get().is_none(),
        "w7 HARD: session must stay up ({:?})",
        cause.get()
    );
    Ok(())
}

/// F4-2 reverse: ADJUST before OPEN_CONFIRMATION is ignored; a later
/// ADJUST after confirm applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w7_adjust_before_confirmation_ignored() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let cause = DisconnectCauseSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.window_observe = Some(wobs.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_rec(rec.clone(), cfg, 0).await;

    let mut ccfg = default_client_config();
    ccfg.window_size = 0;
    ccfg.maximum_packet_size = 64;
    let (session, pending, opened) = connect_w7(addr, ccfg).await?;
    let dummy = session.channel_open_session().await?;
    rec.open_on_data.store(true, Ordering::SeqCst);
    dummy.data_bytes(vec![1u8; 8]).await?;
    wait_for("server CHANNEL_OPEN", Duration::from_secs(4), || {
        opened.load(Ordering::SeqCst)
    })
    .await?;
    let W7Pending { mut channel, reply } = pending
        .lock()
        .expect("w7 pending lock")
        .take()
        .ok_or_else(|| anyhow::anyhow!("w7 reverse: no pending server-open"))?;
    let sid = wobs.last_lane_open();

    let t0 = std::time::Instant::now();
    channel
        .send_raw_payload(Bytes::from(encode_adjust(sid, 4096)))
        .await?;
    wait_for("unconfirmed_adjust>=1", Duration::from_secs(4), || {
        wobs.unconfirmed_adjust() >= 1
    })
    .await?;
    reply.accept().await;
    wait_for("confirmation", Duration::from_secs(4), || {
        rec.server_open_done.load(Ordering::SeqCst)
    })
    .await?;
    // Pre-confirm ADJUST must not have been applied.
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        rec.adjusts.load(Ordering::SeqCst),
        0,
        "w7 reverse HARD: pre-confirm ADJUST must not apply"
    );
    assert!(
        cause.get().is_none(),
        "w7 reverse HARD: session must stay up after ignored ADJUST ({:?})",
        cause.get()
    );

    channel
        .send_raw_payload(Bytes::from(encode_adjust(sid, 4096)))
        .await?;
    let mut got = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline
        && !(rec.adjusts.load(Ordering::SeqCst) >= 1 || got > 0)
    {
        match tokio::time::timeout(Duration::from_millis(30), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    eprintln!(
        "w7 adjust_before_confirm unconfirmed={} adjusts={} data={} bypass={} sid={} elapsed={}ms",
        wobs.unconfirmed_adjust(),
        rec.adjusts.load(Ordering::SeqCst),
        got,
        wobs.adjust_bypass(),
        sid,
        t0.elapsed().as_millis(),
    );
    assert!(
        rec.adjusts.load(Ordering::SeqCst) >= 1 || got > 0,
        "w7 reverse HARD: post-confirm ADJUST must apply (adjusts={} data={got})",
        rec.adjusts.load(Ordering::SeqCst)
    );
    assert!(
        cause.get().is_none(),
        "w7 reverse HARD: session must stay up ({:?})",
        cause.get()
    );
    Ok(())
}

/// F5-2: server-open rejected with OPEN_FAILURE must reclaim the
/// unconfirmed inbound lane. Loop ≥8 times; no ghost growth.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w8_open_failure_reclaims_lane() -> Result<(), anyhow::Error> {
    let rec = Rec::default();
    let wobs = WindowObserveSlot::new();
    let cause = DisconnectCauseSlot::new();
    let mut cfg = base_cfg();
    cfg.window_size = 256;
    cfg.maximum_packet_size = 64;
    cfg.window_observe = Some(wobs.clone());
    cfg.disconnect_cause_slot = Some(cause.clone());
    let addr = spawn_rec(rec.clone(), cfg, 16).await;

    let mut ccfg = default_client_config();
    ccfg.window_size = 256;
    ccfg.maximum_packet_size = 64;
    // Do not use `connect_w7`: it zeros the client window so server DATA parks.
    let pending = Arc::new(Mutex::new(None));
    let opened = Arc::new(AtomicBool::new(false));
    let mut session = client::connect(
        Arc::new(ccfg),
        addr,
        W7Client {
            pending: pending.clone(),
            opened: opened.clone(),
        },
    )
    .await?;
    anyhow::ensure!(
        session.authenticate_none("user").await?.success(),
        "w8 auth failed"
    );
    let dummy = session.channel_open_session().await?;
    wait_for("dummy lane registered", Duration::from_secs(4), || {
        wobs.lane_count() >= 1
    })
    .await?;
    let dummy_id = dummy.id().number();
    let live_before = wobs.lane_count();

    let mut rejected = Vec::new();
    for i in 0..8 {
        rec.server_open_fail.store(false, Ordering::SeqCst);
        rec.server_open_done.store(false, Ordering::SeqCst);
        opened.store(false, Ordering::SeqCst);
        rec.open_on_data.store(true, Ordering::SeqCst);
        dummy.data_bytes(vec![1u8; 8]).await?;
        wait_for(
            &format!("server CHANNEL_OPEN #{i}"),
            Duration::from_secs(4),
            || opened.load(Ordering::SeqCst),
        )
        .await?;
        let W7Pending { channel, reply } = pending
            .lock()
            .expect("w8 pending lock")
            .take()
            .ok_or_else(|| anyhow::anyhow!("w8: no pending server-open #{i}"))?;
        let sid = wobs.last_lane_open();
        assert_ne!(sid, dummy_id, "w8 HARD: last_lane_open must be the server-open, not dummy");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        drop(channel);
        wait_for(
            &format!("rejected id {sid} gone"),
            Duration::from_secs(4),
            || wobs.is_confirmed(sid).is_none() && !wobs.lane_has(sid),
        )
        .await?;
        wait_for(
            &format!("Handle OPEN_FAILURE #{i}"),
            Duration::from_secs(4),
            || rec.server_open_fail.load(Ordering::SeqCst),
        )
        .await?;
        assert!(
            rec.server_open_done.load(Ordering::SeqCst) == false,
            "w8 HARD: reject must not confirm"
        );
        assert!(
            cause.get().is_none(),
            "w8 HARD: session must stay up after reject #{i} ({:?})",
            cause.get()
        );
        rejected.push(sid);
    }

    eprintln!(
        "w8 rejected_ids={rejected:?} lane_count={} live_before={live_before} dummy={dummy_id}",
        wobs.lane_count()
    );
    assert_eq!(
        wobs.lane_count(),
        live_before,
        "w8 HARD: lane_count after 8 rejects must equal live channels (dummy), not dummy+ghosts (count={} live_before={live_before})",
        wobs.lane_count()
    );
    for sid in &rejected {
        assert!(
            wobs.is_confirmed(*sid).is_none(),
            "w8 HARD: rejected id {sid} still a member"
        );
    }

    let bytes0 = rec.bytes.load(Ordering::SeqCst);
    let mut peer = session.channel_open_session().await?;
    peer.data_bytes(vec![5u8; 16]).await?;
    wait_for("peer-open client→server DATA", Duration::from_secs(4), || {
        rec.bytes.load(Ordering::SeqCst) >= bytes0 + 16
    })
    .await?;
    let mut got = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline && got < 16 {
        match tokio::time::timeout(Duration::from_millis(30), peer.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
            Ok(Some(_)) => {}
            _ => {}
        }
    }
    eprintln!(
        "w8 peer-open data_both_ways got={got} bytes={} lane_count={} cause={:?}",
        rec.bytes.load(Ordering::SeqCst),
        wobs.lane_count(),
        cause.get()
    );
    assert!(
        got >= 16,
        "w8 HARD: peer-open must deliver server→client DATA (got={got})"
    );
    assert!(
        cause.get().is_none(),
        "w8 HARD: session must stay up after peer-open ({:?})",
        cause.get()
    );
    Ok(())
}
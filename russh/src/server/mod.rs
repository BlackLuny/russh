// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! # Writing servers
//!
//! There are two ways of accepting connections:
//! * implement the [Server](server::Server) trait and let [run_on_socket](server::Server::run_on_socket)/[run_on_address](server::Server::run_on_address) handle everything
//! * accept connections yourself and pass them to [run_stream](server::run_stream)
//!
//! In both cases, you'll first need to implement the [Handler](server::Handler) trait -
//! this is where you'll handle various events.
//!
//! Check out the following examples:
//!
//! * [Server that forwards your input to all connected clients](https://github.com/warp-tech/russh/blob/main/russh/examples/echoserver.rs)
//! * [Server handing channel processing off to a library (here, `russh-sftp`)](https://github.com/warp-tech/russh/blob/main/russh/examples/sftp_server.rs)
//! * Serving `ratatui` based TUI app to clients: [per-client](https://github.com/warp-tech/russh/blob/main/russh/examples/ratatui_app.rs), [shared](https://github.com/warp-tech/russh/blob/main/russh/examples/ratatui_shared_app.rs)

use std;
use std::collections::{HashMap, VecDeque};
use std::num::Wrapping;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use client::GexParams;
use futures::future::Future;
use log::{debug, error, info, warn};
use msg::{is_kex_msg, validate_client_msg_strict_kex};
use russh_util::runtime::JoinHandle;
use ssh_key::{Certificate, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::pin;
use tokio::sync::{broadcast, mpsc};

use crate::cipher::{OpeningKey, clear};
use crate::kex::dh::groups::{BUILTIN_SAFE_DH_GROUPS, DH_GROUP14, DhGroup};
use crate::kex::{KexProgress, SessionKexState};
use crate::session::*;
use crate::ssh_read::*;
use crate::sshbuffer::*;
use crate::*;

mod kex;
mod session;
mod session_facade;
pub use self::session::*;
mod encrypted;
pub mod supervisor;
pub mod writer;
pub mod reader;
pub(crate) mod inbound_lane;
pub use self::supervisor::{
    AtomicWriteProgress, DisconnectCause, DisconnectCauseSlot, WriteProgress,
};
#[cfg(feature = "_test_hooks")]
pub use self::supervisor::{
    CapacityChainSlot, DeferredGrantSlot, FullLedger, InjectIgnoreGate, InstallAckHoldGate,
    KexInstallObserveSlot, LedgerMaxSlot, NeedSubmitSeenSlot, OutboundOrderSlot,
    ReplyQueueSlot, SchedSlot, StopDiscardSlot, WatchdogObserveSlot,
};
#[cfg(feature = "_test_hooks")]
pub use self::reader::{MidPacketHold, ReadHoldGate, ReaderObserveSlot};
#[cfg(feature = "_test_hooks")]
pub use self::inbound_lane::LaneObserveSlot;
#[cfg(feature = "_test_hooks")]
pub use self::inbound_lane::WindowObserveSlot;
pub use self::inbound_lane::PeerCreditBoard;
pub use self::writer::{WriterHandle, WriterEvent, KEX_QUEUE_CAP};

/// Configuration of a server.
pub struct Config {
    /// The server ID string sent at the beginning of the protocol.
    pub server_id: SshId,
    /// Authentication methods proposed to the client.
    pub methods: auth::MethodSet,
    /// Authentication rejections must happen in constant time for
    /// security reasons. Russh does not handle this by default.
    pub auth_rejection_time: std::time::Duration,
    /// Authentication rejection time override for the initial "none" auth attempt.
    /// OpenSSH clients will send an initial "none" auth to probe for authentication methods.
    pub auth_rejection_time_initial: Option<std::time::Duration>,
    /// The server's keys. The first key pair in the client's preference order will be chosen.
    pub keys: Vec<PrivateKey>,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Buffer size for each channel (a number of unprocessed messages to store before propagating backpressure to the TCP stream)
    pub channel_buffer_size: usize,
    /// Internal event buffer size
    pub event_buffer_size: usize,
    /// S3b ctrl byte budget. Full → Cancelling (I2'). Default 2 MiB.
    pub inbound_ctrl_budget: usize,
    /// Extra zero-byte / REQUEST slots in the per-channel count bound (`K`).
    pub inbound_lane_count_slack: usize,
    /// Smallest packet used for `count_cap = window / min(8, this) + K`.
    pub inbound_min_packet_size: u32,
    /// When true, over-window inbound DATA would disconnect. Default
    /// **false**; this slice does not wire the disconnect (RFC 4254 §5.2
    /// extra-data ignore stays). Independent decision later.
    pub strict_window_enforcement: bool,
    /// Hard safety cap on the number of inbound payload bytes that may be queued per channel
    /// while its application buffer is full (head-of-line backpressure, see
    /// `RC2_HOL_FIX_DESIGN.md`). With delivery-gated window grants a well-behaved peer can hold at
    /// most ~`window_size` bytes in flight, so this only trips when a peer ignores its advertised
    /// window; exceeding it closes that one channel as a protocol violation, never the session.
    pub max_pending_inbound_bytes: usize,
    /// Hard safety cap on the number of outbound payload bytes that may be queued per channel
    /// while the peer's receive window is exhausted.
    ///
    /// Producers that reserve window before enqueueing (`Channel::data` / `Channel::make_writer`)
    /// are already backpressured per channel and never reach this. It bounds the producers that
    /// bypass that accounting — [`Handle::data`] and [`Handle::extended_data`], which enqueue
    /// unconditionally — so a single runaway channel is closed as a protocol violation instead of
    /// growing without bound. Exceeding it closes that one channel, never the session.
    pub max_pending_outbound_bytes: usize,
    /// Lists of preferred algorithms.
    pub preferred: Preferred,
    /// Maximal number of allowed authentication attempts.
    pub max_auth_attempts: usize,
    /// Time after which the connection is garbage-collected.
    pub inactivity_timeout: Option<std::time::Duration>,
    /// If nothing is received from the client for this amount of time, send a keepalive message.
    pub keepalive_interval: Option<std::time::Duration>,
    /// If this many keepalives have been sent without reply, close the connection.
    pub keepalive_max: usize,
    /// If active, invoke `set_nodelay(true)` on client sockets; disabled by default (i.e. Nagle's algorithm is active).
    pub nodelay: bool,
    /// ConnSupervisor (§4.2): no socket write progress while wire-eligible for this long
    /// → `Cancelling(WriteStalled)`. Default 30s.
    pub write_progress_deadline: std::time::Duration,
    /// ConnSupervisor strategy layer: while write-watchdog is armed, if fewer than
    /// `.0` bytes are drained in `.1`, treat as stalled (trickle-read). `None` disables.
    /// **Default `None`** (opt-in): activity-layer `write_progress_deadline` alone covers
    /// permanent write stall; a global min-drain default would mis-kill legitimate slow links.
    pub write_min_drain: Option<(usize, std::time::Duration)>,
    /// ConnSupervisor: banner + initial kex + auth must complete within this budget.
    /// Default 30s.
    pub handshake_deadline: std::time::Duration,
    /// ConnSupervisor: a rekey (InKex) must complete within this budget or the
    /// connection is torn down with `RekeyTimeout`. Default 30s.
    pub rekey_deadline: std::time::Duration,
    /// Best-effort DISCONNECT + drain grace after Cancelling before hard drop.
    /// Default 5s (not stacked with other deadlines).
    pub teardown_grace: std::time::Duration,
    /// Test-only first-cause slot (S1 harness). Production leaves this `None`.
    #[cfg(feature = "_test_hooks")]
    pub disconnect_cause_slot: Option<std::sync::Arc<supervisor::DisconnectCauseSlot>>,
    /// Test-only: delay Session consumption of Writer InstallAck until released.
    #[cfg(feature = "_test_hooks")]
    pub install_ack_hold: Option<std::sync::Arc<supervisor::InstallAckHoldGate>>,
    /// Test-only: count NeedSubmit entries for atomic KEX install.
    #[cfg(feature = "_test_hooks")]
    pub need_submit_seen: Option<std::sync::Arc<supervisor::NeedSubmitSeenSlot>>,
    /// Test-only: live KEX install phase + non-Idle observation for R2/R3/R5/R6.
    #[cfg(feature = "_test_hooks")]
    pub kex_install_observe: Option<std::sync::Arc<supervisor::KexInstallObserveSlot>>,
    /// Test-only: atomic max of sealed_backlog_bytes (R4 numerical bound).
    #[cfg(feature = "_test_hooks")]
    pub ledger_max: Option<std::sync::Arc<supervisor::LedgerMaxSlot>>,
    /// Test-only: next Writer seal fails once (R5 ACK/Writer-fail inject).
    #[cfg(feature = "_test_hooks")]
    pub fail_next_seal: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: when true, Writer hangs socket writes (HangWrite) but still
    /// dequeues/seals into out_q — deterministic Full / NeedSubmit (R2/R3/R4).
    #[cfg(feature = "_test_hooks")]
    pub socket_hang: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: next bulk try_send / SealBatch returns Full once (R2/R3/R4).
    #[cfg(feature = "_test_hooks")]
    pub force_next_bulk_full: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: next Writer socket write fails once with an I/O error (R5).
    #[cfg(feature = "_test_hooks")]
    pub fail_next_socket_write: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: disable the 20ms NeedSubmit poll sleep so the ONLY liveness
    /// source for a parked KEX install is the Writer capacity notify (R3).
    #[cfg(feature = "_test_hooks")]
    pub need_submit_timer_disable: bool,
    /// Test-only: R3 liveness chain counters (dequeue notify → capacity arm →
    /// install advance).
    #[cfg(feature = "_test_hooks")]
    pub capacity_chain: Option<std::sync::Arc<supervisor::CapacityChainSlot>>,
    /// Test-only: count inbound CHANNEL_WINDOW_ADJUST packets (F1 replenishment
    /// proof — each arriving adjust is one credit replenishment).
    #[cfg(feature = "_test_hooks")]
    pub window_adjust_seen: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Test-only: pause Writer mpsc dequeue (R3 one-cmd gate).
    #[cfg(feature = "_test_hooks")]
    pub dequeue_hold: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: wake Session to emit one IGNORE into the Writer mpsc (R3).
    #[cfg(feature = "_test_hooks")]
    pub inject_ignore: Option<std::sync::Arc<supervisor::InjectIgnoreGate>>,
    /// Test-only: deferred WINDOW_ADJUST insert/replay/emitted counters.
    #[cfg(feature = "_test_hooks")]
    pub deferred_grant: Option<std::sync::Arc<supervisor::DeferredGrantSlot>>,
    /// Test-only: write-watchdog armed / eligible / rekey-gen edges.
    #[cfg(feature = "_test_hooks")]
    pub watchdog_observe: Option<std::sync::Arc<supervisor::WatchdogObserveSlot>>,
    /// Test-only: per-channel outbound emit order (S2c fence / wire order).
    #[cfg(feature = "_test_hooks")]
    pub outbound_order: Option<std::sync::Arc<supervisor::OutboundOrderSlot>>,
    /// Test-only: hold Session consumption of Reader inbound InstallAck (N8).
    #[cfg(feature = "_test_hooks")]
    pub inbound_ack_hold: Option<std::sync::Arc<supervisor::InstallAckHoldGate>>,
    /// Test-only: observe Reader park/await/apply (N1–N8 / mid-read).
    #[cfg(feature = "_test_hooks")]
    pub reader_observe: Option<std::sync::Arc<reader::ReaderObserveSlot>>,
    /// Test-only: hold Reader at packet boundary before `cipher::read` (risk 2).
    #[cfg(feature = "_test_hooks")]
    pub reader_read_hold: Option<std::sync::Arc<reader::ReadHoldGate>>,
    /// Test-only: next inbound epoch try_push fails as Full (N7).
    #[cfg(feature = "_test_hooks")]
    pub force_inbound_install_full: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: skip NeedsReply inbound send so NEWKEYS-first is forced (N2).
    #[cfg(feature = "_test_hooks")]
    pub delay_inbound_epoch: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: stall `cipher::read` mid-packet (risk-2 hard test).
    #[cfg(feature = "_test_hooks")]
    pub reader_mid_packet_hold: Option<std::sync::Arc<reader::MidPacketHold>>,
    /// Test-only: next Reader transport read becomes ReadError.
    #[cfg(feature = "_test_hooks")]
    pub reader_fail_next_read: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: hold Reader after inbound epoch recv, before apply (N5).
    #[cfg(feature = "_test_hooks")]
    pub reader_apply_hold: Option<std::sync::Arc<reader::ReadHoldGate>>,
    /// Test-only: Writer took the socket-hang path with sealed-but-undrained bytes.
    #[cfg(feature = "_test_hooks")]
    pub socket_hang_seen: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Test-only: queued SUCCESS/FAILURE count (S2c fix1 generation admit).
    #[cfg(feature = "_test_hooks")]
    pub reply_queue: Option<std::sync::Arc<supervisor::ReplyQueueSlot>>,
    /// Test-only: S2d ready-set / boost counters.
    #[cfg(feature = "_test_hooks")]
    pub sched: Option<std::sync::Arc<supervisor::SchedSlot>>,
    /// Test-only: skip first-packet boost (on/off position contrast).
    #[cfg(feature = "_test_hooks")]
    pub disable_sched_boost: bool,
    /// Test-only: StopDiscard discarded-item / grant-clear counters.
    #[cfg(feature = "_test_hooks")]
    pub stop_discard: Option<std::sync::Arc<supervisor::StopDiscardSlot>>,
    /// Next ctrl try_push fails (S3b Q7).
    #[cfg(feature = "_test_hooks")]
    pub force_ctrl_full: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(feature = "_test_hooks")]
    pub lane_observe: Option<std::sync::Arc<inbound_lane::LaneObserveSlot>>,
    /// Session skips pumping Reader lanes (S3b Q6 fill).
    #[cfg(feature = "_test_hooks")]
    pub lane_pump_hold: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(feature = "_test_hooks")]
    pub inject_zero_data: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// After the next real DATA, flood the lane until Overflow (Q5).
    #[cfg(feature = "_test_hooks")]
    pub inject_until_overflow: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// After the next real DATA, inject CHANNEL_CLOSE for this channel id (0 = off).
    #[cfg(feature = "_test_hooks")]
    pub inject_close_for: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Test-only: grant-order / ADJUST-bypass counters (W2/W3).
    #[cfg(feature = "_test_hooks")]
    pub window_observe: Option<std::sync::Arc<inbound_lane::WindowObserveSlot>>,
    /// Test-only: swap emit-ADJUST / expand in `grant_expand_then_adjust`
    /// (same two production calls, inverted). Proves W3 is a real must-fail.
    #[cfg(feature = "_test_hooks")]
    pub invert_grant_order: bool,
    /// Test-only: inject the in-flight ADJUST aggregation board.
    #[cfg(feature = "_test_hooks")]
    pub peer_credit: Option<std::sync::Arc<inbound_lane::PeerCreditBoard>>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: SshId::Standard(Cow::Borrowed(concat!(
                "SSH-2.0-",
                env!("CARGO_PKG_NAME"),
                "_",
                env!("CARGO_PKG_VERSION")
            ))),
            methods: auth::MethodSet::all(),
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: None,
            keys: Vec::new(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            channel_buffer_size: 100,
            event_buffer_size: 10,
            inbound_ctrl_budget: crate::server::inbound_lane::INBOUND_CTRL_BUDGET,
            inbound_lane_count_slack: crate::server::inbound_lane::INBOUND_LANE_COUNT_SLACK,
            inbound_min_packet_size: crate::server::inbound_lane::INBOUND_LANE_MIN_PACKET as u32,
            strict_window_enforcement: false,
            max_pending_inbound_bytes: 8 * 2_000_000,
            max_pending_outbound_bytes: 8 * 2_000_000,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10,
            inactivity_timeout: Some(std::time::Duration::from_secs(600)),
            keepalive_interval: None,
            keepalive_max: 3,
            nodelay: false,
            write_progress_deadline: std::time::Duration::from_secs(30),
            // Strategy layer OFF by default: low throughput is not protocol-malicious
            // (weak networks / rate-limited downloads). Deployments with a hard min-bandwidth
            // SLA may opt in via `Some((bytes, window))`. Activity layer remains ON.
            write_min_drain: None,
            handshake_deadline: std::time::Duration::from_secs(30),
            rekey_deadline: std::time::Duration::from_secs(30),
            teardown_grace: std::time::Duration::from_secs(5),
            #[cfg(feature = "_test_hooks")]
            disconnect_cause_slot: None,
            #[cfg(feature = "_test_hooks")]
            install_ack_hold: None,
            #[cfg(feature = "_test_hooks")]
            need_submit_seen: None,
            #[cfg(feature = "_test_hooks")]
            kex_install_observe: None,
            #[cfg(feature = "_test_hooks")]
            ledger_max: None,
            #[cfg(feature = "_test_hooks")]
            fail_next_seal: None,
            #[cfg(feature = "_test_hooks")]
            socket_hang: None,
            #[cfg(feature = "_test_hooks")]
            force_next_bulk_full: None,
            #[cfg(feature = "_test_hooks")]
            fail_next_socket_write: None,
            #[cfg(feature = "_test_hooks")]
            need_submit_timer_disable: false,
            #[cfg(feature = "_test_hooks")]
            capacity_chain: None,
            #[cfg(feature = "_test_hooks")]
            window_adjust_seen: None,
            #[cfg(feature = "_test_hooks")]
            dequeue_hold: None,
            #[cfg(feature = "_test_hooks")]
            inject_ignore: None,
            #[cfg(feature = "_test_hooks")]
            deferred_grant: None,
            #[cfg(feature = "_test_hooks")]
            watchdog_observe: None,
            #[cfg(feature = "_test_hooks")]
            outbound_order: None,
            #[cfg(feature = "_test_hooks")]
            inbound_ack_hold: None,
            #[cfg(feature = "_test_hooks")]
            reader_observe: None,
            #[cfg(feature = "_test_hooks")]
            reader_read_hold: None,
            #[cfg(feature = "_test_hooks")]
            force_inbound_install_full: None,
            #[cfg(feature = "_test_hooks")]
            delay_inbound_epoch: None,
            #[cfg(feature = "_test_hooks")]
            reader_mid_packet_hold: None,
            #[cfg(feature = "_test_hooks")]
            reader_fail_next_read: None,
            #[cfg(feature = "_test_hooks")]
            reader_apply_hold: None,
            #[cfg(feature = "_test_hooks")]
            socket_hang_seen: None,
            #[cfg(feature = "_test_hooks")]
            reply_queue: None,
            #[cfg(feature = "_test_hooks")]
            sched: None,
            #[cfg(feature = "_test_hooks")]
            disable_sched_boost: false,
            #[cfg(feature = "_test_hooks")]
            stop_discard: None,
            #[cfg(feature = "_test_hooks")]
            force_ctrl_full: None,
            #[cfg(feature = "_test_hooks")]
            lane_observe: None,
            #[cfg(feature = "_test_hooks")]
            lane_pump_hold: None,
            #[cfg(feature = "_test_hooks")]
            inject_zero_data: None,
            #[cfg(feature = "_test_hooks")]
            inject_until_overflow: None,
            #[cfg(feature = "_test_hooks")]
            inject_close_for: None,
            #[cfg(feature = "_test_hooks")]
            window_observe: None,
            #[cfg(feature = "_test_hooks")]
            invert_grant_order: false,
            #[cfg(feature = "_test_hooks")]
            peer_credit: None,
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // display everything except the private keys
        f.debug_struct("Config")
            .field("server_id", &self.server_id)
            .field("methods", &self.methods)
            .field("auth_rejection_time", &self.auth_rejection_time)
            .field(
                "auth_rejection_time_initial",
                &self.auth_rejection_time_initial,
            )
            .field("keys", &"***")
            .field("window_size", &self.window_size)
            .field("maximum_packet_size", &self.maximum_packet_size)
            .field("channel_buffer_size", &self.channel_buffer_size)
            .field("event_buffer_size", &self.event_buffer_size)
            .field("max_pending_inbound_bytes", &self.max_pending_inbound_bytes)
            .field("max_pending_outbound_bytes", &self.max_pending_outbound_bytes)
            .field("limits", &self.limits)
            .field("preferred", &self.preferred)
            .field("max_auth_attempts", &self.max_auth_attempts)
            .field("inactivity_timeout", &self.inactivity_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_max", &self.keepalive_max)
            .finish()
    }
}

/// A client's response in a challenge-response authentication.
///
/// You should iterate it to get `&[u8]` response slices.
pub struct Response<'a>(&'a mut (dyn Iterator<Item = Option<Bytes>> + Send));

impl Iterator for Response<'_> {
    type Item = Bytes;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().flatten()
    }
}

use std::borrow::Cow;
/// An authentication result, in a challenge-response authentication.
#[derive(Debug, PartialEq, Eq)]
pub enum Auth {
    /// Reject the authentication request.
    Reject {
        proceed_with_methods: Option<MethodSet>,
        partial_success: bool,
    },
    /// Accept the authentication request.
    Accept,

    /// Method was not accepted, but no other check was performed.
    UnsupportedMethod,

    /// Partially accept the challenge-response authentication
    /// request, providing more instructions for the client to follow.
    Partial {
        /// Name of this challenge.
        name: Cow<'static, str>,
        /// Instructions for this challenge.
        instructions: Cow<'static, str>,
        /// A number of prompts to the user. Each prompt has a `bool`
        /// indicating whether the terminal must echo the characters
        /// typed by the user.
        prompts: Cow<'static, [(Cow<'static, str>, bool)]>,
    },
}

impl Auth {
    pub fn reject() -> Self {
        Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        }
    }
}

/// Server handler. Each client will have their own handler.
///
/// Note: this is an async trait. The trait functions return `impl Future`,
/// and you can simply define them as `async fn` instead.
#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
pub trait Handler: Sized {
    type Error: From<crate::Error> + Send;

    /// Check authentication using the "none" method.
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_none(&mut self, user: &str) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::reject()) }
    }

    /// Check authentication using the "password" method.
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::reject()) }
    }

    /// Pre-authentication callback for public key authentication.
    /// This method is called when a client is:
    /// * probing public key authentication without a signature (yet) or
    /// * attempting authentication with a signature without doing
    ///   a prior probe.
    ///
    /// The purpose of this callback is to spare the effort of signing
    /// and verifying the signature if the server will not accept this
    /// public key anyway.
    ///
    /// Note that at this stage, the ownership of the key has
    /// not been verified yet.
    ///
    /// You should not alter your session's authentication state
    /// from this callback. Implement your actual authentication check
    /// in [`Handler::auth_publickey`]. Seeing an unknown key here should
    /// in most cases not be counted towards an eventual authentication
    /// attempt limit.
    ///
    /// The default implementation accepts all keys, allowing them to
    /// proceed to [`Handler::auth_publickey`].
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::Accept) }
    }

    /// Check authentication using the "publickey" method. This method
    /// is called after the signature has been verified and key
    /// ownership has been confirmed.
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::reject()) }
    }

    /// Check authentication using an OpenSSH certificate. This method
    /// is called after the signature has been verified and key
    /// ownership has been confirmed.
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::reject()) }
    }

    /// Check authentication using the "keyboard-interactive"
    /// method.
    ///
    /// Russh makes sure rejection takes a constant [`Config::auth_rejection_time`],
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        submethods: &str,
        response: Option<Response<'a>>,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::reject()) }
    }

    /// Called when authentication succeeds for a session.
    #[allow(unused_variables)]
    fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when authentication starts but before it is successful.
    /// Return value is an authentication banner, usually a warning message shown to the client.
    #[allow(unused_variables)]
    fn authentication_banner(
        &mut self,
    ) -> impl Future<Output = Result<Option<String>, Self::Error>> + Send {
        async { Ok(None) }
    }

    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a new session channel is requested by the client.
    ///
    /// The handler receives a [`ChannelOpenHandle`] that must be used to accept or
    /// reject the request. Dropping the handle without calling either method
    /// automatically rejects the channel.
    #[allow(unused_variables)]
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a new X11 channel is requested by the client.
    ///
    /// The handler receives a [`ChannelOpenHandle`] that must be used to accept or
    /// reject the request. Dropping the handle without calling either method
    /// automatically rejects the channel.
    #[allow(unused_variables)]
    fn channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a new direct TCP/IP ("local TCP forwarding") channel is requested.
    ///
    /// The handler receives a [`ChannelOpenHandle`] that must be used to accept or
    /// reject the request. Dropping the handle without calling either method
    /// automatically rejects the channel.
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a new remote forwarded TCP connection comes in.
    ///
    /// The handler receives a [`ChannelOpenHandle`] that must be used to accept or
    /// reject the request. Dropping the handle without calling either method
    /// automatically rejects the channel.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc4254#section-7>
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    fn channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a new direct-streamlocal ("local UNIX socket forwarding") channel is requested.
    ///
    /// The handler receives a [`ChannelOpenHandle`] that must be used to accept or
    /// reject the request. Dropping the handle without calling either method
    /// automatically rejects the channel.
    #[allow(unused_variables)]
    fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the client confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(
        &mut self,
        channel: ChannelId,
        new_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when this server adjusts the network window. Return the
    /// next target window.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, current: u32) -> u32 {
        current
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn pty_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     term: &str,
    ///     col_width: u32,
    ///     row_height: u32,
    ///     pix_width: u32,
    ///     pix_height: u32,
    ///     modes: &[(Pty, u32)],
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables, clippy::too_many_arguments)]
    fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client requests an X11 connection.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn x11_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     single_connection: bool,
    ///     x11_auth_protocol: &str,
    ///     x11_auth_cookie: &str,
    ///     x11_screen_number: u32,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn env_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     variable_name: &str,
    ///     variable_value: &str,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client requests a shell.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn shell_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn exec_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     data: &[u8],
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client asks to start the subsystem with the given name
    /// (such as sftp).
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn subsystem_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     name: &str,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client's pseudo-terminal window size has changed.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn window_change_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     col_width: u32,
    ///     row_height: u32,
    ///     pix_width: u32,
    ///     pix_height: u32,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The client requests OpenSSH agent forwarding
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// [`Session::channel_success`] or [`Session::channel_failure`] respectively.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// async fn agent_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     session: &mut Session,
    /// ) -> Result<bool, Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    /// The client is sending a signal (usually to pass to the
    /// currently running process).
    #[allow(unused_variables)]
    fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Used for reverse-forwarding ports, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    /// If `port` is 0, you should set it to the allocated port number.
    #[allow(unused_variables)]
    fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    /// Used to stop the reverse-forwarding of a port, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    #[allow(unused_variables)]
    fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    #[allow(unused_variables)]
    fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    /// Override when enabling the `diffie-hellman-group-exchange-*` key exchange methods.
    ///
    /// Should return a Diffie-Hellman group with a safe prime whose length is
    /// between `gex_params.min_group_size` and `gex_params.max_group_size` and
    /// (if possible) over and as close as possible to `gex_params.preferred_group_size`.
    ///
    /// OpenSSH uses a pre-generated database of safe primes stored in `/etc/ssh/moduli`
    ///
    /// The default implementation picks a group from a very short static list
    /// of built-in standard groups and is not really taking advantage of the security
    /// offered by these kex methods.
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc4419#section-3
    #[allow(unused_variables)]
    fn lookup_dh_gex_group(
        &mut self,
        gex_params: &GexParams,
    ) -> impl Future<Output = Result<Option<DhGroup>, Self::Error>> + Send {
        async {
            let mut best_group = &DH_GROUP14;

            // Find _some_ matching group
            for group in BUILTIN_SAFE_DH_GROUPS.iter() {
                if group.bit_size() >= gex_params.min_group_size()
                    && group.bit_size() <= gex_params.max_group_size()
                {
                    best_group = *group;
                    break;
                }
            }

            // Find _closest_ matching group
            for group in BUILTIN_SAFE_DH_GROUPS.iter() {
                if group.bit_size() > gex_params.preferred_group_size() {
                    best_group = *group;
                    break;
                }
            }

            Ok(Some(best_group.clone()))
        }
    }
}

pub struct RunningServerHandle {
    shutdown_tx: broadcast::Sender<String>,
}

impl RunningServerHandle {
    /// Request graceful server shutdown.
    /// Starts the shutdown and immediately returns.
    /// To wait for all the clients to disconnect, await `RunningServer` .
    pub fn shutdown(&self, reason: String) {
        let _ = self.shutdown_tx.send(reason);
    }
}

pub struct RunningServer<F: Future<Output = std::io::Result<()>> + Unpin + Send> {
    inner: F,
    shutdown_tx: broadcast::Sender<String>,
}

impl<F: Future<Output = std::io::Result<()>> + Unpin + Send> RunningServer<F> {
    pub fn handle(&self) -> RunningServerHandle {
        RunningServerHandle {
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

impl<F: Future<Output = std::io::Result<()>> + Unpin + Send> Future for RunningServer<F> {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Future::poll(Pin::new(&mut self.inner), cx)
    }
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
/// Trait used to create new handlers when clients connect.
pub trait Server {
    /// The type of handlers.
    type Handler: Handler + Send + 'static;
    /// Called when a new client connects.
    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler;
    /// Called when an active connection fails.
    fn handle_session_error(&mut self, _error: <Self::Handler as Handler>::Error) {}

    /// Run a server on a specified `tokio::net::TcpListener`. Useful when dropping
    /// privileges immediately after socket binding, for example.
    fn run_on_socket(
        &mut self,
        config: Arc<Config>,
        socket: &TcpListener,
    ) -> RunningServer<impl Future<Output = std::io::Result<()>> + Unpin + Send>
    where
        Self: Send,
    {
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let shutdown_tx2 = shutdown_tx.clone();

        let fut = async move {
            if config.maximum_packet_size > 65535 {
                error!(
                    "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
                    config.maximum_packet_size
                );
            }

            let (error_tx, mut error_rx) = mpsc::unbounded_channel();

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Server shutdown requested");
                        return Ok(());
                    },
                    accept_result = socket.accept() => {
                        match accept_result {
                            Ok((socket, peer_addr)) => {
                                let mut shutdown_rx = shutdown_tx2.subscribe();

                                let config = config.clone();
                                // NOTE: For backwards compatibility, we keep the Option signature as changing it would be a breaking change.
                                let handler = self.new_client(Some(peer_addr));
                                let error_tx = error_tx.clone();

                                russh_util::runtime::spawn(async move {
                                    if config.nodelay {
                                        if let Err(e) = socket.set_nodelay(true) {
                                            warn!("set_nodelay() failed: {e:?}");
                                        }
                                    }

                                    let session = match run_stream(config, socket, handler).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            debug!("Connection setup failed");
                                            let _ = error_tx.send(e);
                                            return
                                        }
                                    };

                                    let handle = session.handle();

                                    tokio::select! {
                                        reason = shutdown_rx.recv() => {
                                            if handle.disconnect(
                                                Disconnect::ByApplication,
                                                reason.unwrap_or_else(|_| "".into()),
                                                "".into()
                                            ).await.is_err() {
                                                debug!("Failed to send disconnect message");
                                            }
                                        },
                                        result = session => {
                                            if let Err(e) = result {
                                                debug!("Connection closed with error");
                                                let _ = error_tx.send(e);
                                            } else {
                                                debug!("Connection closed");
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    },

                    Some(error) = error_rx.recv() => {
                        self.handle_session_error(error);
                    }
                }
            }
        };

        RunningServer {
            inner: Box::pin(fut),
            shutdown_tx,
        }
    }

    /// Run a server.
    /// This is a convenience function; consider using `run_on_socket` for more control.
    fn run_on_address<A: ToSocketAddrs + Send>(
        &mut self,
        config: Arc<Config>,
        addrs: A,
    ) -> impl Future<Output = std::io::Result<()>> + Send
    where
        Self: Send,
    {
        async {
            let socket = TcpListener::bind(addrs).await?;
            self.run_on_socket(config, &socket).await?;
            Ok(())
        }
    }
}

async fn start_reading<R: AsyncRead + Unpin>(
    mut stream_read: R,
    mut buffer: SSHBuffer,
    mut cipher: Box<dyn OpeningKey + Send>,
) -> Result<(usize, R, SSHBuffer, Box<dyn OpeningKey + Send>), Error> {
    buffer.buffer.clear();
    let n = cipher::read(&mut stream_read, &mut buffer, &mut *cipher).await?;
    Ok((n, stream_read, buffer, cipher))
}

/// An active server session returned by [run_stream].
///
/// Implements [Future] and can be awaited to wait for the session to finish.
pub struct RunningSession<H: Handler> {
    handle: Handle,
    join: JoinHandle<Result<(), H::Error>>,
}

impl<H: Handler> RunningSession<H> {
    /// Returns a new handle for the session.
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

impl<H: Handler> Future for RunningSession<H> {
    type Output = Result<(), H::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.join), cx) {
            Poll::Ready(r) => Poll::Ready(match r {
                Ok(Ok(x)) => Ok(x),
                Err(e) => Err(crate::Error::from(e).into()),
                Ok(Err(e)) => Err(e),
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Start a single connection in the background.
pub async fn run_stream<H, R>(
    config: Arc<Config>,
    mut stream: R,
    handler: H,
) -> Result<RunningSession<H>, H::Error>
where
    H: Handler + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Absolute handshake deadline covers banner write/read + initial kex + auth
    // (never restarted mid-handshake).
    let handshake_deadline_at =
        tokio::time::Instant::now() + config.handshake_deadline;

    // Writing SSH id (inside handshake budget).
    let mut write_buffer = SSHBuffer::new();
    write_buffer.send_ssh_id(&config.as_ref().server_id);
    match tokio::time::timeout_at(
        handshake_deadline_at,
        stream.write_all(&write_buffer.buffer[..]),
    )
    .await
    {
        Ok(r) => map_err!(r)?,
        Err(_) => return Err(crate::Error::HandshakeTimeout.into()),
    }

    // Reading SSH id and allocating a session (inside handshake budget).
    let mut stream = SshRead::new(stream);
    let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
    let handle = server::session::Handle {
        sender,
        channel_buffer_size: config.channel_buffer_size,
    };

    let common = match tokio::time::timeout_at(
        handshake_deadline_at,
        read_ssh_id(config, &mut stream),
    )
    .await
    {
        Ok(r) => r.map_err(H::Error::from)?,
        Err(_) => return Err(crate::Error::HandshakeTimeout.into()),
    };
    let (open_reply_tx, open_reply_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut session = Session {
        target_window_size: common.config.window_size,
        common,
        receiver,
        sender: handle.clone(),
        pending_reads: Vec::new(),
        pending_len: 0,
        channels: HashMap::new(),
        inbound: HashMap::new(),
        inbound_needs_reserve: Vec::new(),
        outbound_acks: std::collections::HashMap::new(),
        open_global_requests: VecDeque::new(),
        kex: SessionKexState::Idle,
        open_reply_tx,
        open_reply_rx,
        rekey_gen: 0,
        rekey_deadline: crate::server::supervisor::RekeyDeadline::default(),
        handshake_deadline_at: Some(handshake_deadline_at),
        writer: None,
        reader: None,
        peer_credit: None,
        pending_supervisor_cause: None,
        pending_outbound: crate::server::session::PendingOutbound::default(),
        pending_kex_install: None,
        deferred_window_grants: std::collections::HashSet::new(),
        #[cfg(feature = "_test_hooks")]
        full_ledger: None,
        #[cfg(feature = "_test_hooks")]
        outbound_log_cursor: 0,
        sched_next: None,
        sched_since_boost: crate::BOOST_PERIOD,
        sched_debt: None,
    };

    session.begin_rekey()?;

    let join = russh_util::runtime::spawn(session.run(stream, handler));

    Ok(RunningSession { handle, join })
}

async fn read_ssh_id<R: AsyncRead + Unpin>(
    config: Arc<Config>,
    read: &mut SshRead<R>,
) -> Result<CommonSession<Arc<Config>>, Error> {
    let sshid = if let Some(t) = config.inactivity_timeout {
        tokio::time::timeout(t, read.read_client_ssh_id()).await??
    } else {
        read.read_client_ssh_id().await?
    };

    let session = CommonSession {
        packet_writer: PacketWriter::clear(),
        // kex: Some(Kex::Init(kexinit)),
        auth_user: String::new(),
        auth_method: None, // Client only.
        auth_attempts: 0,
        remote_to_local: Box::new(clear::Key),
        encrypted: None,
        config,
        wants_reply: false,
        disconnected: false,
        buffer: Vec::new(),
        strict_kex: false,
        alive_timeouts: 0,
        received_data: false,
        remote_sshid: sshid.into(),
    };
    Ok(session)
}

async fn reply<H: Handler + Send>(
    session: &mut Session,
    handler: &mut H,
    pkt: &mut IncomingSshPacket,
) -> Result<(), H::Error> {
    if let Some(message_type) = pkt.buffer.first() {
        debug!(
            "< msg type {message_type:?}, seqn {:?}, len {}",
            pkt.seqn.0,
            pkt.buffer.len()
        );
        if session.common.strict_kex && session.common.encrypted.is_none() {
            let seqno = pkt.seqn.0 - 1; // was incremented after read()
            validate_client_msg_strict_kex(*message_type, seqno as usize)?;
        }

        if [msg::IGNORE, msg::UNIMPLEMENTED, msg::DEBUG].contains(message_type) {
            return Ok(());
        }
    }

    // Peer KEXINIT while an outbound-install transaction is still open: park for
    // replay after finalize (do not begin_rekey or mis-handle as encrypted app data).
    if pkt.buffer.first() == Some(&msg::KEXINIT) && session.should_park_kexinit() {
        debug!("parking peer KEXINIT until pending kex install completes");
        session.park_pending_read(pkt.buffer.clone());
        return Ok(());
    }

    if pkt.buffer.first() == Some(&msg::KEXINIT)
        && session.kex == SessionKexState::Idle
        && session.pending_kex_install.is_none()
    {
        // Not currently in a rekey / pending install but received KEXINIT
        info!("Client has initiated re-key");
        session.begin_rekey()?;
        // Kex will consume the packet right away
    }

    let is_kex_msg = pkt.buffer.first().cloned().map(is_kex_msg).unwrap_or(false);

    if is_kex_msg {
        if let SessionKexState::InProgress(mut kex) = session.kex.take() {
            // Collect plaintext; seal via Writer (or atomic batch+install at NEWKEYS).
            let mut coll = crate::sshbuffer::PayloadCollector::default();
            let progress = kex.step(Some(pkt), &mut coll, handler).await?;
            let payloads = std::mem::take(&mut coll.payloads);

            match progress {
                KexProgress::NeedsReply { mut kex, reset_seqn } => {
                    debug!("kex impl continues: {kex:?}");
                    // §4.4: register atomic seal+install (after=None → wait for peer Done).
                    if let Some(half) = kex.take_outbound_epoch_install() {
                        let kex_gen = if kex.is_rekey() {
                            session.rekey_gen
                        } else {
                            0
                        };
                        let post_auth = matches!(
                            session.common.encrypted.as_ref().map(|e| &e.state),
                            Some(
                                EncryptedState::InitCompression
                                    | EncryptedState::Authenticated
                            )
                        );
                        let activate_compress = if half.compression.is_deferred() {
                            post_auth
                        } else {
                            true
                        };
                        if session
                            .register_seal_batch_and_install(
                                payloads,
                                kex_gen,
                                half.cipher,
                                half.compression,
                                activate_compress,
                                half.reset_seqn || reset_seqn,
                                None, // peer Done not yet
                            )
                            .is_err()
                        {
                            // cause staged; do not put kex back / do not flush
                            return Ok(());
                        }
                        let kex_gen = if kex.is_rekey() {
                            session.rekey_gen
                        } else {
                            0
                        };
                        if session.push_inbound_from_kex(&mut kex, kex_gen).is_err() {
                            return Ok(());
                        }
                    } else {
                        if let Err(e) = session.seal_payloads(payloads) {
                            debug!("kex seal_payloads failed: {e:?}");
                            session.stage_cause(
                                crate::server::DisconnectCause::PeerError,
                            );
                            return Ok(());
                        }
                        let _ = reset_seqn;
                        // Keys may still exist (no outbound half) — try inbound anyway.
                        let kex_gen = if kex.is_rekey() {
                            session.rekey_gen
                        } else {
                            0
                        };
                        if session.push_inbound_from_kex(&mut kex, kex_gen).is_err() {
                            return Ok(());
                        }
                    }
                    session.kex = SessionKexState::InProgress(kex);
                }
                KexProgress::Done { mut newkeys, .. } => {
                    debug!("kex impl has completed");
                    session.common.strict_kex =
                        session.common.strict_kex || newkeys.names.strict_kex();

                    let need_outbound_install = !payloads.is_empty();

                    if session.common.encrypted.is_some() {
                        // Rekey Done — **inbound commits this turn** (peer NEWKEYS cutover).
                        if need_outbound_install {
                            // skip_exchange: register outbound install, then commit inbound.
                            let kex_gen = session.rekey_gen;
                            let post_auth = matches!(
                                session.common.encrypted.as_ref().map(|e| &e.state),
                                Some(
                                    EncryptedState::InitCompression
                                        | EncryptedState::Authenticated
                                )
                            );
                            let half = kex::ServerKex::take_outbound_from_newkeys(
                                &mut newkeys,
                                session.common.strict_kex,
                            );
                            let activate_compress = if half.compression.is_deferred() {
                                post_auth
                            } else {
                                true
                            };
                            if session
                                .register_seal_batch_and_install(
                                    payloads,
                                    kex_gen,
                                    half.cipher,
                                    half.compression,
                                    activate_compress,
                                    half.reset_seqn,
                                    Some(
                                        crate::server::session::KexAfterInstall::RekeyComplete,
                                    ),
                                )
                                .is_err()
                            {
                                return Ok(()); // cause staged; no flush
                            }
                            if session
                                .push_inbound_from_newkeys_if_needed(
                                    &mut newkeys,
                                    kex_gen,
                                    session.common.strict_kex,
                                )
                                .is_err()
                            {
                                return Ok(());
                            }
                            session.commit_rekey_inbound(newkeys);
                            // Completion waits for both InstallAcks + peer Done.
                        } else {
                            if session
                                .push_inbound_from_newkeys_if_needed(
                                    &mut newkeys,
                                    session.rekey_gen,
                                    session.common.strict_kex,
                                )
                                .is_err()
                            {
                                return Ok(());
                            }
                            session.commit_rekey_inbound(newkeys);
                            let after =
                                crate::server::session::KexAfterInstall::RekeyComplete;
                            if let Some(ready) =
                                session.merge_peer_done_into_pending(after)
                            {
                                session.apply_kex_after_install(ready);
                                // Unified gate re-entry (not process_packet bypass).
                                session.replay_pending_reads(handler).await?;
                                let _ = session.flush();
                            }
                            // else: wait for InstallAck; kex stays Taken; inbound already live.
                        }
                    } else {
                        // Initial Done — **inbound/Encrypted commit this turn**.
                        if need_outbound_install {
                            let (local, outbound_comp, reset_seqn) =
                                crate::server::session::Session::take_outbound_from_newkeys_server(
                                    &mut newkeys,
                                );
                            let activate = !outbound_comp.is_deferred();
                            if session
                                .register_seal_batch_and_install(
                                    payloads,
                                    0,
                                    local,
                                    outbound_comp,
                                    activate,
                                    reset_seqn,
                                    Some(
                                        crate::server::session::KexAfterInstall::InitialComplete,
                                    ),
                                )
                                .is_err()
                            {
                                return Ok(());
                            }
                            if session
                                .push_inbound_from_newkeys_if_needed(
                                    &mut newkeys,
                                    0,
                                    session.common.strict_kex,
                                )
                                .is_err()
                            {
                                return Ok(());
                            }
                            session.commit_initial_encrypted(
                                EncryptedState::WaitingAuthServiceRequest {
                                    sent: false,
                                    accepted: false,
                                },
                                newkeys,
                            );
                        } else {
                            if session
                                .push_inbound_from_newkeys_if_needed(
                                    &mut newkeys,
                                    0,
                                    session.common.strict_kex,
                                )
                                .is_err()
                            {
                                return Ok(());
                            }
                            session.commit_initial_encrypted(
                                EncryptedState::WaitingAuthServiceRequest {
                                    sent: false,
                                    accepted: false,
                                },
                                newkeys,
                            );
                            let after =
                                crate::server::session::KexAfterInstall::InitialComplete;
                            if let Some(ready) =
                                session.merge_peer_done_into_pending(after)
                            {
                                session.apply_kex_after_install(ready);
                            }
                            // else wait for InstallAck (inbound already committed)
                        }
                    }

                    if session.common.strict_kex {
                        pkt.seqn = Wrapping(0);
                    }

                    debug!("kex done (inbound committed; completion may wait ACK)");
                }
            }

            // Err path (staged cause): do not flush.
            if session.pending_supervisor_cause.is_some() {
                return Ok(());
            }
            let _ = session.flush();

            return Ok(());
        }
    }

    // Handle key exchange/re-exchange.
    session.server_read_encrypted(handler, pkt).await
}

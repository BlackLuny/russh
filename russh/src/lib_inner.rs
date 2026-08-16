use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::future::{Future, Pending};

use futures::future::Either as EitherFuture;
use log::warn;
use parsing::ChannelOpenConfirmation;
pub use russh_cryptovec::CryptoVec;
use ssh_encoding::{Decode, Encode};
use thiserror::Error;

#[cfg(test)]
mod tests;

mod auth;

mod cert;
/// Cipher names
pub mod cipher;
/// Compression algorithm names
pub mod compression;
/// Key exchange algorithm names
pub mod kex;
/// MAC algorithm names
pub mod mac;

pub mod keys;

mod msg;
mod negotiation;
mod ssh_read;
mod sshbuffer;

pub use negotiation::{Names, Preferred};
#[cfg(feature = "_test_hooks")]
pub use negotiation::{KexCompressionOverride, SkipNewkeysWriteback};
#[cfg(feature = "_test_hooks")]
pub use session::newkeys_rewrites_compression_enums;

mod pty;

pub use pty::Pty;
pub use sshbuffer::SshId;

mod helpers;

pub(crate) use helpers::map_err;

macro_rules! push_packet {
    ( $buffer:expr, $x:expr ) => {{
        use byteorder::{BigEndian, ByteOrder};
        let i0 = $buffer.len();
        $buffer.extend(b"\0\0\0\0");
        let x = $x;
        let i1 = $buffer.len();
        use std::ops::DerefMut;
        let buf = $buffer.deref_mut();
        #[allow(clippy::indexing_slicing)] // length checked
        BigEndian::write_u32(&mut buf[i0..], (i1 - i0 - 4) as u32);
        x
    }};
}

mod channels;
#[cfg(feature = "_test_hooks")]
pub use channels::io::{
    acquire_invert_bound2_discard_ready, acquire_invert_park_before_register,
    s8b_object_ack_before_register_round, s8b_object_register_round,
    s8c_object_known_dead_round, InvertParkGuard, S8bObjectClass,
};
pub use channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelStream, ChannelWriteHalf};

mod parsing;
mod session;

/// Server side of this library.
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

/// Client side of this library.
pub mod client;

#[derive(Debug)]
pub enum AlgorithmKind {
    Kex,
    Key,
    Cipher,
    Compression,
    Mac,
}

#[derive(Debug, Error)]
pub enum Error {
    /// The key file could not be parsed.
    #[error("Could not read key")]
    CouldNotReadKey,

    /// Unspecified problem with the beginning of key exchange.
    #[error("Key exchange init failed")]
    KexInit,

    /// Unknown algorithm name.
    #[error("Unknown algorithm")]
    UnknownAlgo,

    /// No common algorithm found during key exchange.
    #[error("No common {kind:?} algorithm - ours: {ours:?}, theirs: {theirs:?}")]
    NoCommonAlgo {
        kind: AlgorithmKind,
        ours: Vec<String>,
        theirs: Vec<String>,
    },

    /// Invalid SSH version string.
    #[error("invalid SSH version string")]
    Version,

    /// Error during key exchange.
    #[error("Key exchange failed")]
    Kex,

    /// Invalid packet authentication code.
    #[error("Wrong packet authentication code")]
    PacketAuth,

    /// The protocol is in an inconsistent state.
    #[error("Inconsistent state of the protocol")]
    Inconsistent,

    /// The client is not yet authenticated.
    #[error("Not yet authenticated")]
    NotAuthenticated,

    /// The client has presented an unsupported authentication method.
    #[error("Unsupported authentication method")]
    UnsupportedAuthMethod,

    /// Index out of bounds.
    #[error("Index out of bounds")]
    IndexOutOfBounds,

    /// Unknown server key.
    #[error("Unknown server key")]
    UnknownKey,

    /// The server provided a wrong signature.
    #[error("Wrong server signature")]
    WrongServerSig,

    /// Excessive packet size.
    #[error("Bad packet size: {0}")]
    PacketSize(usize),

    /// Message received/sent on unopened channel.
    #[error("Channel not open")]
    WrongChannel,

    /// Server refused to open a channel.
    #[error("Failed to open channel ({0:?})")]
    ChannelOpenFailure(ChannelOpenFailure),

    /// Disconnected
    #[error("Disconnected")]
    Disconnect,

    /// No home directory found when trying to learn new host key.
    #[error("No home directory when saving host key")]
    NoHomeDir,

    /// Remote key changed, this could mean a man-in-the-middle attack
    /// is being performed on the connection.
    #[error("Key changed, line {}", line)]
    KeyChanged { line: usize },

    /// Connection closed by the remote side.
    #[error("Connection closed by the remote side")]
    HUP,

    /// Connection timeout.
    #[error("Connection timeout")]
    ConnectionTimeout,

    /// Keepalive timeout.
    #[error("Keepalive timeout")]
    KeepaliveTimeout,

    /// Inactivity timeout.
    #[error("Inactivity timeout")]
    InactivityTimeout,

    /// ConnSupervisor: write path armed with wire-eligible bytes made no progress
    /// within `write_progress_deadline` (or failed the `write_min_drain` policy).
    #[error("Write stalled (supervisor)")]
    WriteStalled,

    /// ConnSupervisor: key re-exchange did not complete within `rekey_deadline`.
    #[error("Rekey timeout (supervisor), generation {0}")]
    RekeyTimeout(u64),

    /// ConnSupervisor: banner / initial kex / auth exceeded `handshake_deadline`.
    #[error("Handshake timeout (supervisor)")]
    HandshakeTimeout,

    /// Per-queue want-reply obligation cap exceeded (protocol abuse).
    #[error("Too many pending want-reply obligations")]
    ReplyObligationOverflow,

    /// CHANNEL_OPEN accept/reject arrived after the decision deadline
    /// or against a superseded generation (S4c). No second wire reply.
    #[error("Channel open decision expired")]
    ChannelOpenExpired,

    /// Process-level `max_connections` reached (S4d). No `Session` was
    /// created; the socket is dropped.
    #[error("Maximum number of connections reached")]
    MaxConnections,

    /// Missing authentication method.
    #[error("No authentication method")]
    NoAuthMethod,

    #[error("Channel send error")]
    SendError,

    #[error("Pending buffer limit reached")]
    Pending,

    #[error("Failed to decrypt a packet")]
    DecryptionError,

    #[error("The request was rejected by the other party")]
    RequestDenied,

    #[error(transparent)]
    Keys(#[from] crate::keys::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    #[cfg(feature = "flate2")]
    Compress(#[from] flate2::CompressError),

    #[error(transparent)]
    #[cfg(feature = "flate2")]
    Decompress(#[from] flate2::DecompressError),

    #[error(transparent)]
    Join(#[from] russh_util::runtime::JoinError),

    #[error(transparent)]
    Elapsed(#[from] tokio::time::error::Elapsed),

    #[error(
        "Violation detected during strict key exchange, message {message_type} at seq no {sequence_number}"
    )]
    StrictKeyExchangeViolation {
        message_type: u8,
        sequence_number: usize,
    },

    #[error("Signature: {0}")]
    Signature(#[from] signature::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    /// This error occurs when the channel is closed and there are no remaining messages in the channel buffer.
    /// This is common in SSH-Agent, for example when the Agent client directly rejects an authorization request.
    #[error("Unable to receive more messages from the channel")]
    RecvError,
}

pub(crate) fn strict_kex_violation(message_type: u8, sequence_number: usize) -> crate::Error {
    warn!(
        "strict kex violated at sequence no. {sequence_number:?}, message type: {message_type:?}"
    );
    crate::Error::StrictKeyExchangeViolation {
        message_type,
        sequence_number,
    }
}

#[derive(Debug, Error)]
#[error("Could not reach the event loop")]
pub struct SendError {}

/// Per-epoch rekey hard limits (I5).
///
/// Default is 2^31 packets and 1 TiB in **either** direction (one
/// `max_bytes` for inbound and outbound). There is no time-based
/// trigger; the in-flight completion deadline remains
/// `Config.rekey_deadline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyPolicy {
    /// Packets (every seqn-consuming packet) per direction per epoch.
    pub max_packets: u64,
    /// Plaintext payload bytes per direction per epoch.
    pub max_bytes: u64,
}

impl RekeyPolicy {
    /// I5 first trigger: 2^31 packets.
    pub const DEFAULT_MAX_PACKETS: u64 = 1 << 31;
    /// I5 second trigger: 1 TiB.
    pub const DEFAULT_MAX_BYTES: u64 = 1 << 40;

    /// Construct a policy. No panic path — 1 TiB (and above) is legal.
    pub fn new(max_packets: u64, max_bytes: u64) -> Self {
        Self {
            max_packets,
            max_bytes,
        }
    }
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self {
            max_packets: Self::DEFAULT_MAX_PACKETS,
            max_bytes: Self::DEFAULT_MAX_BYTES,
        }
    }
}

#[cfg(test)]
mod rekey_policy_api_tests {
    use super::RekeyPolicy;

    /// P1: `server::Config.limits` is `RekeyPolicy`; Default matches I5.
    #[test]
    fn p1_config_limits_is_rekey_policy() {
        let server = crate::server::Config::default();
        let _: RekeyPolicy = server.limits;
        assert_eq!(server.limits.max_packets, RekeyPolicy::DEFAULT_MAX_PACKETS);
        assert_eq!(server.limits.max_bytes, RekeyPolicy::DEFAULT_MAX_BYTES);
        let client = crate::client::Config::default();
        let _: RekeyPolicy = client.limits;
        assert_eq!(client.limits.max_packets, RekeyPolicy::DEFAULT_MAX_PACKETS);
        assert_eq!(client.limits.max_bytes, RekeyPolicy::DEFAULT_MAX_BYTES);
    }

    /// P2: 1 TiB constructs; `new` has no 1 GiB assert.
    #[test]
    fn p2_one_tib_constructs_without_panic() {
        let p = RekeyPolicy {
            max_packets: 1,
            max_bytes: 1 << 40,
        };
        assert_eq!(p.max_bytes, 1 << 40);
        let p = RekeyPolicy::new(1 << 31, 1 << 40);
        assert_eq!(p.max_bytes, 1 << 40);
        assert_eq!(p.max_packets, 1 << 31);
    }

    /// P5: zfc-style `Config { ..Default::default() }` compiles.
    #[test]
    fn p5_zfc_style_default_config_compiles() {
        let _cfg = crate::server::Config {
            ..Default::default()
        };
    }
}

pub use auth::{AgentAuthError, MethodKind, MethodSet, Signer};

/// A reason for disconnection.
#[allow(missing_docs)] // This should be relatively self-explanatory.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub enum Disconnect {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    #[doc(hidden)]
    Reserved = 4,
    MACError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

impl TryFrom<u32> for Disconnect {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MACError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            _ => return Err(crate::Error::Inconsistent),
        })
    }
}

/// The type of signals that can be sent to a remote process. If you
/// plan to use custom signals, read [the
/// RFC](https://tools.ietf.org/html/rfc4254#section-6.10) to
/// understand the encoding.
#[allow(missing_docs)]
// This should be relatively self-explanatory.
#[derive(Debug, Clone)]
pub enum Sig {
    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    Custom(String),
}

impl Sig {
    fn name(&self) -> &str {
        match *self {
            Sig::ABRT => "ABRT",
            Sig::ALRM => "ALRM",
            Sig::FPE => "FPE",
            Sig::HUP => "HUP",
            Sig::ILL => "ILL",
            Sig::INT => "INT",
            Sig::KILL => "KILL",
            Sig::PIPE => "PIPE",
            Sig::QUIT => "QUIT",
            Sig::SEGV => "SEGV",
            Sig::TERM => "TERM",
            Sig::USR1 => "USR1",
            Sig::Custom(ref c) => c,
        }
    }
    fn from_name(name: &str) -> Sig {
        match name {
            "ABRT" => Sig::ABRT,
            "ALRM" => Sig::ALRM,
            "FPE" => Sig::FPE,
            "HUP" => Sig::HUP,
            "ILL" => Sig::ILL,
            "INT" => Sig::INT,
            "KILL" => Sig::KILL,
            "PIPE" => Sig::PIPE,
            "QUIT" => Sig::QUIT,
            "SEGV" => Sig::SEGV,
            "TERM" => Sig::TERM,
            "USR1" => Sig::USR1,
            x => Sig::Custom(x.to_string()),
        }
    }
}

/// Reason for not being able to open a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ChannelOpenFailure {
    AdministrativelyProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
    Other { code: u32, reason: String },
}

impl ChannelOpenFailure {
    pub(crate) fn from_u32(x: u32) -> Option<ChannelOpenFailure> {
        match x {
            1 => Some(Self::AdministrativelyProhibited),
            2 => Some(Self::ConnectFailed),
            3 => Some(Self::UnknownChannelType),
            4 => Some(Self::ResourceShortage),
            code => Some(Self::Other {
                code,
                reason: format!("Unknown code {code}"),
            }),
        }
    }

    /// SSH protocol reason code for this failure
    pub fn code(&self) -> u32 {
        match self {
            Self::AdministrativelyProhibited => 1,
            Self::ConnectFailed => 2,
            Self::UnknownChannelType => 3,
            Self::ResourceShortage => 4,
            Self::Other { code, .. } => *code,
        }
    }

    /// A human-readable description of this failure.
    pub fn description(&self) -> &str {
        match self {
            Self::AdministrativelyProhibited => "Administratively prohibited",
            Self::ConnectFailed => "Connect failed",
            Self::UnknownChannelType => "Unknown channel type",
            Self::ResourceShortage => "Resource shortage",
            Self::Other { reason, .. } => reason.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
/// The identifier of a channel.
pub struct ChannelId(u32);

impl ChannelId {
    // Not public to prevent construction of invalid
    // ChannelIds by the library user
    pub fn number(&self) -> u32 {
        self.0
    }
}

impl Decode for ChannelId {
    type Error = ssh_encoding::Error;

    fn decode(reader: &mut impl ssh_encoding::Reader) -> Result<Self, Self::Error> {
        Ok(Self(u32::decode(reader)?))
    }
}

impl Encode for ChannelId {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.0.encoded_len()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.0.encode(writer)
    }
}

impl From<ChannelId> for u32 {
    fn from(c: ChannelId) -> u32 {
        c.0
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Per-channel outbound lane (I3 / S2c).
///
/// `Opening → Confirmed → Closing`. OPEN_CONFIRMATION is the head fence;
/// EOF/CLOSE are tail fences. Only DATA/EXTENDED_DATA consume the peer
/// window (RFC 4254 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelLaneState {
    Opening,
    Confirmed,
    Closing,
}

/// S2d gather / 1-packet quantum: local transport payload cap.
/// A CHANNEL_DATA / EXTENDED_DATA we assemble is at most
/// `min(peer_maxpacket, remaining window, this)`.
pub(crate) const LOCAL_TRANSPORT_PAYLOAD_CAP: usize = 32 * 1024;

/// Regular quanta between boosts (plan §4.3 / gap #12).
pub(crate) const BOOST_PERIOD: u32 = 8;

/// Control / fence items sharing a submission sequence with `pending_data`.
#[derive(Debug)]
pub(crate) enum ChannelCtrlItem {
    OpenConfirmation {
        recipient_channel: u32,
        sender_channel: u32,
        window_size: u32,
        packet_size: u32,
    },
    Eof,
    Close,
    Success,
    Failure,
    /// CHANNEL_REQUEST body after the message byte (recipient already encoded).
    Request { body: bytes::Bytes },
}

impl ChannelCtrlItem {
    #[allow(dead_code)]
    pub(crate) fn is_fence(&self) -> bool {
        matches!(
            self,
            Self::OpenConfirmation { .. }
                | Self::Eof
                | Self::Close
                | Self::Success
                | Self::Failure
        )
    }

    #[allow(dead_code)]
    pub(crate) fn ssh_msg(&self) -> u8 {
        match self {
            Self::OpenConfirmation { .. } => crate::msg::CHANNEL_OPEN_CONFIRMATION,
            Self::Eof => crate::msg::CHANNEL_EOF,
            Self::Close => crate::msg::CHANNEL_CLOSE,
            Self::Success => crate::msg::CHANNEL_SUCCESS,
            Self::Failure => crate::msg::CHANNEL_FAILURE,
            Self::Request { .. } => crate::msg::CHANNEL_REQUEST,
        }
    }

    /// Wire reservation for a peer-driven CHANNEL_SUCCESS/FAILURE (5+88).
    pub(crate) fn reply_reservation() -> usize {
        5 + 4 + 1 + 19 + 64
    }

    pub(crate) fn is_peer_reply(&self) -> bool {
        matches!(self, Self::Success | Self::Failure)
    }
}

/// Per-scope want-reply obligations. Emit only decided heads so a later
/// FAILURE cannot overtake an earlier pending SUCCESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyVerdict {
    Pending,
    Success,
    Failure,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplyObligation {
    pub(crate) verdict: ReplyVerdict,
    pub(crate) extra_port: Option<u32>,
}

#[derive(Debug, Default)]
pub(crate) struct ReplyQueue {
    items: std::collections::VecDeque<ReplyObligation>,
}

impl ReplyQueue {
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn enqueue_pending(&mut self) {
        self.items.push_back(ReplyObligation {
            verdict: ReplyVerdict::Pending,
            extra_port: None,
        });
    }

    pub(crate) fn decide_last_if_pending(&mut self, success: bool, extra: Option<u32>) -> bool {
        if let Some(o) = self.items.back_mut() {
            if o.verdict == ReplyVerdict::Pending {
                o.verdict = if success {
                    ReplyVerdict::Success
                } else {
                    ReplyVerdict::Failure
                };
                o.extra_port = extra;
                return true;
            }
        }
        false
    }

    pub(crate) fn decide_oldest_pending(&mut self, success: bool, extra: Option<u32>) -> bool {
        for o in &mut self.items {
            if o.verdict == ReplyVerdict::Pending {
                o.verdict = if success {
                    ReplyVerdict::Success
                } else {
                    ReplyVerdict::Failure
                };
                o.extra_port = extra;
                return true;
            }
        }
        false
    }

    pub(crate) fn pop_ready(&mut self) -> Option<ReplyObligation> {
        match self.items.front() {
            Some(o) if o.verdict != ReplyVerdict::Pending => self.items.pop_front(),
            _ => None,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
    }
}

/// The parameters of a channel.
#[derive(Debug)]
pub(crate) struct ChannelParams {
    pub(crate) recipient_channel: u32,
    pub(crate) sender_channel: ChannelId,
    pub(crate) recipient_window_size: u32,
    pub(crate) sender_window_size: u32,
    pub(crate) recipient_maximum_packet_size: u32,
    pub(crate) sender_maximum_packet_size: u32,
    /// Has the other side confirmed the channel?
    pub confirmed: bool,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) wants_reply: bool,
    /// Outstanding want-reply CHANNEL_REQUESTs (S4b). A bool is not
    /// enough once Session posts Invokes without waiting: several
    /// REQUESTs can be parsed before the first SUCCESS is applied.
    pub(crate) want_reply_count: u32,
    /// (buffer, extended stream #, data offset in buffer)
    pub(crate) pending_data: std::collections::VecDeque<(bytes::Bytes, Option<u32>, usize)>,
    /// EOF has been submitted. Sticky after the fence is emitted so
    /// later DATA cannot follow CHANNEL_EOF on the wire (RFC 4254
    /// §5.3 / I3). Also dedups a second `eof()`.
    pub(crate) pending_eof: bool,
    pub(crate) pending_close: bool,
    /// CLOSE has been framed into `enc.write` (or discarded as a
    /// duplicate). After this the channel must not emit ADJUST /
    /// SUCCESS / FAILURE / REQUEST (S2e lifecycle latch).
    pub(crate) outbound_closed: bool,
    /// I3 lane. Independent of `confirmed` (that flag is "peer accepted our
    /// open" / "we accepted theirs"). We stay `Opening` until *our*
    /// OPEN_CONFIRMATION is emitted.
    pub(crate) lane: ChannelLaneState,
    /// First DATA packet after becoming `Confirmed` may take a boost slot.
    pub(crate) boost_pending: bool,
    next_seq: u64,
    /// Submission sequence parallel to `pending_data`.
    data_seqs: std::collections::VecDeque<u64>,
    pending_ctrl: std::collections::VecDeque<(u64, ChannelCtrlItem)>,
    /// RFC 4254 §5.4 want-reply FIFO. Lifetime = this channel.
    pub(crate) reply_queue: ReplyQueue,
}

impl ChannelParams {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        recipient_channel: u32,
        sender_channel: ChannelId,
        recipient_window_size: u32,
        sender_window_size: u32,
        recipient_maximum_packet_size: u32,
        sender_maximum_packet_size: u32,
        confirmed: bool,
    ) -> Self {
        Self {
            recipient_channel,
            sender_channel,
            recipient_window_size,
            sender_window_size,
            recipient_maximum_packet_size,
            sender_maximum_packet_size,
            confirmed,
            wants_reply: false,
            want_reply_count: 0,
            pending_data: std::collections::VecDeque::new(),
            pending_eof: false,
            pending_close: false,
            outbound_closed: false,
            lane: ChannelLaneState::Opening,
            boost_pending: false,
            next_seq: 0,
            data_seqs: std::collections::VecDeque::new(),
            pending_ctrl: std::collections::VecDeque::new(),
            reply_queue: ReplyQueue::default(),
        }
    }

    pub fn confirm(&mut self, c: &ChannelOpenConfirmation) {
        self.recipient_channel = c.sender_channel; // "sender" is the sender of the confirmation
        self.recipient_window_size = c.initial_window_size;
        self.recipient_maximum_packet_size = c.maximum_packet_size;
        self.confirmed = true;
        // We opened this channel; the peer confirmed. No local
        // OPEN_CONFIRMATION is queued, so the lane can go Confirmed.
        // Only Opening → Confirmed (never from Closing).
        if self.lane == ChannelLaneState::Opening
            && !self
                .pending_ctrl
                .iter()
                .any(|(_, i)| matches!(i, ChannelCtrlItem::OpenConfirmation { .. }))
        {
            self.enter_confirmed();
        }
    }

    fn enter_confirmed(&mut self) {
        if self.lane == ChannelLaneState::Opening {
            self.lane = ChannelLaneState::Confirmed;
            self.boost_pending = true;
        }
    }

    /// Ready-set membership for S2d DATA scheduling (plan §4.3).
    /// Fences are emitted on a separate pass and do not enter the set.
    pub(crate) fn in_ready_set(&self) -> bool {
        self.lane == ChannelLaneState::Confirmed
            && !self.pending_data.is_empty()
            && self.recipient_window_size > 0
            && !self.ctrl_ahead_of_data()
    }

    /// Head-of-lane DATA vs EXTENDED_DATA. Used so HWM one-packet
    /// reservation matches the packet we are about to assemble.
    pub(crate) fn pending_head_is_extended(&self) -> bool {
        matches!(self.pending_data.front(), Some((_, Some(_), _)))
    }

    fn alloc_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        s
    }

    /// Enqueue a **new** DATA / EXTENDED_DATA item.
    ///
    /// After EOF or CLOSE has been submitted (`pending_eof` or
    /// `lane == Closing`), new application data is dropped and this
    /// returns `false` (RFC 4254 §5.3 / I3 tail fence). Callers treat
    /// that as success: a concurrent handler `data()` racing `eof()`
    /// must not panic. Remainder of an already-accepted packet is
    /// reinserted via [`Self::push_data_front`], which is **not** gated.
    pub(crate) fn enqueue_data(
        &mut self,
        buf: bytes::Bytes,
        ext: Option<u32>,
        from: usize,
    ) -> bool {
        if self.pending_eof || self.outbound_closed || self.lane == ChannelLaneState::Closing {
            return false;
        }
        let seq = self.alloc_seq();
        self.pending_data.push_back((buf, ext, from));
        self.data_seqs.push_back(seq);
        true
    }

    pub(crate) fn enqueue_ctrl(&mut self, item: ChannelCtrlItem) {
        if self.outbound_closed {
            // CLOSE already framed: drop further control (ADJUST is not
            // a lane item; SUCCESS/FAILURE/REQUEST/EOF/CLOSE are).
            return;
        }
        // CLOSE submitted but not yet framed: same tail-fence as S2c
        // DATA. Late SUCCESS/REQUEST must not sit behind the parked
        // CLOSE and appear on the wire after it. WINDOW_ADJUST is a
        // Session bypass (not a lane item) and may still emit while
        // CLOSE is only parked — it will precede the parked CLOSE.
        if self.pending_close || self.lane == ChannelLaneState::Closing {
            return;
        }
        match &item {
            ChannelCtrlItem::Eof => self.pending_eof = true,
            ChannelCtrlItem::Close => {
                self.pending_close = true;
                self.lane = ChannelLaneState::Closing;
            }
            ChannelCtrlItem::OpenConfirmation { .. } => {
                self.lane = ChannelLaneState::Opening;
            }
            _ => {}
        }
        let seq = self.alloc_seq();
        self.pending_ctrl.push_back((seq, item));
    }

    pub(crate) fn has_pending_ctrl(&self) -> bool {
        !self.pending_ctrl.is_empty()
    }

    /// Peer-driven SUCCESS/FAILURE still sitting in the lane (not yet on
    /// `enc.write`). Used for generation-point admit so a parked DATA head
    /// cannot hide an unbounded reply queue.
    pub(crate) fn queued_reply_count(&self) -> usize {
        self.pending_ctrl
            .iter()
            .filter(|(_, i)| i.is_peer_reply())
            .count()
    }

    pub(crate) fn queued_reply_reservation(&self) -> usize {
        self.queued_reply_count()
            .saturating_mul(ChannelCtrlItem::reply_reservation())
    }

    pub(crate) fn ctrl_ahead_of_data(&self) -> bool {
        match (self.data_seqs.front(), self.pending_ctrl.front()) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(d), Some((c, _))) => *c <= *d,
        }
    }

    pub(crate) fn pop_ctrl_front(&mut self) -> Option<ChannelCtrlItem> {
        let item = self.pending_ctrl.pop_front().map(|(_, i)| i)?;
        match &item {
            // `pending_eof` stays set: the tail fence has been
            // submitted (and is now on the wire). New DATA must
            // remain rejected.
            ChannelCtrlItem::Close => {
                self.pending_close = false;
                self.outbound_closed = true;
            }
            ChannelCtrlItem::OpenConfirmation { .. } => {
                self.enter_confirmed();
            }
            _ => {}
        }
        Some(item)
    }

    pub(crate) fn peek_ctrl_front(&self) -> Option<&ChannelCtrlItem> {
        self.pending_ctrl.front().map(|(_, i)| i)
    }

    pub(crate) fn pop_data_front(
        &mut self,
    ) -> Option<(bytes::Bytes, Option<u32>, usize, u64)> {
        let seq = self.data_seqs.pop_front()?;
        let (buf, ext, from) = self.pending_data.pop_front()?;
        Some((buf, ext, from, seq))
    }

    pub(crate) fn push_data_front(
        &mut self,
        buf: bytes::Bytes,
        ext: Option<u32>,
        from: usize,
        seq: u64,
    ) {
        self.pending_data.push_front((buf, ext, from));
        self.data_seqs.push_front(seq);
    }

    #[allow(dead_code)]
    pub(crate) fn clear_outbound(&mut self) {
        self.pending_data.clear();
        self.data_seqs.clear();
        self.pending_ctrl.clear();
        self.pending_eof = false;
        self.pending_close = false;
        self.boost_pending = false;
    }

    /// Drop every unframed lane item (DATA + non-CLOSE ctrl). CLOSE is
    /// not counted as discarded: StopDiscard still owes the peer exactly
    /// one outbound CLOSE. Does not touch `enc.write` / Writer FIFO.
    pub(crate) fn stop_discard_unframed(&mut self) -> crate::StopDiscardStats {
        let data_items = self.pending_data.len();
        let data_bytes = self
            .pending_data
            .iter()
            .map(|(buf, _, from)| buf.len().saturating_sub(*from))
            .sum::<usize>();
        let ctrl_dropped = self
            .pending_ctrl
            .iter()
            .filter(|(_, i)| !matches!(i, ChannelCtrlItem::Close))
            .count();
        self.pending_data.clear();
        self.data_seqs.clear();
        self.pending_ctrl.clear();
        self.pending_eof = true;
        self.pending_close = false;
        self.boost_pending = false;
        self.lane = ChannelLaneState::Closing;
        self.outbound_closed = true;
        crate::StopDiscardStats {
            discarded_items: data_items.saturating_add(ctrl_dropped),
            discarded_bytes: data_bytes,
            already_gone: false,
        }
    }
}

/// Result of [`Encrypted::close_discarding_pending`] / StopDiscard.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StopDiscardStats {
    pub discarded_items: usize,
    pub discarded_bytes: usize,
    pub already_gone: bool,
}

/// Returns `f(val)` if `val` it is [Some], or a forever pending [Future] if it is [None].
pub(crate) fn future_or_pending<R, F: Future<Output = R>, T>(
    val: Option<T>,
    f: impl FnOnce(T) -> F,
) -> EitherFuture<Pending<R>, F> {
    match val {
        None => EitherFuture::Left(core::future::pending()),
        Some(x) => EitherFuture::Right(f(x)),
    }
}

/// Shared claim for one peer-initiated CHANNEL_OPEN (S4c).
///
/// Session and the reply handle both hold an `Arc`. `accept`/`reject`/`Drop`
/// CAS from pending → claimed; the deadline CAS pending → expired. The loser
/// does not write a second wire reply. Client openings leave this `None`.
#[derive(Debug)]
pub(crate) struct OpeningLease {
    pub generation: u64,
    state: std::sync::atomic::AtomicU8,
}

impl OpeningLease {
    pub(crate) const PENDING: u8 = 0;
    pub(crate) const CLAIMED: u8 = 1;
    pub(crate) const EXPIRED: u8 = 2;

    pub(crate) fn new(generation: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            generation,
            state: std::sync::atomic::AtomicU8::new(Self::PENDING),
        })
    }

    pub(crate) fn try_claim(&self) -> bool {
        self.state
            .compare_exchange(
                Self::PENDING,
                Self::CLAIMED,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }

    pub(crate) fn try_expire(&self) -> bool {
        self.state
            .compare_exchange(
                Self::PENDING,
                Self::EXPIRED,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }
}

/// Pending channel-open state, passed through the reply handle to the session loop.
#[derive(Debug)]
#[doc(hidden)]
pub struct PendingChannelOpen {
    pub(crate) recipient_channel: u32,
    pub(crate) sender_channel: ChannelId,
    pub(crate) window_size: u32,
    pub(crate) packet_size: u32,
    pub(crate) channel_ref: channels::ChannelRef,
    pub(crate) channel_params: ChannelParams,
    /// Slot generation at reserve time. Client leaves this `0`.
    pub(crate) generation: u64,
    /// Server slot claim. `None` on the client (no slot/deadline).
    pub(crate) lease: Option<std::sync::Arc<OpeningLease>>,
}

/// A handle passed to channel-open callbacks that the handler uses to
/// accept or reject the incoming channel request.
///
/// Dropping the handle without calling [`accept`](ChannelOpenHandle::accept) or
/// [`reject`](ChannelOpenHandle::reject) automatically sends an
/// `AdministrativelyProhibited` rejection.
/// The reply travels over a dedicated *unbounded* channel rather than the session's bounded
/// message queue: handlers run inline on the session loop, so a bounded `send().await` here
/// could wait on a queue that only the (currently blocked) loop itself drains — a permanent
/// self-deadlock whenever other channels' writers keep that queue full. Unboundedness is safe
/// because at most one reply exists per peer-initiated CHANNEL_OPEN.
///
/// Do not write to or otherwise drive the channel handed to the handler before calling
/// [`accept`](ChannelOpenHandleInner::accept): the channel is only registered with the session
/// when the reply is processed, and messages that arrive before then are silently discarded.
pub struct ChannelOpenHandleInner<M: Send> {
    sender: tokio::sync::mpsc::UnboundedSender<M>,
    inner: Option<PendingChannelOpen>,
    make_msg: fn(PendingChannelOpen, Result<(), ChannelOpenFailure>) -> M,
}

impl<M: Send> ChannelOpenHandleInner<M> {
    pub(crate) fn new(
        sender: tokio::sync::mpsc::UnboundedSender<M>,
        pending: PendingChannelOpen,
        make_msg: fn(PendingChannelOpen, Result<(), ChannelOpenFailure>) -> M,
    ) -> Self {
        Self {
            sender,
            inner: Some(pending),
            make_msg,
        }
    }

    fn try_send_reply(
        &mut self,
        result: Result<(), ChannelOpenFailure>,
    ) -> Result<(), crate::Error> {
        let Some(pending) = self.inner.take() else {
            return Ok(());
        };
        if let Some(ref lease) = pending.lease {
            if !lease.try_claim() {
                return Err(crate::Error::ChannelOpenExpired);
            }
        }
        let _ = self.sender.send((self.make_msg)(pending, result));
        Ok(())
    }

    /// Accept the channel open request.
    ///
    /// Never blocks (the reply queue is unbounded), so it is safe to call from
    /// inside a handler callback running on the session loop.
    ///
    /// Returns [`Error::ChannelOpenExpired`] if the opening already timed out
    /// or a previous disposition claimed the slot. No second wire reply is sent.
    pub async fn accept(mut self) -> Result<(), crate::Error> {
        self.try_send_reply(Ok(()))
    }

    /// Reject the channel open request with a reason.
    ///
    /// Never blocks (the reply queue is unbounded), so it is safe to call from
    /// inside a handler callback running on the session loop.
    ///
    /// Returns [`Error::ChannelOpenExpired`] if the opening already timed out
    /// or a previous disposition claimed the slot. No second wire reply is sent.
    pub async fn reject(mut self, reason: ChannelOpenFailure) -> Result<(), crate::Error> {
        self.try_send_reply(Err(reason))
    }
}

impl<M: Send> Drop for ChannelOpenHandleInner<M> {
    fn drop(&mut self) {
        // Expired / already-claimed openings must not emit a second FAILURE.
        let _ = self.try_send_reply(Err(ChannelOpenFailure::AdministrativelyProhibited));
    }
}

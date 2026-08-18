//! Compile-checked spike: can channel + session be *fully* implemented as a
//! rustls-style consume-and-return state machine?
//!
//! This module is **not** production protocol code. It exists to pin down three
//! claims before any rewrite:
//!
//! 1. rustls's `Box<dyn State>` pattern fits SSH's *linear* phases (banner /
//!    kex / auth). russh already does the useful half of this for kex
//!    (`ClientKex::step(self)` / `ServerKex::step(self)`).
//! 2. A channel is a *product* of independent halves (read/write close) plus
//!    orthogonal credit (window). Flattening that into one linear rustls SM
//!    duplicates handlers and still cannot encode N multiplexed channels.
//! 3. A session after auth is not one state — it is `Kex ⊗ Auth ⊗ Map<Id, Chan>`.
//!    rustls itself collapses to a single `ExpectTraffic` after handshake;
//!    SSH cannot, because RFC 4254 multiplexes channels on the same record
//!    stream.
//!
//! See `.omc/research/rustls-style-sm-feasibility.md`.

#![allow(dead_code)] // spike types are exercised by tests, not the library

use std::collections::HashMap;

/// rustls-shaped trait: consume `self`, return the next state (or error).
///
/// rustls stores this as `Box<dyn State<Data>>` because TLS 1.2/1.3 handshake
/// states differ wildly in associated data. SSH's linear phases do not.
pub(crate) trait LinearState: Sized {
    type Event;
    type Error;
    fn handle(self, event: Self::Event) -> Result<Self, Self::Error>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Experiment A — linear SM for the pre-auth session (this *does* fit rustls)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeEvent {
    Banner,
    KexInit,
    NewKeys,
    ServiceRequest,
    UserauthSuccess,
    /// A channel-scoped packet arriving before authentication.
    ChannelData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handshake {
    ExpectBanner,
    ExpectKex,
    ExpectNewKeys,
    ExpectService,
    ExpectAuth,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeError {
    Unexpected {
        in_state: &'static str,
        event: HandshakeEvent,
    },
}

impl Handshake {
    fn name(self) -> &'static str {
        match self {
            Self::ExpectBanner => "ExpectBanner",
            Self::ExpectKex => "ExpectKex",
            Self::ExpectNewKeys => "ExpectNewKeys",
            Self::ExpectService => "ExpectService",
            Self::ExpectAuth => "ExpectAuth",
            Self::Authenticated => "Authenticated",
        }
    }
}

impl LinearState for Handshake {
    type Event = HandshakeEvent;
    type Error = HandshakeError;

    fn handle(self, event: HandshakeEvent) -> Result<Self, HandshakeError> {
        let next = match (self, event) {
            (Self::ExpectBanner, HandshakeEvent::Banner) => Self::ExpectKex,
            (Self::ExpectKex, HandshakeEvent::KexInit) => Self::ExpectNewKeys,
            (Self::ExpectNewKeys, HandshakeEvent::NewKeys) => Self::ExpectService,
            (Self::ExpectService, HandshakeEvent::ServiceRequest) => Self::ExpectAuth,
            (Self::ExpectAuth, HandshakeEvent::UserauthSuccess) => Self::Authenticated,
            // After auth, handshake SM is done. Channel traffic is *not* a
            // further handshake state — see Experiment C.
            (Self::Authenticated, HandshakeEvent::ChannelData) => Self::Authenticated,
            (state, event) => {
                return Err(HandshakeError::Unexpected {
                    in_state: state.name(),
                    event,
                });
            }
        };
        Ok(next)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Experiment B — channel as a *product* of two half-close machines
// (this is the RFC 4254 model; rustls has no analogue)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChanEvent {
    Confirm,
    OpenFailure,
    Data,
    WindowAdjust,
    Eof,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChanError {
    NotConfirmed,
    AlreadyEof,
    AlreadyClosed,
    OpeningOnly { event: ChanEvent },
}

/// Local write half. Independent of the read half (RFC 4254 §5.3).
/// CLOSE is a channel-level transition to `Dead`, not a third half-state —
/// keeping `CloseSent` here reintroduces illegal products (`CloseSent × Eof`)
/// that rustc then forces you to handle (the first compile of this spike
/// failed on exactly that hole; boolean flags would have silently allowed it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteHalf {
    Open,
    EofSent,
}

/// Remote read half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadHalf {
    Open,
    EofRecv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Credit {
    pub peer_window: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChannelSm {
    Opening {
        credit: Credit,
    },
    Established {
        write: WriteHalf,
        read: ReadHalf,
        credit: Credit,
    },
    Dead,
}

impl ChannelSm {
    pub fn opening(peer_window: u32) -> Self {
        Self::Opening {
            credit: Credit { peer_window },
        }
    }

    /// Number of *protocol-legal* (write, read) pairs once established.
    /// Close on either half ends the channel; the other combinations are
    /// representable as flags today and several are illegal.
    pub const ESTABLISHED_LIVE_COMBOS: usize = 2 * 2; // {Open,Eof} × {Open,Eof}

    pub fn can_send_data(&self) -> bool {
        matches!(
            self,
            Self::Established {
                write: WriteHalf::Open,
                ..
            }
        )
    }

    pub fn can_recv_data(&self) -> bool {
        matches!(
            self,
            Self::Established {
                read: ReadHalf::Open,
                ..
            }
        )
    }

    /// Window is credit, not a lifecycle state. A zero window must not move
    /// the channel into a different enum variant (G2: legal backpressure).
    pub fn apply_adjust(&mut self, amount: u32) -> Result<(), ChanError> {
        match self {
            Self::Established { credit, .. } | Self::Opening { credit } => {
                credit.peer_window = credit.peer_window.saturating_add(amount);
                Ok(())
            }
            Self::Dead => Err(ChanError::AlreadyClosed),
        }
    }

    pub fn handle_local(&mut self, event: ChanEvent) -> Result<(), ChanError> {
        match (&*self, event) {
            (Self::Opening { credit }, ChanEvent::Confirm) => {
                *self = Self::Established {
                    write: WriteHalf::Open,
                    read: ReadHalf::Open,
                    credit: *credit,
                };
                Ok(())
            }
            (Self::Opening { .. }, ChanEvent::OpenFailure) => {
                *self = Self::Dead;
                Ok(())
            }
            (Self::Opening { .. }, event) => Err(ChanError::OpeningOnly { event }),

            (
                Self::Established {
                    write: WriteHalf::Open,
                    read,
                    credit,
                },
                ChanEvent::Data,
            ) => {
                let _ = (read, credit);
                Ok(())
            }
            (
                Self::Established {
                    write: WriteHalf::EofSent,
                    ..
                },
                ChanEvent::Data,
            ) => Err(ChanError::AlreadyEof),

            (
                Self::Established {
                    write: WriteHalf::Open,
                    read,
                    credit,
                },
                ChanEvent::Eof,
            ) => {
                *self = Self::Established {
                    write: WriteHalf::EofSent,
                    read: *read,
                    credit: *credit,
                };
                Ok(())
            }
            (
                Self::Established {
                    write: WriteHalf::EofSent,
                    ..
                },
                ChanEvent::Eof,
            ) => Err(ChanError::AlreadyEof),

            (Self::Established { credit, .. }, ChanEvent::WindowAdjust) => {
                // Adjust is legal in every live established state (RFC 4254 §5.2).
                let _ = credit;
                Ok(())
            }

            (Self::Established { .. }, ChanEvent::Close) => {
                *self = Self::Dead;
                Ok(())
            }

            (Self::Dead, _) => Err(ChanError::AlreadyClosed),
            (Self::Established { .. }, ChanEvent::Confirm | ChanEvent::OpenFailure) => {
                Err(ChanError::NotConfirmed)
            }
        }
    }

    pub fn handle_remote(&mut self, event: ChanEvent) -> Result<(), ChanError> {
        match (&*self, event) {
            (Self::Opening { .. }, event) => Err(ChanError::OpeningOnly { event }),
            (
                Self::Established {
                    write,
                    read: ReadHalf::Open,
                    credit,
                },
                ChanEvent::Data,
            ) => {
                let _ = (write, credit);
                Ok(())
            }
            (Self::Established { read: ReadHalf::EofRecv, .. }, ChanEvent::Data) => {
                Err(ChanError::AlreadyEof)
            }
            (
                Self::Established {
                    write,
                    read: ReadHalf::Open,
                    credit,
                },
                ChanEvent::Eof,
            ) => {
                *self = Self::Established {
                    write: *write,
                    read: ReadHalf::EofRecv,
                    credit: *credit,
                };
                Ok(())
            }
            (Self::Established { .. }, ChanEvent::WindowAdjust) => Ok(()),
            (Self::Established { .. }, ChanEvent::Close) => {
                *self = Self::Dead;
                Ok(())
            }
            (Self::Dead, _) => Err(ChanError::AlreadyClosed),
            (Self::Established { .. }, ChanEvent::Confirm | ChanEvent::OpenFailure) => {
                Err(ChanError::NotConfirmed)
            }
            (
                Self::Established {
                    read: ReadHalf::EofRecv,
                    ..
                },
                ChanEvent::Eof,
            ) => Err(ChanError::AlreadyEof),
        }
    }
}

/// rustls-style *linear* encoding of the same channel lifecycle.
///
/// Every independent flag multiplies the variant count. Adding a second
/// channel, or rekey, cannot be expressed without nesting — at which point
/// this is no longer "one rustls SM".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinearChannel {
    Opening,
    Open,
    LocalEof,
    RemoteEof,
    BothEof,
    Dead,
}

impl LinearChannel {
    /// Variants needed for 1 channel's half-close product (no window, no
    /// outstanding request, no rekey). `Opening + Dead + 2×2 live`.
    pub const VARIANTS_ONE_CHANNEL: usize = 2 + Self::LIVE_HALF_CLOSE;
    pub const LIVE_HALF_CLOSE: usize = 4;

    /// If kex (Idle/InKex) were folded into the same linear enum:
    pub const TIMES_KEX: usize = 2;

    /// Flattened session with `n` independent channels: `kex × live^n` plus
    /// opening/dead. This is the number that makes a single rustls SM
    /// infeasible for the multiplexed session.
    pub fn flattened_session_states(n_channels: usize) -> u128 {
        // kex variants × (live half-close combos per channel)^n
        // Opening/Dead omitted: even the *live* subspace already explodes.
        (Self::TIMES_KEX as u128)
            .saturating_mul((Self::LIVE_HALF_CLOSE as u128).saturating_pow(n_channels as u32))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Experiment C — session after auth is a *composition*, not a linear SM
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KexLayer {
    Idle,
    InKex,
}

/// The post-auth session: one kex layer + N channel machines. This is what
/// rustls's `ExpectTraffic` would have to become for SSH — and rustls does
/// **not** structure TLS this way, because TLS has a single byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionSm {
    pub handshake: Handshake,
    pub kex: KexLayer,
    pub channels: HashMap<u32, ChannelSm>,
}

impl SessionSm {
    pub fn authenticated() -> Self {
        Self {
            handshake: Handshake::Authenticated,
            kex: KexLayer::Idle,
            channels: HashMap::new(),
        }
    }

    pub fn open_channel(&mut self, id: u32, peer_window: u32) -> Result<(), ChanError> {
        if self.handshake != Handshake::Authenticated {
            // Channel opens are illegal before auth. A rustls-style handshake
            // SM would have rejected this at the outer layer (Experiment A).
            return Err(ChanError::NotConfirmed);
        }
        self.channels.insert(id, ChannelSm::opening(peer_window));
        Ok(())
    }

    /// Rekey does not change any channel variant. Folding it into channel
    /// typestate would multiply every channel's state by 2 for no protocol
    /// benefit — the same bug class as today's `kex.active()` gating all
    /// channels as a single barrier.
    pub fn begin_rekey(&mut self) {
        self.kex = KexLayer::InKex;
    }

    pub fn finish_rekey(&mut self) {
        self.kex = KexLayer::Idle;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn handshake_linear_sm_rejects_channel_data_before_auth() {
        let hs = Handshake::ExpectAuth;
        let err = hs.handle(HandshakeEvent::ChannelData).unwrap_err();
        assert_eq!(
            err,
            HandshakeError::Unexpected {
                in_state: "ExpectAuth",
                event: HandshakeEvent::ChannelData,
            }
        );
    }

    #[test]
    fn handshake_happy_path_is_a_single_chain() {
        let hs = Handshake::ExpectBanner;
        let hs = hs.handle(HandshakeEvent::Banner).unwrap();
        let hs = hs.handle(HandshakeEvent::KexInit).unwrap();
        let hs = hs.handle(HandshakeEvent::NewKeys).unwrap();
        let hs = hs.handle(HandshakeEvent::ServiceRequest).unwrap();
        let hs = hs.handle(HandshakeEvent::UserauthSuccess).unwrap();
        assert_eq!(hs, Handshake::Authenticated);
        // Authenticated is terminal for the *handshake* SM. Further channel
        // messages stay in this variant — they are dispatched to per-channel
        // machines, not to a new handshake state.
        assert_eq!(
            hs.handle(HandshakeEvent::ChannelData).unwrap(),
            Handshake::Authenticated
        );
    }

    #[test]
    fn channel_rejects_data_before_confirm() {
        let mut ch = ChannelSm::opening(32 * 1024);
        let err = ch.handle_local(ChanEvent::Data).unwrap_err();
        assert!(matches!(
            err,
            ChanError::OpeningOnly {
                event: ChanEvent::Data
            }
        ));
        assert!(!ch.can_send_data());
    }

    #[test]
    fn channel_half_close_is_a_product_not_a_line() {
        let mut ch = ChannelSm::opening(1024);
        ch.handle_local(ChanEvent::Confirm).unwrap();
        ch.handle_local(ChanEvent::Eof).unwrap();
        // Local EOF must not block receiving (RFC 4254 §5.3).
        assert!(ch.can_recv_data());
        assert!(!ch.can_send_data());
        ch.handle_remote(ChanEvent::Data).unwrap();
        ch.handle_remote(ChanEvent::Eof).unwrap();
        assert!(!ch.can_recv_data());
        match ch {
            ChannelSm::Established {
                write: WriteHalf::EofSent,
                read: ReadHalf::EofRecv,
                ..
            } => {}
            other => panic!("expected BothEof product, got {other:?}"),
        }
    }

    #[test]
    fn window_is_credit_not_a_state() {
        let mut ch = ChannelSm::opening(0);
        ch.handle_local(ChanEvent::Confirm).unwrap();
        assert!(matches!(
            &ch,
            ChannelSm::Established {
                credit: Credit { peer_window: 0 },
                ..
            }
        ));
        ch.apply_adjust(4096).unwrap();
        // Same variant, different credit — a rustls-linear SM that encoded
        // "zero window" as its own state would have to transition here, and
        // a watchdog that keyed off that state would false-trigger (G2).
        assert!(matches!(
            &ch,
            ChannelSm::Established {
                write: WriteHalf::Open,
                read: ReadHalf::Open,
                credit: Credit { peer_window: 4096 },
            }
        ));
    }

    #[test]
    fn current_flag_encoding_has_illegal_combos() {
        // ChannelParams today: confirmed × pending_eof × pending_close.
        // All 8 bit-patterns are representable. Protocol-legal live combos
        // after open are the 4 half-close products; pending_* without
        // confirmed is one of the illegal leftovers that has already caused
        // WrongChannel / leak fixes in this fork.
        const FLAG_COMBOS: usize = 2 * 2 * 2;
        const LEGAL_LIVE: usize = ChannelSm::ESTABLISHED_LIVE_COMBOS;
        assert_eq!(FLAG_COMBOS, 8);
        assert_eq!(LEGAL_LIVE, 4);
        // Four leftover bit-patterns (e.g. pending_eof without confirmed).
        assert_eq!(FLAG_COMBOS - LEGAL_LIVE, 4);
    }

    #[test]
    fn flattened_linear_sm_explodes_with_multiplexing() {
        // 1 channel: 2 kex × 4 live = 8. Fine — this is what rustls does
        // (handshake then one traffic state; TLS has one stream).
        assert_eq!(LinearChannel::flattened_session_states(1), 8);
        // 4 channels (a modest proxy): 2 × 4^4 = 512.
        assert_eq!(LinearChannel::flattened_session_states(4), 512);
        // 8 channels: 2 × 4^8 = 131_072. Already past "one enum".
        assert_eq!(LinearChannel::flattened_session_states(8), 131_072);
        // Rewrite plan default max_channels=128: 2 × 4^128. Does not fit u128.
        assert_eq!(LinearChannel::flattened_session_states(128), u128::MAX);
    }

    #[test]
    fn composed_session_keeps_rekey_orthogonal_to_channels() {
        let mut s = SessionSm::authenticated();
        s.open_channel(1, 1024).unwrap();
        s.channels
            .get_mut(&1)
            .unwrap()
            .handle_local(ChanEvent::Confirm)
            .unwrap();
        s.begin_rekey();
        // Channel still Open. Rekey is a session-layer flag, not a channel
        // transition — folding it in would re-create the kex.active() barrier.
        assert!(
            s.channels
                .get(&1)
                .is_some_and(ChannelSm::can_send_data)
        );
        assert_eq!(s.kex, KexLayer::InKex);
        s.finish_rekey();
        assert!(
            s.channels
                .get(&1)
                .is_some_and(ChannelSm::can_send_data)
        );
    }

    #[test]
    fn composed_session_rejects_open_before_auth() {
        let mut s = SessionSm {
            handshake: Handshake::ExpectAuth,
            kex: KexLayer::Idle,
            channels: HashMap::new(),
        };
        assert!(s.open_channel(1, 1024).is_err());
        assert!(s.channels.is_empty());
    }
}

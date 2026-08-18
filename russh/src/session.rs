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

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem::replace;
use std::num::Wrapping;

use bytes::{BufMut, Bytes};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, trace};
use ssh_encoding::Encode;
use tokio::sync::oneshot;

use crate::cipher::OpeningKey;
use crate::client::GexParams;
use crate::kex::dh::groups::DhGroup;
use crate::kex::{KexAlgorithm, KexAlgorithmImplementor};
use crate::sshbuffer::PacketWriter;
use crate::{
    ChannelId, ChannelParams, CryptoVec, Disconnect, RekeyPolicy, auth, cipher, mac, msg, negotiation,
};

#[derive(Debug)]
pub(crate) struct Encrypted {
    pub state: EncryptedState,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub session_id: CryptoVec,
    pub channels: HashMap<ChannelId, ChannelParams>,
    pub last_channel_id: Wrapping<u32>,
    // Non-sensitive packet assembly buffer, analogous to
    // OpenSSH sshbuf (output side).  Not mlocked because it
    // holds only protocol framing and ciphertext.
    //
    // `BytesMut` rather than `Vec<u8>` so the Writer hand-off in
    // `flush_apply` can split a whole tail off the front as `Bytes` without
    // copying *and* without surrendering the allocation: what stays behind
    // keeps the rest of the capacity, so one allocation is amortised over
    // every packet carved out of it (S9 P8).
    pub write: bytes::BytesMut,
    pub write_cursor: usize,
    pub server_compression: crate::compression::Compression,
    pub client_compression: crate::compression::Compression,
    pub decompress: crate::compression::Decompress,
    pub rekey_wanted: bool,
    pub received_extensions: Vec<String>,
    pub extension_info_awaiters: HashMap<String, Vec<oneshot::Sender<()>>>,
}

/// Sink that `push_packet!` can build a plaintext packet into.
///
/// Two of them exist: `Encrypted::write` (a `BytesMut`, so the Writer
/// hand-off can split packets off the front without copying) and the
/// `PacketWriter`'s own `Vec` used before encryption is up.
pub(crate) trait StagingSink:
    ssh_encoding::Writer + std::ops::DerefMut<Target = [u8]> + for<'a> Extend<&'a u8>
{
}

impl<T> StagingSink for T where
    T: ssh_encoding::Writer + std::ops::DerefMut<Target = [u8]> + for<'a> Extend<&'a u8>
{
}

pub(crate) struct CommonSession<Config> {
    pub auth_user: String,
    pub remote_sshid: Vec<u8>,
    pub config: Config,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) auth_attempts: usize,
    pub packet_writer: PacketWriter,
    pub remote_to_local: Box<dyn OpeningKey + Send>,
    pub wants_reply: bool,
    pub disconnected: bool,
    // Non-sensitive incoming-packet scratch buffer.
    pub buffer: Vec<u8>,
    pub strict_kex: bool,
    pub alive_timeouts: usize,
    pub received_data: bool,
}

impl<C> Debug for CommonSession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonSession")
            .field("auth_user", &self.auth_user)
            .field("remote_sshid", &self.remote_sshid)
            .field("encrypted", &self.encrypted)
            .field("auth_method", &self.auth_method)
            .field("auth_attempts", &self.auth_attempts)
            .field("packet_writer", &self.packet_writer)
            .field("wants_reply", &self.wants_reply)
            .field("disconnected", &self.disconnected)
            .field("buffer", &self.buffer)
            .field("strict_kex", &self.strict_kex)
            .field("alive_timeouts", &self.alive_timeouts)
            .field("received_data", &self.received_data)
            .finish()
    }
}

#[must_use]
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChannelFlushResult {
    Incomplete {
        wrote: usize,
    },
    Complete {
        wrote: usize,
        pending_eof: bool,
        pending_close: bool,
    },
}
impl ChannelFlushResult {
    pub(crate) fn wrote(&self) -> usize {
        match self {
            ChannelFlushResult::Incomplete { wrote } => *wrote,
            ChannelFlushResult::Complete { wrote, .. } => *wrote,
        }
    }
    pub(crate) fn complete(wrote: usize, _channel: &mut ChannelParams) -> Self {
        // Flags live only on the lane (`pending_ctrl` + enqueue/pop). Do not
        // take-and-clear them here: that dual-track used to drop EOF/CLOSE
        // bookkeeping while the items were still queued (or vice versa).
        ChannelFlushResult::Complete {
            wrote,
            pending_eof: false,
            pending_close: false,
        }
    }
}

impl<C> CommonSession<C> {
    pub fn newkeys(&mut self, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.client_mac = newkeys.names.client_mac;
            enc.server_mac = newkeys.names.server_mac;
            self.remote_to_local = newkeys.cipher.remote_to_local;
            self.packet_writer
                .set_cipher(newkeys.cipher.local_to_remote);
            self.strict_kex = self.strict_kex || newkeys.names.strict_kex();

            // Write back newly negotiated algorithms first (P8-2). The
            // previous body re-inited the *old* enums, so a rekey that
            // picked a different compression kept compressing/decompressing
            // with the previous algorithm.
            #[cfg(feature = "_test_hooks")]
            let skip_writeback = crate::negotiation::skip_newkeys_writeback();
            #[cfg(not(feature = "_test_hooks"))]
            let skip_writeback = false;
            if !skip_writeback {
                enc.client_compression = newkeys.names.client_compression;
                enc.server_compression = newkeys.names.server_compression;
            }
            enc.client_compression
                .init_compress(self.packet_writer.compress());
            enc.server_compression.init_decompress(&mut enc.decompress);
        }
    }

    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        // Client single-task path: outbound = client→server compression.
        let (local, outbound_comp, _) = self.encrypted_split_outbound(state, newkeys, false);
        self.packet_writer.set_cipher(local);
        if let Some(ref mut enc) = self.encrypted {
            if !outbound_comp.is_deferred() {
                outbound_comp.init_compress(self.packet_writer.compress());
            }
        }
    }

    /// Build `Encrypted` + install inbound cipher; return outbound sealing key.
    ///
    /// Direction depends on endpoint:
    /// - **client** (`is_server=false`): outbound = `client_compression`,
    ///   inbound decompress = `server_compression`
    /// - **server** (`is_server=true`): outbound = `server_compression`,
    ///   inbound decompress = `client_compression`
    ///
    /// Deferred (`zlib@openssh.com`) compress/decompress stay inactive until auth.
    pub fn encrypted_split_outbound(
        &mut self,
        state: EncryptedState,
        newkeys: NewKeys,
        is_server: bool,
    ) -> (
        Box<dyn crate::cipher::SealingKey + Send>,
        crate::compression::Compression,
        bool,
    ) {
        let strict_kex = newkeys.names.strict_kex();
        let outbound_comp = if is_server {
            newkeys.names.server_compression.clone()
        } else {
            newkeys.names.client_compression.clone()
        };
        let reset_seqn = strict_kex;
        self.encrypted = Some(Encrypted {
            exchange: Some(newkeys.exchange),
            kex: newkeys.kex,
            key: newkeys.key,
            client_mac: newkeys.names.client_mac,
            server_mac: newkeys.names.server_mac,
            session_id: newkeys.session_id,
            state,
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            write: bytes::BytesMut::new(),
            write_cursor: 0,
            server_compression: newkeys.names.server_compression,
            client_compression: newkeys.names.client_compression,
            decompress: crate::compression::Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        });
        self.remote_to_local = newkeys.cipher.remote_to_local;
        let local_to_remote = newkeys.cipher.local_to_remote;
        self.strict_kex = strict_kex;

        if let Some(ref mut enc) = self.encrypted {
            // Inbound decompress: peer→us.
            let inbound = if is_server {
                &enc.client_compression
            } else {
                &enc.server_compression
            };
            if !inbound.is_deferred() {
                inbound.clone().init_decompress(&mut enc.decompress);
            }
        }
        (local_to_remote, outbound_comp, reset_seqn)
    }

    /// Send a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        // Generic over the sink: the staging buffer is a `BytesMut` while the
        // pre-encryption path still writes into the `PacketWriter`'s `Vec`.
        fn disconnect<W: StagingSink>(
            buf: &mut W,
            reason: Disconnect,
            description: &str,
            language_tag: &str,
        ) -> Result<(), crate::Error> {
            push_packet!(buf, {
                msg::DISCONNECT.encode(buf)?;
                (reason as u32).encode(buf)?;
                description.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        }
        if !self.disconnected {
            self.disconnected = true;
            return if let Some(ref mut enc) = self.encrypted {
                disconnect(&mut enc.write, reason, description, language_tag)
            } else {
                disconnect(
                    &mut self.packet_writer.buffer().buffer,
                    reason,
                    description,
                    language_tag,
                )
            };
        }
        Ok(())
    }

    /// Send a debug message.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        fn debug<W: StagingSink>(
            buf: &mut W,
            always_display: bool,
            message: &str,
            language_tag: &str,
        ) -> Result<(), crate::Error> {
            push_packet!(buf, {
                msg::DEBUG.encode(buf)?;
                (always_display as u8).encode(buf)?;
                message.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        }
        if let Some(ref mut enc) = self.encrypted {
            debug(&mut enc.write, always_display, message, language_tag)
        } else {
            debug(
                &mut self.packet_writer.buffer().buffer,
                always_display,
                message,
                language_tag,
            )
        }
    }

    pub(crate) fn reset_seqn(&mut self) {
        self.packet_writer.reset_seqn();
    }
}

/// S6c C6: apply `CommonSession::newkeys` with a new compression pair and
/// return the enums stored on `Encrypted` afterwards.
#[cfg(feature = "_test_hooks")]
pub fn newkeys_rewrites_compression_enums(
    old_client: crate::compression::Compression,
    old_server: crate::compression::Compression,
    new_client: crate::compression::Compression,
    new_server: crate::compression::Compression,
) -> (crate::compression::Compression, crate::compression::Compression) {
    use crate::kex::{KEXES, NONE};
    let Some(kex_impl) = KEXES.get(&NONE) else {
        return (old_client, old_server);
    };
    let mut common = CommonSession {
        auth_user: String::new(),
        remote_sshid: b"SSH-2.0-test".to_vec(),
        config: (),
        encrypted: Some(Encrypted {
            state: EncryptedState::Authenticated,
            exchange: Some(Exchange::new(b"c", b"s")),
            kex: kex_impl.make(),
            key: 0,
            client_mac: crate::mac::NONE,
            server_mac: crate::mac::NONE,
            session_id: CryptoVec::new(),
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            write: bytes::BytesMut::new(),
            write_cursor: 0,
            server_compression: old_server.clone(),
            client_compression: old_client.clone(),
            decompress: crate::compression::Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        }),
        auth_method: None,
        auth_attempts: 0,
        packet_writer: PacketWriter::clear(),
        remote_to_local: Box::new(crate::cipher::clear::Key {}),
        wants_reply: false,
        disconnected: false,
        buffer: Vec::new(),
        strict_kex: false,
        alive_timeouts: 0,
        received_data: false,
    };
    common.newkeys(NewKeys {
        exchange: Exchange::new(b"c", b"s"),
        names: crate::negotiation::Names::with_compression(new_client, new_server),
        kex: kex_impl.make(),
        key: 0,
        cipher: crate::cipher::CipherPair {
            local_to_remote: Box::new(crate::cipher::clear::Key {}),
            remote_to_local: Box::new(crate::cipher::clear::Key {}),
        },
        session_id: CryptoVec::new(),
    });
    match common.encrypted {
        Some(enc) => (enc.client_compression, enc.server_compression),
        None => (old_client, old_server),
    }
}

impl Encrypted {
    pub fn byte(&mut self, channel: ChannelId, msg: u8) -> Result<(), crate::Error> {
        if let Some(channel) = self.channels.get(&channel) {
            push_packet!(self.write, {
                self.write.put_u8(msg);
                channel.recipient_channel.encode(&mut self.write)?;
            });
        }
        Ok(())
    }

    pub fn park_eof(&mut self, channel: ChannelId) {
        if let Some(ch) = self.channels.get_mut(&channel) {
            if !ch.pending_eof && !ch.pending_close {
                ch.enqueue_ctrl(crate::ChannelCtrlItem::Eof);
            }
        }
    }

    pub fn eof(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        self.park_eof(channel);
        if !self.has_pending_data(channel) {
            let _ = self.flush_pending(channel)?;
        }
        Ok(())
    }

    pub fn park_close(&mut self, channel: ChannelId) {
        if let Some(ch) = self.channels.get_mut(&channel) {
            if !ch.pending_close && !ch.outbound_closed {
                ch.enqueue_ctrl(crate::ChannelCtrlItem::Close);
            }
        }
    }

    pub fn close(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        self.park_close(channel);
        // Do not auto-flush DATA: a full-window flush here would skip HWM.
        // Callers that want emit (unit tests) invoke flush_pending themselves.
        if !self.has_pending_data(channel) {
            let _ = self.flush_pending(channel)?;
        }
        Ok(())
    }

    /// StopDiscard (plan §4.3 / 行 135): drop unframed lane items, emit
    /// exactly one outbound `CHANNEL_CLOSE`. Already-sealed Writer `out_q`
    /// packets are left intact. Unsealed plaintext in enc.write / bulk FIFO
    /// / pending_outbound is dropped at Writer seal via the tombstone.
    ///
    /// This is the single discard implementation. Local `close()` still
    /// parks behind DATA; peer CLOSE, inbound overflow, and outbound
    /// cap all enter here. A second call on a gone channel is a no-op
    /// (CLOSE arbitration: never a second CLOSE).
    pub fn close_discarding_pending(
        &mut self,
        channel: ChannelId,
    ) -> Result<crate::StopDiscardStats, crate::Error> {
        let Some(c) = self.channels.get_mut(&channel) else {
            return Ok(crate::StopDiscardStats {
                already_gone: true,
                ..crate::StopDiscardStats::default()
            });
        };
        if c.outbound_closed {
            // CLOSE already framed this turn (pop_ctrl_front). Do not
            // write a second one; drop any leftover unframed items.
            let stats = c.stop_discard_unframed();
            self.channels.remove(&channel);
            return Ok(stats);
        }
        let stats = c.stop_discard_unframed();
        // Channel still present so `byte` can encode the reply. Lane is
        // empty; this is the unique CLOSE for the channel.
        self.byte(channel, msg::CHANNEL_CLOSE)?;
        self.channels.remove(&channel);
        Ok(stats)
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(channel) = self.channels.get(&channel) {
            channel.sender_window_size as usize
        } else {
            0
        }
    }

    /// I1: consume the inbound receive window for `len` received bytes. The bytes are already off
    /// the wire, so the peer's send allowance is genuinely used up regardless of when (or
    /// whether) they are delivered to the application buffer. Never grants more window.
    pub fn consume_recv_window(&mut self, channel: ChannelId, len: usize) {
        if let Some(channel) = self.channels.get_mut(&channel) {
            trace!(
                "consume_recv_window, channel = {}, len = {}",
                channel.sender_channel, len
            );
            // Ignore extra data. https://tools.ietf.org/html/rfc4254#section-5.2
            if len as u32 <= channel.sender_window_size {
                channel.sender_window_size -= len as u32;
            }
        }
    }

    /// I2: grant more inbound receive window, topping it back up towards `target`. Pushes a
    /// `CHANNEL_WINDOW_ADJUST` and returns `true` iff a grant was emitted.
    ///
    /// The server calls this only **after** the corresponding data has been accepted into the
    /// per-channel application buffer, so a stuck channel withholds its own grant and
    /// backpressures only itself, instead of blocking the shared session loop. The emitted
    /// packet goes into `self.write` and is flushed by the normal session-loop flush path
    /// (consistent with rekey gating); callers must not assume it has hit the wire yet.
    ///
    /// `undelivered` is the number of bytes that are already off the wire but still sitting in
    /// this channel's pending inbound queue. Those bytes have consumed the peer's send allowance
    /// but have *not* been handed to the application, so they must keep occupying the advertised
    /// window: the peer may hold at most `target` bytes of un-consumed window at any time, and
    /// the most we may advertise is therefore `target - undelivered`. Topping straight back up to
    /// `target` here would re-authorise the peer for data we have not yet delivered, letting the
    /// pending queue grow one full window per delivered item. Server callers
    /// pass Reader lane occupancy; the client path passes Scheme C pending
    /// bytes (or 0 when drained).
    pub fn maybe_grant_recv_window(
        &mut self,
        channel: ChannelId,
        target: u32,
        undelivered: u32,
    ) -> Result<bool, crate::Error> {
        let ceiling = target.saturating_sub(undelivered);
        if let Some(channel) = self.channels.get_mut(&channel) {
            if channel.outbound_closed {
                return Ok(false);
            }
            if channel.sender_window_size < ceiling / 2 {
                debug!(
                    "sender_window_size {:?}, target {:?}, undelivered {:?}, ceiling {:?}",
                    channel.sender_window_size, target, undelivered, ceiling
                );
                push_packet!(self.write, {
                    self.write.put_u8(msg::CHANNEL_WINDOW_ADJUST);
                    channel.recipient_channel.encode(&mut self.write)?;
                    (ceiling - channel.sender_window_size).encode(&mut self.write)?;
                });
                channel.sender_window_size = ceiling;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Write a CHANNEL_WINDOW_ADJUST and SET the inbound-window mirror.
    /// Reader already expanded the authoritative remaining; this must not `-=`.
    pub fn emit_window_adjust(
        &mut self,
        channel: ChannelId,
        delta: u32,
        ceiling: u32,
    ) -> Result<bool, crate::Error> {
        let Some(ch) = self.channels.get_mut(&channel) else {
            return Ok(false);
        };
        if ch.outbound_closed {
            return Ok(false);
        }
        push_packet!(self.write, {
            self.write.put_u8(msg::CHANNEL_WINDOW_ADJUST);
            ch.recipient_channel.encode(&mut self.write)?;
            delta.encode(&mut self.write)?;
        });
        ch.sender_window_size = ceiling;
        Ok(true)
    }

    fn encode_ctrl_payload(
        channel: &ChannelParams,
        item: &crate::ChannelCtrlItem,
    ) -> Result<Vec<u8>, crate::Error> {
        let mut body = Vec::new();
        match item {
            crate::ChannelCtrlItem::OpenConfirmation {
                recipient_channel,
                sender_channel,
                window_size,
                packet_size,
            } => {
                msg::CHANNEL_OPEN_CONFIRMATION.encode(&mut body)?;
                recipient_channel.encode(&mut body)?;
                sender_channel.encode(&mut body)?;
                window_size.encode(&mut body)?;
                packet_size.encode(&mut body)?;
            }
            crate::ChannelCtrlItem::Eof => {
                body.push(msg::CHANNEL_EOF);
                channel.recipient_channel.encode(&mut body)?;
            }
            crate::ChannelCtrlItem::Close => {
                body.push(msg::CHANNEL_CLOSE);
                channel.recipient_channel.encode(&mut body)?;
            }
            crate::ChannelCtrlItem::Success => {
                body.push(msg::CHANNEL_SUCCESS);
                channel.recipient_channel.encode(&mut body)?;
            }
            crate::ChannelCtrlItem::Failure => {
                body.push(msg::CHANNEL_FAILURE);
                channel.recipient_channel.encode(&mut body)?;
            }
            crate::ChannelCtrlItem::Request { body: rest } => {
                body.push(msg::CHANNEL_REQUEST);
                body.extend_from_slice(rest);
            }
        }
        Ok(body)
    }

    fn push_ctrl_to_write(write: &mut bytes::BytesMut, payload: &[u8]) -> Result<(), crate::Error> {
        push_packet!(write, {
            write.extend_from_slice(payload);
        });
        Ok(())
    }

    /// Drain one channel's outbound lane. Control/fence items are never
    /// gated on the peer window (I3 / appendix B.8). DATA still consumes
    /// window via `data_noqueue`.
    fn flush_channel(
        write: &mut bytes::BytesMut,
        channel: &mut ChannelParams,
        admit: &mut impl FnMut(&crate::ChannelCtrlItem) -> bool,
        allow_data: bool,
    ) -> Result<ChannelFlushResult, crate::Error> {
        Self::flush_channel_inner(write, None, channel, admit, allow_data)
    }

    fn flush_channel_with_writer(
        write: &mut bytes::BytesMut,
        writer: &mut PacketWriter,
        channel: &mut ChannelParams,
        admit: &mut impl FnMut(&crate::ChannelCtrlItem) -> bool,
    ) -> Result<ChannelFlushResult, crate::Error> {
        Self::flush_channel_inner(write, Some(writer), channel, admit, true)
    }

    fn flush_channel_inner(
        write: &mut bytes::BytesMut,
        mut writer: Option<&mut PacketWriter>,
        channel: &mut ChannelParams,
        admit: &mut impl FnMut(&crate::ChannelCtrlItem) -> bool,
        allow_data: bool,
    ) -> Result<ChannelFlushResult, crate::Error> {
        let mut pending_size = 0;
        loop {
            if channel.ctrl_ahead_of_data() {
                let Some(item) = channel.peek_ctrl_front() else {
                    break;
                };
                if !admit(item) {
                    return Ok(ChannelFlushResult::Incomplete {
                        wrote: pending_size,
                    });
                }
                let item = channel
                    .pop_ctrl_front()
                    .ok_or(crate::Error::Inconsistent)?;
                let payload = Self::encode_ctrl_payload(channel, &item)?;
                if write.is_empty() {
                    if let Some(ref mut w) = writer {
                        w.write_packet(|packet| {
                            packet.extend_from_slice(&payload);
                            Ok(())
                        })?;
                    } else {
                        Self::push_ctrl_to_write(write, &payload)?;
                    }
                } else {
                    Self::push_ctrl_to_write(write, &payload)?;
                }
                continue;
            }
            if channel.pending_data.is_empty() {
                break;
            }
            if !allow_data {
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
            // DATA: window predicate applies (RFC 4254 §5.2).
            if channel.recipient_window_size == 0 {
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
            // S2d: gather consecutive same-stream entries into one packet.
            // Cap = min(peer_maxpacket, remaining window, 32 KiB).
            // Stop at a fence or a different EXTENDED_DATA ext.
            let size = Self::gather_one_data_packet(write, writer.as_deref_mut(), channel)?;
            pending_size += size;
            if size == 0 {
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
        }
        Ok(ChannelFlushResult::complete(pending_size, channel))
    }

    fn handle_flushed_channel(
        &mut self,
        channel: ChannelId,
        _flush_result: ChannelFlushResult,
    ) -> Result<(), crate::Error> {
        // CLOSE already written by the lane drain. Drop the protocol
        // entry once the tail fence is gone and no DATA remains.
        // CLOSE is never admit-gated, so a queued Close cannot sit behind
        // a hard-cap refuse. Window=0 with DATA in front is G2 (channel
        // stays until the peer adjusts or the session dies). Teardown
        // drops Encrypted, so there is no cross-connection leak.
        let gone = self.channels.get(&channel).is_some_and(|ch| {
            ch.lane == crate::ChannelLaneState::Closing
                && ch.pending_data.is_empty()
                && !ch.has_pending_ctrl()
        });
        if gone {
            self.channels.remove(&channel);
        }
        Ok(())
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, crate::Error> {
        self.flush_pending_admitted(channel, |_| true, true)
    }

    /// Like [`flush_pending`], with a per-ctrl admit hook (server HWM hard
    /// cap for CHANNEL_SUCCESS/FAILURE). `false` leaves the item queued.
    /// `allow_data`: when false (kex / pending-install), only fences emit.
    pub fn flush_pending_admitted(
        &mut self,
        channel: ChannelId,
        mut admit: impl FnMut(&crate::ChannelCtrlItem) -> bool,
        allow_data: bool,
    ) -> Result<usize, crate::Error> {
        let flush_result = match self.channels.get_mut(&channel) {
            Some(ch) => Self::flush_channel(&mut self.write, ch, &mut admit, allow_data)?,
            None => return Ok(0),
        };
        let wrote = flush_result.wrote();
        self.handle_flushed_channel(channel, flush_result)?;
        Ok(wrote)
    }

    pub fn flush_pending_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
    ) -> Result<usize, crate::Error> {
        let flush_result = match self.channels.get_mut(&channel) {
            Some(ch) => {
                Self::flush_channel_with_writer(&mut self.write, writer, ch, &mut |_| true)?
            }
            None => return Ok(0),
        };
        let wrote = flush_result.wrote();
        self.handle_flushed_channel(channel, flush_result)?;
        Ok(wrote)
    }

    pub fn flush_all_pending(&mut self) -> Result<(), crate::Error> {
        let channel_ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            self.flush_pending(channel_id)?;
        }
        Ok(())
    }

    pub fn flush_all_pending_with_writer(
        &mut self,
        writer: &mut PacketWriter,
    ) -> Result<(), crate::Error> {
        let channel_ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            self.flush_pending_with_writer(writer, channel_id)?;
        }
        Ok(())
    }

    fn has_pending_data_mut(&mut self, channel: ChannelId) -> Option<&mut ChannelParams> {
        self.channels
            .get_mut(&channel)
            .filter(|c| !c.pending_data.is_empty())
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(channel) = self.channels.get(&channel) {
            !channel.pending_data.is_empty()
        } else {
            false
        }
    }

    /// Sum of wire reservations for SUCCESS/FAILURE still in per-channel lanes.
    pub(crate) fn queued_reply_reservation(&self) -> usize {
        self.channels
            .values()
            .map(|c| c.queued_reply_reservation())
            .sum()
    }

    #[cfg(feature = "_test_hooks")]
    pub(crate) fn queued_reply_count(&self) -> usize {
        self.channels.values().map(|c| c.queued_reply_count()).sum()
    }

    /// DATA or fence/control still queued on the per-channel lane.
    pub fn has_pending_lane(&self, channel: ChannelId) -> bool {
        if let Some(ch) = self.channels.get(&channel) {
            !ch.pending_data.is_empty() || ch.has_pending_ctrl()
        } else {
            false
        }
    }

    /// Bytes still queued for transmission on `channel` (0 if it has none, or is gone).
    ///
    /// Hot path: called once per dispatched message for the *one* channel that message targets,
    /// so it must stay cheap. The deque is empty for producers that reserve window before
    /// enqueueing (`ChannelWriteHalf`, i.e. `Channel::data` / `make_writer`), which is the
    /// steady state, making this O(1) in practice.
    pub(crate) fn pending_data_bytes(&self, channel: ChannelId) -> usize {
        self.channels
            .get(&channel)
            .map(|c| {
                c.pending_data
                    .iter()
                    .map(|(buf, _, from)| buf.len().saturating_sub(*from))
                    .sum::<usize>()
            })
            .unwrap_or(0)
    }

    /// Whether the channel still exists in the protocol state.
    ///
    /// Callers must not conflate "gone" with "drained": [`Self::has_pending_data`] returns
    /// `false` for both, and treating a removed channel as drained would signal *success* to a
    /// producer whose data was actually discarded.
    pub(crate) fn channel_exists(&self, channel: ChannelId) -> bool {
        self.channels.contains_key(&channel)
    }

    /// Assemble and emit **one** CHANNEL_DATA / EXTENDED_DATA from the
    /// head of `pending_data`, concatenating consecutive same-`ext`
    /// entries up to `min(peer_maxpacket, window, 32 KiB)`.
    /// Does not cross a fence (ctrl seq ≤ next data seq) or a different ext.
    fn gather_one_data_packet(
        write: &mut bytes::BytesMut,
        mut writer: Option<&mut PacketWriter>,
        channel: &mut ChannelParams,
    ) -> Result<usize, crate::Error> {
        if channel.recipient_maximum_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }
        if channel.pending_data.is_empty() || channel.recipient_window_size == 0 {
            return Ok(0);
        }
        if channel.ctrl_ahead_of_data() {
            return Ok(0);
        }
        let ext0 = channel.pending_data.front().map(|(_, e, _)| *e).unwrap_or(None);
        let cap = (channel.recipient_maximum_packet_size as usize)
            .min(channel.recipient_window_size as usize)
            .min(crate::LOCAL_TRANSPORT_PAYLOAD_CAP);
        if cap == 0 {
            return Ok(0);
        }
        // Fast path (steady state): the head entry alone fills this packet,
        // so hand its `Bytes` straight to `data_noqueue`. Staging it through
        // `gathered` first costs a full payload memcpy plus the realloc
        // churn of growing a 4 KiB Vec to `max_packet_size` — per packet.
        let head = channel
            .pending_data
            .front()
            .map(|(b, e, f)| (b.len().saturating_sub(*f), *e));
        if let Some((avail, head_ext)) = head {
            let take = avail.min(cap);
            let alone = take == cap
                || channel.pending_data.len() == 1
                || channel.pending_data.get(1).map(|(_, e, _)| *e) != Some(head_ext);
            if take > 0 && alone {
                let Some((buf, ext, from, seq)) = channel.pop_data_front() else {
                    return Ok(0);
                };
                let end = from.saturating_add(take);
                let chunk = buf.slice(from..end);
                if end < buf.len() {
                    channel.push_data_front(buf, ext, end, seq);
                }
                channel.boost_pending = false;
                let size = if write.is_empty() {
                    if let Some(ref mut w) = writer {
                        Self::data_noqueue_direct(w, channel, &chunk, ext, 0)?
                    } else {
                        Self::data_noqueue(write, channel, &chunk, ext, 0)?
                    }
                } else {
                    Self::data_noqueue(write, channel, &chunk, ext, 0)?
                };
                return Ok(size);
            }
        }
        let mut gathered = Vec::with_capacity(cap);
        while gathered.len() < cap {
            if channel.ctrl_ahead_of_data() {
                break;
            }
            let Some((buf, ext, from, seq)) = channel.pop_data_front() else {
                break;
            };
            if ext != ext0 {
                channel.push_data_front(buf, ext, from, seq);
                break;
            }
            let avail = buf.len().saturating_sub(from);
            if avail == 0 {
                continue;
            }
            let take = avail.min(cap - gathered.len());
            gathered.extend_from_slice(&buf[from..from + take]);
            if from + take < buf.len() {
                channel.push_data_front(buf, ext, from + take, seq);
                break;
            }
        }
        if gathered.is_empty() {
            return Ok(0);
        }
        channel.boost_pending = false;
        let size = if write.is_empty() {
            if let Some(ref mut w) = writer {
                Self::data_noqueue_direct(w, channel, &Bytes::from(gathered), ext0, 0)?
            } else {
                Self::data_noqueue(write, channel, &gathered, ext0, 0)?
            }
        } else {
            Self::data_noqueue(write, channel, &gathered, ext0, 0)?
        };
        Ok(size)
    }

    /// Push the largest amount of `&buf0[from..]` that can fit into
    /// the window, dividing it into packets if it is too large, and
    /// return the length that was written.
    fn data_noqueue(
        write: &mut bytes::BytesMut,
        channel: &mut ChannelParams,
        buf0: &[u8],
        a: Option<u32>,
        from: usize,
    ) -> Result<usize, crate::Error> {
        if from >= buf0.len() {
            return Ok(0);
        }
        let window_end = from
            .checked_add(channel.recipient_window_size as usize)
            .unwrap_or(usize::MAX);
        let end = std::cmp::min(buf0.len(), window_end);
        #[allow(clippy::indexing_slicing)] // length checked
        let mut buf = &buf0[from..end];
        let buf_len = buf.len();
        let max_packet_size = channel.recipient_maximum_packet_size as usize;
        if max_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }
        let packet_count = buf_len.div_ceil(max_packet_size);
        let packet_overhead = match a {
            None => 4 + 1 + 4 + 4,
            Some(_) => 4 + 1 + 4 + 4 + 4,
        };
        write.reserve(buf_len.saturating_add(packet_count.saturating_mul(packet_overhead)));

        while !buf.is_empty() {
            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(), max_packet_size);
            match a {
                None => push_packet!(write, {
                    write.put_u8(msg::CHANNEL_DATA);
                    channel.recipient_channel.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
                }),
                Some(ext) => push_packet!(write, {
                    write.put_u8(msg::CHANNEL_EXTENDED_DATA);
                    channel.recipient_channel.encode(write)?;
                    ext.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
                }),
            }
            trace!(
                "buffer: {:?} {:?}",
                write.len(),
                channel.recipient_window_size
            );
            channel.recipient_window_size -= off as u32;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                buf = &buf[off..]
            }
        }
        trace!("buf.len() = {:?}, buf_len = {:?}", buf.len(), buf_len);
        Ok(buf_len)
    }

    fn data_noqueue_direct(
        writer: &mut PacketWriter,
        channel: &mut ChannelParams,
        buf0: &Bytes,
        a: Option<u32>,
        from: usize,
    ) -> Result<usize, crate::Error> {
        if from >= buf0.len() {
            return Ok(0);
        }
        let buf0 = buf0.as_ref();
        let window_end = from
            .checked_add(channel.recipient_window_size as usize)
            .unwrap_or(usize::MAX);
        let end = std::cmp::min(buf0.len(), window_end);
        #[allow(clippy::indexing_slicing)] // length checked
        let mut buf = &buf0[from..end];
        let buf_len = buf.len();
        let max_packet_size = channel.recipient_maximum_packet_size as usize;
        if max_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }
        let packet_count = buf_len.div_ceil(max_packet_size);
        let channel_payload_overhead = match a {
            None => 1 + 4 + 4,
            Some(_) => 1 + 4 + 4 + 4,
        };
        writer.reserve_cleartext_packet_output(
            buf_len.saturating_add(packet_count.saturating_mul(channel_payload_overhead)),
            packet_count,
        );

        while !buf.is_empty() {
            let off = std::cmp::min(buf.len(), max_packet_size);
            match a {
                None => writer.write_packet(|packet| {
                    packet.push(msg::CHANNEL_DATA);
                    channel.recipient_channel.encode(packet)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(packet)?;
                    Ok(())
                })?,
                Some(ext) => writer.write_packet(|packet| {
                    packet.push(msg::CHANNEL_EXTENDED_DATA);
                    channel.recipient_channel.encode(packet)?;
                    ext.encode(packet)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(packet)?;
                    Ok(())
                })?,
            }
            channel.recipient_window_size -= off as u32;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                buf = &buf[off..]
            }
        }
        Ok(buf_len)
    }

    pub fn data(
        &mut self,
        channel: ChannelId,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            // A write to a channel the peer has not confirmed is a caller error, not a reason
            // to abort the process: this runs on the shared session task, so panicking here
            // would take down every other channel on the connection too.
            if !channel.confirmed {
                return Err(crate::Error::WrongChannel);
            }
            let blocked = !channel.pending_data.is_empty()
                || channel.has_pending_ctrl()
                || is_rekeying;
            if !channel.enqueue_data(buf0, None, 0) {
                // Post-EOF/CLOSE: silent drop (see ChannelParams::enqueue_data).
                return Ok(());
            }
            if blocked {
                return Ok(());
            }
        } else {
            debug!("{channel:?} not saved for this session");
        }
        if !is_rekeying {
            self.flush_pending(channel)?;
        }
        Ok(())
    }

    pub fn data_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            // A write to a channel the peer has not confirmed is a caller error, not a reason
            // to abort the process: this runs on the shared session task, so panicking here
            // would take down every other channel on the connection too.
            if !channel.confirmed {
                return Err(crate::Error::WrongChannel);
            }
            let blocked = !channel.pending_data.is_empty()
                || channel.has_pending_ctrl()
                || is_rekeying;
            if !channel.enqueue_data(buf0, None, 0) {
                // Post-EOF/CLOSE: silent drop (see ChannelParams::enqueue_data).
                return Ok(());
            }
            if blocked {
                return Ok(());
            }
        } else {
            debug!("{channel:?} not saved for this session");
        }
        if !is_rekeying {
            self.flush_pending_with_writer(writer, channel)?;
        }
        Ok(())
    }

    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            // A write to a channel the peer has not confirmed is a caller error, not a reason
            // to abort the process: this runs on the shared session task, so panicking here
            // would take down every other channel on the connection too.
            if !channel.confirmed {
                return Err(crate::Error::WrongChannel);
            }
            let blocked = !channel.pending_data.is_empty()
                || channel.has_pending_ctrl()
                || is_rekeying;
            if !channel.enqueue_data(buf0, Some(ext), 0) {
                // Post-EOF/CLOSE: silent drop (see ChannelParams::enqueue_data).
                return Ok(());
            }
            if blocked {
                return Ok(());
            }
        }
        if !is_rekeying {
            self.flush_pending(channel)?;
        }
        Ok(())
    }

    pub fn extended_data_with_writer(
        &mut self,
        writer: &mut PacketWriter,
        channel: ChannelId,
        ext: u32,
        buf0: impl Into<Bytes>,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        let buf0 = buf0.into();
        if let Some(channel) = self.channels.get_mut(&channel) {
            // A write to a channel the peer has not confirmed is a caller error, not a reason
            // to abort the process: this runs on the shared session task, so panicking here
            // would take down every other channel on the connection too.
            if !channel.confirmed {
                return Err(crate::Error::WrongChannel);
            }
            let blocked = !channel.pending_data.is_empty()
                || channel.has_pending_ctrl()
                || is_rekeying;
            if !channel.enqueue_data(buf0, Some(ext), 0) {
                // Post-EOF/CLOSE: silent drop (see ChannelParams::enqueue_data).
                return Ok(());
            }
            if blocked {
                return Ok(());
            }
        }
        if !is_rekeying {
            self.flush_pending_with_writer(writer, channel)?;
        }
        Ok(())
    }

    pub fn flush(
        &mut self,
        limits: &RekeyPolicy,
        writer: &mut PacketWriter,
    ) -> Result<bool, crate::Error> {
        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {
                // Read a single packet, encrypt and send it.
                #[allow(clippy::indexing_slicing)] // length checked
                let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                #[allow(clippy::indexing_slicing)]
                let to_write = &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 + len)];
                trace!("session_write_encrypted, buf = {to_write:?}");

                writer.packet_raw(to_write)?;
                self.write_cursor += 4 + len
            }
        }
        if self.write_cursor >= self.write.len() {
            // If all packets have been written, clear.
            self.write_cursor = 0;
            self.write.clear();
        }

        if self.kex.skip_exchange() {
            return Ok(false);
        }

        // Volume-based rekey initiation (shared by client and server).
        // Packet counting lives on the server Reader/Writer atomics;
        // this single-loop path (client, and server object tests without
        // a Writer) only sees outbound `SSHBuffer.bytes`. No time trigger
        // (S6b / Q3).
        Ok(replace(&mut self.rekey_wanted, false)
            || (writer.buffer().bytes as u64) >= limits.max_bytes)
    }

    pub fn new_channel_id(&mut self) -> ChannelId {
        self.last_channel_id += Wrapping(1);
        while self
            .channels
            .contains_key(&ChannelId(self.last_channel_id.0))
        {
            self.last_channel_id += Wrapping(1)
        }
        ChannelId(self.last_channel_id.0)
    }
    pub fn new_channel(&mut self, window_size: u32, maxpacket: u32) -> ChannelId {
        loop {
            self.last_channel_id += Wrapping(1);
            if let std::collections::hash_map::Entry::Vacant(vacant_entry) =
                self.channels.entry(ChannelId(self.last_channel_id.0))
            {
                vacant_entry.insert(ChannelParams::new(
                    0,
                    ChannelId(self.last_channel_id.0),
                    0,
                    window_size,
                    0,
                    maxpacket,
                    false,
                ));
                return ChannelId(self.last_channel_id.0);
            }
        }
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingAuthServiceRequest { sent: bool, accepted: bool },
    WaitingAuthRequest(auth::AuthRequest),
    InitCompression,
    Authenticated,
}

#[derive(Debug, Default, Clone)]
pub struct Exchange {
    // All Exchange fields are public protocol values (identifiers,
    // kex init payloads, ephemeral public keys) visible on the wire.
    // They carry no secret material and do not require mlock.
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    pub client_kex_init: Bytes,
    pub server_kex_init: Bytes,
    pub client_ephemeral: Vec<u8>,
    pub server_ephemeral: Vec<u8>,
    pub gex: Option<(GexParams, DhGroup)>,
}

impl Exchange {
    pub fn new(client_id: &[u8], server_id: &[u8]) -> Self {
        Exchange {
            client_id: client_id.into(),
            server_id: server_id.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: CryptoVec,
}

#[derive(Debug)]
pub(crate) enum GlobalRequestResponse {
    /// request was for Keepalive, ignore result
    Keepalive,
    /// request was for Keepalive but with notification of the result
    Ping(oneshot::Sender<()>),
    /// request was for NoMoreSessions, disallow additional sessions
    NoMoreSessions,
    /// request was for TcpIpForward, sends Some(port) for success or None for failure
    TcpIpForward(oneshot::Sender<Option<u32>>),
    /// request was for CancelTcpIpForward, sends true for success or false for failure
    CancelTcpIpForward(oneshot::Sender<bool>),
    /// request was for StreamLocalForward, sends true for success or false for failure
    StreamLocalForward(oneshot::Sender<bool>),
    CancelStreamLocalForward(oneshot::Sender<bool>),
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::num::Wrapping;

    use byteorder::{BigEndian, ByteOrder};
    use bytes::{BufMut, Bytes};

    use super::{Encrypted, EncryptedState, Exchange};
    use crate::compression::{Compression, Decompress};
    use crate::kex::{KEXES, NONE};
    use crate::sshbuffer::PacketWriter;
    use crate::{ChannelId, ChannelParams, CryptoVec, RekeyPolicy, mac, msg};

    fn test_encrypted() -> Encrypted {
        Encrypted {
            state: EncryptedState::Authenticated,
            exchange: Some(Exchange::default()),
            kex: KEXES.get(&NONE).unwrap().make(),
            key: 0,
            client_mac: mac::NONE,
            server_mac: mac::NONE,
            session_id: CryptoVec::new(),
            channels: HashMap::new(),
            last_channel_id: Wrapping(0),
            write: bytes::BytesMut::new(),
            write_cursor: 0,
            server_compression: Compression::None,
            client_compression: Compression::None,
            decompress: Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        }
    }

    fn test_channel(
        sender_channel: ChannelId,
        recipient_channel: u32,
        pending_eof: bool,
        pending_close: bool,
    ) -> ChannelParams {
        let mut ch = ChannelParams::new(
            recipient_channel,
            sender_channel,
            1024,
            1024,
            1024,
            1024,
            true,
        );
        ch.lane = crate::ChannelLaneState::Confirmed;
        ch.enqueue_data(Bytes::from_static(b"hello"), None, 0);
        if pending_eof {
            ch.enqueue_ctrl(crate::ChannelCtrlItem::Eof);
        }
        if pending_close {
            ch.enqueue_ctrl(crate::ChannelCtrlItem::Close);
        }
        ch
    }

    fn first_data_payload_len(buf: &[u8]) -> u32 {
        // CHANNEL_DATA: 4B pktlen + msg + recip(4) + string_len(4)
        assert!(buf.len() >= 13, "packet too short: {}", buf.len());
        #[allow(clippy::indexing_slicing)]
        BigEndian::read_u32(&buf[9..13])
    }

    fn packet_types(buf: &[u8]) -> Vec<u8> {
        let mut packet_types = Vec::new();
        let mut cursor = 0;

        while cursor < buf.len() {
            let packet_len = BigEndian::read_u32(&buf[cursor..cursor + 4]) as usize;
            packet_types.push(buf[cursor + 4]);
            cursor += 4 + packet_len;
        }

        packet_types
    }

    fn clear_packet_types(buf: &[u8]) -> Vec<u8> {
        let mut packet_types = Vec::new();
        let mut cursor = 0;

        while cursor < buf.len() {
            let packet_len = BigEndian::read_u32(&buf[cursor..cursor + 4]) as usize;
            packet_types.push(buf[cursor + 5]);
            cursor += 4 + packet_len;
        }

        packet_types
    }

    fn test_ready_channel(sender_channel: ChannelId, recipient_channel: u32) -> ChannelParams {
        let mut channel = test_channel(sender_channel, recipient_channel, false, false);
        channel.clear_outbound();
        channel
    }

    fn test_channel_windowed(
        sender_channel: ChannelId,
        recipient_channel: u32,
        window_size: u32,
        pending_eof: bool,
        pending_close: bool,
    ) -> ChannelParams {
        let mut ch = test_channel(sender_channel, recipient_channel, pending_eof, pending_close);
        ch.recipient_window_size = window_size;
        ch
    }

    // flush_pending (single-channel path)

    #[test]
    fn flush_pending_replays_deferred_eof_once() {
        let channel_id = ChannelId(10);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, false));

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
        assert!(
            encrypted.channels[&channel_id].pending_eof,
            "pending_eof stays latched after emit so later DATA cannot follow EOF"
        );
        assert!(!encrypted.channels[&channel_id].has_pending_ctrl());

        // Second flush must not re-emit EOF.
        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
    }

    /// A peer-initiated CHANNEL_CLOSE must emit its RFC 4254 reply immediately, discarding the
    /// outbound backlog, instead of parking it as `pending_close`. Parking waits on a
    /// CHANNEL_WINDOW_ADJUST the closing peer has no reason to send, which strands the reply and
    /// leaves the channel entry alive forever.
    #[test]
    fn close_discarding_pending_emits_reply_and_drops_channel() {
        let channel_id = ChannelId(12);
        let mut encrypted = test_encrypted();
        // Backlog present, so plain `close()` would defer via `pending_close`.
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 44, false, false));
        assert!(encrypted.has_pending_data(channel_id));

        encrypted.close_discarding_pending(channel_id).unwrap();

        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_CLOSE]);
        assert!(
            !encrypted.channels.contains_key(&channel_id),
            "channel must be dropped, not left waiting on a window adjustment"
        );
    }

    /// Already-framed packets in `enc.write` survive StopDiscard; only
    /// the unframed lane is dropped. A second discard must not emit
    /// another CLOSE.
    #[test]
    fn stop_discard_keeps_framed_and_drops_lane() {
        let channel_id = ChannelId(21);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 50, false, false));
        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_DATA]);
        // Park more unframed DATA + a local CLOSE behind it.
        encrypted
            .data(channel_id, bytes::Bytes::from_static(b"more"), true)
            .unwrap();
        encrypted.park_close(channel_id);
        assert!(encrypted.has_pending_data(channel_id));
        assert!(encrypted.channels[&channel_id].pending_close);

        let stats = encrypted.close_discarding_pending(channel_id).unwrap();
        assert!(
            stats.discarded_items >= 1,
            "unframed lane must be discarded, stats={stats:?}"
        );
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_CLOSE],
            "framed DATA must stay; exactly one CLOSE appended"
        );
        assert!(!encrypted.channels.contains_key(&channel_id));

        let again = encrypted.close_discarding_pending(channel_id).unwrap();
        assert!(again.already_gone);
        assert_eq!(
            packet_types(&encrypted.write)
                .into_iter()
                .filter(|&t| t == msg::CHANNEL_CLOSE)
                .count(),
            1,
            "second StopDiscard must not emit another CLOSE"
        );
    }

    #[test]
    fn enqueue_after_outbound_closed_is_dropped() {
        let channel_id = ChannelId(22);
        let mut encrypted = test_encrypted();
        let mut ch = test_channel(channel_id, 51, false, false);
        ch.outbound_closed = true;
        encrypted.channels.insert(channel_id, ch);
        encrypted.park_close(channel_id);
        encrypted
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .enqueue_ctrl(crate::ChannelCtrlItem::Success);
        assert!(
            !encrypted.channels[&channel_id].has_pending_ctrl(),
            "SUCCESS after outbound_closed must not enqueue"
        );
        assert!(!encrypted.channels[&channel_id].pending_close);
    }

    #[test]
    fn enqueue_after_pending_close_is_dropped() {
        let channel_id = ChannelId(23);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 52, false, true));
        assert!(encrypted.channels[&channel_id].pending_close);
        encrypted
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .enqueue_ctrl(crate::ChannelCtrlItem::Success);
        encrypted
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .enqueue_ctrl(crate::ChannelCtrlItem::Request {
                body: bytes::Bytes::from_static(b"x"),
            });
        let ch = &encrypted.channels[&channel_id];
        assert!(ch.has_pending_ctrl(), "parked CLOSE must remain");
        assert_eq!(
            ch.queued_reply_count(),
            0,
            "SUCCESS/REQUEST after parked CLOSE must not enqueue"
        );
    }

    /// Contrast: plain `close()` still defers behind queued data (the orderly local-close path).
    #[test]
    fn close_defers_behind_pending_data() {
        let channel_id = ChannelId(13);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 45, false, false));

        encrypted.close(channel_id).unwrap();

        assert!(packet_types(&encrypted.write).is_empty());
        assert!(encrypted.channels[&channel_id].pending_close);
    }

    #[test]
    fn flush_pending_replays_deferred_close_and_removes_channel() {
        let channel_id = ChannelId(11);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 43, true, true));

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn flush_pending_no_controls_when_incomplete() {
        // Window smaller than data: flush is incomplete, EOF/CLOSE must not be sent.
        let channel_id = ChannelId(12);
        let mut encrypted = test_encrypted();
        encrypted.channels.insert(
            channel_id,
            test_channel_windowed(channel_id, 44, 3, true, true),
        );

        encrypted.flush_pending(channel_id).unwrap();
        // Only partial data fits; no EOF or CLOSE yet.
        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_DATA]);
        assert!(encrypted.channels.contains_key(&channel_id));
        assert!(encrypted.channels[&channel_id].pending_eof);
        assert!(encrypted.channels[&channel_id].pending_close);
    }

    // flush_all_pending (multi-channel path)

    #[test]
    fn flush_all_pending_replays_deferred_eof_once() {
        let channel_id = ChannelId(1);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, false));

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
        assert!(
            encrypted.channels[&channel_id].pending_eof,
            "pending_eof stays latched after emit so later DATA cannot follow EOF"
        );
        assert!(!encrypted.channels[&channel_id].has_pending_ctrl());

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
    }

    #[test]
    fn flush_all_pending_replays_deferred_close_and_removes_channel() {
        let channel_id = ChannelId(2);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 43, true, true));

        encrypted.flush_all_pending().unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn flush_all_pending_replays_deferred_controls_across_channels() {
        let channel_a = ChannelId(3);
        let channel_b = ChannelId(4);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_a, test_channel(channel_a, 44, true, false));
        encrypted
            .channels
            .insert(channel_b, test_channel(channel_b, 45, false, true));

        encrypted.flush_all_pending().unwrap();

        let packet_types = packet_types(&encrypted.write);
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_DATA)
                .count(),
            2
        );
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_EOF)
                .count(),
            1
        );
        assert_eq!(
            packet_types
                .iter()
                .filter(|&&msg_type| msg_type == msg::CHANNEL_CLOSE)
                .count(),
            1
        );
        assert!(encrypted.channels.contains_key(&channel_a));
        assert!(!encrypted.channels.contains_key(&channel_b));
    }

    #[test]
    fn data_queues_behind_existing_pending_data_when_not_rekeying() {
        let channel_id = ChannelId(5);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let channel = &encrypted.channels[&channel_id];
        let initial_pending = channel.pending_data.len();
        assert!(initial_pending > 0);
        let initial_front = channel.pending_data.front().unwrap();
        let initial_front_data = initial_front.0.to_vec();
        let initial_front_ext = initial_front.1;

        encrypted
            .data(channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), initial_pending + 1);
        assert_eq!(
            channel.pending_data.front().unwrap().0.as_ref(),
            initial_front_data.as_slice()
        );
        assert_eq!(channel.pending_data.front().unwrap().1, initial_front_ext);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, None);
        assert!(encrypted.write.is_empty());
    }

    #[test]
    fn data_after_eof_is_silently_dropped() {
        let channel_id = ChannelId(30);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 50));

        encrypted.eof(channel_id).unwrap();
        let before = encrypted.channels[&channel_id].pending_data.len();
        encrypted
            .data(channel_id, Bytes::from_static(b"after-eof"), false)
            .unwrap();
        encrypted
            .extended_data(channel_id, 1, Bytes::from_static(b"ext-after"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), before);
        assert!(channel.pending_eof);
        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_EOF]);
    }

    #[test]
    fn data_after_close_is_silently_dropped() {
        let channel_id = ChannelId(31);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 51, false, false));

        encrypted.close(channel_id).unwrap();
        let before = encrypted.channels[&channel_id].pending_data.len();
        assert_eq!(
            encrypted.channels[&channel_id].lane,
            crate::ChannelLaneState::Closing
        );
        encrypted
            .data(channel_id, Bytes::from_static(b"after-close"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), before);
        assert_eq!(channel.lane, crate::ChannelLaneState::Closing);
        assert!(encrypted.write.is_empty());
    }

    #[test]
    fn gather_combines_consecutive_same_stream_entries() {
        let channel_id = ChannelId(32);
        let mut encrypted = test_encrypted();
        let mut ch = test_ready_channel(channel_id, 52);
        assert!(ch.enqueue_data(Bytes::from_static(b"aa"), None, 0));
        assert!(ch.enqueue_data(Bytes::from_static(b"bb"), None, 0));
        encrypted.channels.insert(channel_id, ch);

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(packet_types(&encrypted.write), vec![msg::CHANNEL_DATA]);
        assert_eq!(first_data_payload_len(&encrypted.write), 4);
        assert!(encrypted.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn gather_stops_before_eof_fence() {
        let channel_id = ChannelId(33);
        let mut encrypted = test_encrypted();
        let mut ch = test_ready_channel(channel_id, 53);
        assert!(ch.enqueue_data(Bytes::from_static(b"aa"), None, 0));
        ch.enqueue_ctrl(crate::ChannelCtrlItem::Eof);
        assert!(!ch.enqueue_data(Bytes::from_static(b"xx"), None, 0));
        encrypted.channels.insert(channel_id, ch);

        encrypted.flush_pending(channel_id).unwrap();
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF]
        );
        assert_eq!(first_data_payload_len(&encrypted.write), 2);
    }

    #[test]
    fn gather_respects_32kib_cap() {
        let channel_id = ChannelId(34);
        let mut encrypted = test_encrypted();
        let mut ch = test_ready_channel(channel_id, 54);
        ch.recipient_maximum_packet_size = 64 * 1024;
        ch.recipient_window_size = 64 * 1024;
        assert!(ch.enqueue_data(Bytes::from(vec![1u8; 20_000]), None, 0));
        assert!(ch.enqueue_data(Bytes::from(vec![2u8; 20_000]), None, 0));
        encrypted.channels.insert(channel_id, ch);

        encrypted.flush_pending(channel_id).unwrap();
        let types = packet_types(&encrypted.write);
        assert_eq!(types, vec![msg::CHANNEL_DATA, msg::CHANNEL_DATA]);
        assert_eq!(
            first_data_payload_len(&encrypted.write),
            crate::LOCAL_TRANSPORT_PAYLOAD_CAP as u32
        );
    }

    #[test]
    fn confirm_only_transitions_opening_to_confirmed() {
        let mut ch = test_ready_channel(ChannelId(35), 55);
        ch.lane = crate::ChannelLaneState::Closing;
        ch.confirm(&crate::parsing::ChannelOpenConfirmation {
            recipient_channel: 55,
            sender_channel: 99,
            initial_window_size: 1024,
            maximum_packet_size: 1024,
        });
        assert_eq!(ch.lane, crate::ChannelLaneState::Closing);

        let mut open = test_ready_channel(ChannelId(36), 56);
        open.lane = crate::ChannelLaneState::Opening;
        open.boost_pending = false;
        open.confirm(&crate::parsing::ChannelOpenConfirmation {
            recipient_channel: 56,
            sender_channel: 100,
            initial_window_size: 2048,
            maximum_packet_size: 1024,
        });
        assert_eq!(open.lane, crate::ChannelLaneState::Confirmed);
        assert!(open.boost_pending);
    }

    #[test]
    fn extended_data_queues_behind_existing_pending_data_when_not_rekeying() {
        let channel_id = ChannelId(6);
        let ext = 1;
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let channel = &encrypted.channels[&channel_id];
        let initial_pending = channel.pending_data.len();
        assert!(initial_pending > 0);
        let initial_front = channel.pending_data.front().unwrap();
        let initial_front_data = initial_front.0.to_vec();
        let initial_front_ext = initial_front.1;

        encrypted
            .extended_data(channel_id, ext, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), initial_pending + 1);
        assert_eq!(
            channel.pending_data.front().unwrap().0.as_ref(),
            initial_front_data.as_slice()
        );
        assert_eq!(channel.pending_data.front().unwrap().1, initial_front_ext);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, Some(ext));
        assert!(encrypted.write.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_matches_staged_channel_data() {
        let channel_id = ChannelId(7);
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));
        direct
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));

        let mut staged_writer = PacketWriter::clear();
        staged.flush_pending(channel_id).unwrap();
        staged
            .flush(&RekeyPolicy::default(), &mut staged_writer)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .flush_pending_with_writer(&mut direct_writer, channel_id)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_matches_staged_extended_data() {
        let channel_id = ChannelId(8);
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        let mut staged_channel = test_channel(channel_id, 42, false, false);
        staged_channel.pending_data =
            VecDeque::from([(Bytes::from_static(b"hello"), Some(1), 0)]);
        let mut direct_channel = test_channel(channel_id, 42, false, false);
        direct_channel.pending_data =
            VecDeque::from([(Bytes::from_static(b"hello"), Some(1), 0)]);
        staged.channels.insert(channel_id, staged_channel);
        direct.channels.insert(channel_id, direct_channel);

        let mut staged_writer = PacketWriter::clear();
        staged.flush_pending(channel_id).unwrap();
        staged
            .flush(&RekeyPolicy::default(), &mut staged_writer)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .flush_pending_with_writer(&mut direct_writer, channel_id)
            .unwrap();

        assert_eq!(direct_writer.buffer().buffer, staged_writer.buffer().buffer);
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn flush_pending_with_writer_falls_back_when_write_queue_nonempty() {
        let channel_id = ChannelId(9);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, false, false));
        push_packet!(encrypted.write, encrypted.write.put_u8(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id)
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );
    }

    #[test]
    fn flush_pending_with_writer_preserves_partial_window_remainder() {
        let channel_id = ChannelId(13);
        let payload = Bytes::from_static(b"abcdef");
        let mut encrypted = test_encrypted();
        let mut channel = test_channel_windowed(channel_id, 42, 3, false, false);
        channel.pending_data = VecDeque::from([(payload.clone(), None, 0)]);
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA]
        );
        assert_eq!(channel.recipient_window_size, 0);
        assert_eq!(channel.pending_data.len(), 1);
        let pending = channel.pending_data.back().unwrap();
        assert_eq!(pending.0, payload);
        assert_eq!(pending.1, None);
        assert_eq!(pending.2, 3);
    }

    #[test]
    fn flush_pending_with_writer_emits_controls_after_replayed_data() {
        let channel_id = ChannelId(14);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 42, true, true));

        let mut writer = PacketWriter::clear();
        encrypted
            .flush_pending_with_writer(&mut writer, channel_id)
            .unwrap();
        encrypted.flush(&RekeyPolicy::default(), &mut writer).unwrap();

        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::CHANNEL_DATA, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE]
        );
        assert!(!encrypted.channels.contains_key(&channel_id));
    }

    #[test]
    fn data_direct_matches_staged_channel_data() {
        let channel_id = ChannelId(20);
        let payload = Bytes::from_static(b"direct channel data");
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 42));
        direct
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 42));

        let mut staged_writer = PacketWriter::clear();
        staged.data(channel_id, payload.clone(), false).unwrap();
        staged
            .flush(&RekeyPolicy::default(), &mut staged_writer)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .data_with_writer(&mut direct_writer, channel_id, payload, false)
            .unwrap();

        assert_eq!(
            direct_writer.buffer().buffer,
            staged_writer.buffer().buffer
        );
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn extended_data_direct_matches_staged_channel_data() {
        let channel_id = ChannelId(21);
        let payload = Bytes::from_static(b"direct extended channel data");
        let mut staged = test_encrypted();
        let mut direct = test_encrypted();
        staged
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 43));
        direct
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 43));

        let mut staged_writer = PacketWriter::clear();
        staged
            .extended_data(channel_id, 1, payload.clone(), false)
            .unwrap();
        staged
            .flush(&RekeyPolicy::default(), &mut staged_writer)
            .unwrap();

        let mut direct_writer = PacketWriter::clear();
        direct
            .extended_data_with_writer(&mut direct_writer, channel_id, 1, payload, false)
            .unwrap();

        assert_eq!(
            direct_writer.buffer().buffer,
            staged_writer.buffer().buffer
        );
        assert_eq!(
            direct.channels[&channel_id].recipient_window_size,
            staged.channels[&channel_id].recipient_window_size
        );
        assert!(direct.channels[&channel_id].pending_data.is_empty());
    }

    #[test]
    fn data_direct_is_disabled_when_write_queue_nonempty() {
        let channel_id = ChannelId(22);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 44));
        push_packet!(encrypted.write, encrypted.write.put_u8(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        assert_eq!(
            packet_types(&encrypted.write),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );

        encrypted.flush(&RekeyPolicy::default(), &mut writer).unwrap();
        assert_eq!(
            clear_packet_types(&writer.buffer().buffer),
            vec![msg::REQUEST_SUCCESS, msg::CHANNEL_DATA]
        );
    }

    #[test]
    fn data_staged_large_payload_when_write_queue_nonempty_preserves_order_and_chunks() {
        let channel_id = ChannelId(26);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 48);
        channel.recipient_window_size = 256 * 1024;
        channel.recipient_maximum_packet_size = 32 * 1024;
        encrypted.channels.insert(channel_id, channel);
        push_packet!(encrypted.write, encrypted.write.put_u8(msg::REQUEST_SUCCESS));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(
                &mut writer,
                channel_id,
                Bytes::from(vec![0x5a; 256 * 1024]),
                false,
            )
            .unwrap();

        assert!(writer.buffer().buffer.is_empty());
        let packet_types = packet_types(&encrypted.write);
        assert_eq!(packet_types.first(), Some(&msg::REQUEST_SUCCESS));
        assert_eq!(packet_types.len(), 9);
        assert!(
            packet_types
                .iter()
                .skip(1)
                .all(|&msg_type| msg_type == msg::CHANNEL_DATA)
        );
        assert!(encrypted.channels[&channel_id].pending_data.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 0);
    }

    #[test]
    fn data_staged_rejects_zero_recipient_max_packet_size() {
        let channel_id = ChannelId(27);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 49);
        channel.recipient_maximum_packet_size = 0;
        encrypted.channels.insert(channel_id, channel);

        let result = encrypted.data(channel_id, Bytes::from_static(b"new"), false);

        assert!(matches!(result, Err(crate::Error::Inconsistent)));
        assert!(encrypted.write.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 1024);
    }

    #[test]
    fn data_direct_rejects_zero_recipient_max_packet_size() {
        let channel_id = ChannelId(28);
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 50);
        channel.recipient_maximum_packet_size = 0;
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        let result =
            encrypted.data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false);

        assert!(matches!(result, Err(crate::Error::Inconsistent)));
        assert!(writer.buffer().buffer.is_empty());
        assert!(encrypted.write.is_empty());
        assert_eq!(encrypted.channels[&channel_id].recipient_window_size, 1024);
    }

    #[test]
    fn data_direct_is_disabled_while_rekeying() {
        let channel_id = ChannelId(23);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_ready_channel(channel_id, 45));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), true)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), 1);
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert_eq!(channel.pending_data.back().unwrap().1, None);
        assert!(encrypted.write.is_empty());
        assert!(writer.buffer().buffer.is_empty());
    }

    #[test]
    fn data_direct_queues_remainder_when_window_is_partial() {
        let channel_id = ChannelId(24);
        let payload = Bytes::from_static(b"abcdef");
        let mut encrypted = test_encrypted();
        let mut channel = test_ready_channel(channel_id, 46);
        channel.recipient_window_size = 3;
        encrypted.channels.insert(channel_id, channel);

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, payload.clone(), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(clear_packet_types(&writer.buffer().buffer), vec![msg::CHANNEL_DATA]);
        assert_eq!(channel.recipient_window_size, 0);
        assert_eq!(channel.pending_data.len(), 1);
        let pending = channel.pending_data.back().unwrap();
        assert_eq!(pending.0, payload);
        assert_eq!(pending.1, None);
        assert_eq!(pending.2, 3);
    }

    #[test]
    fn data_direct_disabled_behind_existing_pending_data() {
        let channel_id = ChannelId(25);
        let mut encrypted = test_encrypted();
        encrypted
            .channels
            .insert(channel_id, test_channel(channel_id, 47, false, false));

        let mut writer = PacketWriter::clear();
        encrypted
            .data_with_writer(&mut writer, channel_id, Bytes::from_static(b"new"), false)
            .unwrap();

        let channel = &encrypted.channels[&channel_id];
        assert_eq!(channel.pending_data.len(), 2);
        assert_eq!(channel.pending_data.front().unwrap().0.as_ref(), b"hello");
        assert_eq!(channel.pending_data.back().unwrap().0.as_ref(), b"new");
        assert!(encrypted.write.is_empty());
        assert!(writer.buffer().buffer.is_empty());
    }
}

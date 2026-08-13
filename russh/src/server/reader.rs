//! S3a ReaderTask: owns the socket read half + inbound epoch.
//!
//! Session receives already-decrypted (and decompressed) packets over a
//! **capacity-1** decoded pipe. That pipe is a temporary S3a exception
//! (Reader stops reading while Session still holds the previous packet)
//! and is deleted in S3b.
//!
//! Inbound epoch install is a **capacity-1** Session→Reader channel.
//! The epoch sits in that channel (or is applied only after NEWKEYS is
//! opened and forwarded). `cipher::read` never sees a newly installed
//! key mid-packet: install is received only at a packet boundary after
//! NEWKEYS, never selected against an in-flight read.

use std::num::Wrapping;
#[cfg(feature = "_test_hooks")]
use std::sync::Arc;
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use log::debug;
use tokio::io::AsyncRead;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::cipher::{self, OpeningKey};
use crate::compression::{Compression, Decompress};
use crate::msg;
use crate::sshbuffer::{IncomingSshPacket, SSHBuffer};
use crate::Error;

/// Session → Reader inbound epoch (capacity 1).
pub struct InstallInboundEpoch {
    pub generation: u64,
    pub cipher: Box<dyn OpeningKey + Send>,
    pub compression: Compression,
    pub activate_decompress: bool,
    pub reset_seqn: bool,
}

impl std::fmt::Debug for InstallInboundEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallInboundEpoch")
            .field("generation", &self.generation)
            .field("activate_decompress", &self.activate_decompress)
            .field("reset_seqn", &self.reset_seqn)
            .finish()
    }
}

#[derive(Debug)]
pub enum TryInstallInboundError {
    /// Capacity-1 slot still occupied (previous epoch not yet applied).
    Full(InstallInboundEpoch),
    /// Reader task is gone.
    Closed(InstallInboundEpoch),
}

/// Reader → Session events (unbounded; never used for bulk DATA).
#[derive(Debug)]
pub enum ReaderEvent {
    InstallAckInbound { generation: u64 },
    ReadError,
    Eof,
}

/// Enable deferred inbound decompress after auth (`zlib@openssh.com`).
pub struct EnableInboundDecompress {
    pub compression: Compression,
}

/// Test/production hooks for ReaderTask.
#[derive(Clone, Default)]
pub struct ReaderHooks {
    #[cfg(feature = "_test_hooks")]
    pub observe: Option<Arc<ReaderObserveSlot>>,
    /// When held, Reader waits at the packet boundary *before* starting
    /// `cipher::read` (and stays out of `cipher::read` while held). An
    /// `InstallInboundEpoch` sitting in the capacity-1 channel must not
    /// be applied.
    #[cfg(feature = "_test_hooks")]
    pub read_hold: Option<Arc<ReadHoldGate>>,
    /// When armed, the read half returns `Pending` after `hold_after` bytes
    /// so `cipher::read` is in-flight mid-packet (risk-2 hard test).
    #[cfg(feature = "_test_hooks")]
    pub mid_packet_hold: Option<Arc<MidPacketHold>>,
    /// Next successful transport read is turned into `ReaderEvent::ReadError`.
    #[cfg(feature = "_test_hooks")]
    pub fail_next_read: Option<Arc<AtomicBool>>,
    /// When held, Reader parks after receiving the inbound epoch and before
    /// `apply_epoch` (N5: hang Writer first, then prove apply).
    #[cfg(feature = "_test_hooks")]
    pub apply_hold: Option<Arc<ReadHoldGate>>,
}

/// Live Reader observation (`_test_hooks`).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct ReaderObserveSlot {
    /// Session successfully queued an inbound epoch (channel occupied).
    queued: AtomicBool,
    /// Sticky: queued was true at least once (N1 cannot miss a 20ms window).
    queued_ever: AtomicBool,
    /// Reader is blocked after NEWKEYS waiting for the epoch (NEWKEYS-first).
    awaiting: AtomicBool,
    awaiting_ever: AtomicBool,
    /// Last generation actually installed into the OpeningKey. 0 = none yet
    /// (initial clear epoch is not counted).
    applied_gen: AtomicU64,
    /// How many times `apply_epoch` ran (N3: exactly one apply per rekey).
    applies: AtomicU64,
    last_reset_seqn: AtomicBool,
    packets_this_epoch: AtomicU64,
    in_read_hold: AtomicBool,
    seqn: AtomicU32,
    stopped: AtomicBool,
}

#[cfg(feature = "_test_hooks")]
impl ReaderObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_queued(&self, v: bool) {
        self.queued.store(v, Ordering::SeqCst);
        if v {
            self.queued_ever.store(true, Ordering::SeqCst);
        }
    }
    pub fn queued_ever(&self) -> bool {
        self.queued_ever.load(Ordering::SeqCst)
    }

    /// Clear sticky latches after the initial handshake so a rekey can
    /// prove its own park/await edges.
    pub fn reset_latches(&self) {
        self.queued_ever.store(false, Ordering::SeqCst);
        self.awaiting_ever.store(false, Ordering::SeqCst);
        self.queued.store(false, Ordering::SeqCst);
        self.awaiting.store(false, Ordering::SeqCst);
    }
    pub fn queued(&self) -> bool {
        self.queued.load(Ordering::SeqCst)
    }
    pub fn set_awaiting(&self, v: bool) {
        self.awaiting.store(v, Ordering::SeqCst);
        if v {
            self.awaiting_ever.store(true, Ordering::SeqCst);
        }
    }
    pub fn awaiting_ever(&self) -> bool {
        self.awaiting_ever.load(Ordering::SeqCst)
    }
    pub fn awaiting(&self) -> bool {
        self.awaiting.load(Ordering::SeqCst)
    }
    pub fn set_applied_gen(&self, g: u64) {
        self.applied_gen.store(g, Ordering::SeqCst);
    }
    pub fn applied_gen(&self) -> u64 {
        self.applied_gen.load(Ordering::SeqCst)
    }
    pub fn mark_apply(&self) {
        self.applies.fetch_add(1, Ordering::SeqCst);
    }
    pub fn applies(&self) -> u64 {
        self.applies.load(Ordering::SeqCst)
    }
    pub fn set_last_reset_seqn(&self, v: bool) {
        self.last_reset_seqn.store(v, Ordering::SeqCst);
    }
    pub fn last_reset_seqn(&self) -> bool {
        self.last_reset_seqn.load(Ordering::SeqCst)
    }
    pub fn set_packets_this_epoch(&self, n: u64) {
        self.packets_this_epoch.store(n, Ordering::SeqCst);
    }
    pub fn packets_this_epoch(&self) -> u64 {
        self.packets_this_epoch.load(Ordering::SeqCst)
    }
    pub fn set_in_read_hold(&self, v: bool) {
        self.in_read_hold.store(v, Ordering::SeqCst);
    }
    pub fn in_read_hold(&self) -> bool {
        self.in_read_hold.load(Ordering::SeqCst)
    }
    pub fn set_seqn(&self, s: u32) {
        self.seqn.store(s, Ordering::SeqCst);
    }
    pub fn seqn(&self) -> u32 {
        self.seqn.load(Ordering::SeqCst)
    }
    pub fn set_stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Gate: hold Reader at the packet boundary before `cipher::read`.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct ReadHoldGate {
    held: AtomicBool,
    notify: tokio::sync::Notify,
}

#[cfg(feature = "_test_hooks")]
impl ReadHoldGate {
    pub fn new_held() -> Arc<Self> {
        Arc::new(Self {
            held: AtomicBool::new(true),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn is_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    pub fn hold(&self) {
        self.held.store(true, Ordering::SeqCst);
    }

    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait_released(&self) {
        loop {
            if !self.held.load(Ordering::SeqCst) {
                return;
            }
            let n = self.notify.notified();
            if !self.held.load(Ordering::SeqCst) {
                return;
            }
            n.await;
        }
    }
}

/// `_test_hooks`: stall the socket `AsyncRead` after `hold_after` bytes so
/// `cipher::read` is parked mid-packet (length consumed, body pending).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct MidPacketHold {
    hold_after: AtomicUsize,
    delivered: AtomicUsize,
    held: AtomicBool,
    in_flight: AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

#[cfg(feature = "_test_hooks")]
impl MidPacketHold {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Deliver `after` bytes, then `Poll::Pending` until [`release`].
    pub fn arm(&self, after: usize) {
        self.hold_after.store(after, Ordering::SeqCst);
        self.delivered.store(0, Ordering::SeqCst);
        self.held.store(true, Ordering::SeqCst);
        self.in_flight.store(false, Ordering::SeqCst);
    }

    pub fn in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.waker.lock() {
            if let Some(w) = g.take() {
                w.wake();
            }
        }
    }
}

#[cfg(feature = "_test_hooks")]
struct MidPacketHoldRead<R> {
    inner: R,
    gate: Option<Arc<MidPacketHold>>,
}

#[cfg(feature = "_test_hooks")]
impl<R: AsyncRead + Unpin> tokio::io::AsyncRead for MidPacketHoldRead<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(g) = this.gate.as_ref() else {
            return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        let after = g.hold_after.load(Ordering::SeqCst);
        if after > 0
            && g.held.load(Ordering::SeqCst)
            && g.delivered.load(Ordering::SeqCst) >= after
        {
            g.in_flight.store(true, Ordering::SeqCst);
            if let Ok(mut w) = g.waker.lock() {
                *w = Some(cx.waker().clone());
            }
            return std::task::Poll::Pending;
        }
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let n = buf.filled().len().saturating_sub(before);
                g.delivered.fetch_add(n, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[derive(Clone)]
pub struct ReaderHandle {
    install_tx: mpsc::Sender<InstallInboundEpoch>,
    enable_tx: mpsc::Sender<EnableInboundDecompress>,
    #[cfg(feature = "_test_hooks")]
    observe: Option<Arc<ReaderObserveSlot>>,
}

impl std::fmt::Debug for ReaderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderHandle").finish_non_exhaustive()
    }
}

impl ReaderHandle {
    /// Capacity-1 try_push. Full → caller must Cancelling (I2'). Never await.
    pub fn try_install_inbound(
        &self,
        epoch: InstallInboundEpoch,
    ) -> Result<(), TryInstallInboundError> {
        match self.install_tx.try_send(epoch) {
            Ok(()) => {
                #[cfg(feature = "_test_hooks")]
                if let Some(ref o) = self.observe {
                    o.set_queued(true);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(e)) => Err(TryInstallInboundError::Full(e)),
            Err(mpsc::error::TrySendError::Closed(e)) => Err(TryInstallInboundError::Closed(e)),
        }
    }

    pub fn try_enable_decompress(
        &self,
        compression: Compression,
    ) -> Result<(), EnableInboundDecompress> {
        self.enable_tx
            .try_send(EnableInboundDecompress { compression })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(x) | mpsc::error::TrySendError::Closed(x) => x,
            })
    }
}

pub const DECODED_PIPE_CAP: usize = 1;
pub const INBOUND_EPOCH_CAP: usize = 1;

/// Spawn Reader owning `stream_read` + inbound cipher + `SSHBuffer`.
pub fn spawn_reader<R>(
    stream_read: R,
    cipher: Box<dyn OpeningKey + Send>,
    buffer: SSHBuffer,
    cancel: watch::Receiver<bool>,
    hooks: ReaderHooks,
) -> (
    ReaderHandle,
    JoinHandle<()>,
    mpsc::Receiver<IncomingSshPacket>,
    mpsc::UnboundedReceiver<ReaderEvent>,
)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (install_tx, install_rx) = mpsc::channel::<InstallInboundEpoch>(INBOUND_EPOCH_CAP);
    let (enable_tx, enable_rx) = mpsc::channel::<EnableInboundDecompress>(4);
    let (decoded_tx, decoded_rx) = mpsc::channel::<IncomingSshPacket>(DECODED_PIPE_CAP);
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<ReaderEvent>();

    let handle = ReaderHandle {
        install_tx,
        enable_tx,
        #[cfg(feature = "_test_hooks")]
        observe: hooks.observe.clone(),
    };

    let join = tokio::spawn(reader_loop(
        stream_read,
        cipher,
        buffer,
        cancel,
        install_rx,
        enable_rx,
        decoded_tx,
        evt_tx,
        hooks,
    ));

    (handle, join, decoded_rx, evt_rx)
}

fn apply_epoch(
    cipher: &mut Box<dyn OpeningKey + Send>,
    decompress: &mut Decompress,
    buffer: &mut SSHBuffer,
    packets_this_epoch: &mut u64,
    epoch: InstallInboundEpoch,
    #[cfg(feature = "_test_hooks")] observe: &Option<Arc<ReaderObserveSlot>>,
) -> u64 {
    let generation = epoch.generation;
    *cipher = epoch.cipher;
    if epoch.activate_decompress {
        epoch.compression.init_decompress(decompress);
    } else {
        *decompress = Decompress::None;
    }
    if epoch.reset_seqn {
        buffer.seqn = Wrapping(0);
    }
    *packets_this_epoch = 0;
    #[cfg(feature = "_test_hooks")]
    if let Some(o) = observe {
        o.set_applied_gen(generation);
        o.mark_apply();
        o.set_last_reset_seqn(epoch.reset_seqn);
        o.set_queued(false);
        o.set_awaiting(false);
        o.set_packets_this_epoch(0);
        o.set_seqn(buffer.seqn.0);
    }
    debug!("reader: installed inbound epoch gen={generation} reset_seqn={}", epoch.reset_seqn);
    generation
}

#[allow(clippy::too_many_arguments)]
async fn reader_loop<R: AsyncRead + Unpin>(
    mut stream: R,
    mut cipher: Box<dyn OpeningKey + Send>,
    mut buffer: SSHBuffer,
    mut cancel: watch::Receiver<bool>,
    mut install_rx: mpsc::Receiver<InstallInboundEpoch>,
    mut enable_rx: mpsc::Receiver<EnableInboundDecompress>,
    decoded_tx: mpsc::Sender<IncomingSshPacket>,
    evt_tx: mpsc::UnboundedSender<ReaderEvent>,
    hooks: ReaderHooks,
) {
    #[cfg(not(feature = "_test_hooks"))]
    let _ = &hooks;
    let mut decompress = Decompress::None;
    let mut packets_this_epoch: u64 = 0;
    #[cfg(feature = "_test_hooks")]
    let observe = hooks.observe.clone();
    #[cfg(feature = "_test_hooks")]
    let mut stream = MidPacketHoldRead {
        inner: stream,
        gate: hooks.mid_packet_hold.clone(),
    };

    'reader: loop {
        if *cancel.borrow_and_update() {
            debug!("reader: cancel observed");
            break;
        }

        // Drain enable-decompress at packet boundary (and during read via select).
        while let Ok(en) = enable_rx.try_recv() {
            en.compression.init_decompress(&mut decompress);
        }

        // S3a mid-read / risk-2 hook: do not start cipher::read while held.
        // InstallInboundEpoch may sit in install_rx the whole time — not applied.
        #[cfg(feature = "_test_hooks")]
        if let Some(ref hold) = hooks.read_hold {
            if hold.is_held() {
                if let Some(ref o) = observe {
                    o.set_in_read_hold(true);
                }
                tokio::select! {
                    _ = hold.wait_released() => {}
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            if let Some(ref o) = observe {
                                o.set_in_read_hold(false);
                            }
                            break;
                        }
                    }
                }
                if let Some(ref o) = observe {
                    o.set_in_read_hold(false);
                }
                if *cancel.borrow() {
                    break;
                }
            }
        }

        // In-flight read: NEVER recv install here (risk 2). The epoch stays
        // in the capacity-1 channel. Enable-decompress is safe mid-read
        // (applied after open, before decompress of *this* packet).
        let n = {
            let read_fut = cipher::read(&mut stream, &mut buffer, &mut *cipher);
            tokio::pin!(read_fut);
            loop {
                tokio::select! {
                    r = &mut read_fut => break r,
                    Some(en) = enable_rx.recv() => {
                        en.compression.init_decompress(&mut decompress);
                    }
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            debug!("reader: cancel during read");
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref o) = observe {
                                o.set_stopped();
                            }
                            return;
                        }
                    }
                }
            }
        };

        let n = match n {
            Ok(n) => n,
            Err(Error::IO(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let _ = evt_tx.send(ReaderEvent::Eof);
                break;
            }
            Err(_) => {
                let _ = evt_tx.send(ReaderEvent::ReadError);
                break;
            }
        };
        #[cfg(feature = "_test_hooks")]
        if hooks
            .fail_next_read
            .as_ref()
            .is_some_and(|f| f.swap(false, Ordering::SeqCst))
        {
            let _ = evt_tx.send(ReaderEvent::ReadError);
            break;
        }
        if n == 0 || buffer.buffer.len() < 5 {
            let _ = evt_tx.send(ReaderEvent::Eof);
            break;
        }

        packets_this_epoch = packets_this_epoch.saturating_add(1);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = observe {
            o.set_packets_this_epoch(packets_this_epoch);
            o.set_seqn(buffer.seqn.0);
        }

        let pkt = match decompress_packet(&mut decompress, &buffer) {
            Ok(p) => p,
            Err(_) => {
                let _ = evt_tx.send(ReaderEvent::ReadError);
                break;
            }
        };

        let is_newkeys = pkt.buffer.first() == Some(&msg::NEWKEYS);

        // Capacity-1 decoded pipe: Reader waits here if Session still holds
        // the previous packet. TEMPORARY S3a exception — deleted in S3b.
        // `cancel.changed()` returning false must retry this select, not
        // drop the send / skip install (R1 latent-debt fix).
        {
            let send_fut = decoded_tx.send(pkt);
            tokio::pin!(send_fut);
            loop {
                tokio::select! {
                    r = &mut send_fut => {
                        if r.is_err() {
                            debug!("reader: decoded pipe closed");
                            break 'reader;
                        }
                        break;
                    }
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            break 'reader;
                        }
                    }
                }
            }
        }

        if is_newkeys {
            // Opened NEWKEYS with the OLD epoch and forwarded it. Now wait
            // for the new inbound epoch (already in the channel if key-first).
            // Do not start the next cipher::read until it is installed.
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = observe {
                o.set_awaiting(true);
            }
            let epoch = loop {
                tokio::select! {
                    e = install_rx.recv() => break e,
                    _ = cancel.changed() => {
                        if *cancel.borrow() {
                            break 'reader;
                        }
                    }
                }
            };
            let Some(epoch) = epoch else {
                debug!("reader: install channel closed while awaiting NEWKEYS epoch");
                break;
            };
            #[cfg(feature = "_test_hooks")]
            if let Some(ref hold) = hooks.apply_hold {
                while hold.is_held() {
                    tokio::select! {
                        _ = hold.wait_released() => {}
                        _ = cancel.changed() => {
                            if *cancel.borrow() {
                                break 'reader;
                            }
                        }
                    }
                }
            }
            let installed_gen = apply_epoch(
                &mut cipher,
                &mut decompress,
                &mut buffer,
                &mut packets_this_epoch,
                epoch,
                #[cfg(feature = "_test_hooks")]
                &observe,
            );
            let _ = evt_tx.send(ReaderEvent::InstallAckInbound { generation: installed_gen });
        }
    }

    #[cfg(feature = "_test_hooks")]
    if let Some(ref o) = observe {
        o.set_stopped();
        o.set_awaiting(false);
        o.set_in_read_hold(false);
    }
}

fn decompress_packet(
    decompress: &mut Decompress,
    buffer: &SSHBuffer,
) -> Result<IncomingSshPacket, Error> {
    let mut decomp = Vec::new();
    Ok(IncomingSshPacket {
        #[allow(clippy::indexing_slicing)] // length checked by caller
        buffer: decompress
            .decompress(&buffer.buffer[5..], &mut decomp)?
            .into(),
        seqn: buffer.seqn,
    })
}

/// Join a Reader task against the shared absolute `grace_at`.
#[cfg(all(test, feature = "_test_hooks"))]
mod mid_read_tests {
    use super::*;
    use crate::msg;
    use crate::sshbuffer::PacketWriter;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    /// Epoch-tagged OpeningKey: XOR payload with `tag`. Wrong epoch cannot
    /// recover msg type (copied from Session unit tests).
    struct TagOpen(u8);
    impl OpeningKey for TagOpen {
        fn decrypt_packet_length(&self, _seqn: u32, packet_length: &[u8]) -> [u8; 4] {
            let mut out = [0u8; 4];
            out.copy_from_slice(&packet_length[..4]);
            out
        }
        fn tag_len(&self) -> usize {
            0
        }
        fn open<'a>(
            &mut self,
            _seqn: u32,
            ciphertext_and_tag: &'a mut [u8],
        ) -> Result<&'a [u8], crate::Error> {
            if ciphertext_and_tag.len() < 5 {
                return Err(crate::Error::IndexOutOfBounds);
            }
            for b in &mut ciphertext_and_tag[5..] {
                *b ^= self.0;
            }
            Ok(&ciphertext_and_tag[4..])
        }
    }

    struct TagSeal(u8);
    impl crate::cipher::SealingKey for TagSeal {
        fn padding_length(&self, payload: &[u8]) -> usize {
            let block_size = 8;
            let padding_len = block_size - ((5 + payload.len()) % block_size);
            if padding_len < 4 {
                padding_len + block_size
            } else {
                padding_len
            }
        }
        fn fill_padding(&self, padding_out: &mut [u8]) {
            for b in padding_out {
                *b = 0;
            }
        }
        fn tag_len(&self) -> usize {
            0
        }
        fn seal(&mut self, _seqn: u32, plaintext: &mut [u8], _tag: &mut [u8]) {
            if plaintext.len() > 5 {
                for b in &mut plaintext[5..] {
                    *b ^= self.0;
                }
            }
        }
    }

    fn seal_with(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut pw = PacketWriter::clear();
        pw.set_cipher(Box::new(TagSeal(tag)));
        pw.packet_raw(payload).unwrap();
        pw.take_pending_wire_bytes().to_vec()
    }

    /// Risk 2 (hard): install while `cipher::read` is mid-packet (`read_exact`
    /// body pending) must not apply. Release → that packet opens with the
    /// **old** tag; NEWKEYS then apply; next packet opens with the **new** tag.
    #[tokio::test]
    async fn mid_read_install_does_not_apply() {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let observe = ReaderObserveSlot::new();
        let mid = MidPacketHold::new();
        let hooks = ReaderHooks {
            observe: Some(observe.clone()),
            read_hold: None,
            mid_packet_hold: Some(mid.clone()),
            fail_next_read: None,
            apply_hold: None,
        };
        let (handle, join, mut decoded, mut evts) = spawn_reader(
            server,
            Box::new(TagOpen(0x11)),
            SSHBuffer::new(),
            cancel_rx,
            hooks,
        );

        // Warm-up packet, full write, old key.
        let ign = seal_with(0x11, &[msg::IGNORE, 0, 0, 0, 0]);
        client.write_all(&ign).await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), decoded.recv())
            .await
            .expect("first packet")
            .expect("decoded");
        assert_eq!(first.buffer.first(), Some(&msg::IGNORE));

        // Second IGNORE: deliver only the 4-byte length so cipher::read is
        // parked inside the body `read_exact`.
        let ign2 = seal_with(0x11, &[msg::IGNORE, 0, 0, 0, 1]);
        assert!(ign2.len() > 4, "sealed packet must be longer than length field");
        mid.arm(4);
        client.write_all(&ign2[..4]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !mid.in_flight() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cipher::read in-flight mid-packet");

        handle
            .try_install_inbound(InstallInboundEpoch {
                generation: 7,
                cipher: Box::new(TagOpen(0x22)),
                compression: Compression::None,
                activate_decompress: true,
                reset_seqn: true,
            })
            .expect("cap-1 install");
        assert!(observe.queued(), "epoch must sit in the channel");
        assert_eq!(
            observe.applied_gen(),
            0,
            "HARD: must not apply while cipher::read is mid-packet"
        );
        assert_eq!(observe.applies(), 0);

        client.write_all(&ign2[4..]).await.unwrap();
        mid.release();
        let second = tokio::time::timeout(Duration::from_secs(2), decoded.recv())
            .await
            .expect("second IGNORE after release")
            .expect("decoded");
        assert_eq!(
            second.buffer.first(),
            Some(&msg::IGNORE),
            "HARD: in-flight packet must open with OLD tag 0x11 (new tag 0x22 would scramble type)"
        );
        assert_eq!(observe.applied_gen(), 0, "IGNORE is not NEWKEYS");

        // NEWKEYS under old tag → apply new tag.
        let nk = seal_with(0x11, &[msg::NEWKEYS]);
        client.write_all(&nk).await.unwrap();
        let nk_pkt = tokio::time::timeout(Duration::from_secs(2), decoded.recv())
            .await
            .expect("NEWKEYS forwarded")
            .expect("decoded");
        assert_eq!(nk_pkt.buffer.first(), Some(&msg::NEWKEYS));
        tokio::time::timeout(Duration::from_secs(2), async {
            while observe.applied_gen() != 7 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("applied after NEWKEYS");
        assert_eq!(observe.applies(), 1);
        let ev = evts.recv().await.expect("ack event");
        match ev {
            ReaderEvent::InstallAckInbound { generation } => assert_eq!(generation, 7),
            other => panic!("expected inbound ack, got {other:?}"),
        }

        // Post-install packet must open with NEW tag.
        let ign3 = seal_with(0x22, &[msg::IGNORE, 0, 0, 0, 2]);
        client.write_all(&ign3).await.unwrap();
        let third = tokio::time::timeout(Duration::from_secs(2), decoded.recv())
            .await
            .expect("new-epoch IGNORE")
            .expect("decoded");
        assert_eq!(
            third.buffer.first(),
            Some(&msg::IGNORE),
            "HARD: post-NEWKEYS packet must open with NEW tag 0x22"
        );

        drop(client);
        let _ = join.await;
    }
}

pub async fn stop_reader_task(
    join: &mut Option<JoinHandle<()>>,
    grace_at: tokio::time::Instant,
) {
    let Some(mut handle) = join.take() else {
        return;
    };
    let abort = handle.abort_handle();
    let mut timed_out = false;
    loop {
        tokio::select! {
            biased;
            res = &mut handle => {
                match res {
                    Ok(()) => {}
                    Err(e) if e.is_cancelled() => {
                        debug!("reader join: cancelled (expected after abort)");
                    }
                    Err(e) if e.is_panic() => {
                        log::warn!("reader task panicked during stop: {e}");
                    }
                    Err(e) => {
                        log::warn!("reader join error: {e}");
                    }
                }
                return;
            }
            _ = tokio::time::sleep_until(grace_at), if !timed_out => {
                debug!("reader grace elapsed → abort");
                abort.abort();
                timed_out = true;
            }
        }
    }
}

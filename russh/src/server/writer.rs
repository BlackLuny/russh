//! S2b WriterTask: owns PacketWriter + outbound epoch + socket write half.
//!
//! Session submits ordered `SealPayload` / `SealRaw` / `InstallOutboundEpoch`
//! messages. Cipher/MAC/compress/seqn live only here after spawn.
//!
//! S2a invariants preserved: continuous `drain_writes`, `notify_one`, single
//! absolute grace stop, FIFO seal order (no kex wire priority).

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use log::{debug, warn};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

use crate::cipher::SealingKey;
use crate::compression::Compression;
use crate::server::supervisor::AtomicWriteProgress;
#[cfg(feature = "_test_hooks")]
use crate::server::supervisor::{CapacityChainSlot, FullLedger};
use crate::sshbuffer::PacketWriter;
use crate::Error;

/// Shared StopDiscard tombstone: recipient channel ids whose unsealed
/// plaintext must not be sealed (plan §4.3 / line 135). Keyed by the
/// peer's recipient id parsed from the payload itself.
#[derive(Debug, Default)]
pub struct CloseTombstone {
    ids: Mutex<HashSet<u32>>,
}

impl CloseTombstone {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, recipient: u32) {
        if let Ok(mut g) = self.ids.lock() {
            g.insert(recipient);
        }
    }

    pub fn contains(&self, recipient: u32) -> bool {
        self.ids
            .lock()
            .map(|g| g.contains(&recipient))
            .unwrap_or(false)
    }

    pub fn remove(&self, recipient: u32) {
        if let Ok(mut g) = self.ids.lock() {
            g.remove(&recipient);
        }
    }
}

/// Optional test/production hooks for WriterTask (fail inject, ledger max).
#[derive(Clone, Default)]
pub struct WriterHooks {
    /// StopDiscard tombstone shared with Session (always present).
    pub tombstone: Arc<CloseTombstone>,
    /// Full-pipeline ledger components — sampled at **every** Writer ledger
    /// mutation (accept / rollback / seal-adjust / drain) so the observed max
    /// is the complete sum, not the Writer-local `pending_bytes` (R4).
    #[cfg(feature = "_test_hooks")]
    pub full_ledger: Option<Arc<FullLedger>>,
    /// Use this externally-created `pending_bytes` atomic (so the Session can
    /// reference the same component in its `FullLedger`).
    #[cfg(feature = "_test_hooks")]
    pub pending_override: Option<Arc<AtomicUsize>>,
    /// When true, next SealPayload/SealRaw/Batch seal fails with SealError (R5).
    #[cfg(feature = "_test_hooks")]
    pub fail_next_seal: Option<Arc<AtomicBool>>,
    /// When true, next socket write in `drain_writes` fails with an I/O error
    /// (R5 Writer-fail after outbound install committed).
    #[cfg(feature = "_test_hooks")]
    pub fail_next_socket_write: Option<Arc<AtomicBool>>,
    /// When held (true), socket write returns Pending (deterministic HangWrite).
    #[cfg(feature = "_test_hooks")]
    pub socket_hang: Option<Arc<AtomicBool>>,
    /// Set true when the hang path runs with sealed bytes waiting (N5).
    #[cfg(feature = "_test_hooks")]
    pub socket_hang_seen: Option<Arc<AtomicBool>>,
    /// When true, SealBatchAndInstall returns Full (sticky) — deterministic
    /// Full/NeedSubmit. Tests clear the flag to allow install to advance.
    #[cfg(feature = "_test_hooks")]
    pub force_next_bulk_full: Option<Arc<AtomicBool>>,
    /// R3 chain: count dequeue-side `notify_one` events.
    #[cfg(feature = "_test_hooks")]
    pub capacity_chain: Option<Arc<CapacityChainSlot>>,
    /// When true, do not pull from the bulk mpsc (R3 one-cmd dequeue gate).
    #[cfg(feature = "_test_hooks")]
    pub dequeue_hold: Option<Arc<AtomicBool>>,
    /// Test-only: observe unsealed queue inserts and seal-time drops.
    #[cfg(feature = "_test_hooks")]
    pub stop_discard: Option<Arc<crate::server::supervisor::StopDiscardSlot>>,
    /// Share this packets atomic with Session (S6a wrap-near inject).
    #[cfg(feature = "_test_hooks")]
    pub packets_override: Option<Arc<AtomicU64>>,
    /// Share this cipher-bytes atomic with Session (S6a W6 inject).
    #[cfg(feature = "_test_hooks")]
    pub cipher_bytes_override: Option<Arc<AtomicU64>>,
    /// I6/W3: live observation of outbound epoch packet count / seqn.
    #[cfg(feature = "_test_hooks")]
    pub observe: Option<Arc<WriterObserveSlot>>,
    /// Invert: increment packets even on tombstone drop (must-red).
    #[cfg(feature = "_test_hooks")]
    pub invert_tombstone_counts: bool,
    /// S6c invert: do not rebuild Compress on epoch install.
    #[cfg(feature = "_test_hooks")]
    pub invert_keep_old_decompress: bool,
    #[cfg(feature = "_test_hooks")]
    pub compression_observe: Option<Arc<crate::server::supervisor::CompressionObserveSlot>>,
}

/// Live Writer I5 observation (`_test_hooks`). Separate from the production
/// atomics so "seed observe only" cannot fake a trigger unless flush is
/// inverted to read this slot.
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct WriterObserveSlot {
    packets_this_epoch: AtomicU64,
    seqn: std::sync::atomic::AtomicU32,
}

#[cfg(feature = "_test_hooks")]
impl WriterObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn set_packets_this_epoch(&self, n: u64) {
        self.packets_this_epoch.store(n, Ordering::SeqCst);
    }
    pub fn packets_this_epoch(&self) -> u64 {
        self.packets_this_epoch.load(Ordering::SeqCst)
    }
    pub fn set_seqn(&self, s: u32) {
        self.seqn.store(s, Ordering::SeqCst);
    }
    pub fn seqn(&self) -> u32 {
        self.seqn.load(Ordering::SeqCst)
    }
}

pub const KEX_QUEUE_CAP: usize = 16;
pub const BULK_QUEUE_CAP: usize = 256;
const OUT_Q_SOFT_CAP: usize = 64;

/// Must match [`crate::server::session::Session::WIRE_OVERHEAD_PER_PACKET`]:
/// 4B length + 1B padlen + ≤19B pad + ≤64B MAC/tag.
pub const WIRE_OVERHEAD_PER_PACKET: usize = 4 + 1 + 19 + 64;

/// Ledger weight for a seal payload from the moment of Session accept until
/// Writer seal rewrites it to the actual wire length (no under-reservation gap).
#[inline]
fn seal_reservation(payload_len: usize) -> usize {
    payload_len.saturating_add(WIRE_OVERHEAD_PER_PACKET)
}

#[derive(Debug)]
pub enum TrySendWireError {
    /// Bulk queue full; `Bytes` is the unsent seal payload (restore / park).
    Full(Bytes),
    /// Bulk queue full for a non-payload command (install / compress barrier).
    FullCmd,
    /// Writer receiver dropped — terminal, not recoverable backpressure.
    Closed,
}

/// Full/Closed for epoch install commands (never collapsed into one error).
pub enum TrySendEpochError {
    /// Bulk queue full; caller must retain materials and retry after capacity.
    Full {
        payloads: Vec<Bytes>,
        generation: u64,
        cipher: Box<dyn SealingKey + Send>,
        outbound_compression: Compression,
        activate_compress: bool,
        reset_seqn: bool,
    },
    /// Writer receiver dropped — terminal.
    Closed,
}

impl std::fmt::Debug for TrySendEpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full {
                payloads,
                generation,
                activate_compress,
                reset_seqn,
                ..
            } => f
                .debug_struct("Full")
                .field("n_payloads", &payloads.len())
                .field("generation", generation)
                .field("activate_compress", activate_compress)
                .field("reset_seqn", reset_seqn)
                .finish(),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

/// Ordered Session → Writer commands (seal + install share FIFO with bulk).
pub enum WriterCmd {
    /// Plaintext SSH message payload (msg type + body).
    SealPayload(Bytes),
    /// Same as SealPayload (alias for flush-extracted cleartext packets).
    SealRaw(Bytes),
    /// **Atomic** NEWKEYS outbound half: seal `payloads` with the *current* (old)
    /// epoch, then install the new cipher/seqn/compressor, then ACK — all inside
    /// one `handle_writer_cmd` with **no await**. Soft-cap cannot split this.
    SealBatchAndInstallEpoch {
        payloads: Vec<Bytes>,
        generation: u64,
        cipher: Box<dyn SealingKey + Send>,
        outbound_compression: Compression,
        /// If false, leave compressor as `None` (deferred zlib@openssh.com pre-auth).
        activate_compress: bool,
        reset_seqn: bool,
        ack: oneshot::Sender<Result<(), Error>>,
    },
    /// Install new outbound epoch only (no preceding seals). Still no await in handler.
    InstallOutboundEpoch {
        generation: u64,
        cipher: Box<dyn SealingKey + Send>,
        outbound_compression: Compression,
        activate_compress: bool,
        reset_seqn: bool,
        ack: oneshot::Sender<Result<(), Error>>,
    },
    /// Deferred compression activation after auth (zlib@openssh.com).
    InitOutboundCompress {
        compression: Compression,
        ack: oneshot::Sender<Result<(), Error>>,
    },
    Shutdown(oneshot::Sender<()>),
}

impl std::fmt::Debug for WriterCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SealPayload(b) => f.debug_tuple("SealPayload").field(&b.len()).finish(),
            Self::SealRaw(b) => f.debug_tuple("SealRaw").field(&b.len()).finish(),
            Self::SealBatchAndInstallEpoch {
                payloads,
                generation,
                reset_seqn,
                activate_compress,
                ..
            } => f
                .debug_struct("SealBatchAndInstallEpoch")
                .field("n_payloads", &payloads.len())
                .field("generation", generation)
                .field("reset_seqn", reset_seqn)
                .field("activate_compress", activate_compress)
                .finish(),
            Self::InstallOutboundEpoch {
                generation,
                reset_seqn,
                activate_compress,
                ..
            } => f
                .debug_struct("InstallOutboundEpoch")
                .field("generation", generation)
                .field("reset_seqn", reset_seqn)
                .field("activate_compress", activate_compress)
                .finish(),
            Self::InitOutboundCompress { .. } => f.write_str("InitOutboundCompress"),
            Self::Shutdown(_) => f.write_str("Shutdown"),
        }
    }
}

/// Kex control only (Shutdown prefer); install rides the ordered bulk FIFO.
#[derive(Debug)]
pub enum KexCmd {
    Shutdown(oneshot::Sender<()>),
}

#[derive(Debug)]
pub enum WriterEvent {
    InstallAckOutbound { generation: u64 },
    KexQueueFull,
    WriteError(std::io::ErrorKind),
    SealError,
}

#[derive(Debug, Clone)]
pub struct WriterHandle {
    bulk_tx: mpsc::Sender<WriterCmd>,
    kex_tx: mpsc::Sender<KexCmd>,
    /// Submitted-but-not-on-socket bytes (queue + out_q + current).
    pending_bytes: Arc<AtomicUsize>,
    /// PacketWriter.buffer().bytes for rekey volume limits.
    cipher_bytes: Arc<AtomicU64>,
    /// I5 outbound packet count this key-epoch (Session-readable).
    packets_this_epoch: Arc<AtomicU64>,
    capacity: Arc<Notify>,
    #[cfg(feature = "_test_hooks")]
    full_ledger: Option<Arc<FullLedger>>,
    #[cfg(feature = "_test_hooks")]
    fail_next_seal: Option<Arc<AtomicBool>>,
    #[cfg(feature = "_test_hooks")]
    force_next_bulk_full: Option<Arc<AtomicBool>>,
    tombstone: Arc<CloseTombstone>,
    #[cfg(feature = "_test_hooks")]
    stop_discard: Option<Arc<crate::server::supervisor::StopDiscardSlot>>,
}

impl WriterHandle {
    /// Credit `n` into the linearized pipeline total (Writer accept / top-up).
    #[cfg(feature = "_test_hooks")]
    fn credit_ledger(&self, n: usize) {
        if let Some(ref fl) = self.full_ledger {
            fl.credit(n);
        }
    }

    /// Debit `n` from the linearized pipeline total (rollback / drain / shrink).
    #[cfg(feature = "_test_hooks")]
    fn debit_ledger(&self, n: usize) {
        if let Some(ref fl) = self.full_ledger {
            fl.debit(n);
        }
    }

    #[cfg(feature = "_test_hooks")]
    fn note_ledger_mismatch(&self) {
        if let Some(ref fl) = self.full_ledger {
            fl.slot.note_mismatch();
        }
    }

    #[cfg(feature = "_test_hooks")]
    fn note_full_hit(&self) {
        if let Some(ref fl) = self.full_ledger {
            fl.slot.note_full_hit();
        }
    }

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    fn credit_ledger(&self, _n: usize) {}

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    fn debit_ledger(&self, _n: usize) {}

    /// Test hook: sticky force-Full while flag is true (tests clear when done).
    #[cfg(feature = "_test_hooks")]
    fn force_full_active(&self) -> bool {
        self.force_next_bulk_full
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
    }

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    fn force_full_active(&self) -> bool {
        false
    }

    /// Roll back a reservation after a rejected `try_send`. A failed checked
    /// subtraction is an observable ledger error (log + `LedgerMaxSlot`
    /// mismatch counter under `_test_hooks`), never silently dropped (R4).
    fn rollback_reservation(&self, weight: usize) {
        if weight == 0 {
            return;
        }
        let ok = self.pending_bytes.fetch_update(
            Ordering::Release,
            Ordering::Acquire,
            |cur| cur.checked_sub(weight),
        );
        if ok.is_err() {
            log::error!("writer: pending_bytes rollback underflow weight={weight}");
            #[cfg(feature = "_test_hooks")]
            self.note_ledger_mismatch();
        }
        self.debit_ledger(weight);
    }

    /// SealBatch accept failed: undo pending_bytes and linearized kex identity.
    fn rollback_kex_reservation(&self, weight: usize) {
        if weight == 0 {
            return;
        }
        let ok = self.pending_bytes.fetch_update(
            Ordering::Release,
            Ordering::Acquire,
            |cur| cur.checked_sub(weight),
        );
        if ok.is_err() {
            log::error!("writer: pending_bytes kex rollback underflow weight={weight}");
            #[cfg(feature = "_test_hooks")]
            self.note_ledger_mismatch();
        }
        self.debit_kex_ledger(weight);
    }

    #[cfg(feature = "_test_hooks")]
    fn credit_kex_ledger(&self, n: usize) {
        if let Some(ref fl) = self.full_ledger {
            fl.credit_kex_to_writer(n);
        }
    }

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    fn credit_kex_ledger(&self, _n: usize) {}

    #[cfg(feature = "_test_hooks")]
    fn debit_kex_ledger(&self, n: usize) {
        if let Some(ref fl) = self.full_ledger {
            fl.debit_kex_from_writer(n);
        }
    }

    #[cfg(not(feature = "_test_hooks"))]
    #[inline]
    fn debit_kex_ledger(&self, _n: usize) {}

    pub(crate) fn close_tombstone(&self) -> &Arc<CloseTombstone> {
        &self.tombstone
    }

    fn try_send_cmd(&self, cmd: WriterCmd, weight: usize) -> Result<(), TrySendWireError> {
        // force_next_bulk_full is intentionally **batch-install only** (see
        // try_seal_batch_and_install) so flood SealPayload traffic cannot consume it.
        if weight > 0 {
            self.pending_bytes.fetch_add(weight, Ordering::Release);
            self.credit_ledger(weight);
        }
        #[cfg(feature = "_test_hooks")]
        let queued_obs = match &cmd {
            WriterCmd::SealPayload(b) | WriterCmd::SealRaw(b) => parse_channel_payload(b),
            _ => None,
        };
        match self.bulk_tx.try_send(cmd) {
            Ok(()) => {
                #[cfg(feature = "_test_hooks")]
                if let (Some(slot), Some((msg, recip))) = (self.stop_discard.as_ref(), queued_obs) {
                    slot.note_queued_unsealed(recip, msg);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(cmd)) => {
                self.rollback_reservation(weight);
                #[cfg(feature = "_test_hooks")]
                self.note_full_hit();
                match cmd {
                    WriterCmd::SealPayload(b) | WriterCmd::SealRaw(b) => {
                        Err(TrySendWireError::Full(b))
                    }
                    _ => Err(TrySendWireError::FullCmd),
                }
            }
            Err(mpsc::error::TrySendError::Closed(_cmd)) => {
                self.rollback_reservation(weight);
                // Closed is terminal — never masquerade as recoverable Full.
                Err(TrySendWireError::Closed)
            }
        }
    }

    pub fn try_seal_payload(&self, payload: Bytes) -> Result<(), TrySendWireError> {
        if payload.is_empty() {
            return Ok(());
        }
        let n = seal_reservation(payload.len());
        self.try_send_cmd(WriterCmd::SealPayload(payload), n)
    }

    pub fn try_seal_raw(&self, payload: Bytes) -> Result<(), TrySendWireError> {
        if payload.is_empty() {
            return Ok(());
        }
        let n = seal_reservation(payload.len());
        self.try_send_cmd(WriterCmd::SealRaw(payload), n)
    }

    /// Atomic seal(payloads, old epoch) + install new epoch + ACK (S2b §4.4).
    pub fn try_seal_batch_and_install(
        &self,
        payloads: Vec<Bytes>,
        generation: u64,
        cipher: Box<dyn SealingKey + Send>,
        outbound_compression: Compression,
        activate_compress: bool,
        reset_seqn: bool,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, TrySendEpochError> {
        // Deterministic Full inject (test): same Full material return as real bulk Full.
        // Sticky while flag is true so retries stay NeedSubmit until the test clears it.
        if self.force_full_active() {
            return Err(TrySendEpochError::Full {
                payloads,
                generation,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
            });
        }
        // Full wire reservation from accept → seal (no payload-only undercount window).
        let weight: usize = payloads.iter().map(|p| seal_reservation(p.len())).sum();
        if weight > 0 {
            self.pending_bytes.fetch_add(weight, Ordering::Release);
            self.credit_kex_ledger(weight);
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        match self.bulk_tx.try_send(WriterCmd::SealBatchAndInstallEpoch {
            payloads,
            generation,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            ack: ack_tx,
        }) {
            Ok(()) => Ok(ack_rx),
            Err(mpsc::error::TrySendError::Full(WriterCmd::SealBatchAndInstallEpoch {
                payloads,
                generation,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
                ..
            })) => {
                self.rollback_kex_reservation(weight);
                #[cfg(feature = "_test_hooks")]
                self.note_full_hit();
                Err(TrySendEpochError::Full {
                    payloads,
                    generation,
                    cipher,
                    outbound_compression,
                    activate_compress,
                    reset_seqn,
                })
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.rollback_kex_reservation(weight);
                Err(TrySendEpochError::Closed)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.rollback_kex_reservation(weight);
                #[cfg(feature = "_test_hooks")]
                self.note_full_hit();
                Err(TrySendEpochError::Closed)
            }
        }
    }

    /// Install-only (no preceding seals). Prefer `try_seal_batch_and_install` at NEWKEYS.
    pub fn try_install_outbound_epoch(
        &self,
        generation: u64,
        cipher: Box<dyn SealingKey + Send>,
        outbound_compression: Compression,
        activate_compress: bool,
        reset_seqn: bool,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, TrySendEpochError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        match self.bulk_tx.try_send(WriterCmd::InstallOutboundEpoch {
            generation,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            ack: ack_tx,
        }) {
            Ok(()) => Ok(ack_rx),
            Err(mpsc::error::TrySendError::Full(WriterCmd::InstallOutboundEpoch {
                generation,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
                ..
            })) => Err(TrySendEpochError::Full {
                payloads: Vec::new(),
                generation,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
            }),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TrySendEpochError::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TrySendEpochError::Closed),
        }
    }

    /// Deferred compression activation after auth.
    ///
    /// Returns immediately after enqueue — handler is synchronous (no await).
    /// Callers must **not** block the run-loop on the optional ACK forever.
    pub fn try_init_outbound_compress(
        &self,
        compression: Compression,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, TrySendWireError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        match self.bulk_tx.try_send(WriterCmd::InitOutboundCompress {
            compression,
            ack: ack_tx,
        }) {
            Ok(()) => Ok(ack_rx),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TrySendWireError::FullCmd),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TrySendWireError::Closed),
        }
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes.load(Ordering::Acquire)
    }

    /// Volume counter for rekey write limit (PacketWriter.buffer().bytes).
    pub fn cipher_bytes(&self) -> u64 {
        self.cipher_bytes.load(Ordering::Acquire)
    }

    /// Packets sealed on the current outbound epoch (I5).
    pub fn packets_this_epoch(&self) -> u64 {
        self.packets_this_epoch.load(Ordering::Acquire)
    }

    pub fn capacity_notify(&self) -> Arc<Notify> {
        self.capacity.clone()
    }

    pub fn request_shutdown(&self) {
        let (tx, _rx) = oneshot::channel();
        if self.kex_tx.try_send(KexCmd::Shutdown(tx)).is_err() {
            let (tx2, _rx2) = oneshot::channel();
            let _ = self.bulk_tx.try_send(WriterCmd::Shutdown(tx2));
        }
    }
}

pub async fn stop_writer_task(
    cancel_tx: &watch::Sender<bool>,
    writer: Option<&WriterHandle>,
    join: &mut Option<JoinHandle<()>>,
    grace_at: tokio::time::Instant,
) {
    let _ = cancel_tx.send(true);
    if let Some(w) = writer {
        w.request_shutdown();
    }
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
                        debug!("writer join: cancelled (expected after abort)");
                    }
                    Err(e) if e.is_panic() => {
                        warn!("writer task panicked during stop: {e}");
                    }
                    Err(e) => {
                        warn!("writer join error: {e}");
                    }
                }
                return;
            }
            _ = tokio::time::sleep_until(grace_at), if !timed_out => {
                debug!("writer grace elapsed → abort");
                abort.abort();
                timed_out = true;
            }
        }
    }
}

/// Spawn Writer owning `packet_writer` (moved from Session after initial KEX flush).
pub fn spawn_writer<W>(
    stream_write: W,
    packet_writer: PacketWriter,
    progress: Arc<AtomicWriteProgress>,
    cancel: watch::Receiver<bool>,
) -> (
    WriterHandle,
    JoinHandle<()>,
    mpsc::UnboundedReceiver<WriterEvent>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    spawn_writer_with_hooks(stream_write, packet_writer, progress, cancel, WriterHooks::default())
}

/// Spawn Writer with optional fail-inject / ledger hooks (`_test_hooks`).
pub fn spawn_writer_with_hooks<W>(
    mut stream_write: W,
    mut packet_writer: PacketWriter,
    progress: Arc<AtomicWriteProgress>,
    mut cancel: watch::Receiver<bool>,
    hooks: WriterHooks,
) -> (
    WriterHandle,
    JoinHandle<()>,
    mpsc::UnboundedReceiver<WriterEvent>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<WriterCmd>(BULK_QUEUE_CAP);
    let (kex_tx, mut kex_rx) = mpsc::channel::<KexCmd>(KEX_QUEUE_CAP);
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<WriterEvent>();
    #[cfg(feature = "_test_hooks")]
    let pending_bytes = hooks
        .pending_override
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
    #[cfg(not(feature = "_test_hooks"))]
    let pending_bytes = Arc::new(AtomicUsize::new(0));
    let pending_bytes_w = pending_bytes.clone();
    #[cfg(feature = "_test_hooks")]
    let cipher_bytes = hooks
        .cipher_bytes_override
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    #[cfg(not(feature = "_test_hooks"))]
    let cipher_bytes = Arc::new(AtomicU64::new(0));
    let cipher_bytes_w = cipher_bytes.clone();
    #[cfg(feature = "_test_hooks")]
    let packets_this_epoch = hooks
        .packets_override
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    #[cfg(not(feature = "_test_hooks"))]
    let packets_this_epoch = Arc::new(AtomicU64::new(0));
    let packets_this_epoch_w = packets_this_epoch.clone();
    let capacity = Arc::new(Notify::new());
    let capacity_w = capacity.clone();
    #[cfg(feature = "_test_hooks")]
    let socket_hang_w = hooks.socket_hang.clone();
    #[cfg(feature = "_test_hooks")]
    let dequeue_hold_w = hooks.dequeue_hold.clone();

    let handle = WriterHandle {
        bulk_tx,
        kex_tx,
        pending_bytes,
        cipher_bytes,
        packets_this_epoch,
        capacity,
        #[cfg(feature = "_test_hooks")]
        full_ledger: hooks.full_ledger.clone(),
        #[cfg(feature = "_test_hooks")]
        fail_next_seal: hooks.fail_next_seal.clone(),
        #[cfg(feature = "_test_hooks")]
        force_next_bulk_full: hooks.force_next_bulk_full.clone(),
        tombstone: hooks.tombstone.clone(),
        #[cfg(feature = "_test_hooks")]
        stop_discard: hooks.stop_discard.clone(),
    };

    let hooks_w = hooks.clone();
    let join = tokio::spawn(async move {
        let mut out_q: VecDeque<Bytes> = VecDeque::new();
        #[cfg(feature = "_test_hooks")]
        let mut drain_segs: VecDeque<(usize, bool)> = VecDeque::new();
        let mut flush_cursor: usize = 0;
        let mut current: Option<Bytes> = None;
        let mut shutting_down = false;
        let mut shutdown_ack: Option<oneshot::Sender<()>> = None;
        let mut bulk_closed = false;
        let mut poll_cancel = true;

        // Any sealed-but-unflushed bytes already in the moved PacketWriter.
        {
            let pre = packet_writer.take_pending_wire_bytes();
            if !pre.is_empty() {
                pending_bytes_w.fetch_add(pre.len(), Ordering::Release);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref fl) = hooks_w.full_ledger {
                    fl.credit(pre.len());
                }
                #[cfg(feature = "_test_hooks")]
                let pre_len = pre.len();
                out_q.push_back(pre);
                #[cfg(feature = "_test_hooks")]
                drain_segs.push_back((pre_len, false));
            }
            cipher_bytes_w.store(packet_writer.buffer().bytes as u64, Ordering::Release);
        }

        loop {
            progress.store_eligible(pending_bytes_w.load(Ordering::Acquire) as u64);

            if poll_cancel && *cancel.borrow_and_update() {
                shutting_down = true;
                poll_cancel = false;
                debug!("writer: cancel=true observed, graceful drain then exit");
            }

            while let Ok(cmd) = kex_rx.try_recv() {
                match cmd {
                    KexCmd::Shutdown(ack) => {
                        shutting_down = true;
                        poll_cancel = false;
                        shutdown_ack = Some(ack);
                    }
                }
            }

            #[cfg(feature = "_test_hooks")]
            let socket_hang_active = socket_hang_w
                .as_ref()
                .is_some_and(|h| h.load(Ordering::SeqCst));
            #[cfg(not(feature = "_test_hooks"))]
            let socket_hang_active = false;
            #[cfg(feature = "_test_hooks")]
            let dequeue_hold_active = dequeue_hold_w
                .as_ref()
                .is_some_and(|h| h.load(Ordering::SeqCst));
            #[cfg(not(feature = "_test_hooks"))]
            let dequeue_hold_active = false;

            // Non-blocking pull of bulk cmds; seal/install happen without await.
            // Under load, also pulled from select! bulk arm.
            // Notify capacity when we free an mpsc slot (not only on socket drain),
            // so Session NeedSubmit can retry without waiting for socket progress.
            // `dequeue_hold` parks one real cmd in mpsc (R3); hang still pulls.
            while !dequeue_hold_active && out_q.len() < OUT_Q_SOFT_CAP {
                match bulk_rx.try_recv() {
                    Ok(cmd) => {
                        capacity_w.notify_one();
                        #[cfg(feature = "_test_hooks")]
                        if let Some(ref cc) = hooks_w.capacity_chain {
                            cc.mark_dequeue_notify();
                        }
                        if let Err(()) = handle_writer_cmd(
                            cmd,
                            &mut packet_writer,
                            &mut out_q,
                            &pending_bytes_w,
                            &cipher_bytes_w,
                            &packets_this_epoch_w,
                            &evt_tx,
                            &mut shutting_down,
                            &mut poll_cancel,
                            &mut shutdown_ack,
                            &mut bulk_closed,
                            &hooks_w,
                            #[cfg(feature = "_test_hooks")]
                            &mut drain_segs,
                        ) {
                            // seal error — continue; event already sent
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        bulk_closed = true;
                        shutting_down = true;
                        poll_cancel = false;
                        break;
                    }
                }
            }

            if shutting_down && !bulk_closed {
                loop {
                    match bulk_rx.try_recv() {
                        Ok(cmd) => {
                            let _ = handle_writer_cmd(
                                cmd,
                                &mut packet_writer,
                                &mut out_q,
                                &pending_bytes_w,
                                &cipher_bytes_w,
                                &packets_this_epoch_w,
                                &evt_tx,
                                &mut shutting_down,
                                &mut poll_cancel,
                                &mut shutdown_ack,
                                &mut bulk_closed,
                                &hooks_w,
                                #[cfg(feature = "_test_hooks")]
                                &mut drain_segs,
                            );
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            bulk_closed = true;
                            break;
                        }
                    }
                }
            }

            let has_out = current.is_some() || !out_q.is_empty();

            // Empty-queue exit BEFORE select! (S2a r2).
            if shutting_down && !has_out {
                if !bulk_closed {
                    while let Ok(cmd) = bulk_rx.try_recv() {
                        capacity_w.notify_one();
                        let _ = handle_writer_cmd(
                            cmd,
                            &mut packet_writer,
                            &mut out_q,
                            &pending_bytes_w,
                            &cipher_bytes_w,
                            &packets_this_epoch_w,
                            &evt_tx,
                            &mut shutting_down,
                            &mut poll_cancel,
                            &mut shutdown_ack,
                            &mut bulk_closed,
                            &hooks_w,
                            #[cfg(feature = "_test_hooks")]
                            &mut drain_segs,
                        );
                    }
                }
                if current.is_none() && out_q.is_empty() {
                    let _ = stream_write.shutdown().await;
                    if let Some(ack) = shutdown_ack.take() {
                        let _ = ack.send(());
                    }
                    break;
                }
            }

            let has_out = current.is_some() || !out_q.is_empty();
            let can_pull_bulk = !shutting_down
                && !bulk_closed
                && out_q.len() < OUT_Q_SOFT_CAP
                && !dequeue_hold_active;

            if dequeue_hold_active {
                // One-cmd gate: leave the parked bulk cmd in mpsc until the
                // test releases. No pull, no socket — the notify must come
                // from the subsequent real dequeue.
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                continue;
            }

            if socket_hang_active && has_out {
                // HangWrite: keep sealing/dequeue into out_q, never touch the
                // socket (R2/R4 kex peak hold).
                #[cfg(feature = "_test_hooks")]
                if let Some(ref seen) = hooks_w.socket_hang_seen {
                    seen.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                continue;
            }

            tokio::select! {
                biased;

                changed = cancel.changed(), if poll_cancel => {
                    match changed {
                        Ok(()) => {
                            if *cancel.borrow_and_update() {
                                shutting_down = true;
                                poll_cancel = false;
                                debug!("writer: cancel.changed(Ok true) → graceful drain");
                            }
                        }
                        Err(_sender_dropped) => {
                            shutting_down = true;
                            poll_cancel = false;
                            debug!("writer: cancel watch closed → graceful drain");
                        }
                    }
                }

                cmd = kex_rx.recv(), if !shutting_down => {
                    match cmd {
                        Some(KexCmd::Shutdown(ack)) => {
                            shutting_down = true;
                            poll_cancel = false;
                            shutdown_ack = Some(ack);
                        }
                        None => {
                            shutting_down = true;
                            poll_cancel = false;
                        }
                    }
                }

                result = drain_writes(
                    &mut stream_write,
                    &mut current,
                    &mut out_q,
                    &mut flush_cursor,
                    &progress,
                    &pending_bytes_w,
                    &capacity_w,
                    &hooks_w,
                    #[cfg(feature = "_test_hooks")]
                    &mut drain_segs,
                ), if has_out => {
                    if let Err(e) = result {
                        warn!("writer: socket write error: {e}");
                        let _ = evt_tx.send(WriterEvent::WriteError(e.kind()));
                        break;
                    }
                }

                cmd = bulk_rx.recv(), if can_pull_bulk => {
                    match cmd {
                        Some(c) => {
                            capacity_w.notify_one();
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref cc) = hooks_w.capacity_chain {
                                cc.mark_dequeue_notify();
                            }
                            let _ = handle_writer_cmd(
                                c,
                                &mut packet_writer,
                                &mut out_q,
                                &pending_bytes_w,
                                &cipher_bytes_w,
                                &packets_this_epoch_w,
                                &evt_tx,
                                &mut shutting_down,
                                &mut poll_cancel,
                                &mut shutdown_ack,
                                &mut bulk_closed,
                                &hooks_w,
                                #[cfg(feature = "_test_hooks")]
                                &mut drain_segs,
                            );
                        }
                        None => {
                            bulk_closed = true;
                            shutting_down = true;
                            poll_cancel = false;
                            capacity_w.notify_one();
                        }
                    }
                }
            }
        }
        progress.store_eligible(0);
        capacity_w.notify_one();
        debug!("writer: task exit");
    });

    (handle, join, evt_rx)
}

/// SSH channel payload: `byte msg` + `uint32 recipient` (RFC 4253/4254).
fn parse_channel_payload(payload: &[u8]) -> Option<(u8, u32)> {
    if payload.len() < 5 {
        return None;
    }
    let msg = *payload.first()?;
    let recip = u32::from_be_bytes([
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
        *payload.get(4)?,
    ]);
    Some((msg, recip))
}

fn tombstone_should_drop(payload: &[u8], tombstone: &CloseTombstone) -> bool {
    let Some((msg, recip)) = parse_channel_payload(payload) else {
        return false;
    };
    if msg == crate::msg::CHANNEL_CLOSE {
        return false;
    }
    let droppable = matches!(
        msg,
        crate::msg::CHANNEL_DATA
            | crate::msg::CHANNEL_EXTENDED_DATA
            | crate::msg::CHANNEL_EOF
            | crate::msg::CHANNEL_WINDOW_ADJUST
            | crate::msg::CHANNEL_REQUEST
            | crate::msg::CHANNEL_SUCCESS
            | crate::msg::CHANNEL_FAILURE
    );
    droppable && tombstone.contains(recip)
}

fn seal_one_payload(
    packet_writer: &mut PacketWriter,
    out_q: &mut VecDeque<Bytes>,
    pending_bytes: &AtomicUsize,
    cipher_bytes: &AtomicU64,
    packets_this_epoch: &AtomicU64,
    p: Bytes,
    hooks: &WriterHooks,
    #[cfg_attr(not(feature = "_test_hooks"), allow(unused_variables))]
    as_kex: bool,
    #[cfg(feature = "_test_hooks")]
    drain_segs: &mut VecDeque<(usize, bool)>,
) -> Result<(), Error> {
    let reserved = seal_reservation(p.len());
    if tombstone_should_drop(p.as_ref(), &hooks.tombstone) {
        // Unstarted seal: drop plaintext, refund reservation, do not
        // consume outbound seqn. CLOSE is never dropped (exemption).
        let ok = pending_bytes.fetch_update(Ordering::Release, Ordering::Acquire, |cur| {
            cur.checked_sub(reserved)
        });
        if ok.is_err() {
            warn!("writer: tombstone-drop reservation underflow reserved={reserved}");
            #[cfg(feature = "_test_hooks")]
            if let Some(ref fl) = hooks.full_ledger {
                fl.slot.note_mismatch();
            }
        } else {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref fl) = hooks.full_ledger {
                if as_kex {
                    fl.debit_kex_from_writer(reserved);
                } else {
                    fl.debit(reserved);
                }
            }
        }
        #[cfg(feature = "_test_hooks")]
        if let Some(ref s) = hooks.stop_discard {
            s.note_seal_drop();
        }
        #[cfg(feature = "_test_hooks")]
        if hooks.invert_tombstone_counts {
            // Invert: pretend a dropped payload consumed seqn (must-red).
            packets_this_epoch.fetch_add(1, Ordering::AcqRel);
        }
        return Ok(());
    }
    let clear_recip = parse_channel_payload(p.as_ref()).and_then(|(msg, recip)| {
        (msg == crate::msg::CHANNEL_CLOSE).then_some(recip)
    });
    #[cfg(feature = "_test_hooks")]
    if hooks
        .fail_next_seal
        .as_ref()
        .is_some_and(|f| f.swap(false, Ordering::SeqCst))
    {
        warn!("writer: test fail_next_seal injected");
        return Err(Error::Inconsistent);
    }
    packet_writer.packet_raw(p.as_ref())?;
    if let Some(recip) = clear_recip {
        // FIFO: every earlier cmd for this recipient has been seen.
        hooks.tombstone.remove(recip);
    }
    let wire = packet_writer.take_pending_wire_bytes();
    let wire_len = wire.len();
    if wire_len > reserved {
        let delta = wire_len - reserved;
        pending_bytes.fetch_add(delta, Ordering::Release);
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = hooks.full_ledger {
            if as_kex {
                fl.credit_kex_to_writer(delta);
            } else {
                fl.credit(delta);
            }
        }
    } else if wire_len < reserved {
        let delta = reserved - wire_len;
        let ok = pending_bytes.fetch_update(Ordering::Release, Ordering::Acquire, |cur| {
            cur.checked_sub(delta)
        });
        if ok.is_err() {
            warn!(
                "writer: pending_bytes underflow reserved={reserved} wire={wire_len} delta={delta}"
            );
            #[cfg(feature = "_test_hooks")]
            if let Some(ref fl) = hooks.full_ledger {
                fl.slot.note_mismatch();
            }
            return Err(Error::Inconsistent);
        }
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = hooks.full_ledger {
            if as_kex {
                fl.debit_kex_from_writer(delta);
            } else {
                fl.debit(delta);
            }
        }
    }
    if !wire.is_empty() {
        out_q.push_back(wire);
        // Segment records post-seal wire. Accept credited `reserved`;
        // seal then credits/debits `wire - reserved` with the same
        // identity, so this packet's remaining ledger weight equals
        // `wire_len`. Drain consumes exactly those wire bytes.
        // Tombstone / Full rollback / batch-error refund reservation
        // before any wire exists and never push a segment.
        #[cfg(feature = "_test_hooks")]
        drain_segs.push_back((wire_len, as_kex));
    }
    cipher_bytes.store(packet_writer.buffer().bytes as u64, Ordering::Release);
    packets_this_epoch.fetch_add(1, Ordering::AcqRel);
    #[cfg(feature = "_test_hooks")]
    if let Some(ref o) = hooks.observe {
        o.set_seqn(packet_writer.buffer().seqn.0);
    }
    Ok(())
}

fn install_epoch(
    packet_writer: &mut PacketWriter,
    cipher_bytes: &AtomicU64,
    packets_this_epoch: &AtomicU64,
    cipher: Box<dyn SealingKey + Send>,
    outbound_compression: Compression,
    activate_compress: bool,
    reset_seqn: bool,
    generation: u64,
    #[cfg(feature = "_test_hooks")] observe: &Option<Arc<WriterObserveSlot>>,
    #[cfg(feature = "_test_hooks")] invert_keep_old_compress: bool,
    #[cfg(feature = "_test_hooks")]
    compression_observe: &Option<Arc<crate::server::supervisor::CompressionObserveSlot>>,
) {
    packet_writer.set_cipher(cipher);
    #[cfg(feature = "_test_hooks")]
    // Invert only on rekey (gen>0). Initial kex (gen 0) must still
    // install, otherwise a zlib-first handshake cannot authenticate.
    let skip_rebuild = invert_keep_old_compress && generation > 0;
    #[cfg(not(feature = "_test_hooks"))]
    let skip_rebuild = false;
    if !skip_rebuild {
        if activate_compress {
            #[cfg(all(feature = "_test_hooks", feature = "flate2"))]
            let had_zlib = matches!(packet_writer.compress(), crate::compression::Compress::Zlib(_));
            outbound_compression.init_compress(packet_writer.compress());
            #[cfg(all(feature = "_test_hooks", feature = "flate2"))]
            if had_zlib {
                if let Some(o) = compression_observe {
                    o.mark_zlib_reset();
                }
            }
        } else {
            // Keep Compress::None through USERAUTH (zlib@openssh.com deferred).
            *packet_writer.compress() = crate::compression::Compress::None;
        }
    }
    #[cfg(feature = "_test_hooks")]
    if let Some(o) = compression_observe {
        o.set_outbound_activated(activate_compress && !skip_rebuild);
    }
    if reset_seqn {
        packet_writer.reset_seqn();
    }
    packet_writer.buffer().bytes = 0;
    cipher_bytes.store(0, Ordering::Release);
    // I5 count reset is independent of strict-kex wire seqn reset.
    packets_this_epoch.store(0, Ordering::Release);
    #[cfg(feature = "_test_hooks")]
    if let Some(o) = observe {
        o.set_packets_this_epoch(0);
        o.set_seqn(packet_writer.buffer().seqn.0);
    }
    debug!(
        "writer: installed outbound epoch gen={generation} reset_seqn={reset_seqn} activate_compress={activate_compress}"
    );
}

/// Process one WriterCmd. Seal/install have **no await** (NEWKEYS atomicity).
fn handle_writer_cmd(
    cmd: WriterCmd,
    packet_writer: &mut PacketWriter,
    out_q: &mut VecDeque<Bytes>,
    pending_bytes: &AtomicUsize,
    cipher_bytes: &AtomicU64,
    packets_this_epoch: &AtomicU64,
    evt_tx: &mpsc::UnboundedSender<WriterEvent>,
    shutting_down: &mut bool,
    poll_cancel: &mut bool,
    shutdown_ack: &mut Option<oneshot::Sender<()>>,
    bulk_closed: &mut bool,
    hooks: &WriterHooks,
    #[cfg(feature = "_test_hooks")]
    drain_segs: &mut VecDeque<(usize, bool)>,
) -> Result<(), ()> {
    match cmd {
        WriterCmd::SealPayload(p) | WriterCmd::SealRaw(p) => {
            let reserved = seal_reservation(p.len());
            if let Err(e) = seal_one_payload(
                packet_writer,
                out_q,
                pending_bytes,
                cipher_bytes,
                packets_this_epoch,
                p,
                hooks,
                false,
                #[cfg(feature = "_test_hooks")]
                drain_segs,
            ) {
                warn!("writer: seal error: {e:?}");
                let ok = pending_bytes.fetch_update(Ordering::Release, Ordering::Acquire, |cur| {
                    cur.checked_sub(reserved)
                });
                if ok.is_err() {
                    warn!("writer: seal-error cleanup underflow reserved={reserved}");
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref fl) = hooks.full_ledger {
                        fl.slot.note_mismatch();
                    }
                } else {
                    #[cfg(feature = "_test_hooks")]
                    if let Some(ref fl) = hooks.full_ledger {
                        fl.debit(reserved);
                    }
                }
                let _ = evt_tx.send(WriterEvent::SealError);
                return Err(());
            }
            Ok(())
        }
        WriterCmd::SealBatchAndInstallEpoch {
            payloads,
            generation,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            ack,
        } => {
            // 1) Seal all with OLD epoch — no await between seals or install.
            let mut remaining = payloads.into_iter();
            while let Some(p) = remaining.next() {
                let reserved = seal_reservation(p.len());
                if let Err(e) = seal_one_payload(
                    packet_writer,
                    out_q,
                    pending_bytes,
                    cipher_bytes,
                    packets_this_epoch,
                    p,
                    hooks,
                    true,
                    #[cfg(feature = "_test_hooks")]
                    drain_segs,
                ) {
                    // Accept credited the whole batch. Failed payload never
                    // became wire; refund it *and* every not-yet-sealed
                    // remainder so pending_bytes / kex identity return to
                    // only what actually entered out_q.
                    let rest: usize = remaining.map(|q| seal_reservation(q.len())).sum();
                    let refund = reserved.saturating_add(rest);
                    warn!(
                        "writer: batch seal error: {e:?} refund={refund} (failed={reserved} rest={rest})"
                    );
                    if refund > 0 {
                        let ok = pending_bytes.fetch_update(
                            Ordering::Release,
                            Ordering::Acquire,
                            |cur| cur.checked_sub(refund),
                        );
                        if ok.is_err() {
                            warn!(
                                "writer: batch seal-error cleanup underflow refund={refund}"
                            );
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref fl) = hooks.full_ledger {
                                fl.slot.note_mismatch();
                            }
                        } else {
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref fl) = hooks.full_ledger {
                                fl.debit_kex_from_writer(refund);
                            }
                        }
                    }
                    let _ = ack.send(Err(e));
                    let _ = evt_tx.send(WriterEvent::SealError);
                    return Err(());
                }
            }
            // 2) Install NEW epoch (still no await).
            install_epoch(
                packet_writer,
                cipher_bytes,
                packets_this_epoch,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
                generation,
                #[cfg(feature = "_test_hooks")]
                &hooks.observe,
                #[cfg(feature = "_test_hooks")]
                hooks.invert_keep_old_decompress,
                #[cfg(feature = "_test_hooks")]
                &hooks.compression_observe,
            );
            let _ = ack.send(Ok(()));
            let _ = evt_tx.send(WriterEvent::InstallAckOutbound { generation });
            Ok(())
        }
        WriterCmd::InstallOutboundEpoch {
            generation,
            cipher,
            outbound_compression,
            activate_compress,
            reset_seqn,
            ack,
        } => {
            install_epoch(
                packet_writer,
                cipher_bytes,
                packets_this_epoch,
                cipher,
                outbound_compression,
                activate_compress,
                reset_seqn,
                generation,
                #[cfg(feature = "_test_hooks")]
                &hooks.observe,
                #[cfg(feature = "_test_hooks")]
                hooks.invert_keep_old_decompress,
                #[cfg(feature = "_test_hooks")]
                &hooks.compression_observe,
            );
            let _ = ack.send(Ok(()));
            let _ = evt_tx.send(WriterEvent::InstallAckOutbound { generation });
            Ok(())
        }
        WriterCmd::InitOutboundCompress { compression, ack } => {
            compression.init_compress(packet_writer.compress());
            debug!("writer: deferred outbound compress activated");
            let _ = ack.send(Ok(()));
            Ok(())
        }
        WriterCmd::Shutdown(ack) => {
            *shutting_down = true;
            *poll_cancel = false;
            if shutdown_ack.is_none() {
                *shutdown_ack = Some(ack);
            }
            let _ = bulk_closed;
            Ok(())
        }
    }
}

/// Consume `n` sealed-but-not-drained wire bytes from the head of the
/// Writer-local segment FIFO. Identity follows physical `[A][K][B]`
/// order; a drain that crosses the A/K boundary retires K even if B
/// is still queued. Seal and drain share the Writer task — no atomics.
#[cfg(feature = "_test_hooks")]
fn debit_drain_segments(
    segs: &mut VecDeque<(usize, bool)>,
    fl: &FullLedger,
    mut n: usize,
) {
    while n > 0 {
        let Some((rem, is_kex)) = segs.front_mut() else {
            fl.slot.note_mismatch();
            return;
        };
        let take = n.min(*rem);
        *rem -= take;
        n -= take;
        if *is_kex {
            fl.debit_kex_from_writer(take);
        } else {
            fl.debit(take);
        }
        if *rem == 0 {
            segs.pop_front();
        }
    }
}

async fn drain_writes<W: AsyncWrite + Unpin>(
    w: &mut W,
    current: &mut Option<Bytes>,
    out_q: &mut VecDeque<Bytes>,
    flush_cursor: &mut usize,
    progress: &AtomicWriteProgress,
    pending_bytes: &AtomicUsize,
    capacity: &Notify,
    #[cfg_attr(not(feature = "_test_hooks"), allow(unused_variables))]
    hooks: &WriterHooks,
    #[cfg(feature = "_test_hooks")]
    drain_segs: &mut VecDeque<(usize, bool)>,
) -> std::io::Result<()> {
    loop {
        // R5 test inject: fail the next socket write once.
        #[cfg(feature = "_test_hooks")]
        if hooks
            .fail_next_socket_write
            .as_ref()
            .is_some_and(|f| f.swap(false, Ordering::SeqCst))
        {
            warn!("writer: test fail_next_socket_write injected");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "injected socket write failure",
            ));
        }
        if current.is_none() {
            *current = out_q.pop_front();
            *flush_cursor = 0;
        }
        let Some(buf) = current.as_ref() else {
            capacity.notify_one();
            return Ok(());
        };
        if *flush_cursor >= buf.len() {
            *current = None;
            *flush_cursor = 0;
            continue;
        }
        // Gather: one syscall for the head packet plus everything already
        // queued behind it. With the S9 credit window a producer keeps
        // several packets in flight, so `out_q` is routinely non-empty and
        // a per-packet `write` would spend a syscall on each 32 KiB.
        let n = if out_q.is_empty() || !w.is_write_vectored() {
            w.write(&buf[*flush_cursor..]).await?
        } else {
            const EMPTY: &[u8] = &[];
            let mut iov = [std::io::IoSlice::new(EMPTY); MAX_GATHER_SEGMENTS];
            let mut k = 0;
            for (slot, seg) in iov.iter_mut().zip(
                std::iter::once(buf.get(*flush_cursor..).unwrap_or(&[]))
                    .chain(out_q.iter().map(|b| b.as_ref()))
                    .take(MAX_GATHER_SEGMENTS),
            ) {
                *slot = std::io::IoSlice::new(seg);
                k += 1;
            }
            w.write_vectored(iov.get(..k).unwrap_or(&[])).await?
        };
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write zero",
            ));
        }
        progress.note_write(n);
        let ok = pending_bytes.fetch_update(Ordering::Release, Ordering::Acquire, |cur| {
            cur.checked_sub(n)
        });
        if ok.is_err() {
            warn!("writer: socket drain pending_bytes underflow n={n}");
            #[cfg(feature = "_test_hooks")]
            if let Some(ref fl) = hooks.full_ledger {
                fl.slot.note_mismatch();
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "pending_bytes ledger underflow on drain",
            ));
        }
        #[cfg(feature = "_test_hooks")]
        if let Some(ref fl) = hooks.full_ledger {
            debit_drain_segments(drain_segs, fl, n);
        }
        capacity.notify_one();

        // Spend `n` across the head packet and any gathered followers.
        let mut left = n;
        loop {
            let Some(head) = current.as_ref() else { break };
            let remaining = head.len().saturating_sub(*flush_cursor);
            if left < remaining {
                *flush_cursor += left;
                break;
            }
            left -= remaining;
            *current = out_q.pop_front();
            *flush_cursor = 0;
            if left == 0 {
                break;
            }
        }
        if current.is_none() && out_q.is_empty() {
            w.flush().await?;
            capacity.notify_one();
            return Ok(());
        }
    }
}

/// Upper bound on `writev` segments per socket write.
const MAX_GATHER_SEGMENTS: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    struct HangWrite;
    impl AsyncWrite for HangWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_join_finishes_after_grace_abort() {
        let progress = AtomicWriteProgress::new();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        let _ = handle.try_seal_payload(Bytes::from(vec![1u8; 64]));
        tokio::task::yield_now().await;
        let mut join = Some(join);
        let grace_at = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        stop_writer_task(&cancel_tx, Some(&handle), &mut join, grace_at).await;
        assert!(join.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_empty_queue_shutdown_no_panic() {
        let progress = AtomicWriteProgress::new();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (_handle, join, _evt) =
            spawn_writer(tokio::io::sink(), PacketWriter::clear(), progress, cancel_rx);
        let _ = cancel_tx.send(true);
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("writer join error: {e}"),
            Err(_) => panic!("writer did not exit (select hang/panic?)"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capacity_notify_before_waiter_is_not_lost() {
        let progress = AtomicWriteProgress::new();
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(tokio::io::sink(), PacketWriter::clear(), progress, cancel_rx);
        let cap = handle.capacity_notify();
        handle
            .try_seal_payload(Bytes::from(vec![7u8; 32]))
            .expect("send");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while handle.pending_bytes() > 0 {
            if tokio::time::Instant::now() >= deadline {
                panic!("writer did not drain");
            }
            tokio::task::yield_now().await;
        }
        let woke =
            tokio::time::timeout(std::time::Duration::from_millis(200), cap.notified()).await;
        assert!(woke.is_ok(), "notify_one permit must survive pre-waiter drain");
        join.abort();
        let _ = join.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn install_outbound_epoch_is_real() {
        let progress = AtomicWriteProgress::new();
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let (handle, join, mut evt) =
            spawn_writer(tokio::io::sink(), PacketWriter::clear(), progress, cancel_rx);

        // Seal a clear packet then install a new clear key (still clear) with reset_seqn.
        handle
            .try_seal_payload(Bytes::from_static(&[crate::msg::IGNORE]))
            .unwrap();
        let rx = handle
            .try_seal_batch_and_install(
                vec![Bytes::from_static(&[crate::msg::NEWKEYS])],
                1,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                true,
                true,
            )
            .unwrap();
        let ack = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
            .await
            .expect("ack timeout")
            .expect("ack dropped")
            .expect("ack err");
        let _ = ack;
        let _ = evt.try_recv();
        join.abort();
        let _ = join.await;
    }

    /// Tagging sealing key: XOR every plaintext byte with `tag` so old/new
    /// epochs produce distinguishable wire bytes (clear keys cannot).
    struct TagKey(u8);
    impl crate::cipher::SealingKey for TagKey {
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
                *b = self.0;
            }
        }
        fn tag_len(&self) -> usize {
            0
        }
        fn seal(
            &mut self,
            _seqn: u32,
            plaintext_in_ciphertext_out: &mut [u8],
            tag_out: &mut [u8],
        ) {
            let _ = tag_out;
            for b in plaintext_in_ciphertext_out.iter_mut() {
                *b ^= self.0;
            }
        }
    }

    /// Soft-cap cannot split SealBatchAndInstall: HangWrite never drains, so a
    /// **non-atomic** "N seals + Install" would stall after OUT_Q_SOFT_CAP and
    /// never ACK. Atomic batch of >soft_cap seals must still ACK, and NEWKEYS
    /// wire bytes must match the **old** epoch tag (not the installed tag).
    #[tokio::test(flavor = "current_thread")]
    async fn seal_batch_and_install_is_atomic_wrt_soft_cap() {
        use std::sync::Mutex;

        struct RecordWrite {
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl AsyncWrite for RecordWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.buf.lock().unwrap().extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // --- HangWrite path: > soft-cap seals in ONE cmd must still ACK ---
        {
            let progress = AtomicWriteProgress::new();
            let (_cancel_tx, cancel_rx) = watch::channel(false);
            // Start with TagKey(0x11) as current (old) epoch.
            let mut pw = PacketWriter::clear();
            pw.set_cipher(Box::new(TagKey(0x11)));
            let (handle, join, mut evt) =
                spawn_writer(HangWrite, pw, progress, cancel_rx);

            // OUT_Q_SOFT_CAP=64; 70 seals in one atomic cmd would stall if split.
            let mut payloads = Vec::new();
            for _ in 0..70 {
                payloads.push(Bytes::from_static(&[crate::msg::IGNORE]));
            }
            payloads.push(Bytes::from_static(&[crate::msg::NEWKEYS]));
            let rx = handle
                .try_seal_batch_and_install(
                    payloads,
                    7,
                    Box::new(TagKey(0x22)), // new epoch tag
                    Compression::None,
                    false,
                    true,
                )
                .expect("enqueue atomic");
            // Must complete without any socket drain (proves no mid-cmd await /
            // no split across soft-cap).
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
                .await
                .expect("atomic must ACK past soft-cap without drain")
                .expect("ack dropped")
                .expect("ack err");
            let mut saw_ack = false;
            while let Ok(e) = evt.try_recv() {
                if matches!(e, WriterEvent::InstallAckOutbound { generation: 7 }) {
                    saw_ack = true;
                }
            }
            assert!(saw_ack, "InstallAckOutbound gen=7 after atomic batch");
            join.abort();
            let _ = join.await;
        }

        // --- RecordWrite path: NEWKEYS sealed with old tag, post with new ---
        {
            let wire = Arc::new(Mutex::new(Vec::new()));
            let progress = AtomicWriteProgress::new();
            let (_cancel_tx, cancel_rx) = watch::channel(false);
            let mut pw = PacketWriter::clear();
            pw.set_cipher(Box::new(TagKey(0x11)));
            let (handle, join, _) = spawn_writer(
                RecordWrite { buf: wire.clone() },
                pw,
                progress,
                cancel_rx,
            );
            let rx = handle
                .try_seal_batch_and_install(
                    vec![Bytes::from_static(&[crate::msg::NEWKEYS])],
                    7,
                    Box::new(TagKey(0x22)),
                    Compression::None,
                    false,
                    true,
                )
                .unwrap();
            handle
                .try_seal_payload(Bytes::from_static(&[crate::msg::IGNORE, 0xAA]))
                .unwrap();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            while handle.pending_bytes() > 0 {
                if tokio::time::Instant::now() >= deadline {
                    panic!("drain timeout");
                }
                tokio::task::yield_now().await;
            }
            let recorded = wire.lock().unwrap().clone();
            // OLD epoch XORs with 0x11 → NEWKEYS wire byte = 21 ^ 0x11 = 0x04
            // (payload sits after 4-byte len + 1-byte padlen; pad also tagged 0x11).
            let old_newkeys = crate::msg::NEWKEYS ^ 0x11;
            let new_ignore = crate::msg::IGNORE ^ 0x22;
            let new_marker = 0xAAu8 ^ 0x22;
            let idx_old = recorded
                .iter()
                .position(|&b| b == old_newkeys)
                .expect("NEWKEYS must appear under OLD epoch tag 0x11");
            // Post-install IGNORE+0xAA under NEW tag 0x22
            let idx_new = recorded
                .windows(2)
                .position(|w| w == [new_ignore, new_marker])
                .expect("post-install payload under NEW epoch tag 0x22");
            assert!(
                idx_old < idx_new,
                "old-epoch NEWKEYS before new-epoch post payload"
            );
            // Degenerate "install first then seal NEWKEYS" would put NEWKEYS under 0x22.
            let new_newkeys = crate::msg::NEWKEYS ^ 0x22;
            // Allow new_newkeys only if it is not the only NEWKEYS representation;
            // require at least one old-tagged NEWKEYS (already asserted via idx_old).
            let _ = new_newkeys;
            join.abort();
            let _ = join.await;
        }
    }

    /// Fill bulk item queue against a hanging socket → real Full; after Writer
    /// exit → Closed (never misclassified as Full).
    #[tokio::test(flavor = "current_thread")]
    async fn try_send_observes_full_then_closed() {
        let progress = AtomicWriteProgress::new();
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let (handle, join, _evt) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);

        let mut full_hits = 0usize;
        // BULK_QUEUE_CAP=256; hang socket so out_q soft-cap also stalls pulls.
        for _ in 0..(BULK_QUEUE_CAP + 64) {
            match handle.try_seal_payload(Bytes::from(vec![0x2u8; 8])) {
                Ok(()) => {}
                Err(TrySendWireError::Full(_)) => full_hits += 1,
                Err(TrySendWireError::FullCmd) => panic!("seal must not return FullCmd"),
                Err(TrySendWireError::Closed) => panic!("must not see Closed while writer alive"),
            }
        }
        assert!(
            full_hits > 0,
            "hanging Writer must produce at least one real Full once bulk queue is full"
        );
        assert!(
            handle.pending_bytes() > 0,
            "Full path must leave pending_bytes ledger non-zero"
        );

        join.abort();
        let _ = join.await;

        match handle.try_seal_payload(Bytes::from_static(&[crate::msg::IGNORE])) {
            Err(TrySendWireError::Closed) => {}
            Err(TrySendWireError::Full(_)) => {
                panic!("Closed Writer must not be reported as Full")
            }
            Err(TrySendWireError::FullCmd) => panic!("unexpected FullCmd"),
            Ok(()) => panic!("send to dead Writer must fail"),
        }
    }

    /// GateWrite: hang until released, then record — real Full→retry on **same**
    /// Writer, replaying accepted-in-queue + parked payloads in submit order.
    #[tokio::test(flavor = "current_thread")]
    async fn seal_order_preserved_across_full_retry() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Mutex;

        struct GateWrite {
            released: Arc<AtomicBool>,
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl AsyncWrite for GateWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                if !self.released.load(AtomicOrdering::Acquire) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.buf.lock().unwrap().extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let released = Arc::new(AtomicBool::new(false));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let (handle, join, _) = spawn_writer(
            GateWrite {
                released: released.clone(),
                buf: wire.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
        );

        // Submit unique magic-tagged payloads; collect Full-returned ones in order.
        let n = BULK_QUEUE_CAP + 40;
        const MAGIC: [u8; 4] = [0xA5, 0x5A, 0xC3, 0x3C];
        let mut accepted = 0usize;
        let mut parked: Vec<Bytes> = Vec::new();
        let mut submit_order: Vec<usize> = Vec::new();
        for i in 0..n {
            submit_order.push(i);
            let mut payload = vec![crate::msg::IGNORE];
            payload.extend_from_slice(&MAGIC);
            payload.push((i >> 8) as u8);
            payload.push((i & 0xff) as u8);
            match handle.try_seal_payload(Bytes::from(payload)) {
                Ok(()) => accepted += 1,
                Err(TrySendWireError::Full(p)) => parked.push(p),
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert!(accepted > 0, "some payloads must enter the bulk queue");
        assert!(!parked.is_empty(), "must observe Full under gated socket");

        // Release socket first so Writer drains queue + accepts retries.
        released.store(true, AtomicOrdering::Release);
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        // Replay parked onto the **same** handle (not a fresh Writer).
        for p in parked.iter().cloned() {
            let mut payload = p;
            loop {
                match handle.try_seal_payload(payload) {
                    Ok(()) => break,
                    Err(TrySendWireError::Full(p2)) => {
                        payload = p2;
                        tokio::task::yield_now().await;
                    }
                    Err(e) => panic!("unexpected {e:?}"),
                }
            }
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while handle.pending_bytes() > 0 {
            if tokio::time::Instant::now() >= deadline {
                panic!("drain timeout pending={}", handle.pending_bytes());
            }
            tokio::task::yield_now().await;
        }

        let recorded = wire.lock().unwrap().clone();
        let mut positions = Vec::new();
        for &i in &submit_order {
            let mut needle = vec![crate::msg::IGNORE];
            needle.extend_from_slice(&MAGIC);
            needle.push((i >> 8) as u8);
            needle.push((i & 0xff) as u8);
            let count = recorded
                .windows(needle.len())
                .filter(|w| *w == needle.as_slice())
                .count();
            assert_eq!(
                count, 1,
                "packet {i} must appear exactly once (got {count}); wire_len={}",
                recorded.len()
            );
            let start = positions.last().map(|p| p + 1).unwrap_or(0);
            let rel = recorded[start..]
                .windows(needle.len())
                .position(|w| w == needle.as_slice())
                .expect("ordered scan must find packet");
            positions.push(start + rel);
        }
        for w in positions.windows(2) {
            assert!(w[0] < w[1], "wire order must match submit order");
        }

        join.abort();
        let _ = join.await;
    }

    /// Dequeue frees bulk capacity and notifies even when the socket never drains.
    #[tokio::test(flavor = "current_thread")]
    async fn capacity_notify_on_dequeue_without_socket_progress() {
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let (handle, join, _) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        let cap = handle.capacity_notify();
        // Fill well past soft-cap so Writer dequeues into out_q then stalls.
        for _ in 0..80 {
            let _ = handle.try_seal_payload(Bytes::from(vec![1u8; 16]));
        }
        // Must observe capacity notify from dequeue (not socket drain — HangWrite never writes).
        let woke =
            tokio::time::timeout(std::time::Duration::from_secs(2), cap.notified()).await;
        assert!(
            woke.is_ok(),
            "dequeue must notify capacity without socket progress"
        );
        assert!(
            handle.pending_bytes() > 0,
            "socket still blocked; backlog remains"
        );
        join.abort();
        let _ = join.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn try_seal_batch_classifies_full_and_closed() {
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let (handle, join, _) =
            spawn_writer(HangWrite, PacketWriter::clear(), progress, cancel_rx);
        // Fill bulk queue.
        for _ in 0..(BULK_QUEUE_CAP + 8) {
            let _ = handle.try_seal_payload(Bytes::from(vec![1u8; 4]));
        }
        match handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[crate::msg::NEWKEYS])],
            1,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            false,
        ) {
            Err(TrySendEpochError::Full { payloads, .. }) => {
                assert_eq!(payloads.len(), 1);
            }
            other => panic!("expected Full, got {other:?}"),
        }
        join.abort();
        let _ = join.await;
        match handle.try_seal_batch_and_install(
            vec![Bytes::from_static(&[crate::msg::NEWKEYS])],
            1,
            Box::new(crate::cipher::clear::Key {}),
            Compression::None,
            true,
            false,
        ) {
            Err(TrySendEpochError::Closed) => {}
            other => panic!("expected Closed after writer exit, got {other:?}"),
        }
    }

    #[cfg(feature = "_test_hooks")]
    async fn wait_pred(mut pred: impl FnMut() -> bool, label: &str) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !pred() {
            if tokio::time::Instant::now() >= deadline {
                panic!("timeout waiting for {label}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// R4 / fix5: physical `[A][K][B]` drain across A/K must retire kex
    /// while B is still queued. Aggregate `pending_before - kex_in_writer`
    /// would debit A+B first and leave K live — this test is red on that
    /// formula whenever `B >= K`.
    #[cfg(feature = "_test_hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn drain_akb_fifo_retires_kex_before_trailing_nonkex() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Mutex;
        use std::task::Waker;
        use crate::server::supervisor::{FullLedger, LedgerMaxSlot};

        struct QuotaWrite {
            allow: Arc<AtomicUsize>,
            written: Arc<AtomicUsize>,
            waker: Arc<Mutex<Option<Waker>>>,
        }
        impl AsyncWrite for QuotaWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let allow = self.allow.load(Ordering::SeqCst);
                let written = self.written.load(Ordering::SeqCst);
                if written >= allow {
                    *self.waker.lock().unwrap() = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let n = buf.len().min(allow - written);
                self.written.fetch_add(n, Ordering::SeqCst);
                Poll::Ready(Ok(n))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let slot = LedgerMaxSlot::new();
        let pending_arc = Arc::new(AtomicUsize::new(0));
        let fl = Arc::new(FullLedger::new(
            pending_arc.clone(),
            Arc::new(AtomicUsize::new(0)),
            slot.clone(),
        ));
        let allow = Arc::new(AtomicUsize::new(0));
        let written = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(Mutex::new(None));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let hooks = WriterHooks {
            full_ledger: Some(fl.clone()),
            pending_override: Some(pending_arc),
            ..WriterHooks::default()
        };
        let (handle, join, _evt) = spawn_writer_with_hooks(
            QuotaWrite {
                allow: allow.clone(),
                written: written.clone(),
                waker: waker.clone(),
            },
            PacketWriter::clear(),
            progress,
            cancel_rx,
            hooks,
        );

        // A: small non-kex. K: two-packet batch. B: larger than K so the
        // old "all non-kex first" formula mis-attributes a drain of A+K.
        handle
            .try_seal_raw(Bytes::from(vec![crate::msg::IGNORE; 40]))
            .expect("A");
        wait_pred(|| handle.pending_bytes() > 0, "A sealed").await;
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;
        let a_wire = handle.pending_bytes();
        assert!(a_wire > 0);

        handle
            .try_seal_batch_and_install(
                vec![
                    Bytes::from(vec![0u8; 80]),
                    Bytes::from_static(&[crate::msg::NEWKEYS]),
                ],
                7,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                false,
                false,
            )
            .expect("K accept");
        wait_pred(|| fl.kex_in_writer() > 0, "K accepted").await;
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;
        let after_k = handle.pending_bytes();
        let k_wire = after_k.saturating_sub(a_wire);
        assert!(k_wire > 0, "K must contribute wire after seal");
        assert_eq!(
            fl.kex_in_writer(),
            k_wire,
            "post-seal kex_in_writer must equal K wire"
        );

        handle
            .try_seal_raw(Bytes::from(vec![crate::msg::IGNORE; 400]))
            .expect("B");
        wait_pred(|| handle.pending_bytes() > after_k, "B sealed").await;
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;
        let after_b = handle.pending_bytes();
        let b_wire = after_b.saturating_sub(after_k);
        assert!(
            b_wire >= k_wire,
            "B >= K is the old-formula must-red shape (b={b_wire} k={k_wire})"
        );

        let max_ex_queued = slot.max_excluding_kex_need();
        let live_non_kex = fl.total().saturating_sub(fl.kex_live());
        eprintln!(
            "f14-fix5 akb queued: a={a_wire} k={k_wire} b={b_wire} \
             kex_in_writer={} kex_live={} non_kex={live_non_kex} max_ex={max_ex_queued}",
            fl.kex_in_writer(),
            fl.kex_live()
        );
        assert_eq!(live_non_kex, a_wire + b_wire, "B must stay non-kex");
        assert!(
            max_ex_queued >= a_wire + b_wire,
            "non-kex peak lower bound must include A+B (max_ex={max_ex_queued})"
        );

        // Drain exactly A+K. Aggregate FIFO would debit A+B and leave K live.
        allow.store(a_wire + k_wire, Ordering::SeqCst);
        if let Some(w) = waker.lock().unwrap().take() {
            w.wake();
        }
        wait_pred(
            || written.load(Ordering::SeqCst) >= a_wire + k_wire,
            "drained A+K",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(8)).await;

        eprintln!(
            "f14-fix5 akb after A+K drain: pending={} kex_in_writer={} kex_live={} \
             written={} mismatch={}",
            handle.pending_bytes(),
            fl.kex_in_writer(),
            fl.kex_live(),
            written.load(Ordering::SeqCst),
            slot.mismatch()
        );
        assert_eq!(
            fl.kex_in_writer(),
            0,
            "HARD: kex identity must retire when A+K have left (old FIFO leaves K)"
        );
        assert_eq!(fl.kex_live(), 0, "HARD: kex_live must follow kex_in_writer");
        assert_eq!(
            handle.pending_bytes(),
            b_wire,
            "B must still be queued after A+K drain"
        );
        assert_eq!(
            fl.total().saturating_sub(fl.kex_live()),
            b_wire,
            "HARD: remaining B is non-kex, not residual K"
        );
        assert_eq!(slot.mismatch(), 0);

        allow.store(usize::MAX, Ordering::SeqCst);
        if let Some(w) = waker.lock().unwrap().take() {
            w.wake();
        }
        wait_pred(|| handle.pending_bytes() == 0, "full drain").await;
        assert_eq!(fl.kex_live(), 0);
        assert_eq!(fl.kex_in_writer(), 0);
        assert_eq!(slot.mismatch(), 0);

        join.abort();
        let _ = join.await;
    }

    /// R4 / fix5: two-packet SealBatch, first seal injected fail — refund
    /// failed reserved *and* the unprocessed remainder.
    #[cfg(feature = "_test_hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn batch_seal_first_fail_refunds_remainder() {
        use std::sync::atomic::AtomicUsize;
        use crate::server::supervisor::{FullLedger, LedgerMaxSlot};

        let slot = LedgerMaxSlot::new();
        let pending_arc = Arc::new(AtomicUsize::new(0));
        let fl = Arc::new(FullLedger::new(
            pending_arc.clone(),
            Arc::new(AtomicUsize::new(0)),
            slot.clone(),
        ));
        let fail = Arc::new(AtomicBool::new(true));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let hooks = WriterHooks {
            full_ledger: Some(fl.clone()),
            pending_override: Some(pending_arc),
            fail_next_seal: Some(fail),
            ..WriterHooks::default()
        };
        let (handle, join, mut evt) = spawn_writer_with_hooks(
            HangWrite,
            PacketWriter::clear(),
            progress,
            cancel_rx,
            hooks,
        );
        let baseline = handle.pending_bytes();
        assert_eq!(baseline, 0);

        let ack = handle
            .try_seal_batch_and_install(
                vec![Bytes::from(vec![0u8; 120]), Bytes::from(vec![0u8; 80])],
                3,
                Box::new(crate::cipher::clear::Key {}),
                Compression::None,
                false,
                false,
            )
            .expect("batch accepted before seal");
        let seal_res = ack.await.expect("ack channel");
        assert!(seal_res.is_err(), "first payload fail_next_seal");

        wait_pred(
            || handle.pending_bytes() == baseline && fl.kex_live() == 0,
            "remainder refunded",
        )
        .await;
        let _ = evt.try_recv();
        eprintln!(
            "f14-fix5 batch fail refund: pending={} kex_live={} kex_in_writer={} mismatch={}",
            handle.pending_bytes(),
            fl.kex_live(),
            fl.kex_in_writer(),
            slot.mismatch()
        );
        assert_eq!(handle.pending_bytes(), baseline);
        assert_eq!(fl.kex_live(), 0);
        assert_eq!(fl.kex_in_writer(), 0);
        assert_eq!(slot.mismatch(), 0);

        join.abort();
        let _ = join.await;
    }

    fn data_payload(recip: u32) -> Bytes {
        let mut v = vec![crate::msg::CHANNEL_DATA];
        v.extend_from_slice(&recip.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 1, b'x']);
        Bytes::from(v)
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn tombstone_drop_does_not_count_packets() {
        let tomb = CloseTombstone::new();
        tomb.insert(7);
        let packets = Arc::new(AtomicU64::new(0));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let hooks = WriterHooks {
            tombstone: tomb,
            packets_override: Some(packets.clone()),
            ..WriterHooks::default()
        };
        let (handle, join, _evt) = spawn_writer_with_hooks(
            tokio::io::sink(),
            PacketWriter::clear(),
            progress,
            cancel_rx,
            hooks,
        );
        handle.try_seal_payload(data_payload(7)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            packets.load(Ordering::SeqCst),
            0,
            "S6a HARD: tombstone drop must not increment packets"
        );
        join.abort();
        let _ = join.await;
    }

    #[cfg(feature = "_test_hooks")]
    #[tokio::test(flavor = "current_thread")]
    async fn invert_tombstone_counts_is_red() {
        let tomb = CloseTombstone::new();
        tomb.insert(7);
        let packets = Arc::new(AtomicU64::new(0));
        let progress = AtomicWriteProgress::new();
        let (_c, cancel_rx) = watch::channel(false);
        let hooks = WriterHooks {
            tombstone: tomb,
            packets_override: Some(packets.clone()),
            invert_tombstone_counts: true,
            ..WriterHooks::default()
        };
        let (handle, join, _evt) = spawn_writer_with_hooks(
            tokio::io::sink(),
            PacketWriter::clear(),
            progress,
            cancel_rx,
            hooks,
        );
        handle.try_seal_payload(data_payload(7)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            packets.load(Ordering::SeqCst) >= 1,
            "S6a HARD invert class tombstone_counted: drop incremented packets"
        );
        join.abort();
        let _ = join.await;
    }
}

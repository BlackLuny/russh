//! S4b HandlerExecutor: owns `&mut Handler` after the auth barrier.
//!
//! Invoke/Result are bounded. SessionTask posts channel/global callbacks
//! without awaiting (H2) and harvests Result on the main loop. Return-gated
//! points (`adjust_window`, `agent_request`) inline-await while nest-draining
//! only facade commands / Result / cancel. Facade commands use a bounded
//! queue + oneshot (scheme 2): the callback returns after SessionTask has
//! run the same `*_apply` body. Queue full → `Err`, never park on enqueue.
//! `accept`/`reject` stay on the reserved unbounded open-reply path.

use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "_test_hooks")]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use log::{debug, warn};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};

use super::session::{ChannelOpenHandle, Handle, Msg, Session};
use super::supervisor::DisconnectCause;
use super::{Config, Handler};
use crate::channels::Channel;
use crate::client::GexParams;
use crate::kex::dh::groups::{BUILTIN_SAFE_DH_GROUPS, DH_GROUP14, DhGroup};
use crate::{ChannelId, Disconnect, Error, Pty, Sig};

/// Per-callback facade command queue. Sized above any reasonable number of
/// `session.*` calls a single callback can issue. True full → `Err` (the
/// callback must not `await` enqueue).
pub const FACADE_QUEUE_CAP: usize = 64;

/// Default `Config::max_in_flight_handler_queue` (1 running + queued).
pub const DEFAULT_HANDLER_QUEUE: usize = 32;

/// Default `Config::max_pending_want_replies` (per obligation queue).
/// 4096 sits above the S2c 2000-reply generation-admit flood so that
/// path still trips first; H16 pins the cap with an explicit small value.
pub const DEFAULT_MAX_PENDING_WANT_REPLIES: usize = 4096;

/// Default `Config::handler_callback_timeout`.
pub const DEFAULT_HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Default `Config::max_channels` (opening + active + closing).
pub const DEFAULT_MAX_CHANNELS: usize = 128;

/// Default `Config::open_decision_deadline`.
pub const DEFAULT_OPEN_DECISION_DEADLINE: Duration = Duration::from_secs(30);

// ── test hooks ──────────────────────────────────────────────────────────────

/// Handle event-queue occupancy / parked-sender observation (H9 / S4a P2-2).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct HandleObserveSlot {
    occupancy: AtomicUsize,
    parked: AtomicUsize,
    max_occupancy: AtomicUsize,
    full_seen: AtomicBool,
}

#[cfg(feature = "_test_hooks")]
impl HandleObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn occupancy(&self) -> usize {
        self.occupancy.load(Ordering::SeqCst)
    }
    pub fn parked(&self) -> usize {
        self.parked.load(Ordering::SeqCst)
    }
    pub fn max_occupancy(&self) -> usize {
        self.max_occupancy.load(Ordering::SeqCst)
    }
    pub fn full_seen(&self) -> bool {
        self.full_seen.load(Ordering::SeqCst)
    }
    pub(crate) fn note_occupancy(&self, occ: usize) {
        self.occupancy.store(occ, Ordering::SeqCst);
        self.max_occupancy.fetch_max(occ, Ordering::SeqCst);
    }
    pub(crate) fn note_full(&self) {
        self.full_seen.store(true, Ordering::SeqCst);
    }
    pub(crate) fn park_inc(&self) {
        self.parked.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn park_dec(&self) {
        self.parked.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Executor-side counters (H8 data calls, I6 linger, skipped Invokes).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct HandlerObserveSlot {
    pub data_calls: AtomicU64,
    pub timeout_linger: AtomicU64,
    pub invoke_dropped: AtomicU64,
    pub timeouts: AtomicU64,
    pub executor_exited: AtomicBool,
    pub open_calls: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl HandlerObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn data_calls(&self) -> u64 {
        self.data_calls.load(Ordering::SeqCst)
    }
    pub fn timeout_linger(&self) -> u64 {
        self.timeout_linger.load(Ordering::SeqCst)
    }
    pub fn invoke_dropped(&self) -> u64 {
        self.invoke_dropped.load(Ordering::SeqCst)
    }
    pub fn timeouts(&self) -> u64 {
        self.timeouts.load(Ordering::SeqCst)
    }
    pub fn executor_exited(&self) -> bool {
        self.executor_exited.load(Ordering::SeqCst)
    }
    pub fn open_calls(&self) -> u64 {
        self.open_calls.load(Ordering::SeqCst)
    }
    pub(crate) fn mark_exited(&self) {
        self.executor_exited.store(true, Ordering::SeqCst);
    }
    pub(crate) fn note_timeout_harvest(&self) {
        self.timeouts.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn note_open_call(&self) {
        self.open_calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// Channel slot occupancy / late-disposition counters (L1–L5).
#[cfg(feature = "_test_hooks")]
#[derive(Debug, Default)]
pub struct SlotObserveSlot {
    opening: AtomicUsize,
    active: AtomicUsize,
    closing: AtomicUsize,
    used: AtomicUsize,
    max_used: AtomicUsize,
    max_opening: AtomicUsize,
    expired: AtomicU64,
    rejected_full: AtomicU64,
    confirm_before_lane: AtomicU64,
}

#[cfg(feature = "_test_hooks")]
impl SlotObserveSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn opening(&self) -> usize {
        self.opening.load(Ordering::SeqCst)
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
    pub fn closing(&self) -> usize {
        self.closing.load(Ordering::SeqCst)
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
    pub fn max_used(&self) -> usize {
        self.max_used.load(Ordering::SeqCst)
    }
    pub fn max_opening(&self) -> usize {
        self.max_opening.load(Ordering::SeqCst)
    }
    pub fn expired(&self) -> u64 {
        self.expired.load(Ordering::SeqCst)
    }
    pub fn rejected_full(&self) -> u64 {
        self.rejected_full.load(Ordering::SeqCst)
    }
    pub fn confirm_before_lane(&self) -> u64 {
        self.confirm_before_lane.load(Ordering::SeqCst)
    }
    pub(crate) fn observe(&self, opening: usize, active: usize, closing: usize) {
        self.opening.store(opening, Ordering::SeqCst);
        self.active.store(active, Ordering::SeqCst);
        self.closing.store(closing, Ordering::SeqCst);
        let used = opening.saturating_add(active).saturating_add(closing);
        self.used.store(used, Ordering::SeqCst);
        self.max_used.fetch_max(used, Ordering::SeqCst);
        self.max_opening.fetch_max(opening, Ordering::SeqCst);
    }
    pub(crate) fn note_expired(&self) {
        self.expired.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn note_rejected_full(&self) {
        self.rejected_full.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn note_confirm_before_lane(&self) {
        self.confirm_before_lane.fetch_add(1, Ordering::SeqCst);
    }
}

// ── commands / invokes ──────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum FacadeCmd {
    Data {
        channel: ChannelId,
        data: Bytes,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ExtendedData {
        channel: ChannelId,
        ext: u32,
        data: Bytes,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ChannelSuccess {
        channel: ChannelId,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ChannelFailure {
        channel: ChannelId,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    RequestSuccess {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    RequestFailure {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Eof {
        channel: ChannelId,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Close {
        channel: ChannelId,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Flush {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    FlushPending {
        channel: ChannelId,
        reply: oneshot::Sender<Result<usize, Error>>,
    },
    FlushPendingFences {
        channel: ChannelId,
        reply: oneshot::Sender<Result<usize, Error>>,
    },
    Disconnect {
        reason: Disconnect,
        description: String,
        language_tag: String,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Debug {
        always_display: bool,
        message: String,
        language_tag: String,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ChannelOpenFailure {
        channel: ChannelId,
        reason: crate::ChannelOpenFailure,
        description: String,
        language: String,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    XonXoff {
        channel: ChannelId,
        client_can_do: bool,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Keepalive {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SendPing {
        reply_channel: oneshot::Sender<()>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ExitStatus {
        channel: ChannelId,
        exit_status: u32,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ExitSignal {
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: String,
        language_tag: String,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    ChannelOpenSession {
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenDirectTcpip {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenDirectStreamlocal {
        socket_path: String,
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenForwardedTcpip {
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenForwardedStreamlocal {
        socket_path: String,
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    ChannelOpenAgent {
        reply: oneshot::Sender<Result<ChannelId, Error>>,
    },
    TcpipForward {
        address: String,
        port: u32,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    CancelTcpipForward {
        address: String,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    WindowSize {
        channel: ChannelId,
        reply: oneshot::Sender<u32>,
    },
    WritablePacketSize {
        channel: ChannelId,
        reply: oneshot::Sender<u32>,
    },
    MaxPacketSize {
        channel: ChannelId,
        reply: oneshot::Sender<u32>,
    },
    SenderWindowSize {
        channel: ChannelId,
        reply: oneshot::Sender<usize>,
    },
    HasPendingData {
        channel: ChannelId,
        reply: oneshot::Sender<bool>,
    },
}

/// Post-auth user callback posted to the Executor.
pub(crate) enum Invoke {
    Data {
        id: ChannelId,
        data: Bytes,
    },
    ExtendedData {
        id: ChannelId,
        ext: u32,
        data: Bytes,
    },
    ChannelEof {
        id: ChannelId,
    },
    ChannelClose {
        id: ChannelId,
    },
    WindowAdjusted {
        id: ChannelId,
        new_size: u32,
    },
    AdjustWindow {
        id: ChannelId,
        current: u32,
    },
    PtyRequest {
        id: ChannelId,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: Vec<(Pty, u32)>,
    },
    X11Request {
        id: ChannelId,
        single_connection: bool,
        x11_auth_protocol: String,
        x11_auth_cookie: String,
        x11_screen_number: u32,
    },
    EnvRequest {
        id: ChannelId,
        variable_name: String,
        variable_value: String,
    },
    ShellRequest {
        id: ChannelId,
    },
    ExecRequest {
        id: ChannelId,
        command: Bytes,
    },
    SubsystemRequest {
        id: ChannelId,
        name: String,
    },
    WindowChange {
        id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    Signal {
        id: ChannelId,
        signal: Sig,
    },
    AgentRequest {
        id: ChannelId,
    },
    ChannelOpenSession {
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
    },
    ChannelOpenX11 {
        channel: Channel<Msg>,
        originator_address: String,
        originator_port: u32,
        reply: ChannelOpenHandle,
    },
    ChannelOpenDirectTcpip {
        channel: Channel<Msg>,
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        reply: ChannelOpenHandle,
    },
    ChannelOpenForwardedTcpip {
        channel: Channel<Msg>,
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        reply: ChannelOpenHandle,
    },
    ChannelOpenDirectStreamlocal {
        channel: Channel<Msg>,
        socket_path: String,
        reply: ChannelOpenHandle,
    },
    ChannelOpenConfirmation {
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
    },
    TcpipForward {
        address: String,
        port: u32,
    },
    CancelTcpipForward {
        address: String,
        port: u32,
    },
    StreamlocalForward {
        socket_path: String,
    },
    CancelStreamlocalForward {
        socket_path: String,
    },
    LookupDhGex {
        params: GexParams,
    },
}

#[derive(Debug)]
pub(crate) enum ExecPayload {
    Unit(Result<(), Error>),
    Window(u32),
    Agent(Result<bool, Error>),
    Global {
        accepted: Result<bool, Error>,
        port: u32,
    },
    Gex(Result<Option<DhGroup>, Error>),
    /// Callback future was dropped by per-callback timeout. Not a PeerError.
    TimedOut,
}

#[derive(Debug)]
pub(crate) struct ExecResult {
    pub generation: u64,
    pub payload: ExecPayload,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PendingHarvest {
    Unit,
    /// CHANNEL_OPEN callback still holds the `Channel`. Same-lane pump
    /// must wait for harvest so a drop-Channel handler still sees
    /// `ChannelGone` → `Handler::data` (not Delivered-into-dropped-rx).
    Open { id: ChannelId },
    /// want-reply CHANNEL_REQUEST. Harvest leaves the obligation open;
    /// Handle::channel_success/failure or close decides it (fix2).
    ChannelReq,
    GlobalForward { wants_reply: bool, orig_port: u32 },
    GlobalBool { wants_reply: bool },
}

/// SessionTask-side handle to the Executor (JoinHandle stays in `run()`).
pub(crate) struct HandlerExecutor {
    pub invoke_tx: mpsc::Sender<InvokeMsg>,
    pub result_rx: mpsc::Receiver<ExecResult>,
    pub cancel: watch::Sender<bool>,
}

pub(crate) struct InvokeMsg {
    pub generation: u64,
    pub invoke: Invoke,
}

impl HandlerExecutor {
    pub fn is_full(&self) -> bool {
        self.invoke_tx.capacity() == 0
    }

    pub fn try_post(&self, generation: u64, invoke: Invoke) -> Result<(), TryPostError> {
        self.invoke_tx
            .try_send(InvokeMsg { generation, invoke })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => TryPostError::Full,
                mpsc::error::TrySendError::Closed(_) => TryPostError::Closed,
            })
    }
}

/// Invoke queue reject. `Full` is backpressure; `Closed` is fatal.
pub(crate) enum TryPostError {
    Full,
    Closed,
}

impl std::fmt::Debug for HandlerExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerExecutor")
            .field("invoke_cap", &self.invoke_tx.capacity())
            .finish()
    }
}

// ── spawn / stop ────────────────────────────────────────────────────────────

pub(crate) struct ExecutorSpawn {
    pub exec: HandlerExecutor,
    pub join: JoinHandle<()>,
    pub abort: AbortHandle,
    pub facade_rx: mpsc::Receiver<FacadeCmd>,
}

pub(crate) fn spawn_handler_executor<H>(
    mut handler: H,
    config: Arc<Config>,
    session_handle: Handle,
    remote_sshid: Vec<u8>,
    open_reply_tx: mpsc::UnboundedSender<Msg>,
    facade_notify: Arc<tokio::sync::Notify>,
    result_notify: Arc<tokio::sync::Notify>,
) -> ExecutorSpawn
where
    H: Handler + Send + 'static,
{
    let queue = config.max_in_flight_handler_queue.max(1);
    let timeout = config.handler_callback_timeout;
    let (invoke_tx, mut invoke_rx) = mpsc::channel(queue);
    let (result_tx, result_rx) = mpsc::channel(queue);
    let (facade_tx, facade_rx) = mpsc::channel(FACADE_QUEUE_CAP);
    let (cancel, mut cancel_rx) = watch::channel(false);

    #[cfg(feature = "_test_hooks")]
    let observe = config.handler_observe.clone();

    let mut facade_session = Session::facade_proxy(
        facade_tx,
        config,
        session_handle,
        remote_sshid,
        open_reply_tx,
        facade_notify,
    );

    let exec_loop = async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.changed() => {
                    debug!("handler executor: cancel");
                    break;
                }
                msg = invoke_rx.recv() => {
                    let Some(InvokeMsg { generation, invoke }) = msg else {
                        break;
                    };
                    let kind = invoke_kind(&invoke);
                    let fut = run_invoke(&mut handler, &mut facade_session, invoke);
                    tokio::pin!(fut);
                    let payload = match tokio::time::timeout(timeout, fut).await {
                        Ok(p) => p,
                        Err(_) => {
                            debug!(
                                "handler executor: timeout drop gen={generation} kind={kind}"
                            );
                            #[cfg(feature = "_test_hooks")]
                            if let Some(ref o) = observe {
                                o.timeout_linger.fetch_add(1, Ordering::SeqCst);
                            }
                            ExecPayload::TimedOut
                        }
                    };
                    if result_tx.send(ExecResult { generation, payload }).await.is_err() {
                        break;
                    }
                    result_notify.notify_waiters();
                }
            }
        }
        debug!("handler executor: exit");
        #[cfg(feature = "_test_hooks")]
        if let Some(ref o) = observe {
            o.mark_exited();
        }
    };

    // Multi-thread: stay on the app runtime (`block_in_place` + oneshot).
    // current_thread: a private OS thread so `wait_facade_oneshot` cannot
    // stall SessionTask (lib tests use `#[tokio::test]` default).
    let isolated = !matches!(
        tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    );
    let join = if isolated {
        let (exit_tx, exit_rx) = oneshot::channel::<()>();
        std::thread::Builder::new()
            .name("russh-handler-exec".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("handler executor runtime");
                rt.block_on(exec_loop);
                let _ = exit_tx.send(());
            })
            .expect("spawn russh-handler-exec");
        tokio::spawn(async move {
            let _ = exit_rx.await;
        })
    } else {
        tokio::spawn(exec_loop)
    };
    let abort = join.abort_handle();
    ExecutorSpawn {
        exec: HandlerExecutor {
            invoke_tx,
            result_rx,
            cancel,
        },
        join,
        abort,
        facade_rx,
    }
}

pub(crate) async fn stop_handler_executor(
    exec: Option<&HandlerExecutor>,
    join: &mut Option<JoinHandle<()>>,
    grace_at: tokio::time::Instant,
) {
    if let Some(e) = exec {
        let _ = e.cancel.send(true);
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
                        debug!("executor join: cancelled");
                    }
                    Err(e) if e.is_panic() => {
                        warn!("executor task panicked during stop: {e}");
                    }
                    Err(e) => {
                        warn!("executor join error: {e}");
                    }
                }
                return;
            }
            _ = tokio::time::sleep_until(grace_at), if !timed_out => {
                debug!("executor grace elapsed → abort");
                abort.abort();
                timed_out = true;
            }
        }
    }
}

fn invoke_kind(inv: &Invoke) -> &'static str {
    match inv {
        Invoke::Data { .. } => "data",
        Invoke::ExtendedData { .. } => "ext_data",
        Invoke::ChannelEof { .. } => "eof",
        Invoke::ChannelClose { .. } => "close",
        Invoke::WindowAdjusted { .. } => "window_adjusted",
        Invoke::AdjustWindow { .. } => "adjust_window",
        Invoke::PtyRequest { .. } => "pty",
        Invoke::X11Request { .. } => "x11",
        Invoke::EnvRequest { .. } => "env",
        Invoke::ShellRequest { .. } => "shell",
        Invoke::ExecRequest { .. } => "exec",
        Invoke::SubsystemRequest { .. } => "subsystem",
        Invoke::WindowChange { .. } => "window_change",
        Invoke::Signal { .. } => "signal",
        Invoke::AgentRequest { .. } => "agent",
        Invoke::ChannelOpenSession { .. } => "open_session",
        Invoke::ChannelOpenX11 { .. } => "open_x11",
        Invoke::ChannelOpenDirectTcpip { .. } => "open_direct_tcpip",
        Invoke::ChannelOpenForwardedTcpip { .. } => "open_fwd_tcpip",
        Invoke::ChannelOpenDirectStreamlocal { .. } => "open_direct_streamlocal",
        Invoke::ChannelOpenConfirmation { .. } => "open_confirm",
        Invoke::TcpipForward { .. } => "tcpip_forward",
        Invoke::CancelTcpipForward { .. } => "cancel_tcpip_forward",
        Invoke::StreamlocalForward { .. } => "streamlocal_forward",
        Invoke::CancelStreamlocalForward { .. } => "cancel_streamlocal_forward",
        Invoke::LookupDhGex { .. } => "gex",
    }
}

fn map_unit<E: From<Error>>(r: Result<(), E>) -> ExecPayload {
    match r {
        Ok(()) => ExecPayload::Unit(Ok(())),
        Err(e) => ExecPayload::Unit(Err(coerce_err(e))),
    }
}

fn coerce_err<E: From<Error>>(e: E) -> Error {
    // Handler::Error: From<Error>. We cannot go the other way; treat any
    // handler failure as a generic send/protocol error for harvest. The
    // SessionTask maps Unit(Err) → PeerError first-cause (S3b #12).
    let _ = e;
    Error::SendError
}

async fn run_invoke<H: Handler + Send>(
    handler: &mut H,
    session: &mut Session,
    invoke: Invoke,
) -> ExecPayload {
    match invoke {
        Invoke::Data { id, data } => {
            #[cfg(feature = "_test_hooks")]
            if let Some(ref o) = session.common.config.handler_observe {
                o.data_calls.fetch_add(1, Ordering::SeqCst);
            }
            map_unit(handler.data(id, &data, session).await)
        }
        Invoke::ExtendedData { id, ext, data } => {
            map_unit(handler.extended_data(id, ext, &data, session).await)
        }
        Invoke::ChannelEof { id } => map_unit(handler.channel_eof(id, session).await),
        Invoke::ChannelClose { id } => map_unit(handler.channel_close(id, session).await),
        Invoke::WindowAdjusted { id, new_size } => {
            map_unit(handler.window_adjusted(id, new_size, session).await)
        }
        Invoke::AdjustWindow { id, current } => {
            ExecPayload::Window(handler.adjust_window(id, current))
        }
        Invoke::PtyRequest {
            id,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes,
        } => map_unit(
            handler
                .pty_request(
                    id, &term, col_width, row_height, pix_width, pix_height, &modes, session,
                )
                .await,
        ),
        Invoke::X11Request {
            id,
            single_connection,
            x11_auth_protocol,
            x11_auth_cookie,
            x11_screen_number,
        } => map_unit(
            handler
                .x11_request(
                    id,
                    single_connection,
                    &x11_auth_protocol,
                    &x11_auth_cookie,
                    x11_screen_number,
                    session,
                )
                .await,
        ),
        Invoke::EnvRequest {
            id,
            variable_name,
            variable_value,
        } => map_unit(
            handler
                .env_request(id, &variable_name, &variable_value, session)
                .await,
        ),
        Invoke::ShellRequest { id } => map_unit(handler.shell_request(id, session).await),
        Invoke::ExecRequest { id, command } => {
            map_unit(handler.exec_request(id, &command, session).await)
        }
        Invoke::SubsystemRequest { id, name } => {
            map_unit(handler.subsystem_request(id, &name, session).await)
        }
        Invoke::WindowChange {
            id,
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => map_unit(
            handler
                .window_change_request(id, col_width, row_height, pix_width, pix_height, session)
                .await,
        ),
        Invoke::Signal { id, signal } => map_unit(handler.signal(id, signal, session).await),
        Invoke::AgentRequest { id } => match handler.agent_request(id, session).await {
            Ok(b) => ExecPayload::Agent(Ok(b)),
            Err(e) => ExecPayload::Agent(Err(coerce_err(e))),
        },
        Invoke::ChannelOpenSession { channel, reply } => {
            map_unit(handler.channel_open_session(channel, reply, session).await)
        }
        Invoke::ChannelOpenX11 {
            channel,
            originator_address,
            originator_port,
            reply,
        } => map_unit(
            handler
                .channel_open_x11(
                    channel,
                    &originator_address,
                    originator_port,
                    reply,
                    session,
                )
                .await,
        ),
        Invoke::ChannelOpenDirectTcpip {
            channel,
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
            reply,
        } => map_unit(
            handler
                .channel_open_direct_tcpip(
                    channel,
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                    reply,
                    session,
                )
                .await,
        ),
        Invoke::ChannelOpenForwardedTcpip {
            channel,
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
            reply,
        } => map_unit(
            handler
                .channel_open_forwarded_tcpip(
                    channel,
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                    reply,
                    session,
                )
                .await,
        ),
        Invoke::ChannelOpenDirectStreamlocal {
            channel,
            socket_path,
            reply,
        } => map_unit(
            handler
                .channel_open_direct_streamlocal(channel, &socket_path, reply, session)
                .await,
        ),
        Invoke::ChannelOpenConfirmation {
            id,
            max_packet_size,
            window_size,
        } => map_unit(
            handler
                .channel_open_confirmation(id, max_packet_size, window_size, session)
                .await,
        ),
        Invoke::TcpipForward { address, mut port } => {
            match handler.tcpip_forward(&address, &mut port, session).await {
                Ok(b) => ExecPayload::Global {
                    accepted: Ok(b),
                    port,
                },
                Err(e) => ExecPayload::Global {
                    accepted: Err(coerce_err(e)),
                    port,
                },
            }
        }
        Invoke::CancelTcpipForward { address, port } => {
            match handler.cancel_tcpip_forward(&address, port, session).await {
                Ok(b) => ExecPayload::Global {
                    accepted: Ok(b),
                    port,
                },
                Err(e) => ExecPayload::Global {
                    accepted: Err(coerce_err(e)),
                    port,
                },
            }
        }
        Invoke::StreamlocalForward { socket_path } => {
            match handler.streamlocal_forward(&socket_path, session).await {
                Ok(b) => ExecPayload::Global {
                    accepted: Ok(b),
                    port: 0,
                },
                Err(e) => ExecPayload::Global {
                    accepted: Err(coerce_err(e)),
                    port: 0,
                },
            }
        }
        Invoke::CancelStreamlocalForward { socket_path } => {
            match handler
                .cancel_streamlocal_forward(&socket_path, session)
                .await
            {
                Ok(b) => ExecPayload::Global {
                    accepted: Ok(b),
                    port: 0,
                },
                Err(e) => ExecPayload::Global {
                    accepted: Err(coerce_err(e)),
                    port: 0,
                },
            }
        }
        Invoke::LookupDhGex { params } => match handler.lookup_dh_gex_group(&params).await {
            Ok(g) => ExecPayload::Gex(Ok(g)),
            Err(e) => ExecPayload::Gex(Err(coerce_err(e))),
        },
    }
}

// ── Session helpers (facade proxy, dispatch, nest-drain) ────────────────────

impl Session {
    pub(crate) fn facade_proxy(
        cmd_tx: mpsc::Sender<FacadeCmd>,
        config: Arc<Config>,
        handle: Handle,
        remote_sshid: Vec<u8>,
        open_reply_tx: mpsc::UnboundedSender<Msg>,
        facade_notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        let (_open_tx, open_reply_rx) = mpsc::unbounded_channel();
        let _ = _open_tx;
        let (dummy_tx, dummy_rx) = mpsc::channel(1);
        let _ = dummy_tx;
        Session {
            common: crate::session::CommonSession {
                auth_user: String::new(),
                remote_sshid,
                config,
                encrypted: None,
                auth_method: None,
                auth_attempts: 0,
                packet_writer: crate::sshbuffer::PacketWriter::clear(),
                remote_to_local: Box::new(crate::cipher::clear::Key),
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
            },
            sender: handle,
            receiver: dummy_rx,
            target_window_size: 0,
            pending_reads: Vec::new(),
            pending_len: 0,
            channels: HashMap::new(),
            inbound_gate: HashMap::new(),
            inbound_needs_reserve: Vec::new(),
            backpressured: std::collections::HashSet::new(),
            outbound_acks: HashMap::new(),
            open_global_requests: std::collections::VecDeque::new(),
            kex: crate::kex::SessionKexState::Idle,
            open_reply_tx,
            open_reply_rx,
            rekey_gen: 0,
            rekey_deadline: crate::server::supervisor::RekeyDeadline::default(),
            handshake_deadline_at: None,
            writer: None,
            reader: None,
            peer_credit: None,
            pending_supervisor_cause: None,
            pending_outbound: Default::default(),
            pending_kex_install: None,
            deferred_window_grants: std::collections::HashSet::new(),
            #[cfg(feature = "_test_hooks")]
            full_ledger: None,
            #[cfg(feature = "_test_hooks")]
            outbound_log_cursor: 0,
            sched_next: None,
            sched_since_boost: crate::BOOST_PERIOD,
            sched_debt: None,
            facade_cmd_tx: Some(cmd_tx),
            facade_cmd_rx: None,
            executor: None,
            next_invoke_gen: 0,
            pending_harvest: HashMap::new(),
            facade_notify,
            result_notify: Arc::new(tokio::sync::Notify::new()),
            pending_open_ids: std::collections::HashSet::new(),
            global_replies: crate::ReplyQueue::default(),
            openings: HashMap::new(),
            channel_gens: HashMap::new(),
            conn_budget: None,
            channel_global_held: HashMap::new(),
        }
    }

    pub(crate) fn executor_full(&self) -> bool {
        self.executor.as_ref().is_some_and(|e| e.is_full())
    }

    fn next_gen(&mut self) -> u64 {
        self.next_invoke_gen = self.next_invoke_gen.wrapping_add(1);
        if self.next_invoke_gen == 0 {
            self.next_invoke_gen = 1;
        }
        self.next_invoke_gen
    }

    fn finish_try_post(
        &mut self,
        generation: u64,
        posted: Result<(), TryPostError>,
    ) -> Result<bool, Error> {
        match posted {
            Ok(()) => Ok(true),
            Err(TryPostError::Full) => {
                self.pending_harvest.remove(&generation);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref o) = self.common.config.handler_observe {
                    o.invoke_dropped.fetch_add(1, Ordering::SeqCst);
                }
                Ok(false)
            }
            Err(TryPostError::Closed) => {
                self.pending_harvest.remove(&generation);
                self.stage_cause(DisconnectCause::HandlerExecutorGone);
                Err(Error::SendError)
            }
        }
    }

    /// Fire-and-forget post. Queue full → skip + count (lifecycle already done).
    /// Closed → fatal (executor gone).
    pub(crate) fn try_post_unit(&mut self, invoke: Invoke) -> Result<bool, Error> {
        if self.executor.is_none() {
            return Ok(false);
        }
        let generation = self.next_gen();
        self.pending_harvest.insert(generation, PendingHarvest::Unit);
        let posted = self
            .executor
            .as_ref()
            .unwrap()
            .try_post(generation, invoke);
        self.finish_try_post(generation, posted)
    }

    pub(crate) fn try_post_channel(
        &mut self,
        _id: ChannelId,
        invoke: Invoke,
    ) -> Result<bool, Error> {
        self.try_post_harvest(invoke, PendingHarvest::ChannelReq)
    }

    /// Fire-and-forget CHANNEL_OPEN. Holds that lane until harvest so a
    /// handler that drops `Channel` still gets ChannelGone → Handler::data.
    pub(crate) fn try_post_open(&mut self, id: ChannelId, invoke: Invoke) -> Result<bool, Error> {
        let ok = self.try_post_harvest(invoke, PendingHarvest::Open { id })?;
        if ok {
            self.pending_open_ids.insert(id);
        }
        Ok(ok)
    }

    pub(crate) fn try_post_global(
        &mut self,
        invoke: Invoke,
        harvest: PendingHarvest,
    ) -> Result<bool, Error> {
        self.try_post_harvest(invoke, harvest)
    }

    fn try_post_harvest(
        &mut self,
        invoke: Invoke,
        harvest: PendingHarvest,
    ) -> Result<bool, Error> {
        if self.executor.is_none() {
            return Ok(false);
        }
        let generation = self.next_gen();
        self.pending_harvest.insert(generation, harvest);
        let posted = self
            .executor
            .as_ref()
            .unwrap()
            .try_post(generation, invoke);
        self.finish_try_post(generation, posted)
    }

    pub(crate) fn skip_facade_drain(&self) -> bool {
        #[cfg(feature = "_test_hooks")]
        {
            self.common.config.invert_skip_facade_drain
        }
        #[cfg(not(feature = "_test_hooks"))]
        {
            false
        }
    }

    /// Apply one facade command with the live Session (scheme 2).
    /// Finalize pending accept/reject first so accept-then-data keeps
    /// CONFIRMATION ahead of DATA (S3c #13).
    pub(crate) fn apply_facade_cmd(&mut self, cmd: FacadeCmd) {
        if !self.invert_open_confirm_before_lane() {
            let _ = self.drain_open_replies();
        }
        match cmd {
            FacadeCmd::Data {
                channel,
                data,
                reply,
            } => {
                let _ = reply.send(self.data_apply(channel, data));
            }
            FacadeCmd::ExtendedData {
                channel,
                ext,
                data,
                reply,
            } => {
                let _ = reply.send(self.extended_data_apply(channel, ext, data));
            }
            FacadeCmd::ChannelSuccess { channel, reply } => {
                let _ = reply.send(self.channel_success_apply(channel));
            }
            FacadeCmd::ChannelFailure { channel, reply } => {
                let _ = reply.send(self.channel_failure_apply(channel));
            }
            FacadeCmd::RequestSuccess { reply } => {
                self.request_success_apply();
                let _ = reply.send(Ok(()));
            }
            FacadeCmd::RequestFailure { reply } => {
                self.request_failure_apply();
                let _ = reply.send(Ok(()));
            }
            FacadeCmd::Eof { channel, reply } => {
                let _ = reply.send(self.eof_apply(channel));
            }
            FacadeCmd::Close { channel, reply } => {
                let _ = reply.send(self.close_apply(channel));
            }
            FacadeCmd::Flush { reply } => {
                let _ = reply.send(self.flush_apply());
            }
            FacadeCmd::FlushPending { channel, reply } => {
                let _ = reply.send(self.flush_pending_apply(channel));
            }
            FacadeCmd::FlushPendingFences { channel, reply } => {
                let _ = reply.send(self.flush_pending_fences_apply(channel));
            }
            FacadeCmd::Disconnect {
                reason,
                description,
                language_tag,
                reply,
            } => {
                let _ = reply.send(self.disconnect_apply(reason, &description, &language_tag));
            }
            FacadeCmd::Debug {
                always_display,
                message,
                language_tag,
                reply,
            } => {
                let _ = reply.send(self.debug_apply(always_display, &message, &language_tag));
            }
            FacadeCmd::ChannelOpenFailure {
                channel,
                reason,
                description,
                language,
                reply,
            } => {
                let _ = reply.send(self.channel_open_failure_apply(
                    channel,
                    reason,
                    &description,
                    &language,
                ));
            }
            FacadeCmd::XonXoff {
                channel,
                client_can_do,
                reply,
            } => {
                let _ = reply.send(self.xon_xoff_request_apply(channel, client_can_do));
            }
            FacadeCmd::Keepalive { reply } => {
                let _ = reply.send(self.keepalive_request_apply());
            }
            FacadeCmd::SendPing {
                reply_channel,
                reply,
            } => {
                let _ = reply.send(self.send_ping_apply(reply_channel));
            }
            FacadeCmd::ExitStatus {
                channel,
                exit_status,
                reply,
            } => {
                let _ = reply.send(self.exit_status_request_apply(channel, exit_status));
            }
            FacadeCmd::ExitSignal {
                channel,
                signal,
                core_dumped,
                error_message,
                language_tag,
                reply,
            } => {
                let _ = reply.send(self.exit_signal_request_apply(
                    channel,
                    signal,
                    core_dumped,
                    &error_message,
                    &language_tag,
                ));
            }
            FacadeCmd::ChannelOpenSession { reply } => {
                let _ = reply.send(self.channel_open_session_apply());
            }
            FacadeCmd::ChannelOpenDirectTcpip {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                reply,
            } => {
                let _ = reply.send(self.channel_open_direct_tcpip_apply(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                ));
            }
            FacadeCmd::ChannelOpenDirectStreamlocal { socket_path, reply } => {
                let _ = reply.send(self.channel_open_direct_streamlocal_apply(&socket_path));
            }
            FacadeCmd::ChannelOpenForwardedTcpip {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
                reply,
            } => {
                let _ = reply.send(self.channel_open_forwarded_tcpip_apply(
                    &connected_address,
                    connected_port,
                    &originator_address,
                    originator_port,
                ));
            }
            FacadeCmd::ChannelOpenForwardedStreamlocal { socket_path, reply } => {
                let _ = reply.send(self.channel_open_forwarded_streamlocal_apply(&socket_path));
            }
            FacadeCmd::ChannelOpenX11 {
                originator_address,
                originator_port,
                reply,
            } => {
                let _ = reply.send(
                    self.channel_open_x11_apply(&originator_address, originator_port),
                );
            }
            FacadeCmd::ChannelOpenAgent { reply } => {
                let _ = reply.send(self.channel_open_agent_apply());
            }
            FacadeCmd::TcpipForward {
                address,
                port,
                reply_channel,
                reply,
            } => {
                let _ = reply.send(self.tcpip_forward_apply(&address, port, reply_channel));
            }
            FacadeCmd::CancelTcpipForward {
                address,
                port,
                reply_channel,
                reply,
            } => {
                let _ = reply.send(self.cancel_tcpip_forward_apply(&address, port, reply_channel));
            }
            FacadeCmd::WindowSize { channel, reply } => {
                let _ = reply.send(self.window_size_apply(&channel));
            }
            FacadeCmd::WritablePacketSize { channel, reply } => {
                let _ = reply.send(self.writable_packet_size_apply(&channel));
            }
            FacadeCmd::MaxPacketSize { channel, reply } => {
                let _ = reply.send(self.max_packet_size_apply(&channel));
            }
            FacadeCmd::SenderWindowSize { channel, reply } => {
                let _ = reply.send(self.sender_window_size_apply(channel));
            }
            FacadeCmd::HasPendingData { channel, reply } => {
                let _ = reply.send(self.has_pending_data_apply(channel));
            }
        }
    }

    /// Drain already-queued facade commands without pumping reader/ctrl/ACK.
    pub(crate) fn drain_facade_cmds(&mut self) {
        if self.skip_facade_drain() {
            return;
        }
        loop {
            let cmd = match self.facade_cmd_rx.as_mut() {
                Some(rx) => match rx.try_recv() {
                    Ok(c) => c,
                    Err(_) => return,
                },
                None => return,
            };
            self.apply_facade_cmd(cmd);
        }
    }

    /// Harvest one Executor Result if present. Returns `Err` on handler failure
    /// (PeerError path). Timeout is not a PeerError.
    pub(crate) fn try_harvest_result(&mut self) -> Result<bool, Error> {
        let Some(ex) = self.executor.as_mut() else {
            return Ok(false);
        };
        match ex.result_rx.try_recv() {
            Ok(res) => {
                self.on_exec_result(res)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub(crate) fn on_exec_result(&mut self, res: ExecResult) -> Result<(), Error> {
        let harvest = self.pending_harvest.remove(&res.generation);
        if let Some(PendingHarvest::Open { id }) = harvest {
            self.pending_open_ids.remove(&id);
        }
        match res.payload {
            ExecPayload::TimedOut => {
                debug!("handler result: timed out gen={}", res.generation);
                #[cfg(feature = "_test_hooks")]
                if let Some(ref o) = self.common.config.handler_observe {
                    o.note_timeout_harvest();
                }
                self.fail_pending_obligation(harvest)
            }
            ExecPayload::Unit(Ok(())) | ExecPayload::Window(_) => {
                self.fail_pending_obligation(harvest)
            }
            ExecPayload::Unit(Err(e)) | ExecPayload::Agent(Err(e)) | ExecPayload::Gex(Err(e)) => {
                let _ = self.fail_pending_obligation(harvest);
                Err(e)
            }
            ExecPayload::Agent(Ok(_)) => Ok(()),
            ExecPayload::Gex(Ok(_)) => Ok(()),
            ExecPayload::Global { accepted, port } => {
                match accepted {
                    Err(e) => {
                        let _ = self.fail_pending_obligation(harvest);
                        Err(e)
                    }
                    Ok(ok) => {
                        if let Some(h) = harvest {
                            let (wants, extra) = match h {
                                PendingHarvest::GlobalForward {
                                    wants_reply,
                                    orig_port,
                                } => {
                                    let extra = if ok && wants_reply && orig_port == 0 && port != 0 {
                                        Some(port)
                                    } else {
                                        None
                                    };
                                    (wants_reply, extra)
                                }
                                PendingHarvest::GlobalBool { wants_reply } => (wants_reply, None),
                                PendingHarvest::Unit
                                | PendingHarvest::Open { .. }
                                | PendingHarvest::ChannelReq => {
                                    (self.common.wants_reply, None)
                                }
                            };
                            if wants {
                                self.global_replies.decide_oldest_pending(ok, extra);
                                self.flush_global_replies()?;
                            }
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    /// Nested select: only facade cmds + Executor Result + cancel. Used for
    /// return-gated inline awaits (`adjust_window`, `agent_request`, GEX).
    pub(crate) async fn nest_wait_result(&mut self, expect_gen: u64) -> Result<ExecPayload, Error> {
        loop {
            let mut cancel_rx = self
                .executor
                .as_ref()
                .ok_or(Error::SendError)?
                .cancel
                .subscribe();
            if *cancel_rx.borrow() {
                return Err(Error::SendError);
            }
            if self.skip_facade_drain() {
                // Invert H4: do not drain facade. Still wait for Result so
                // adjust_window/agent can complete; data() oneshots hang.
                let ex = self
                    .executor
                    .as_mut()
                    .ok_or(Error::SendError)?;
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => return Err(Error::SendError),
                    res = ex.result_rx.recv() => match res {
                        Some(res) if res.generation == expect_gen => return Ok(res.payload),
                        Some(res) => self.on_exec_result(res)?,
                        None => return Err(Error::SendError),
                    }
                }
                continue;
            }
            let has_rx = self.facade_cmd_rx.is_some();
            tokio::select! {
                biased;
                _ = cancel_rx.changed() => {
                    return Err(Error::SendError);
                }
                cmd = async {
                    if has_rx {
                        self.facade_cmd_rx.as_mut().unwrap().recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(cmd) = cmd {
                        self.apply_facade_cmd(cmd);
                    }
                }
                res = async {
                    self.executor.as_mut().unwrap().result_rx.recv().await
                } => {
                    let Some(res) = res else {
                        return Err(Error::SendError);
                    };
                    if res.generation == expect_gen {
                        return Ok(res.payload);
                    }
                    self.on_exec_result(res)?;
                }
            }
        }
    }

    async fn post_and_wait(&mut self, invoke: Invoke) -> Result<ExecPayload, Error> {
        let generation = self.next_gen();
        self.pending_harvest.insert(generation, PendingHarvest::Unit);
        let posted = self
            .executor
            .as_ref()
            .ok_or(Error::SendError)?
            .try_post(generation, invoke);
        match posted {
            Ok(()) => {}
            Err(TryPostError::Closed) => {
                self.pending_harvest.remove(&generation);
                self.stage_cause(DisconnectCause::HandlerExecutorGone);
                return Err(Error::SendError);
            }
            Err(TryPostError::Full) => {
                self.pending_harvest.remove(&generation);
                return Err(Error::SendError);
            }
        }
        self.nest_wait_result(generation).await
    }

    pub(crate) async fn nest_adjust_window(&mut self, id: ChannelId, current: u32) -> u32 {
        match self.post_and_wait(Invoke::AdjustWindow { id, current }).await {
            Ok(ExecPayload::Window(w)) => w,
            Ok(ExecPayload::TimedOut) => current,
            _ => current,
        }
    }

    pub(crate) async fn nest_agent_request(&mut self, id: ChannelId) -> Result<bool, Error> {
        match self.post_and_wait(Invoke::AgentRequest { id }).await? {
            ExecPayload::Agent(r) => r,
            ExecPayload::TimedOut => Ok(false),
            other => {
                let _ = other;
                Ok(false)
            }
        }
    }

    pub(crate) async fn nest_lookup_gex(
        &mut self,
        params: GexParams,
    ) -> Result<Option<DhGroup>, Error> {
        match self
            .post_and_wait(Invoke::LookupDhGex { params })
            .await?
        {
            ExecPayload::Gex(r) => r,
            ExecPayload::TimedOut => Ok(default_gex_group()),
            _ => Ok(default_gex_group()),
        }
    }

    /// Call Handler::data: inline if still on-loop, else post (or invert-wait).
    pub(crate) async fn dispatch_data<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        data: &[u8],
        inline_wait: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let inv = Invoke::Data {
                id,
                data: Bytes::copy_from_slice(data),
            };
            if inline_wait {
                match self.post_and_wait(inv).await {
                    Ok(ExecPayload::Unit(Err(e))) | Err(e) => return Err(e.into()),
                    _ => return Ok(()),
                }
            }
            self.try_post_unit(inv)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.data(id, data, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_extended_data<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        ext: u32,
        data: &[u8],
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            self.try_post_unit(Invoke::ExtendedData {
                id,
                ext,
                data: Bytes::copy_from_slice(data),
            })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.extended_data(id, ext, data, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_eof<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            self.try_post_unit(Invoke::ChannelEof { id })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.channel_eof(id, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_close<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            self.try_post_unit(Invoke::ChannelClose { id })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.channel_close(id, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_window_adjusted<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        new_size: u32,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            self.try_post_unit(Invoke::WindowAdjusted { id, new_size })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.window_adjusted(id, new_size, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_adjust_window<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        current: u32,
    ) -> u32 {
        if self.executor.is_some() {
            return self.nest_adjust_window(id, current).await;
        }
        handler
            .map(|h| h.adjust_window(id, current))
            .unwrap_or(current)
    }

    pub(crate) async fn dispatch_exec<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        cmd: &[u8],
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(
                id,
                Invoke::ExecRequest {
                    id,
                    command: Bytes::copy_from_slice(cmd),
                },
            )?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.exec_request(id, cmd, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_pty<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(
                id,
                Invoke::PtyRequest {
                    id,
                    term: term.to_string(),
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    modes: modes.to_vec(),
                },
            )?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .pty_request(
                    id, term, col_width, row_height, pix_width, pix_height, modes, self,
                )
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_x11_req<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        single_connection: bool,
        proto: &str,
        cookie: &str,
        screen: u32,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(
                id,
                Invoke::X11Request {
                    id,
                    single_connection,
                    x11_auth_protocol: proto.to_string(),
                    x11_auth_cookie: cookie.to_string(),
                    x11_screen_number: screen,
                },
            )?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .x11_request(id, single_connection, proto, cookie, screen, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_env<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        name: &str,
        value: &str,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(
                id,
                Invoke::EnvRequest {
                    id,
                    variable_name: name.to_string(),
                    variable_value: value.to_string(),
                },
            )?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.env_request(id, name, value, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_shell<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(id, Invoke::ShellRequest { id })?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.shell_request(id, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_subsystem<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        name: &str,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_channel(
                id,
                Invoke::SubsystemRequest {
                    id,
                    name: name.to_string(),
                },
            )?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.subsystem_request(id, name, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_window_change<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_unit(Invoke::WindowChange {
                id,
                col_width,
                row_height,
                pix_width,
                pix_height,
            })?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .window_change_request(id, col_width, row_height, pix_width, pix_height, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_signal<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        signal: Sig,
        wants_reply: bool,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            let posted = self.try_post_unit(Invoke::Signal { id, signal })?;
            self.on_channel_invoke_posted(id, posted, wants_reply)?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.signal(id, signal, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_agent<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
    ) -> Result<bool, H::Error> {
        if self.executor.is_some() {
            return self.nest_agent_request(id).await.map_err(|e| e.into());
        }
        if let Some(h) = handler {
            return h.agent_request(id, self).await;
        }
        Ok(false)
    }

    pub(crate) async fn dispatch_open_session<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
    ) -> Result<(), H::Error> {
        self.note_open_handler();
        if self.executor.is_some() {
            let id = channel.id();
            self.try_post_open(id, Invoke::ChannelOpenSession { channel, reply })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h.channel_open_session(channel, reply, self).await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_open_x11<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
    ) -> Result<(), H::Error> {
        self.note_open_handler();
        if self.executor.is_some() {
            let id = channel.id();
            self.try_post_open(
                id,
                Invoke::ChannelOpenX11 {
                    channel,
                    originator_address: originator_address.to_string(),
                    originator_port,
                    reply,
                },
            )?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .channel_open_x11(channel, originator_address, originator_port, reply, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_open_direct_tcpip<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        orig_addr: &str,
        orig_port: u32,
        reply: ChannelOpenHandle,
    ) -> Result<(), H::Error> {
        self.note_open_handler();
        if self.executor.is_some() {
            let id = channel.id();
            self.try_post_open(
                id,
                Invoke::ChannelOpenDirectTcpip {
                    channel,
                    host_to_connect: host.to_string(),
                    port_to_connect: port,
                    originator_address: orig_addr.to_string(),
                    originator_port: orig_port,
                    reply,
                },
            )?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .channel_open_direct_tcpip(channel, host, port, orig_addr, orig_port, reply, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_open_forwarded_tcpip<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        orig_addr: &str,
        orig_port: u32,
        reply: ChannelOpenHandle,
    ) -> Result<(), H::Error> {
        self.note_open_handler();
        if self.executor.is_some() {
            let id = channel.id();
            self.try_post_open(
                id,
                Invoke::ChannelOpenForwardedTcpip {
                    channel,
                    host_to_connect: host.to_string(),
                    port_to_connect: port,
                    originator_address: orig_addr.to_string(),
                    originator_port: orig_port,
                    reply,
                },
            )?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .channel_open_forwarded_tcpip(
                    channel, host, port, orig_addr, orig_port, reply, self,
                )
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_open_direct_streamlocal<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
    ) -> Result<(), H::Error> {
        self.note_open_handler();
        if self.executor.is_some() {
            let id = channel.id();
            self.try_post_open(
                id,
                Invoke::ChannelOpenDirectStreamlocal {
                    channel,
                    socket_path: socket_path.to_string(),
                    reply,
                },
            )?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .channel_open_direct_streamlocal(channel, socket_path, reply, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_open_confirmation<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
    ) -> Result<(), H::Error> {
        if self.executor.is_some() {
            self.try_post_unit(Invoke::ChannelOpenConfirmation {
                id,
                max_packet_size,
                window_size,
            })?;
            return Ok(());
        }
        if let Some(h) = handler {
            return h
                .channel_open_confirmation(id, max_packet_size, window_size, self)
                .await;
        }
        Ok(())
    }

    pub(crate) async fn dispatch_tcpip_forward<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        address: &str,
        port: &mut u32,
    ) -> Result<bool, H::Error> {
        if self.executor.is_some() {
            let orig = *port;
            let wants = self.common.wants_reply;
            let posted = self.try_post_global(
                Invoke::TcpipForward {
                    address: address.to_string(),
                    port: orig,
                },
                PendingHarvest::GlobalForward {
                    wants_reply: wants,
                    orig_port: orig,
                },
            )?;
            if !posted && wants {
                self.fail_last_global_obligation()?;
            }
            return Ok(false);
        }
        if let Some(h) = handler {
            return h.tcpip_forward(address, port, self).await;
        }
        Ok(false)
    }

    pub(crate) async fn dispatch_cancel_tcpip_forward<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        address: &str,
        port: u32,
    ) -> Result<bool, H::Error> {
        if self.executor.is_some() {
            let wants = self.common.wants_reply;
            let posted = self.try_post_global(
                Invoke::CancelTcpipForward {
                    address: address.to_string(),
                    port,
                },
                PendingHarvest::GlobalBool {
                    wants_reply: wants,
                },
            )?;
            if !posted && wants {
                self.fail_last_global_obligation()?;
            }
            return Ok(false);
        }
        if let Some(h) = handler {
            return h.cancel_tcpip_forward(address, port, self).await;
        }
        Ok(false)
    }

    pub(crate) async fn dispatch_streamlocal_forward<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        path: &str,
    ) -> Result<bool, H::Error> {
        if self.executor.is_some() {
            let wants = self.common.wants_reply;
            let posted = self.try_post_global(
                Invoke::StreamlocalForward {
                    socket_path: path.to_string(),
                },
                PendingHarvest::GlobalBool {
                    wants_reply: wants,
                },
            )?;
            if !posted && wants {
                self.fail_last_global_obligation()?;
            }
            return Ok(false);
        }
        if let Some(h) = handler {
            return h.streamlocal_forward(path, self).await;
        }
        Ok(false)
    }

    pub(crate) async fn dispatch_cancel_streamlocal_forward<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        path: &str,
    ) -> Result<bool, H::Error> {
        if self.executor.is_some() {
            let wants = self.common.wants_reply;
            let posted = self.try_post_global(
                Invoke::CancelStreamlocalForward {
                    socket_path: path.to_string(),
                },
                PendingHarvest::GlobalBool {
                    wants_reply: wants,
                },
            )?;
            if !posted && wants {
                self.fail_last_global_obligation()?;
            }
            return Ok(false);
        }
        if let Some(h) = handler {
            return h.cancel_streamlocal_forward(path, self).await;
        }
        Ok(false)
    }

    pub(crate) async fn dispatch_lookup_gex<H: Handler + Send>(
        &mut self,
        handler: Option<&mut H>,
        params: &GexParams,
    ) -> Result<Option<DhGroup>, H::Error> {
        if self.executor.is_some() {
            return self
                .nest_lookup_gex(params.clone())
                .await
                .map_err(|e| e.into());
        }
        if let Some(h) = handler {
            return h.lookup_dh_gex_group(params).await;
        }
        Ok(default_gex_group())
    }
}

fn default_gex_group() -> Option<DhGroup> {
    default_lookup_gex(&GexParams::default())
}

/// Builtin GEX pick used when Handler is gone and Executor is not live.
pub(crate) fn default_lookup_gex(gex_params: &GexParams) -> Option<DhGroup> {
    let mut best_group = &DH_GROUP14;
    for group in BUILTIN_SAFE_DH_GROUPS.iter() {
        if group.bit_size() >= gex_params.min_group_size()
            && group.bit_size() <= gex_params.max_group_size()
        {
            best_group = *group;
            break;
        }
    }
    for group in BUILTIN_SAFE_DH_GROUPS.iter() {
        if group.bit_size() > gex_params.preferred_group_size() {
            best_group = *group;
            break;
        }
    }
    Some(best_group.clone())
}

/// Block the Executor until SessionTask has run `*_apply`.
/// Multi-thread: `block_in_place` so other workers keep draining.
/// Isolated current_thread Executor: `block_on` only stalls that thread.
pub(crate) fn wait_facade_oneshot<T>(rx: oneshot::Receiver<T>) -> Result<T, Error> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| rx.blocking_recv().map_err(|_| Error::SendError))
        }
        _ => futures::executor::block_on(rx).map_err(|_| Error::SendError),
    }
}

pub(crate) fn facade_try_send(
    tx: &mpsc::Sender<FacadeCmd>,
    cmd: FacadeCmd,
) -> Result<(), Error> {
    tx.try_send(cmd).map_err(|_| Error::SendError)
}

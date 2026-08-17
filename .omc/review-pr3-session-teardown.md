# Adversarial review: PR3 session / teardown / executor (HEAD `5cb1f8a`)

**Repo:** BlackLuny/russh  
**PR:** https://github.com/BlackLuny/russh/pull/3  
**Commit:** `5cb1f8aba2e9d1290008c56ffffd977b9b04a17f`  
**Scope:** `session.rs` run loop / spawn / teardown, `executor.rs`, `session_facade.rs`, `mod.rs` Config/`run_stream`, `channels/io/tx.rs` wake, CLOSE/`StopDiscard` in `writer.rs`+`session.rs`.  
**Lens:** Real deadlock, hang, lost-wake, soak leaks. Style ignored.

---

## Overall verdict: **FIX-FIRST**

Do **not** ship until the lane-pump `continue` path stops starving ConnSupervisor / `select!` (Finding 1). That is a concrete 24h-soak / adversarial-peer session immortalization mode.

Handler↔Session facade deadlock under executor Full is largely closed (H21). ChannelTx S8b/S8c production path looks fixed. Teardown grace is absolute (not stacked). Remaining issues are real but secondary to Finding 1.

---

## Focus verdicts (requested checklist)

| # | Question | Verdict |
|---|----------|---------|
| 1 | Deadlock HandlerExecutor ↔ SessionTask (`session.data` + exec queue full) | **CLOSED** for facade path (H21); residual nest/`Handle::data` footgun |
| 2 | Teardown hang (abort / grace / socket) | **MOSTLY OK**; absolute `grace_at`; early `return Err` skips graceful stop |
| 3 | Lost wakeup ChannelTx / permit | **FIXED** in production (invert still red) |
| 4 | Handler hang containment actually working? | **PARTIAL** — async `.await` hangs yes; `wait_facade_oneshot` / sync CPU no |
| 5 | `select!` fairness / busy loop | **REAL DEFECT** — `more_lanes` busy-continue |
| 6 | Shutdown vs in-flight rekey | **OK enough** — WriteStalled can win; fail-closed on Writer death |
| 7 | 24h soak: fd/task/mutex leak | **RISK** via Finding 1 + isolated-executor abort weakness |

---

## Finding 1 — P0: `more_lanes` continue starves watchdog / rekey / keepalive / reserve harvest

**Evidence**

```3232:3234:russh/src/server/session.rs
            if more_lanes && !self.common.disconnected {
                continue;
            }
```

```1347:1410:russh/src/server/session.rs
    const LANE_PUMP_QUANTUM: usize = 64;
    // ...
            if popped >= Self::LANE_PUMP_QUANTUM {
                return Ok(true);
            }
```

WriteWatchdog / rekey deadline polls and all of `select!` (including `inbound_reserves.next()`, keepalive, inactivity, writer/reader events) sit **after** that `continue`:

```3256:3291:russh/src/server/session.rs
            let sealed_backlog = self.sealed_backlog_bytes();
            write_watchdog.observe_eligible(sealed_backlog as u64);
            // ...
            if let Some(cause) = write_watchdog.poll_timeout(write_progress_deadline, write_min_drain)
            {
                record_cause(cause, &mut supervisor_cause);
                self.common.disconnected = true;
                break;
            }
            if let Some(kex_gen) = self.rekey_deadline.poll(self.active_rekey_gen()) {
                // ...
                break;
            }
```

Facade drain **does** run before the continue (H21 covers that). Supervisor does **not**.

**Concrete scenario**

1. Peer floods `CHANNEL_REQUEST` / DATA so every `pump_reader_lanes` hits the 64-item quantum → `more_lanes == true`.
2. SessionTask spins: loop-top → pump → `continue` → never enters `select!`, never `observe_eligible` / `poll_timeout`.
3. Simultaneously Writer is stalled (peer TCP window 0, or slow drain): sealed backlog stays > 0, but `WriteStalled` never fires (`write_progress_deadline` default 30s is irrelevant if never polled).
4. Default `keepalive_interval: None`, `inactivity_timeout: 600s` also never armed in `select!`.
5. Completed `inbound_reserves` futures (app buffer freed) are only taken in the select arm at `session.rs:3754` — under the busy loop, backpressured channels stay parked forever even though permits are Ready.

**Why it matters for 24h soak**

Adversarial or merely chatty peers keep the session immortal with a wedged write path: no supervisor kill, CPU spin, channels half-dead, fds held. 2h soak with cooperative clients would miss this; a REQUEST flood harness would not.

**Fix shape (not prescribing a patch):** on quantum exhaustion, fall through to supervisor sample + at least one `select!` tick (or poll watchdog/rekey before `continue`). H21 must stay green (facade still drained).

---

## Finding 2 — P1: Hang containment does not bound `session.*` facade waits

**Evidence**

Timeout wraps the invoke future on the **same** task:

```622:635:russh/src/server/executor.rs
                    let fut = run_invoke(&mut handler, &mut facade_session, invoke);
                    tokio::pin!(fut);
                    let payload = match tokio::time::timeout(timeout, fut).await {
                        Ok(p) => p,
                        Err(_) => {
                            // ...
                            ExecPayload::TimedOut
                        }
                    };
```

Facade completion is **synchronous** block:

```2259:2265:russh/src/server/executor.rs
pub(crate) fn wait_facade_oneshot<T>(rx: oneshot::Receiver<T>) -> Result<T, Error> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| rx.blocking_recv().map_err(|_| Error::SendError))
        }
        _ => futures::executor::block_on(rx).map_err(|_| Error::SendError),
    }
}
```

While `blocking_recv` / `block_on` runs, `timeout` cannot be polled → **no TimedOut** until the oneshot resolves (Session drains or drops `facade_cmd_rx`).

H6 only proves containment for **async** hangs (`Notify::notified().await`).

**Concrete scenario**

1. Invert-style: Session stuck in a path that does not drain facade (or process frozen).
2. Handler calls `session.data()` → `push_facade` + `wait_facade_oneshot`.
3. `handler_callback_timeout` (default 30s) never fires.
4. Only Session teardown dropping `facade_cmd_rx` (`session.rs:4000-4003`) unblocks the Executor.

Under Finding 1’s busy-continue, facade **is** drained each iteration, so H21 passes — but containment still does not independently bound a facade wait if Session is elsewhere stuck (e.g. long `replay_pending_reads`, poisoned test hold in prod builds, future await without nest-drain).

**Also:** sync infinite loops in `adjust_window` (sync fn) likewise never yield to `timeout`.

**Verdict:** Containment works for cooperative async awaits; it does **not** “actually” contain facade/`block_in_place` hangs.

---

## Finding 3 — P1: Isolated HandlerExecutor OS thread is not abortable

**Evidence**

```654:676:russh/src/server/executor.rs
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
            // ...
        tokio::spawn(async move {
            let _ = exit_rx.await;
        })
    } else {
        tokio::spawn(exec_loop)
    };
```

`AbortHandle` aborts only the wrapper JoinHandle. `stop_handler_executor` sends `cancel` then aborts that same handle after `grace_at`. Cancel is only observed **between** invokes (`select!` on `cancel_rx`), not during a stuck invoke.

`IoTeardownGuard` aborts executor but **never** sends `executor.cancel` — only Writer/Reader cancel:

```2998:3007:russh/src/server/session.rs
            fn drop(&mut self) {
                if self.armed {
                    let _ = self.cancel_tx.send(true);
                    self.writer_abort.abort();
                    self.reader_abort.abort();
                    if let Some(a) = self.executor_abort.take() {
                        a.abort();
                    }
                }
            }
```

**Concrete scenario (current_thread / many unit tests / embedders)**

1. Handler sync-spins or blocks outside cancellation points.
2. Session hits Keepalive/Inactivity/`return Err` → guard aborts wrapper only.
3. OS thread `russh-handler-exec` lives until process exit → **thread leak** on soak under fault injection.

Multi-thread production servers use `tokio::spawn(exec_loop)` (abortable), so severity is environment-dependent — still a real defect in the isolation path the code explicitly maintains.

---

## Finding 4 — P2: `nest_wait_result` × `Handle::data().await` = bounded deadlock

**Evidence**

Return-gated waits only nest-drain facade / result / cancel — **not** the Handle `receiver` queue:

```1485:1544:russh/src/server/executor.rs
    /// Nested select: only facade cmds + Executor Result + cancel.
    pub(crate) async fn nest_wait_result(...)
```

`Handle::data` documents not to call from Handler (`session.rs:593-595`) but still parks on `sender.send` + ack oneshot (`session.rs:644-668`).

`agent_request` is nest-gated and receives `&mut Session` (can also reach `session.handle()`).

**Scenario**

1. Session `post_and_wait(AgentRequest)` → `nest_wait_result`.
2. Handler does `session.handle().data(...).await` (or Channel writer → same mpsc).
3. Msg sits on `receiver`; nest never `dispatch_msg` → deadlock until invoke timeout drops the async wait (timeout **can** fire here — unlike facade).

**Verdict:** Not the “exec queue full + session.data” deadlock (that’s closed). Still a real nest-path hang class; timeout is the only safety net.

---

## Finding 5 — HandlerExecutor ↔ `session.data` under queue Full: **CLOSED**

**Evidence**

- Facade: `try_send` never parks (`facade_try_send`, `session_facade.rs:16-20`); Full → `Err`.
- Notify + drain: `facade_notify.notify_waiters()`; main loop drains before/after pump and on select arm.
- Quantum path explicitly preserves facade drain; H21 (`tests/test_s4b_executor.rs`) must-green under exec Full + REQUEST flood.
- `nest_wait_result` drains facade while waiting for adjust/agent/GEX.

**Scenario that used to deadlock:** Handler `session.data()` while invoke queue Full and Session pumping lanes — **fixed** for production drain order.

Residual: Finding 2 (containment) and Finding 4 (`Handle::data`).

---

## Finding 6 — ChannelTx lost-wake (S8b/S8c): **FIXED** (production)

**Evidence**

Production registers Notify **before** parking; no self-wake lost window:

```321:346:russh/src/channels/io/tx.rs
                    match self.register_window_notify(cx) {
                        Poll::Ready(()) => { /* early Ok; known_dead checked */ }
                        Poll::Pending => {
                            // Registered. No wake_by_ref...
                            self.acked_waiting = true;
                            return Poll::Pending;
                        }
                    }
```

Discard path: live-set remove **then** wake (`session.rs:2525-2531`); early-Ok arms check `known_dead()` (`tx.rs:288-293`, `331-336`).

Object gates: `s8b_object_register_round` / `s8c_object_known_dead_round` + `test_s8b_register.rs` — production green, invert red.

**Verdict:** No remaining production lost-wake defect found in the acked park path. Multi-writer `notify_one` steals are tolerated via early Ok (documented).

---

## Finding 7 — Teardown / grace / socket: **MOSTLY OK**

**Evidence**

```3989:4011:russh/src/server/session.rs
        // Single absolute grace (S1: no stacked deadlines). Writer + Reader share
        // the same `grace_at`.
        let grace_at = tokio::time::Instant::now() + teardown_grace;
        stop_writer_task(...).await;
        stop_reader_task(...).await;
        drop(self.facade_cmd_rx.take());
        stop_handler_executor(...).await;
        io_guard.armed = false;
```

- Writer stop sends shared `cancel` (`writer.rs:652`); Reader selects on same watch (`reader.rs:1405-1413`).
- Absolute deadline: late Writer eat-all-grace → Reader/Executor abort immediately — correct, not stacked.
- Facade rx dropped before executor stop wakes `wait_facade_oneshot`.
- Config default `teardown_grace: 5s` (`mod.rs:499`).

**Gaps**

- Early `return Err` (handler PeerError harvest, KeepaliveTimeout, InactivityTimeout at `session.rs:3774-3783`) skips best-effort DISCONNECT + `stop_*`; relies on `IoTeardownGuard` abort. Socket halves drop when tasks cancel — OK if cancel points are hit; no grace drain of Writer out_q.
- Finding 3 on isolated executor under those early returns.

**Verdict:** Graceful Cancelling path is sound; panic/early-err path is hard-abort (acceptable if abort always reaches IO tasks).

---

## Finding 8 — CLOSE / StopDiscard arbitration: **OK**

**Evidence**

- Tombstone insert before framing CLOSE (`session.rs:2477-2487`).
- Writer drops DATA/EOF/ADJUST/REQUEST/SUCCESS/FAILURE for tombstoned recip; **CLOSE never dropped** (`writer.rs:1076-1094`, `1143-1158`).
- Tombstone cleared when CLOSE seals (`writer.rs:1156-1158`).
- Peer CLOSE while Full/`exec_full`: `discard_close_queued_lanes` / `maybe_discard_for_peer_close` (`session.rs:1388-1396`, `1559-1568`) — does not wait for invoke permit.
- `we_closed_first` / `already_gone` prevent double CLOSE (`session.rs:1533-1556`).
- `finalize_close` wakes writers **before** `channels.remove` (`session.rs:2574-2588`) — invert `invert_skip_teardown_wake` proves the hang class.

**Residual (low):** if CLOSE never reaches seal (session abort mid-flight), tombstone dies with Writer — no cross-connection leak. Recipient reuse before peer sees CLOSE is peer-protocol-bound.

---

## Finding 9 — Shutdown vs in-flight rekey: **OK enough**

**Evidence**

- `blocks_outbound_intake` while `kex.active() || pending_kex_install` (`session.rs:4412-4414`).
- NeedSubmit bytes count in `sealed_backlog_bytes` → watchdog stays armed (`session.rs:4051-4074`); tests assert WriteStalled can beat RekeyTimeout.
- Writer death / SealError → `fail_pending_kex_install` (`session.rs:3604-3628`, `4987-4992`) stages PeerError without forcing Idle.
- Dual InstallAck + `apply_kex_after_install` completion flush only on success path.

**Gap:** under Finding 1 busy-loop, rekey deadline also never polls — rekey stall + inbound flood = immortal session (amplifies P0).

---

## Finding 10 — Config / `run_stream` soak notes

**Defaults** (`mod.rs` Default): `handler_callback_timeout=30s`, `max_in_flight_handler_queue=32`, `teardown_grace=5s`, `write_progress_deadline=30s`, `write_min_drain=None`, `keepalive_interval=None`, `inactivity_timeout=Some(600s)`, `rekey_deadline=30s`.

**`run_stream`:** GlobalBudget `ConnAccount` acquired before banner; Drop refunds on handshake failure — no connection-slot leak found. Session spawned via `russh_util::runtime::spawn` (`mod.rs:1735`).

**`run_on_socket`:** one task per accept (`mod.rs:1497`); shutdown only `Handle::disconnect` — relies on session run exiting. Combined with Finding 1, a wedged session ignores disconnect traffic if it never selects on `receiver`… disconnect is also a Handle msg on `receiver`, drained only in batch/`select!` **after** the `more_lanes` continue → **local shutdown may not reach a flooded session**.

---

## What is *not* a defect (checked)

- Facade queue Full → `Err` (no park-on-enqueue) — correct backpressure.
- `exec_full` gating ctrl/lane DATA with Close-at-head StopDiscard — intentional I2' / P1 close path.
- Biased `select!` favoring `writer_events` — events are rare; not a busy spin source.
- ChannelTx production register-before-park + known_dead — S8b/S8c closed.
- Absolute teardown grace shared by Writer/Reader/Executor — not stacked.

---

## Priority summary

| ID | Sev | Title | Action |
|----|-----|-------|--------|
| F1 | **P0** | `more_lanes` continue starves supervisor / select / reserves / disconnect | **Must fix before ship** |
| F2 | P1 | Facade `wait_facade_oneshot` defeats callback timeout | Fix or document hard limit + ensure Session always drains |
| F3 | P1 | Isolated executor thread not aborted | Join/kill OS thread or run cancel during waits |
| F4 | P2 | nest_wait × Handle::data | Drain Handle queue in nest, or harden docs/API |
| F5–F6 | — | Facade+Full deadlock / ChannelTx lost-wake | Closed |
| F7–F9 | — | Teardown grace / StopDiscard / rekey | OK with F1 dependency |

---

## Overall: **FIX-FIRST**

Ship only after F1 (lane-pump must not skip ConnSupervisor + `select!`). F2/F3 should be fixed or explicitly accepted with tests proving bounded teardown under sync/facade hang on both runtime flavors. Without F1, a 24h soak against a chatty/stalling peer can hold fds/tasks forever with zero WriteStalled/RekeyTimeout/inactivity progress.

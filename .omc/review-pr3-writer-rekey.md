# Adversarial review: PR #3 writer / rekey / watchdog (HEAD `5cb1f8a`)

**Scope (only):**
- `russh/src/server/writer.rs`
- `russh/src/server/supervisor.rs` (write watchdog, `AtomicWriteProgress`, rekey deadline)
- `russh/src/sshbuffer.rs` (`flush_into`, `drained_total`, watermarks)
- Rekey / NEWKEYS install ACK path in `russh/src/server/session.rs`
- `russh/src/session.rs` rekey trigger / `Encrypted::flush`
- `russh/src/lib_inner.rs` `RekeyPolicy`

**Lens:** production failure under zfc reverse-proxy load (many concurrent `direct-tcpip`, heavy bidirectional flood, volume rekey). Style ignored.

---

## Overall: **FIX-FIRST**

The S2b redesign largely closes the 2026-08-10 *permanent wedge* class (saturated downlink during rekey with neither progress nor disconnect): `NeedSubmit` + capacity/`20ms` poll, `WriteStalled`, and generation-checked `RekeyTimeout` give bounded exits. InstallAck dual-condition, atomic `SealBatchAndInstall`, and Reader NEWKEYS-before-apply are sound.

Two real production defects remain in the Session↔watchdog / volume-rekey start path. Ship after those are fixed.

---

## Verdicts by area

| Area | Verdict |
|------|---------|
| `writer.rs` (seal/install/drain/seqn) | **OK** |
| `supervisor.rs` (watchdog / progress / rekey deadline primitives) | **OK** (mechanisms); Session wiring below is the problem |
| `sshbuffer.rs` (`flush_into` / watermarks / `take_pending`) | **OK** |
| InstallAck / NEWKEYS path (`server/session.rs` + `mod.rs` callers) | **OK** |
| Rekey trigger / held-`enc.write` / watchdog eligibility | **DEFECT** |
| `Encrypted::flush` + `RekeyPolicy` | **OK** (server Writer path); client/no-writer packet limit is by design |

---

## Must-fix

### M1 — Kex-held `CHANNEL_DATA` counted as wire-eligible → WriteStalled false-kill of healthy rekey

**Verdict:** DEFECT  
**Files:** `server/session.rs:4051–4074`, `4416–4424`, `5399–5412`, `3256–3284`; conflicts with `supervisor.rs:1271–1276`

**What the code does**

1. During `kex.active() || pending_kex_install`, `flush_apply` **stops** at the first `CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA` in `enc.write` and leaves it staged (`hold_enc_packet_during_kex`, comment explicitly: “keeps wire-eligible > 0”).
2. Watchdog eligibility is `sealed_backlog_bytes()`, which **includes** `enc_write_wire_weight` of that unconsumed tail.
3. Supervisor docs claim kex-gated app bulk is **excluded** so pure InKex with empty staging disarms and only `RekeyTimeout` applies (`supervisor.rs:1273–1276`). Session violates that contract.

**Concrete failure (zfc profile)**

1. Bidirectional flood fills the pipeline; a mid-flush HWM break leaves one or more `CHANNEL_DATA` packets in `enc.write[cursor..]` (`flush_apply` hard-cap `break` after moving the current packet to `pending_outbound`).
2. Peer (or local volume) starts rekey → `blocks_outbound_intake` true.
3. Writer drains all *actually sealed* ciphertext; TCP is healthy; `pending_bytes == 0`.
4. Held `CHANNEL_DATA` keeps `sealed_backlog > 0` → watchdog **stays armed**, but no `note_write` ever occurs (nothing is submitted to the socket).
5. After `write_progress_deadline` (default 30s; often tuned **shorter** than `rekey_deadline` in proxies) → `DisconnectCause::WriteStalled`.
6. Peer may still be mid-DH / under CPU load; rekey would have completed — connection dies as a false write stall.

F13 (`tests/test_s2b1_session_run.rs` “slow kex after drain must not WriteStalled”) only passes when staging reaches **eligible=0**. Flood + leftover `enc.write` DATA is exactly the case F13 does not cover and production hits.

**Fix direction:** Exclude kex-held app DATA from watchdog eligibility (move those frames back to `pending_data`, or compute eligible from Writer+pending_outbound+NeedSubmit only). Do **not** treat policy-held plaintext as “wire-eligible.”

---

### M2 — `enc.exchange.take()` before `begin_rekey` can permanently disable volume rekey (and can arm InKex without a deadline)

**Verdict:** DEFECT  
**Files:** `server/session.rs:5348–5351`, `6657–6705`; `RekeyDeadline::poll` at `supervisor.rs:1460–1471`

**What the code does**

```text
apply_i5_rekey:
  enc.exchange.take()          // destroys Option first
  begin_rekey()?               // may fail afterward

begin_rekey:
  kexinit(...)?                // fail ⇒ kex still Idle, exchange already gone
  kex = InProgress
  seal_payloads(...)?          // fail ⇒ InProgress, deadline not registered yet
  rekey_gen++; deadline.register(...)
```

**Concrete failures**

**A — Silent forever-no-rekey**

1. `i5_volume_due()` true; `kex == Idle`.
2. `exchange.take()` succeeds → `enc.exchange = None`.
3. `kex.kexinit` fails (encoding / preferred list edge) → `begin_rekey` returns `Err` **before** `InProgress`.
4. Next flushes: due may still be true, but `exchange` is `None` → the `if take().is_some()` body never runs again.
5. Connection keeps serving past `RekeyPolicy` limits with **no** further volume rekey.

**B — InKex without `RekeyTimeout` (wedge-class if disconnect is swallowed)**

1. `exchange` taken; `kexinit` OK; `kex = InProgress`; `seal_payloads` returns `Err(SendError)` (Writer closed).
2. Deadline registration never runs (`register` is after seal).
3. `active_rekey_gen()` can still be `Some(rekey_gen)` via `kex.active()`, but `RekeyDeadline::poll` requires `self.generation == Some(gen)` → **never fires**.
4. If the flush error is recorded, teardown saves you; if a `let _ = self.flush()` path ignores it while intake stays blocked by `kex.active()`, you get **neither progress nor rekey timeout** — the 2026-08-10 wedge shape.

**Fix direction:** Do not `take()` exchange until `begin_rekey` succeeds (or restore on `Err`). Register `rekey_deadline` as soon as `InProgress` is set (before seal), or fail closed with a staged supervisor cause on any mid-`begin_rekey` error.

---

## Area findings

### 1. `writer.rs` — **OK**

- **Atomic NEWKEYS:** `SealBatchAndInstallEpoch` seals all payloads then `install_epoch` with **no await** (`writer.rs:1275–1407`). Soft-cap cannot split NEWKEYS from its pre-payloads (covered by `seal_batch_and_install_is_atomic_wrt_soft_cap`).
- **Seqn vs in-flight:** `install_epoch` only resets `PacketWriter` seqn/bytes (`1217–1264`). Ciphertext already moved to `out_q` via `take_pending_wire_bytes` after each seal (`1155–1198`). In-flight MAC/AEAD already baked — correct for RFC 4253.
- **Cancel-safety of drain:** `drain_writes` advances `flush_cursor` + `progress.note_write` + `pending_bytes` before the next await (`1524–1535`). Partial writes survive `select!` cancel. Cipher swap does not touch `out_q`/`current`.
- **InstallAck:** Emitted with the cmd’s `generation` after successful install (`1405–1406`, `1433–1434`). Session ignores oneshot and consumes `WriterEvent` — OK.
- **Bounds:** `BULK_QUEUE_CAP=256`, `OUT_Q_SOFT_CAP=64` — no unbounded Writer queues under hang.

No must-fix in this file for the stated goals.

---

### 2. `supervisor.rs` (watchdog / `AtomicWriteProgress` / `RekeyDeadline`) — **OK** (primitive)

- **G2 peer-window=0:** Activity arms only on `wire_eligible > 0`; zero disarms (`1277–1288`). Correct **if** Session passes only sealed/submittable bytes. Pure window=0 data in `pending_data` is excluded by Session — tests `s0_zero_window_legit` match.
- **`write_min_drain`:** Default `None` (`server/mod.rs:496`) — no false-kill of legitimate slow links unless opted in.
- **`AtomicWriteProgress`:** Mutex whole-struct replace; `note_write` before further awaits from Writer — no torn reads (`1170–1218`).
- **`RekeyDeadline`:** Generation-checked poll (`1460–1471`) is correct; M2 is about failing to **register**, not about poll logic.

---

### 3. `sshbuffer.rs` — **OK**

- **`flush_into`:** Cursor + `drained_total` incremented immediately after `Ok(n>0)` (`738–762`). Cancel-safe; unit test `drained_total_survives_select_cancel_after_partial_write`.
- **`take_pending_wire_bytes`:** Skips `[0..flush_cursor)` (`489–506`) — closes the old S2a P2 duplicate-prefix hazard.
- **`OUTBOUND_HIGH_WATERMARK` (128 KiB):** Soft intake bound; hard cap is HWM+one elsewhere. Not a rekey hang by itself.
- Post-Writer-spawn, production drain is Writer `drain_writes`; `flush_into` remains for initial KEX pre-split (`session.rs:2829–2840`) — still cancel-safe under handshake timeout.

---

### 4. InstallAck / NEWKEYS path — **OK**

- **Dual condition:** Outbound `InstallAcked` ∧ peer `after` ∧ inbound ACK (if Reader) (`250–256`, `4968–4983`).
- **Generation mismatch:** Ignored (`4789–4790`, `4936–4937`) — stale ACK cannot complete the wrong txn; live txn still bounded by `rekey_deadline` when registered.
- **Phase guard:** ACK only accepted in `WaitingAck` (`4939–4941`) — no double-complete.
- **Ordering race:** `try_send` then set `WaitingAck` before returning to `select!` (`4726–4742`); Writer event may already be queued — buffered, not lost.
- **Half-install on failure:** `fail_pending_kex_install` stages `PeerError` (`4986–4992`); Writer `SealError`/`Closed` disconnects (`3604–3629`).
- **Skip NEWKEYS / double-install:** NeedsReply takes outbound once (`outbound_half_taken`); Done with empty payloads merges peer Done only (`mod.rs:1889–1962`). Reader applies inbound **after** decrypting peer NEWKEYS with old keys (out of file scope but closes the cutover).
- **`kex.active` barrier:** Intake / open-reply / data flush gated on `blocks_outbound_intake` (`4412–4414`). Post-Done waiting for ACK leaves `Taken` via `kex.take()` — barrier holds until `apply_kex_after_install` → Idle.

No InstallAck generation / skip-NEWKEYS must-fix found.

---

### 5. Rekey trigger / `Encrypted::flush` / `RekeyPolicy`

#### Server volume path — **DEFECT** (see M1, M2)

- Server uses `i5_volume_due` (packets **and** bytes, both directions) then `apply_i5_rekey` (`5211–5353`), not bare `Encrypted::flush` limits.

#### `Encrypted::flush` (`session.rs:1123–1158`) — **OK** for its role

- No-writer / client path: `rekey_wanted || buffer.bytes >= max_bytes`.
- Packet limits intentionally on Reader/Writer atomics (comment at `1152–1156`). Not a server Writer regression.

#### `RekeyPolicy` (`lib_inner.rs:297–333`) — **OK**

- Defaults `2^31` packets / `1 TiB`; no time trigger; completion budget is `Config.rekey_deadline`. Matches I5 design. Breaking rename from `Limits` is API, not a runtime hang.

---

### 6. Memory / maps — **OK** with one soft note

| Structure | Bound? |
|-----------|--------|
| Writer bulk / out_q | Yes (256 / 64) |
| `pending_kex_install` | Single txn |
| `CloseTombstone` | Per-connection; cleared on CLOSE seal (`writer.rs:1156–1158`) |
| Channel `pending_data` | `max_pending_outbound_bytes` → StopDiscard (`2550–2563`) |

**SUSPICIOUS (not must-fix):** `park_pending_read` has no byte/count cap (`5092–5098`). Malicious KEXINIT flood during the narrow `should_park_kexinit` window can grow `pending_reads` until `rekey_deadline` tears down. Time-bounded, not a permanent leak.

**SUSPICIOUS:** `flush_apply` HOL-stops at held `CHANNEL_DATA`, so later `GLOBAL_REQUEST` keepalive / IGNORE in the same `enc.write` cannot drain (`5399–5412` vs comment `4416–4421`). Default `keepalive_interval` is `None`; zfc with keepalives + inbound kex traffic usually resets `alive_timeouts` via `received_data`. Secondary to M1.

---

## Goal checklist

| Goal | Result |
|------|--------|
| 1. Rekey hang / deadlock / livelock / half-install / seqn vs in-flight | Seqn/in-flight **OK**; InstallAck **OK**; **M2** can leave InKex without deadline; barrier itself **OK** |
| 2. Memory leaks | No unbounded production maps found; park list soft-unbounded only |
| 3. Connection wedge under saturated downlink during rekey | Permanent wedge largely **closed** (WriteStalled / RekeyTimeout / NeedSubmit poll); **M2-B** residual if deadline never armed |
| 4. Write watchdog false-kill of peer-window=0 (G2) | **OK** for pure window=0; **M1** is a related false-kill via kex-held staged DATA |
| 5. Cancel-safety / partial writes across cipher swap | **OK** (Writer drain + `flush_into`) |
| 6. InstallAck gen mismatch / double-install / skip NEWKEYS | **OK** |

---

## Must-fix list

1. **M1** — Stop treating kex-held `CHANNEL_DATA*` in `enc.write` as write-watchdog eligible (restore supervisor contract; protect flood+rekey).
2. **M2** — Make `apply_i5_rekey` / `begin_rekey` failure-atomic w.r.t. `enc.exchange` and arm `rekey_deadline` before any fallible seal (or fail closed with disconnect).

---

## Not defects (explicitly cleared)

- Peer SSH window=0 alone does not arm the watchdog (G2).
- `SealBatchAndInstall` atomicity vs `OUT_Q_SOFT_CAP`.
- Outbound seqn reset with old ciphertext still in `out_q`.
- InstallAck generation / phase / dual-condition completion.
- Default-off `write_min_drain`.
- `RekeyPolicy` defaults / no time-based *trigger* (deadline is separate).

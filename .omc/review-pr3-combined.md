# PR #3 adversarial code review (S2–S8 rewrite, HEAD `5cb1f8a`)

Independent review of https://github.com/BlackLuny/russh/pull/3 on the
`russh-s2a-writer-task` tree. Style nits ignored. Claims below are from
reading the code (file:line in the per-area notes). **24h soak measurements
are in `soak-results/SOAK_REPORT.md` and override inference where they
disagree.**

Overall: **FIX-FIRST** for the session-loop control-plane bugs below.
WriterTask / ReaderTask / InstallAck / G2 window=0 mechanics look sound.
The 2026-08-10 *permanent* rekey wedge is bounded by `WriteStalled` +
`RekeyTimeout` **when those timers actually run**.

## Must-fix

### P0 — `more_lanes` `continue` skips watchdog, rekey deadline, and peer credit

`russh/src/server/session.rs` ~3207–3234: after `pump_reader_lanes`,
`if more_lanes && !disconnected { continue; }` jumps to the next loop
iteration **before** `apply_pending_peer_credit`, `write_watchdog.poll_timeout`,
`rekey_deadline.poll`, and the `select!`.

If inbound DATA/REQUEST keeps the 64-item quantum full, SessionTask busy-spins:
- peer `WINDOW_ADJUST` sits on `PeerCreditBoard` → outbound can stall
  (cross-channel HOL)
- write/rekey deadlines never sampled → the S1 “bounded teardown” guarantee
  does not hold on the hottest path
- CPU pegged on the session task

Detailed write-up: `.omc/review-pr3-session-teardown.md`,
`.omc/review-pr3-reader-budget.md` (F1).

### P1 — Kex-held CHANNEL_DATA counted as wire-eligible → false WriteStalled

During `kex.active()`, `flush_apply` leaves CHANNEL_DATA in `enc.write`.
`sealed_backlog_bytes()` still counts that tail, so the write watchdog stays
armed while no socket write can happen. After `write_progress_deadline`
(default 30s) the connection is killed as `WriteStalled` even if rekey is
progressing.

Conflicts with `supervisor.rs` contract (kex-gated bulk excluded; InKex with
empty staging is RekeyTimeout-only). F13 does not cover leftover `enc.write`
DATA after Writer drain.

Details: `.omc/review-pr3-writer-rekey.md` M1.

### P1 — GlobalBudget leak on `CtrlMsg::Overflow` StopDiscard

Overflow StopDiscards without `release_channel_global` → per-connection
ledger + `channel_global_held` leak under channel churn.

Details: `.omc/review-pr3-reader-budget.md` F2.

### P1 — `apply_i5_rekey` takes `enc.exchange` before `begin_rekey` can fail

`enc.exchange.take()` then `begin_rekey()?`. If `kexinit` fails, volume rekey
never fires again; if seal fails, `InProgress` without a registered deadline.

Details: `.omc/review-pr3-writer-rekey.md` M2.

### P1 — `Handler::adjust_window` growth is session-wide but occupancy caps are per-channel

Growing the window updates `target_window_size` globally but only raises the
occupancy cap for the channel that called it → other channels can Overflow
(D29 hole on multi-channel).

Details: `.omc/review-pr3-reader-budget.md` F3.

## Closed / OK (do not rediscover)

- Writer InstallAck generation dual-condition, seqn vs in-flight ciphertext,
  cancel-safe `flush_into` across cipher swap
- Reader mid-packet inbound epoch install (install only at packet boundary)
- G2: peer-window=0 `pending_data` is not sealed, so idle backpressure should
  not arm the watchdog **when the loop reaches `observe_eligible`**
- S8b/S8c ChannelTx register-before-park / `known_dead` (production path)
- S9 F2 `channel_gens` unbounded map replaced by monotonic gen
- S9 F3 deferred WINDOW_ADJUST 50ms re-poll
- D28 global ledger no longer counts cumulative grants
- Facade `session.data()` vs executor Full (H21 + nest drain)
- Teardown grace is absolute, not stacked; socket drop does not wait on DISCONNECT

## Residual (not must-fix for soak, still real)

- Handler hang containment fails for `wait_facade_oneshot` / `block_in_place`
  (timeout never polls); isolated `russh-handler-exec` OS thread is not abortable
- `nest_wait` × `Handle::data().await` can deadlock until timeout
- Gen-0 `CloseDropped` ABA after channel-id wrap (P2)
- Unfair HashMap lane peek (P2)

## Soak plan (this change)

`scripts/soak/run_24h.sh` runs three concurrent localhost stacks for ≥24h,
64 MiB rekey, 8 MiB/s × (down+up+echo), RSS/CPU/fd/thread sampling every 10s:

1. OpenSSH 9.6 client → russh `s8_matrix_server`
2. russh `soak_client` → russh `s8_matrix_server` (with 30s channel churn)
3. OpenSSH 9.6 client → OpenSSH 9.6 `sshd` (baseline)

Judge: stall ≥60s, payload verify errors, unexpected disconnect, RSS slope
>8 MiB/h, fd/thread growth. Report: `soak-results/SOAK_REPORT.md`.

# OpenSSH→russh upload channel close (12.7h soak)

Measured on the 12.7h localhost soak, then re-read against the code.
The first write-up treated over-window DATA as the close root cause.
That is **not** what the ledger supports. This note records the
corrected chain.

## What happened (measured)

- Stack: OpenSSH 9.6 `-L` → russh `s8_matrix_server` (3 channels: down/up/echo).
- At `t=37066.6s` (~10.3h) the **upload** channel died (`channels_live` 3→2, `io_errors=1`).
- Session stayed up (`disconnects=0`). Download kept running.
- Stats gap `t=34296.9` → `t=37056.6` (~46 min, ~60 MiB progress), then ~400 MB/s catch-up, then close.
- russh server RSS 8.2→51.7 MiB then plateau; fds/threads 13/5; `rekey_triggers≈5854`.

The original soak did **not** set `RUST_LOG`. `s8_matrix_server` only
initializes `env_logger` when that var is present, so overflow /
over-window `warn!` would not have printed. Those logs neither confirm
nor exclude `CtrlMsg::Overflow`. Raw jsonl is not in git
(`soak-results/run-12h/` is local-only).

## Main cause of the 46 min stall + 400 MB/s burst

`pump_reader_lanes` returning `more_lanes` used to `continue` the
session loop and skip `select!`. That skipped:

- ctrl (peer `CHANNEL_WINDOW_ADJUST`, KEXINIT)
- writer_events (`InstallAck`)
- capacity_notify (`retry_deferred_window_grants`)
- `apply_pending_peer_credit` and write/rekey watchdog `observe_eligible`

`more_lanes` is true while inbound lanes still have a quantum of work.
Self-lock: inbound flood → forever `continue` → no peer ADJUST →
downlink stops → no writer ack → `sealed_backlog ≥ HWM` → every local
`WINDOW_ADJUST` goes into `deferred_window_grants` and the retry is
also skipped → uplink window exhausted → ~0 traffic (~46 min) → lanes
drain, `more_lanes=false` → one dump → 400 MB/s burst.

Fix: do not `continue`. Keep pumping via an immediately-ready
`select!` arm placed last-but-one (`biased`, before supervisor sleep)
so ctrl / writer / lane_notified / receiver stay higher priority.

## Over-window DATA is not a proven soak close

`grant_expand_then_adjust` uses the same `delta` for
`expand_inbound_cap` then `emit_window_adjust`. For a compliant peer,
`lane.window_remaining ≥` peer's idea of the window plus in-flight
bytes. `LaneTable::ingest`'s over-window branch is therefore dead
against OpenSSH.

`over_window_data_is_ignored_not_queued` and
`q5_wire_over_window_is_ignored` prove the RFC-ignore behaviour when
the extra bytes are forced. They do not prove the soak over-windowed.

The ingest change is **unproven hardening** (RFC 4254 §5.2). On drop,
`window_remaining` is cleared so the ledger does not keep advertising
credit the peer already spent. Warns are once-per-lane.
`DroppedOverWindow` has its own observe counter (not `note_zero`).

A window-ignoring flood used to be the Q5 **wire** byte_cap path.
That path now ignores. The remaining production-adjacent byte_cap
DoS gate is `q5_occupancy_bound_closes_only_victim` (inject
`try_push`, not ingest).

## Real Overflow path for a compliant peer: torn grant reads

`maybe_grant_after_delivery` used to take the lane lock twice:

1. `occupancy_bytes(id)` → L
2. `sender_window(id)` → R'  (Reader can ingest N in between)

Then `delta = (target - L) - R'`, expand sets `window_remaining =
target - L`, actual occupancy is `L + N`, so
`lane_bytes + window_remaining = target + N`.
`byte_cap = target + maxpkt` (2 MiB + 32 KiB). N > 32 KiB Overflows
a compliant peer. At 400 MB/s that gap is ~82 µs.

Fix: `LaneTable::grant_plan(id) -> (occ, remaining)` under one lock;
`maybe_grant_after_delivery` uses that pair. Unit:
`grant_plan_is_atomic_against_ingest`.

## Other fixes in this PR

- `CtrlMsg::Overflow` now `release_channel_global` (was a real leak:
  this arm `channels.remove`s and never hits `finalize_close`) and
  `publish_slots()`.
- I5 rekey no longer `enc.exchange.take()` before `begin_rekey`
  (unrelated leftover; `begin_rekey` does not use `enc.exchange`).

## Verification

- Unit: over-window drop + remaining cleared; torn vs atomic grant Δ.
- Integration: Q5 inject still Overflows (`overflows=1`); Q5-wire over-window is
  ignored (`occupancy=64`, `overflows=0`, `over_window_drops=2`).
  `window_grant_is_lane_only` / omit-lane red / G7 still pass.
- Live, **unlimited** OpenSSH freeze-catchup with `RUST_LOG=russh=warn`
  and a pass/fail judge (`soak-results/REPEAT_VERIFY.md`, JSON in
  `soak-results/judges/`):
  - 15s freeze × 5, 3×15s on one connection, upload-only × 3, 30s freeze × 2,
    180s unlimited, **180s with 8 MiB rekey** (`idle_drops=29`)
  - **Negative control:** putting `more_lanes { continue }` back did **not**
    fail 180s unlimited or 15s freeze-catchup. Fast sink drain keeps
    `more_lanes` from staying true; this harness does not nail that as the
    soak root cause. The select-arm change is still the right code.



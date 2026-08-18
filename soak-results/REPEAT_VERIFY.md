# Repeat verification (OpenSSH → russh freeze-catchup)

All runs: `RUST_LOG=russh=warn`, `RATE_BPS=0`, judged by
`scripts/soak/judge_repro.py`. Judge JSON for these runs is in
`soak-results/judges/` (no ssh keys).

This is still not a 12.7h soak.

## Cargo

| suite | result |
| --- | --- |
| `grant_plan_is_atomic_against_ingest` | pass |
| `over_window_data_is_ignored_not_queued` | pass |
| `window_grant_*` including **`window_grant_torn_reads_is_red`** | pass (5) |
| `g7_*` (2) | pass |
| `test_s3b_lanes` (17) | pass |
| `test_s6a_rekey` (12) | pass |

`window_grant_torn_reads_is_red` drives `maybe_grant_after_delivery` with
`invert_torn_grant_reads` + a hold/mid gate. Reader ingest N=20 between
the two locks; asserts `occ + remaining > target`. Production counterpart
`window_grant_atomic_reads_keep_invariant` stays `≤ target`.

Judge ready-line: an s8 log without `S8_LISTEN`/`S8_READY` is FAIL (empty
log is no longer a silent pass).

## Live OpenSSH → `s8_matrix_server` (fixed binary)

| case | n | result | notes |
| --- | --- | --- | --- |
| 15s freeze, 3ch | 5 | **5/5** | peaks 769–800 MB/s |
| 3×15s freeze, one connection | 1 | **pass** | 3 SIGSTOP gaps; peak 913 MB/s |
| 15s freeze, upload only | 3 | **3/3** | peaks 886–967 MB/s |
| 30s freeze (io-timeout=freeze+60) | 2 | **2/2** | peaks 765–778 MB/s |
| 180s unlimited, no freeze | 1 | **pass** | 156.5 GiB; peak 933 MB/s; zero gaps |
| 180s unlimited, **8 MiB rekey** | 1 | **pass** | 109.6 GiB; peak 662 MB/s; zero gaps; `rekey_triggers=1` `rekey_idle_drops=29` `disconnects=0` |

## Negative control (`more_lanes { continue }` restored, then reverted)

Same judge, same s8 fixture, `continue` put back after `pump_reader_lanes`.

| case | result | notes |
| --- | --- | --- |
| 180s unlimited, no freeze | **PASS (did not go red)** | 153.6 GiB; peak 918 MB/s; zero gaps; min_live=3 |
| 15s freeze, 3ch | **PASS (did not go red)** | peak 788 MB/s; one SIGSTOP gap; min_live=3 |

So this harness does **not** distinguish `continue` vs the select-arm fix
on a 180s flood or a 15s freeze-catchup. `more_lanes` is only true when a
pump quantum actually completes (`popped >= 64`). A fast sink/echo handler
drains the lane; select still runs most iterations. The 12.7h self-lock
needs the extra conjunction (inbound still at quantum + `sealed_backlog ≥
HWM` so every `WINDOW_ADJUST` is deferred **and** the retry is skipped).
45s–180s localhost did not hit that conjunction.

The code change (do not skip `select!`) is still correct. The 180s
zero-gap run on the **fixed** binary is not a differential proof against
`continue`.

## What is nailed vs what is not

- **Torn grant:** Session-level must-red on the invariant. Nailed.
- **Judge silent-log hole:** missing `S8_READY` fails. Nailed.
- **Flood × volume rekey:** 8 MiB I5 + OpenSSH `RekeyLimit=8M` for 180s;
  `idle_drops=29` (predicate true while `kex != Idle`); no stall/close.
  Covered, not a 5854-trigger 10h soak.
- **`more_lanes` as soak root cause:** code still matches the 46 min
  timeline, but a live negative control in this harness did not FAIL.
  Not nailed by 12/12.

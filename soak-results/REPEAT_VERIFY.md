# Repeat verification (OpenSSH → russh freeze-catchup)

All runs: `RUST_LOG=russh=warn`, `RATE_BPS=0`, judged by
`scripts/soak/judge_repro.py` (fail on overflow/over-window warn,
mid-run `channels_live` drop, extra jsonl stalls, catch-up below 80 MB/s).

This is still not a 12.7h soak. It is repeated soak-**class** catch-up
(400–900 MB/s) with overflow warns actually enabled.

## Cargo (this revision)

| suite | result |
| --- | --- |
| `grant_plan_is_atomic_against_ingest` | pass |
| `over_window_data_is_ignored_not_queued` | pass |
| `window_grant_*` (3) | pass |
| `g7_*` (2) | pass |
| `test_s3b_lanes` (17) | pass (`q5` inject overflows=1; wire over_window=2, overflows=0) |
| `test_s6a_rekey` (12) | pass |

## Live OpenSSH → `s8_matrix_server`

| case | n | result | notes |
| --- | --- | --- | --- |
| 15s freeze, 3ch (down+up+echo) | 5 | **5/5 pass** | peaks 769–800 MB/s; one SIGSTOP gap; min_live=3; no overflow warn |
| 3×15s freeze, one connection | 1 | **pass** | gaps 15.92/15.95/15.95s; peak 913 MB/s; 43.7 GiB / 100s; min_live=3 |
| 15s freeze, **upload only** | 3 | **3/3 pass** | victim channel of the 12.7h close; peaks 886–967 MB/s; min_live=1 |
| 30s freeze, 3ch (before io-timeout fix) | 1 | fail (harness) | `SOAK_PUMP_ECHO_ERR TimeoutError` — echo `wait_for(30)` on CONT. s8 log empty. Not Overflow. |
| 30s freeze, 3ch (io-timeout=freeze+60) | 2 | **2/2 pass** | peaks 765–778 MB/s; min_live=3 |
| 180s unlimited, no freeze | 1 | **pass** | 156.5 GiB upload; peak 933 MB/s; **zero jsonl gaps**; min_live=3; disconnects=0 |

Judged live passes after discarding the harness false positive: **12/12**.

No run printed `inbound lane overflow` or `exceeds remaining window`.

## What this does and does not show

- `more_lanes` no longer starve-stalls through a 400+ MB/s inbound flood:
  after SIGSTOP the only jsonl gap is the freeze itself; CONT resumes at
  700–900 MB/s without a second stall.
- Torn-grant Overflow did not fire on these catch-ups (warns were on).
- Echo timeout at freeze=30s was the traffic generator, not russh.
- A 12.7h close is still not reproduced here. `rekey_triggers=0` on these
  short runs (I5 volume rekey is not the thing being stressed).

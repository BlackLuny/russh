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
| `window_grant_*` including **`window_grant_torn_reads_is_red`** and **`window_grant_atomic_expand_keeps_invariant`** | pass (6) |
| **`more_lanes_continue_starves_peer_credit_is_red`** / **`more_lanes_does_not_skip_peer_credit`** | pass |
| `g7_*` (2) | pass |
| `test_s3b_lanes` (17) | pass |
| `test_s6a_rekey` (12) | pass |

`window_grant_torn_reads_is_red` drives `maybe_grant_after_delivery` with
`invert_torn_grant_reads` + a hold/mid gate. Reader ingest N=20 between
the two locks; asserts `occ + remaining > target`. Production counterpart
`window_grant_atomic_reads_keep_invariant` is the no-expand half-full
snapshot (Δ=0). `window_grant_atomic_expand_keeps_invariant` fills,
pops occupancy so `remaining < ceiling/2`, expands, then asserts
`occ + rem ≤ target`.

`more_lanes_continue_starves_peer_credit_is_red` pre-fills ≥64 lane
items (`pump_reader_lanes` returns true), posts a peer
`WINDOW_ADJUST` on `PeerCreditBoard`, and restores `continue` via
`invert_more_lanes_continue`. Eight loop turns leave the credit
unapplied. Production `more_lanes_does_not_skip_peer_credit` drains
the board even when `more_lanes` is true. The `for` around
`skip_select_after_more_lanes` is a replica of the after-pump site,
not of `select!`: these tests lock "credit still drains when
`more_lanes=true`". They do not lock the immediately-ready arm's
position or `biased` order. Live 45–180s still does not hit the
quantum∧HWM conjunction; this is the session-level nail.

Judge ready-line: an s8 log without `S8_LISTEN`/`S8_READY` is FAIL (empty
log is no longer a silent pass).

`/stats` now exports `rekey_begins` / `rekey_peer_starts` /
`rekey_completes` in addition to I5 `rekey_triggers` /
`rekey_idle_drops` / `rekey_merges`. `--min-rekey-triggers` only
counts server-initiated I5; `--min-rekey-completes` is the coverage
gate.

Confirmed (25s upload-only, `REKEY_LIMIT=8M`, `--max-bytes=8388608`,
`SSH_VERBOSE=-vv`, `soak-results/judges/rekey8m-verbose/`):

- 14.2 GiB in, peak 585 MB/s, zero gaps, `disconnects=0`
- `rekey_triggers=0` `idle_drops=0` `merges=0`
- `rekey_peer_starts=1749` `rekey_begins=1749` `rekey_completes=1749`
- ssh.stderr: `SSH2_MSG_KEXINIT` 3500 (sent+recv ≈ 2×1749 + initial),
  `ssh_set_newkeys: rekeying in` 1749

So I5/`bytes_this_epoch` is **not** stuck at ~0. OpenSSH wins the 8 MiB
race almost every time; russh completes the peer-driven kex (same
family as a successful `begin_rekey`, not the `exchange.take()` bug).
The 180s 109.6 GiB run (`triggers=1`, `idle_drops=29`) is the same
regime: ~109.6 GiB / ~8.1 MiB ≈ **13500** completed rekeys, not "I5
only fired 30 times". That is stronger than the original soak's 5854
I5 triggers. `triggers=1` on that run is I5 winning once; it is not
the completion count.

The matched 8 MiB race leaves `i5_volume_due` false (`triggers=0`,
`idle_drops=0`): the peer KEXINIT arrives before the epoch counter
crosses 8 MiB. That is the **peer** half. The original 12.7h soak's
5854 triggers were the **server I5** half (`apply_i5_rekey` →
`begin_rekey`, the `exchange.take()` fix).

Confirmed (25s upload-only, `--max-bytes=4MiB`, OpenSSH
`RekeyLimit=32M`, `soak-results/judges/rekey-i5win/`):

- 11.56 GiB in, peak 514 MB/s, zero gaps, `disconnects=0`
- `rekey_triggers=2557` `rekey_begins=2557` `rekey_completes=2557`
- `rekey_peer_starts=0` `merges=0`
- `rekey_idle_drops=101337` (~40 due-while-InKex per trigger; storm
  counted, no stall/close)
- ~4.63 MiB/complete (4 MiB threshold + in-flight during kex)

Both halves of flood × rekey are now live: peer-driven (8M=8M) and
server I5 (4M vs 32M).

## Live OpenSSH → `s8_matrix_server` (fixed binary)

| case | n | result | notes |
| --- | --- | --- | --- |
| 15s freeze, 3ch | 5 | **5/5** | peaks 769–800 MB/s |
| 3×15s freeze, one connection | 1 | **pass** | 3 SIGSTOP gaps; peak 913 MB/s |
| 15s freeze, upload only | 3 | **3/3** | peaks 886–967 MB/s |
| 30s freeze (io-timeout=freeze+60) | 2 | **2/2** | peaks 765–778 MB/s |
| 180s unlimited, no freeze | 1 | **pass** | 156.5 GiB; peak 933 MB/s; zero gaps |
| 180s unlimited, **8 MiB rekey** | 1 | **pass** | 109.6 GiB; peak 662 MB/s; zero gaps; I5 `triggers=1` `idle_drops=29`; peer-driven completes not exported yet |
| 25s upload, **8 MiB rekey** + verbose | 1 | **pass** | 14.2 GiB; peak 585 MB/s; `completes=1749` `peer_starts=1749` `triggers=0` |
| 25s upload, **4 MiB I5 vs OpenSSH 32M** | 1 | **pass** | 11.56 GiB; peak 514 MB/s; `triggers=2557` `completes=2557` `peer_starts=0` `idle_drops=101337` |

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
`continue`. Session-level invert (`more_lanes_continue_starves_peer_credit_is_red`)
is.

## What is nailed vs what is not

- **Torn grant:** Session-level must-red on the invariant, plus a Δ>0
  atomic expand green. Nailed.
- **Judge silent-log hole:** missing `S8_READY` fails. Nailed.
- **`more_lanes` skip-select:** session must-red (peer ADJUST starved).
  Locks the after-pump `continue` invariant, not the `select!`
  ready-arm / `biased` order. Live 12/12 remains "healthy after fix",
  not causality. Nailed in unit, not by this harness's negative control.
- **Flood × volume rekey, peer half:** 25s verbose, matched 8 MiB:
  **1749** peer-driven completes, `triggers=0`. The 180s 109.6 GiB run
  is the same race (~13500 completes). Nailed as "peer-driven volume
  rekey under flood does not stall/close".
- **Flood × volume rekey, server I5 half:** 25s, `--max-bytes=4MiB`
  vs OpenSSH `RekeyLimit=32M`: **2557** I5 `begin_rekey` + completes,
  `peer_starts=0`, `idle_drops=101337`, zero gaps. This is the
  `exchange.take()` fix path the 12.7h soak actually ran (5854
  triggers). Nailed as "server I5 volume rekey under flood does not
  stall/close"; not a 10h soak.

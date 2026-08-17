# OpenSSH→russh upload channel close (12h soak)

Measured on the 12.7h localhost soak (not inferred).

## What happened

- Stack: OpenSSH 9.6 `-L` → russh `s8_matrix_server` (3 channels: down/up/echo).
- At `t=37066.6s` (~10.3h) the **upload** channel died (`channels_live` 3→2, `io_errors=1`).
- Session stayed up (`disconnects=0`). Download kept running.
- Last 10s before close: `bytes_out` jumped ~400 MB/s (rate-limiter catch-up), then dropped to ~0.

## Stats gap immediately before the burst

`traffic_openssh_to_russh.jsonl` jumps from `t=34296.9` to `t=37056.6` (~46 min) with almost no byte progress (~60 MiB). Then a 10s catch-up flood, then the upload channel close.

That pattern matches Session skipping `select!` while inbound lanes still had work (`more_lanes` `continue`): KEXINIT / Writer acks / window credit / watchdogs starve, traffic crawls, then a burst when the loop runs again. Occupancy then Overflow-closes only the upload channel.

## Root cause (code + unit test)

`Reader` consumed the inbound window but still **queued** DATA that exceeded `window_remaining`. RFC 4254 §5.2 says extra data SHOULD be ignored. Queuing it let lane occupancy grow past `window + maxpkt`, which is `CtrlMsg::Overflow` → StopDiscard **that channel only**.

Confirmed by `over_window_data_is_ignored_not_queued` (was: extra packet queued; occupancy could Overflow).

## Fix

1. `LaneTable::ingest`: over-window DATA/EXT is `DroppedOverWindow`, not queued.
2. Session no longer `continue`s past `select!` when `more_lanes`; an immediately-ready select arm keeps pumping without starving ctrl.
3. `CtrlMsg::Overflow` now `release_channel_global` (GlobalBudget leak).
4. I5 rekey no longer `enc.exchange.take()` before `begin_rekey`.

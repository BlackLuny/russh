# OpenSSH inbound-proxy loopback soak results (main)

**Verdict: no deadlock, no stall, no freeze, no drop, no echo corruption** over 2 hours
on both 1-stream and 8-stream OpenSSH multiplexed `direct-tcpip` paths.

## Setup

| Item | Value |
| --- | --- |
| russh library | `1c013cd` (main); harness commit `2a29cc4` |
| Client | OpenSSH_9.6p1 Ubuntu-3ubuntu13.16 |
| Topology | traffic → `ssh -N -L` (one SSH connection) → russh `inbound_tcp_proxy` → TCP echo → reverse path |
| Host | loopback `127.0.0.1` |
| Duration | 7200 s, sample every 300 s, stall threshold 30 s |
| Window | library defaults (`window_size` 2 MiB, `event_buffer_size` 10, `channel_buffer_size` 100) |
| Timeouts | `inactivity_timeout=None` (so `-N` is not killed at 10 min); keepalive 60 s; OpenSSH `ServerAliveInterval=30` |

Scenarios ran **in parallel** (two russh servers, two OpenSSH clients).

## Results

| Scenario | Streams | Samples | Anomalies | TX | RX | Avg rate | Rekeys (client-initiated) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1-stream | 1 | 24/24 `ok` | 0 | 11.19 GiB | 11.19 GiB | 13.35 Mbit/s | 11 (~every 10.7 min) |
| 8-stream | 8 (one SSH conn) | 24/24 `ok` | 0 | 89.51 GiB | 89.50 GiB | 106.80 Mbit/s | 89 (~every 80 s) |

Per-5-minute rates stayed in a tight band (1-stream 13.04–13.56 Mbit/s; 8-stream 104.26–108.47 Mbit/s). No 5-minute window had zero throughput. Echo payloads matched; idle at teardown was ~20 ms.

OpenSSH volume rekey (`RekeyLimit` ~1 GiB) ran throughout. Throughput did not dip to zero across those rekeys.

## Non-issues observed

- One `ssh session error: Disconnected` at startup on each proxy: the soak script’s TCP port-probe (`wait_tcp` to the SSH port) is not an SSH handshake. The real OpenSSH session then connected and stayed up for 2 h.
- OpenSSH briefly opened an extra `direct-tcpip` that closed with 0 bytes (forward-liveness check). Traffic used the live channel(s).
- `proxy_exit: -15` is SIGTERM from harness teardown.

## What this does *not* cover

Loopback has almost no socket backpressure. This run answers “does a healthy OpenSSH client + russh inbound proxy deadlock or freeze under continuous bidirectional echo for 2 h, including rekey.” It does **not** reproduce a slow/stalled upstream HoL (see `test_inbound_window_stall.rs`).

## Artifacts

- `soak.stdout` — 5-minute monitor lines
- `*-samples.jsonl` — per-sample counters and flags
- `*-summary.json`, `REPORT.json`
- `*-proxy.log`, `*-ssh.log`

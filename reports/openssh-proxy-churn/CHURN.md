# OpenSSH inbound-proxy short-connection churn (main)

**Verdict: no deadlock, stall, channel leak, echo mismatch, port exhaustion,
or FIN_WAIT pileup** over 2 hours at ~100 in-flight short `direct-tcpip`
channels.

## Setup

| Item | Value |
| --- | --- |
| russh library | `1c013cd` (main); harness `b2f4675` |
| Client | OpenSSH_9.6p1, one `ssh -N -L` (multiplexed channels) |
| Target in-flight | ~100 established connections |
| Workers | 143 (duty cycle ≈ 17.5s / 25s ≈ 0.7) |
| Lifetime | uniform 5–30 s |
| Cooldown | uniform 5–10 s after orderly close |
| Payload | 1 KiB echo chunks |
| Duration | 7200 s, sample every 300 s |
| Close | client `shutdown(WR)` + drain peer FIN (no `SO_LINGER`/RST) |
| Connect | ≤15 concurrent SYNs; bind `127.0.0.1:0` only |

TIME_WAIT is expected (~conn_rate × 60s). FIN_WAIT growth or `EADDRNOTAVAIL` is not.

## Results

| Metric | Value |
| --- | --- |
| 5-min samples | 24/24 `ok`, 0 anomalies |
| Connections opened/closed | 41248 / 41248 (no leak) |
| In-flight at samples | min 93, avg 100.1, max 112 (peak 131 at ramp) |
| TIME-WAIT (our ports) | 670–710, **plateaued** (not growing) |
| FIN-WAIT-1/2 | **0** every sample |
| CLOSE-WAIT | **0** |
| `EADDRNOTAVAIL` / connect fail / timeout | 0 |
| Echo bytes TX=RX | 87.12 GiB each, 0 mismatches |
| Rate | ~104 Mbit/s sustained |
| OpenSSH client rekeys | 88, no throughput collapse |
| copy errors on proxy | 0 |

Connection rate ≈ 5.7/s. TIME_WAIT ≈ 5.7 × 60 × ~2 hops ≈ 700, matching the plateau.

## Mitigations that were used (not production russh changes)

- Stagger worker start so cooldowns do not align.
- Cap concurrent `connect()`.
- Orderly FIN instead of abort/`SO_LINGER 0`.
- Listen-wait via `/proc/net/tcp` (no extra SSH handshake probes).
- Bind clients to `127.0.0.1` ephemeral ports only.

## Artifacts

`soak.stdout`, `churn-samples.jsonl`, `churn-summary.json`, `REPORT.json`, `churn-proxy.log`.

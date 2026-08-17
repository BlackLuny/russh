# 90-second smoke (harness verification)

Real localhost run before the 24h soak. Same topology, 4 MiB/s per stream,
64 MiB rekey. **Not a leak verdict** (window too short for RSS slope).

| stack | seconds | bytes_in | bytes_out | MiB/s | stall | verify | io |
|---|---:|---:|---:|---:|---|---:|---:|
| OpenSSH 9.6 client → russh s8 server | 90 | 755,293,024 | 755,294,056 | 8.000 | no | 0 | 0 |
| OpenSSH 9.6 client → OpenSSH 9.6 sshd | 90 | 755,267,224 | 755,268,256 | 8.000 | no | 0 | 0 |
| russh soak_client → russh s8 server | 90 | 755,687,648 | 755,671,264 | 8.000 | no | 0 | 0 |

- russh `rekey_triggers`: **6** in 90s (volume rekey actually firing)
- russh `disconnects`: **0**, live sessions **2**
- russh_server CPU avg **44.6%** / p95 **53.1%** (2 sessions × 3 streams)
- OpenSSH client CPU ~**15%** per client process
- fd/thread: stable (russh_server 15 fds, 5 threads)

24h numbers: `SOAK_REPORT.md` (written when `scripts/soak/run_24h.sh` finishes).

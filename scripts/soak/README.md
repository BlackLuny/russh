# 24h SSH soak harness

Localhost comparison of russh PR #3 (`s8_matrix_server` + `soak_client`) against
OpenSSH 9.6. Real traffic, not unit-test inference.

```bash
# full 24h
./scripts/soak/run_24h.sh

# shorter
SOAK_SECONDS=120 ./scripts/soak/run_24h.sh
```

Stacks:

1. OpenSSH client `direct-tcpip` / `-L` → russh `s8_matrix_server` (64 MiB rekey)
2. russh `soak_client` → russh server (same, plus 30s channel churn)
3. OpenSSH client → OpenSSH `sshd` (baseline, `RekeyLimit 64M`)

Each stack runs 1 download + 1 upload + 1 echo at 8 MiB/s (override `RATE_BPS`).
`monitor.py` samples RSS / CPU / fds / threads every 10s. Judge writes
`soak-results/SOAK_REPORT.md`.

`run_24h.sh` sets `RUST_LOG=russh=warn` for `s8_matrix_server` (override
the env var to change it). Without that, overflow / over-window warns
are silent and a stall cannot be classified. See
`soak-results/CHANNEL_CLOSE.md`.

Short freeze-catchup against a russh server only:

```bash
# unlimited catch-up (soak-class burst), 15s SIGSTOP, 3 channels
DOWN=1 UP=1 ECHO=1 RATE_BPS=0 FREEZE_SECS=15 SECONDS_RUN=45 \
  ./scripts/soak/repro_upload_close.sh
```

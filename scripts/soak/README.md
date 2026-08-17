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

# OpenSSH loopback soak — russh inbound proxy (main)

Measurement of **main** (`1c013cd`) in a pure SSH-proxy topology using the
OpenSSH 9.6 client:

```
traffic --TCP--> ssh -N -L  (1 or 8 forwards, one SSH connection)
             --direct-tcpip multiplex--> russh inbound_tcp_proxy
             --TCP--> loopback echo --round-trip--> same path
```

## How to run

```bash
cargo build -p russh --example inbound_tcp_proxy --release
python3 scripts/openssh_loopback_soak.py \
  --duration-secs 7200 --sample-secs 300 --stall-secs 30 \
  --out reports/openssh-proxy-soak --scenarios 1,8
```

- Samples every 5 minutes.
- Flags: `proxy_dead`, `ssh_dead`, `stream_stall` (no echo progress ≥ 30s),
  `stream_dead`, `mismatch`, `zero_window_throughput`.
- Server `inactivity_timeout` is disabled so `-N` is not killed at 10 minutes;
  rekey stays at library defaults (1 GiB / 1 h).

Results of the 2-hour long-lived stream run: [RESULTS.md](RESULTS.md).
Short-connection churn (2h, ~100 in-flight): [../openssh-proxy-churn/CHURN.md](../openssh-proxy-churn/CHURN.md).

```bash
python3 scripts/openssh_loopback_soak.py \
  --scenarios churn --inflight 100 \
  --duration-secs 7200 --sample-secs 300 \
  --out reports/openssh-proxy-soak
```

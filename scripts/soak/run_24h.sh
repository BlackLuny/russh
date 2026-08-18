#!/usr/bin/env bash
# 24h localhost SSH soak: russh server vs OpenSSH sshd, real OpenSSH + russh clients.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOAK_HOURS="${SOAK_HOURS:-24}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
STALL_SECS="${STALL_SECS:-60}"
REKEY_BYTES="${REKEY_BYTES:-67108864}"   # 64 MiB — force frequent rekey
RATE_BPS="${RATE_BPS:-8388608}"          # 8 MiB/s per stream, leave CPU headroom
WORKDIR="${WORKDIR:-/tmp/ssh-soak}"
RESULT_DIR="${RESULT_DIR:-$ROOT/soak-results}"
export PATH="/usr/sbin:/usr/bin:/usr/local/cargo/bin:$PATH"

mkdir -p "$WORKDIR" "$RESULT_DIR"
exec > >(stdbuf -oL tee -a "$WORKDIR/orchestrator.log") 2>&1

echo "SOAK_START $(date -u +%Y-%m-%dT%H:%M:%SZ) seconds=$SOAK_SECONDS rekey_bytes=$REKEY_BYTES rate_bps=$RATE_BPS"

if [[ ! -x "$ROOT/target/release/examples/s8_matrix_server" ]]; then
  echo "building s8_matrix_server + soak_client (release)"
  (cd "$ROOT" && cargo build -p russh --release --example s8_matrix_server --features s8_fixture)
  (cd "$ROOT" && cargo build -p russh --release --example soak_client)
fi

if [[ ! -f "$WORKDIR/id_ed25519" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$WORKDIR/id_ed25519" -C soak >/dev/null
fi
cp "$WORKDIR/id_ed25519.pub" "$WORKDIR/authorized_keys"
chmod 600 "$WORKDIR/authorized_keys" "$WORKDIR/id_ed25519"

if [[ ! -f "$WORKDIR/ssh_host_ed25519_key" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$WORKDIR/ssh_host_ed25519_key" -C soak-host >/dev/null
fi

sudo mkdir -p /run/sshd
sudo chmod 0755 /run/sshd

sed -e "s|__HOSTKEY__|$WORKDIR/ssh_host_ed25519_key|" \
    -e "s|__PIDFILE__|$WORKDIR/sshd.pid|" \
    -e "s|__AUTHKEYS__|$WORKDIR/authorized_keys|" \
    -e "s|__REKEY__|64M 1h|g" \
    "$ROOT/scripts/soak/sshd_config.in" > "$WORKDIR/sshd_config"

python3 "$ROOT/scripts/soak/traffic.py" backend \
  --echo-port 19000 --sink-port 19001 --source-port 19002 \
  --ready-file "$WORKDIR/backend.ready" \
  >"$WORKDIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$WORKDIR/backend.pid"
for _ in $(seq 1 50); do
  [[ -f "$WORKDIR/backend.ready" ]] && break
  sleep 0.1
done

# env_logger is silent unless RUST_LOG is set. Overflow / over-window
# warns must be on or a 46-minute stall cannot be classified.
RUST_LOG="${RUST_LOG:-russh=warn}" "$ROOT/target/release/examples/s8_matrix_server" \
  --listen 127.0.0.1:2222 \
  --control 127.0.0.1:18080 \
  --user s8 --password s8pass \
  --authorized-key "$WORKDIR/id_ed25519.pub" \
  --max-bytes "$REKEY_BYTES" \
  --nodelay \
  --ready-file "$WORKDIR/s8.ready" \
  >"$WORKDIR/s8_server.log" 2>&1 &
S8_PID=$!
echo "$S8_PID" > "$WORKDIR/s8.pid"
for _ in $(seq 1 100); do
  [[ -f "$WORKDIR/s8.ready" ]] && break
  sleep 0.1
done
if [[ ! -f "$WORKDIR/s8.ready" ]]; then
  echo "s8_matrix_server failed to become ready"
  tail -50 "$WORKDIR/s8_server.log" || true
  exit 1
fi

/usr/sbin/sshd -f "$WORKDIR/sshd_config" -E "$WORKDIR/sshd.log" -D &
SSHD_PID=$!
echo "$SSHD_PID" > "$WORKDIR/sshd.pid"
for _ in $(seq 1 50); do
  if python3 - <<'PY'
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", 2223)); sys.exit(0)
except Exception:
    sys.exit(1)
PY
  then
    break
  fi
  sleep 0.1
done

SSH_COMMON=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o IdentityFile="$WORKDIR/id_ed25519"
  -o PreferredAuthentications=publickey
  -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=6
  -o RekeyLimit=64M
  -o IPQoS=throughput
  -N
)

# Stack 1: OpenSSH client → russh server (s8 in-process echo/sink/source)
ssh "${SSH_COMMON[@]}" \
  -p 2222 -l s8 \
  -L 127.0.0.1:10001:source:1 \
  -L 127.0.0.1:10009:sink:9 \
  -L 127.0.0.1:10007:echo:7 \
  127.0.0.1 \
  >"$WORKDIR/ssh_to_russh.log" 2>&1 &
SSH_R_PID=$!
echo "$SSH_R_PID" > "$WORKDIR/ssh_to_russh.pid"

# Stack 3: OpenSSH client → OpenSSH sshd (real TCP backends)
ssh "${SSH_COMMON[@]}" \
  -p 2223 -l ubuntu \
  -L 127.0.0.1:11001:127.0.0.1:19002 \
  -L 127.0.0.1:11009:127.0.0.1:19001 \
  -L 127.0.0.1:11007:127.0.0.1:19000 \
  127.0.0.1 \
  >"$WORKDIR/ssh_to_sshd.log" 2>&1 &
SSH_O_PID=$!
echo "$SSH_O_PID" > "$WORKDIR/ssh_to_sshd.pid"

wait_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    if python3 - <<PY
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", int("$port"))); sys.exit(0)
except Exception:
    sys.exit(1)
PY
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_port 10001
wait_port 10009
wait_port 10007
wait_port 11001
wait_port 11009
wait_port 11007

python3 "$ROOT/scripts/soak/traffic.py" client \
  --host 127.0.0.1 \
  --down-port 10001 --up-port 10009 --echo-port 10007 \
  --down 1 --up 1 --echo 1 \
  --seconds "$SOAK_SECONDS" --stall-secs "$STALL_SECS" --rate-bps "$RATE_BPS" \
  --stats "$WORKDIR/traffic_openssh_to_russh.jsonl" \
  >"$WORKDIR/traffic_openssh_to_russh.log" 2>&1 &
TR_R_PID=$!
echo "$TR_R_PID" > "$WORKDIR/traffic_openssh_to_russh.pid"

python3 "$ROOT/scripts/soak/traffic.py" client \
  --host 127.0.0.1 \
  --down-port 11001 --up-port 11009 --echo-port 11007 \
  --down 1 --up 1 --echo 1 \
  --seconds "$SOAK_SECONDS" --stall-secs "$STALL_SECS" --rate-bps "$RATE_BPS" \
  --stats "$WORKDIR/traffic_openssh_to_sshd.jsonl" \
  >"$WORKDIR/traffic_openssh_to_sshd.log" 2>&1 &
TR_O_PID=$!
echo "$TR_O_PID" > "$WORKDIR/traffic_openssh_to_sshd.pid"

# Stack 2: russh client → russh server (library pair, same rekey)
"$ROOT/target/release/examples/soak_client" \
  --host 127.0.0.1 --port 2222 --user s8 --password s8pass \
  --down 1 --up 1 --echo 1 \
  --seconds "$SOAK_SECONDS" --stall-secs "$STALL_SECS" \
  --rekey-bytes "$REKEY_BYTES" --rate-bps "$RATE_BPS" --churn-secs 30 \
  --stats "$WORKDIR/traffic_russh_to_russh.jsonl" \
  >"$WORKDIR/traffic_russh_to_russh.log" 2>&1 &
RC_PID=$!
echo "$RC_PID" > "$WORKDIR/russh_client.pid"

TARGETS_JSON=$(python3 - <<PY
import json
print(json.dumps([
  {"name":"russh_server","pid": $S8_PID},
  {"name":"openssh_sshd","pid": $SSHD_PID},
  {"name":"openssh_client_to_russh","pid": $SSH_R_PID},
  {"name":"openssh_client_to_sshd","pid": $SSH_O_PID},
  {"name":"russh_client","pid": $RC_PID},
  {"name":"traffic_openssh_to_russh","pid": $TR_R_PID},
  {"name":"traffic_openssh_to_sshd","pid": $TR_O_PID},
]))
PY
)
CONTROLS_JSON='[{"name":"russh_server","url":"http://127.0.0.1:18080/stats"}]'
TRAFFIC_JSON=$(python3 - <<PY
import json
print(json.dumps([
  {"name":"openssh_client_to_russh","path":"$WORKDIR/traffic_openssh_to_russh.jsonl"},
  {"name":"openssh_client_to_sshd","path":"$WORKDIR/traffic_openssh_to_sshd.jsonl"},
  {"name":"russh_client","path":"$WORKDIR/traffic_russh_to_russh.jsonl"},
]))
PY
)

python3 "$ROOT/scripts/soak/monitor.py" \
  --targets "$TARGETS_JSON" \
  --controls "$CONTROLS_JSON" \
  --traffic "$TRAFFIC_JSON" \
  --out "$WORKDIR/monitor.csv" \
  --interval 10 \
  --seconds "$SOAK_SECONDS" \
  >"$WORKDIR/monitor.log" 2>&1 &
MON_PID=$!
echo "$MON_PID" > "$WORKDIR/monitor.pid"

echo "SOAK_PIDS s8=$S8_PID sshd=$SSHD_PID ssh_r=$SSH_R_PID ssh_o=$SSH_O_PID russh_c=$RC_PID tr_r=$TR_R_PID tr_o=$TR_O_PID mon=$MON_PID backend=$BACKEND_PID"

cleanup() {
  echo "SOAK_CLEANUP $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for pidfile in "$WORKDIR"/*.pid; do
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pidfile in "$WORKDIR"/*.pid; do
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  curl -sS "http://127.0.0.1:18080/shutdown" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait for the longest-lived workload (monitor lasts SOAK_SECONDS).
wait "$MON_PID" || true
wait "$TR_R_PID" || true
wait "$TR_O_PID" || true
wait "$RC_PID" || true

python3 "$ROOT/scripts/soak/summarize.py" \
  --workdir "$WORKDIR" \
  --result "$RESULT_DIR/SOAK_REPORT.md" \
  --seconds "$SOAK_SECONDS" \
  || true

echo "SOAK_END $(date -u +%Y-%m-%dT%H:%M:%SZ)"
cp -a "$WORKDIR/monitor.csv" "$RESULT_DIR/" 2>/dev/null || true
cp -a "$WORKDIR/orchestrator.log" "$RESULT_DIR/" 2>/dev/null || true

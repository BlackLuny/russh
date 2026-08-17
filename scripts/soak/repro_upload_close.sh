#!/usr/bin/env bash
# Reproduce the OpenSSH→russh upload-channel close with russh warn logs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WD="${WORKDIR:-/tmp/repro-upload-close}"
SECONDS_RUN="${SECONDS_RUN:-90}"
REKEY_BYTES="${REKEY_BYTES:-67108864}"
RATE_BPS="${RATE_BPS:-0}"   # 0 = unlimited (soak catch-up burst)
DOWN="${DOWN:-0}"
UP="${UP:-1}"
ECHO="${ECHO:-0}"
FREEZE_SECS="${FREEZE_SECS:-0}"
DOWN_PORT="${DOWN_PORT:-10001}"
UP_PORT="${UP_PORT:-10009}"
ECHO_PORT="${ECHO_PORT:-10000}"
export PATH="/usr/sbin:/usr/bin:/usr/local/cargo/bin:$PATH"
mkdir -p "$WD"
rm -f "$WD"/*.log "$WD"/*.jsonl "$WD"/s8.ready "$WD"/ssh.pid

if [[ ! -x "$ROOT/target/release/examples/s8_matrix_server" ]]; then
  (cd "$ROOT" && cargo build -p russh --release --example s8_matrix_server --features s8_fixture)
fi

if [[ ! -f "$WD/id_ed25519" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$WD/id_ed25519" -C repro >/dev/null
fi

RUST_LOG=russh=warn "$ROOT/target/release/examples/s8_matrix_server" \
  --listen 127.0.0.1:2222 \
  --control 127.0.0.1:18080 \
  --user s8 --password s8pass \
  --authorized-key "$WD/id_ed25519.pub" \
  --max-bytes "$REKEY_BYTES" \
  --nodelay \
  --ready-file "$WD/s8.ready" \
  >"$WD/s8_server.log" 2>&1 &
echo $! > "$WD/s8.pid"
for _ in $(seq 1 100); do
  [[ -f "$WD/s8.ready" ]] && break
  sleep 0.05
done

ssh -vv \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes \
  -o IdentityFile="$WD/id_ed25519" \
  -o PreferredAuthentications=publickey \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o RekeyLimit=64M \
  -o IPQoS=throughput \
  -N -p 2222 -l s8 \
  -L 127.0.0.1:${DOWN_PORT}:source:1 \
  -L 127.0.0.1:${UP_PORT}:sink:9 \
  -L 127.0.0.1:${ECHO_PORT}:echo:7 \
  127.0.0.1 \
  >"$WD/ssh.stderr" 2>&1 &
echo $! > "$WD/ssh.pid"

for _ in $(seq 1 100); do
  python3 - <<PY && break
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", ${UP_PORT})); sys.exit(0)
except Exception:
    sys.exit(1)
PY
  sleep 0.05
done

python3 "$ROOT/scripts/soak/traffic.py" client \
  --host 127.0.0.1 \
  --down-port "$DOWN_PORT" --up-port "$UP_PORT" --echo-port "$ECHO_PORT" \
  --down "$DOWN" --up "$UP" --echo "$ECHO" \
  --seconds "$SECONDS_RUN" --stall-secs 30 --rate-bps "$RATE_BPS" \
  --stats "$WD/traffic.jsonl" \
  >"$WD/traffic.log" 2>&1 &
TPID=$!
echo $TPID > "$WD/traffic.pid"
if [[ "$FREEZE_SECS" -gt 0 ]]; then
  sleep 5
  kill -STOP "$TPID" 2>/dev/null || true
  sleep "$FREEZE_SECS"
  kill -CONT "$TPID" 2>/dev/null || true
fi
wait "$TPID" || true

echo '===== s8 warn/error ====='
grep -E 'overflow|StopDiscard|CHANNEL_CLOSE|SESSION_ERROR|exceeds remaining|pending cap' "$WD/s8_server.log" | tail -50 || true
echo '===== ssh channel close ====='
grep -E -i 'channel|close|reset|window|overflow' "$WD/ssh.stderr" | tail -40 || true
echo '===== traffic ====='
grep -E 'SOAK_|io_errors' "$WD/traffic.log" | tail -20 || true
tail -3 "$WD/traffic.jsonl" 2>/dev/null || true
echo '===== control ====='
curl -sS http://127.0.0.1:18080/stats || true
echo

kill "$(cat "$WD/ssh.pid")" 2>/dev/null || true
curl -sS http://127.0.0.1:18080/shutdown >/dev/null 2>&1 || true
kill "$(cat "$WD/s8.pid")" 2>/dev/null || true
sleep 0.5
kill -9 "$(cat "$WD/ssh.pid")" 2>/dev/null || true
kill -9 "$(cat "$WD/s8.pid")" 2>/dev/null || true
echo REPRO_DONE

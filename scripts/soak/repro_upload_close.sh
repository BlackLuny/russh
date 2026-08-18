#!/usr/bin/env bash
# Reproduce the OpenSSH→russh upload-channel close with russh warn logs.
# Exit 0 only if judge_repro.py passes (no overflow warn, no mid-run close,
# freeze gaps match SIGSTOP, catch-up is soak-class).
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
FREEZE_CYCLES="${FREEZE_CYCLES:-1}"
FREEZE_GAP="${FREEZE_GAP:-8}"
DOWN_PORT="${DOWN_PORT:-10001}"
UP_PORT="${UP_PORT:-10009}"
ECHO_PORT="${ECHO_PORT:-10000}"
LISTEN="${LISTEN:-127.0.0.1:2222}"
CONTROL="${CONTROL:-127.0.0.1:18080}"
SSH_VERBOSE="${SSH_VERBOSE:-0}"
export PATH="/usr/sbin:/usr/bin:/usr/local/cargo/bin:$PATH"

EXPECTED_LIVE=$((DOWN + UP + ECHO))
if [[ "$EXPECTED_LIVE" -le 0 ]]; then
  echo "DOWN+UP+ECHO must be > 0" >&2
  exit 2
fi
STALL_SECS="${STALL_SECS:-30}"
if [[ "$FREEZE_SECS" -gt 0 ]]; then
  need=$((FREEZE_SECS + 15))
  if [[ "$STALL_SECS" -lt "$need" ]]; then
    STALL_SECS="$need"
  fi
fi
if [[ -z "${MIN_PEAK_OUT_BPS+x}" ]]; then
  if [[ "$RATE_BPS" -gt 0 ]]; then
    MIN_PEAK_OUT_BPS=0
  else
    MIN_PEAK_OUT_BPS=80000000
  fi
fi

mkdir -p "$WD"
cleanup() {
  local p
  for p in "$WD/traffic.pid" "$WD/ssh.pid" "$WD/s8.pid"; do
    [[ -f "$p" ]] || continue
    kill "$(cat "$p")" 2>/dev/null || true
  done
  curl -sS "http://${CONTROL}/shutdown" >/dev/null 2>&1 || true
  sleep 0.2
  for p in "$WD/traffic.pid" "$WD/ssh.pid" "$WD/s8.pid"; do
    [[ -f "$p" ]] || continue
    kill -9 "$(cat "$p")" 2>/dev/null || true
  done
}
trap cleanup EXIT
cleanup || true
sleep 0.2
rm -f "$WD"/*.log "$WD"/*.jsonl "$WD"/s8.ready "$WD"/judge.json "$WD"/control.json

if [[ ! -x "$ROOT/target/release/examples/s8_matrix_server" ]]; then
  (cd "$ROOT" && cargo build -p russh --release --example s8_matrix_server --features s8_fixture)
fi

if [[ ! -f "$WD/id_ed25519" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$WD/id_ed25519" -C repro >/dev/null
fi

RUST_LOG="${RUST_LOG:-russh=warn}" "$ROOT/target/release/examples/s8_matrix_server" \
  --listen "$LISTEN" \
  --control "$CONTROL" \
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
if [[ ! -f "$WD/s8.ready" ]]; then
  echo "s8_matrix_server failed to become ready" >&2
  tail -50 "$WD/s8_server.log" >&2 || true
  exit 1
fi

SSH_V=()
if [[ "$SSH_VERBOSE" -gt 0 ]]; then
  SSH_V=(-vv)
fi
ssh "${SSH_V[@]}" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes \
  -o IdentityFile="$WD/id_ed25519" \
  -o PreferredAuthentications=publickey \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o RekeyLimit=64M \
  -o IPQoS=throughput \
  -N -p "${LISTEN##*:}" -l s8 \
  -L 127.0.0.1:${DOWN_PORT}:source:1 \
  -L 127.0.0.1:${UP_PORT}:sink:9 \
  -L 127.0.0.1:${ECHO_PORT}:echo:7 \
  "${LISTEN%:*}" \
  >"$WD/ssh.stderr" 2>&1 &
echo $! > "$WD/ssh.pid"

wait_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    python3 - <<PY && return 0
import socket,sys
s=socket.socket(); s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", int("$port"))); sys.exit(0)
except Exception:
    sys.exit(1)
PY
    sleep 0.05
  done
  return 1
}
CONNECT_PORT="$UP_PORT"
[[ "$UP" -gt 0 ]] || CONNECT_PORT="$DOWN_PORT"
[[ "$UP" -gt 0 || "$DOWN" -gt 0 ]] || CONNECT_PORT="$ECHO_PORT"
if ! wait_port "$CONNECT_PORT"; then
  echo "ssh forward $CONNECT_PORT never became ready" >&2
  tail -30 "$WD/ssh.stderr" >&2 || true
  exit 1
fi

python3 "$ROOT/scripts/soak/traffic.py" client \
  --host 127.0.0.1 \
  --down-port "$DOWN_PORT" --up-port "$UP_PORT" --echo-port "$ECHO_PORT" \
  --down "$DOWN" --up "$UP" --echo "$ECHO" \
  --seconds "$SECONDS_RUN" --stall-secs "$STALL_SECS" --rate-bps "$RATE_BPS" \
  --stats "$WD/traffic.jsonl" \
  >"$WD/traffic.log" 2>&1 &
TPID=$!
echo $TPID > "$WD/traffic.pid"
if [[ "$FREEZE_SECS" -gt 0 && "$FREEZE_CYCLES" -gt 0 ]]; then
  sleep "$FREEZE_GAP"
  for _ in $(seq 1 "$FREEZE_CYCLES"); do
    kill -STOP "$TPID" 2>/dev/null || true
    sleep "$FREEZE_SECS"
    kill -CONT "$TPID" 2>/dev/null || true
    if [[ "$FREEZE_CYCLES" -gt 1 ]]; then
      sleep "$FREEZE_GAP"
    fi
  done
fi
wait "$TPID" || true

STATS="$(curl -sS "http://${CONTROL}/stats" || true)"
echo "$STATS" > "$WD/control.json"
echo '===== s8 warn/error ====='
grep -E 'overflow|StopDiscard|CHANNEL_CLOSE|SESSION_ERROR|exceeds remaining|pending cap' "$WD/s8_server.log" | tail -50 || true
echo '===== traffic ====='
grep -E 'SOAK_|io_errors' "$WD/traffic.log" | tail -20 || true
tail -3 "$WD/traffic.jsonl" 2>/dev/null || true
echo '===== control ====='
echo "$STATS"
echo

JUDGE_ARGS=(
  python3 "$ROOT/scripts/soak/judge_repro.py"
  --jsonl "$WD/traffic.jsonl"
  --s8-log "$WD/s8_server.log"
  --expect-live "$EXPECTED_LIVE"
  --freeze-secs "$FREEZE_SECS"
  --freeze-cycles "$FREEZE_CYCLES"
  --min-peak-out-bps "$MIN_PEAK_OUT_BPS"
  --out "$WD/judge.json"
)
if [[ "${JUDGE:-1}" != "0" ]]; then
  echo '===== judge ====='
  if ! "${JUDGE_ARGS[@]}"; then
    echo REPRO_FAIL
    exit 1
  fi
fi
echo REPRO_DONE

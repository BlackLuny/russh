#!/usr/bin/env bash
# Run repro_upload_close.sh N times (fresh ssh+s8 each time) and require all to pass.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
N="${N:-5}"
LABEL="${LABEL:-repeat}"
OUT="${RESULT_DIR:-$ROOT/soak-results/repeat-verify/${LABEL}}"
mkdir -p "$OUT"
pass=0
fail=0
echo "REPEAT_START n=$N label=$LABEL $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/summary.txt"
for i in $(seq 1 "$N"); do
  wd="$OUT/run-$i"
  rm -rf "$wd"
  mkdir -p "$wd"
  echo "===== run $i/$N =====" | tee -a "$OUT/summary.txt"
  set +e
  WORKDIR="$wd" \
    DOWN="${DOWN:-1}" UP="${UP:-1}" ECHO="${ECHO:-1}" \
    RATE_BPS="${RATE_BPS:-0}" \
    FREEZE_SECS="${FREEZE_SECS:-15}" \
    FREEZE_CYCLES="${FREEZE_CYCLES:-1}" \
    FREEZE_GAP="${FREEZE_GAP:-8}" \
    SECONDS_RUN="${SECONDS_RUN:-45}" \
    LISTEN="${LISTEN:-127.0.0.1:2222}" \
    CONTROL="${CONTROL:-127.0.0.1:18080}" \
    "$ROOT/scripts/soak/repro_upload_close.sh" \
    >"$wd/orchestrator.log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "run $i PASS" | tee -a "$OUT/summary.txt"
    pass=$((pass + 1))
  else
    echo "run $i FAIL rc=$rc" | tee -a "$OUT/summary.txt"
    fail=$((fail + 1))
    tail -40 "$wd/orchestrator.log" | tee -a "$OUT/summary.txt" || true
  fi
  if [[ -f "$wd/judge.json" ]]; then
    python3 - <<PY | tee -a "$OUT/summary.txt"
import json
r=json.load(open("$wd/judge.json"))
print("  min_live={min_live} peak_out={p:.1f}MB/s bytes_out={bytes_out} gaps={n} ok={ok}".format(
    min_live=r.get("min_live"), p=(r.get("peak_out_bps") or 0)/1e6,
    bytes_out=r.get("bytes_out"), n=len(r.get("gaps") or []), ok=r.get("ok")))
if r.get("fails"):
    print("  fails:", r["fails"])
PY
  fi
done
echo "REPEAT_DONE pass=$pass fail=$fail" | tee -a "$OUT/summary.txt"
[[ "$fail" -eq 0 ]]

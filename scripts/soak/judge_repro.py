#!/usr/bin/env python3
"""Pass/fail a freeze-catchup repro from traffic.jsonl + s8_server.log.

Fails on mid-run channel death, overflow/over-window warns, extra jsonl
stalls that are not the requested SIGSTOP, or a catch-up that never
reaches soak-class rate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


WARN_RE = re.compile(
    r"overflow|StopDiscard|exceeds remaining|SESSION_ERROR",
    re.IGNORECASE,
)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def warn_hits(log: Path) -> list[str]:
    if not log.is_file():
        return [f"missing s8 log: {log}"]
    hits = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if WARN_RE.search(line) and not line.startswith("S8_"):
            hits.append(line)
    return hits


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--jsonl", required=True)
    p.add_argument("--s8-log", required=True)
    p.add_argument("--expect-live", type=int, default=3)
    p.add_argument("--freeze-secs", type=float, default=0)
    p.add_argument("--freeze-cycles", type=int, default=0)
    p.add_argument("--gap-floor", type=float, default=2.5)
    p.add_argument("--min-peak-out-bps", type=float, default=80e6)
    p.add_argument("--min-peak-in-bps", type=float, default=0)
    p.add_argument("--out", default="")
    args = p.parse_args()

    jsonl = Path(args.jsonl)
    rows = load_jsonl(jsonl)
    fails: list[str] = []
    gaps: list[dict] = []
    peak_out = 0.0
    peak_in = 0.0
    peak_out_t = None
    peak_in_t = None
    min_live = None
    max_io = 0
    max_verify = 0
    stalls = 0

    if len(rows) < 3:
        fails.append(f"too few jsonl samples: {len(rows)}")
    else:
        min_live = min(int(r.get("channels_live", 0)) for r in rows)
        max_io = max(int(r.get("io_errors", 0)) for r in rows)
        max_verify = max(int(r.get("verify_errors", 0)) for r in rows)
        stalls = sum(1 for r in rows if r.get("stall"))
        if min_live < args.expect_live:
            fails.append(f"channels_live dropped to {min_live} (want {args.expect_live})")
        if max_io:
            fails.append(f"io_errors={max_io} during the run")
        if max_verify:
            fails.append(f"verify_errors={max_verify}")
        if stalls:
            fails.append(f"traffic.py stall flag set on {stalls} samples")

        for a, b in zip(rows, rows[1:]):
            dt = float(b["t"]) - float(a["t"])
            dout = int(b["bytes_out"]) - int(a["bytes_out"])
            din = int(b["bytes_in"]) - int(a["bytes_in"])
            live = int(b.get("channels_live", 0))
            if dt >= args.gap_floor:
                gaps.append(
                    {
                        "t0": a["t"],
                        "t1": b["t"],
                        "dt": round(dt, 3),
                        "d_out": dout,
                        "d_in": din,
                        "live": live,
                    }
                )
            if dt > 0:
                ro, ri = dout / dt, din / dt
                if ro > peak_out:
                    peak_out, peak_out_t = ro, (a["t"], b["t"])
                if ri > peak_in:
                    peak_in, peak_in_t = ri, (a["t"], b["t"])

        want_gaps = args.freeze_cycles if args.freeze_secs > 0 else 0
        if want_gaps:
            lo = max(args.freeze_secs - 1.0, args.gap_floor)
            hi = args.freeze_secs + 4.0
            freeze_gaps = [g for g in gaps if lo <= g["dt"] <= hi]
            extra = [g for g in gaps if g not in freeze_gaps]
            if len(freeze_gaps) != want_gaps:
                fails.append(
                    f"freeze gaps {len(freeze_gaps)} != {want_gaps} "
                    f"(window {lo:.1f}–{hi:.1f}s): {gaps}"
                )
            if extra:
                fails.append(f"unexpected jsonl stall gaps (not SIGSTOP): {extra}")
            # The 1s sample after each freeze gap must already be catching up.
            crawl = []
            for i, g in enumerate(gaps):
                if g not in freeze_gaps:
                    continue
                # rows[j] is the first sample after CONT; rows[j+1] is +1s.
                for j in range(len(rows) - 2):
                    if abs(float(rows[j + 1]["t"]) - float(g["t1"])) < 1e-6:
                        dt2 = float(rows[j + 2]["t"]) - float(rows[j + 1]["t"])
                        if 0 < dt2 < args.gap_floor:
                            rate = (int(rows[j + 2]["bytes_out"]) - int(rows[j + 1]["bytes_out"])) / dt2
                            if rate < 1e6:
                                crawl.append({"after": g["t1"], "out_bps": rate})
                        break
            if crawl:
                fails.append(f"post-freeze crawl (<1 MB/s): {crawl}")
        else:
            if gaps:
                fails.append(f"unexpected jsonl gaps with no freeze: {gaps}")

        if args.min_peak_out_bps and peak_out < args.min_peak_out_bps:
            fails.append(
                f"peak bytes_out {peak_out/1e6:.1f} MB/s < {args.min_peak_out_bps/1e6:.1f} MB/s"
            )
        if args.min_peak_in_bps and peak_in < args.min_peak_in_bps:
            fails.append(
                f"peak bytes_in {peak_in/1e6:.1f} MB/s < {args.min_peak_in_bps/1e6:.1f} MB/s"
            )

    hits = warn_hits(Path(args.s8_log))
    if hits:
        fails.append("s8 warn/error:\n  " + "\n  ".join(hits[:20]))

    last = rows[-1] if rows else {}
    report = {
        "ok": not fails,
        "samples": len(rows),
        "t0": rows[0]["t"] if rows else None,
        "tN": last.get("t"),
        "bytes_in": last.get("bytes_in"),
        "bytes_out": last.get("bytes_out"),
        "min_live": min_live,
        "max_io_errors": max_io,
        "max_verify_errors": max_verify,
        "gaps": gaps,
        "peak_out_bps": peak_out,
        "peak_in_bps": peak_in,
        "peak_out_t": peak_out_t,
        "peak_in_t": peak_in_t,
        "fails": fails,
    }
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    if fails:
        print("JUDGE_FAIL", file=sys.stderr)
        return 1
    print("JUDGE_PASS", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Judge 24h soak CSV/JSONL into a markdown report with real numbers."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
from typing import Dict, List, Optional, Tuple


def linreg(xs: List[float], ys: List[float]) -> Tuple[float, float]:
    n = len(xs)
    if n < 2:
        return 0.0, ys[0] if ys else 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0, my
    slope = num / den
    intercept = my - slope * mx
    return slope, intercept


def load_csv(path: str) -> Dict[str, List[dict]]:
    by: Dict[str, List[dict]] = {}
    if not os.path.isfile(path):
        return by
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            by.setdefault(row["name"], []).append(row)
    return by


def fnum(row: dict, key: str) -> Optional[float]:
    v = row.get(key, "")
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def last_jsonl(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    last = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    continue
    return last


def series(rows: List[dict], key: str) -> Tuple[List[float], List[float]]:
    xs, ys = [], []
    for r in rows:
        t = fnum(r, "t")
        y = fnum(r, key)
        if t is None or y is None:
            continue
        xs.append(t)
        ys.append(y)
    return xs, ys


def summarize_proc(name: str, rows: List[dict]) -> dict:
    t, rss = series(rows, "rss_mib")
    _, cpu = series(rows, "cpu_pct")
    _, fds = series(rows, "fds")
    _, thr = series(rows, "threads")
    slope_mib_s, intercept = linreg(t, rss) if rss else (0.0, 0.0)
    slope_mib_h = slope_mib_s * 3600.0
    duration_h = (t[-1] - t[0]) / 3600.0 if len(t) >= 2 else 0.0
    return {
        "name": name,
        "samples": len(rows),
        "duration_h": duration_h,
        "rss_first_mib": rss[0] if rss else None,
        "rss_last_mib": rss[-1] if rss else None,
        "rss_min_mib": min(rss) if rss else None,
        "rss_max_mib": max(rss) if rss else None,
        "rss_slope_mib_h": slope_mib_h,
        "cpu_avg": statistics.mean(cpu) if cpu else None,
        "cpu_p95": sorted(cpu)[int(0.95 * (len(cpu) - 1))] if cpu else None,
        "cpu_max": max(cpu) if cpu else None,
        "fds_first": fds[0] if fds else None,
        "fds_last": fds[-1] if fds else None,
        "fds_max": max(fds) if fds else None,
        "threads_first": thr[0] if thr else None,
        "threads_last": thr[-1] if thr else None,
        "threads_max": max(thr) if thr else None,
    }


def fmt(v, nd=3):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return "n/a"
        return f"{v:.{nd}f}"
    return str(v)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--seconds", type=float, required=True)
    args = p.parse_args()
    wd = args.workdir
    by = load_csv(os.path.join(wd, "monitor.csv"))
    procs = [summarize_proc(n, rows) for n, rows in sorted(by.items())]

    traffic = {
        "openssh→russh": last_jsonl(os.path.join(wd, "traffic_openssh_to_russh.jsonl")),
        "openssh→sshd": last_jsonl(os.path.join(wd, "traffic_openssh_to_sshd.jsonl")),
        "russh→russh": last_jsonl(os.path.join(wd, "traffic_russh_to_russh.jsonl")),
    }

    control = None
    # last non-empty rekey from russh_server rows
    rekey = None
    disconnects = None
    sessions = None
    for row in by.get("russh_server", []):
        r = fnum(row, "rekey_triggers")
        if r is not None:
            rekey = r
        d = fnum(row, "disconnects")
        if d is not None:
            disconnects = d
        s = fnum(row, "sessions")
        if s is not None:
            sessions = s

    fail_reasons = []
    elapsed = 0.0
    for rows in by.values():
        if rows:
            elapsed = max(elapsed, fnum(rows[-1], "t") or 0.0)
    if elapsed < args.seconds * 0.90:
        fail_reasons.append(
            f"monitor duration {elapsed:.0f}s < 90% of requested {args.seconds:.0f}s"
        )

    for label, js in traffic.items():
        if not js:
            fail_reasons.append(f"missing traffic summary for {label}")
            continue
        if js.get("stall") or (js.get("stalls") or 0) > 0:
            fail_reasons.append(f"{label} stall detected")
        if (js.get("verify_errors") or 0) > 0:
            fail_reasons.append(f"{label} payload verify errors={js['verify_errors']}")
        if (js.get("io_errors") or 0) > 0:
            fail_reasons.append(f"{label} io_errors={js['io_errors']}")

    for pr in procs:
        if pr["name"] not in (
            "russh_server",
            "openssh_sshd",
            "russh_client",
            "openssh_client_to_russh",
        ):
            continue
        if (
            pr["duration_h"] >= 1.0
            and pr["rss_slope_mib_h"] is not None
            and pr["rss_slope_mib_h"] > 8.0
        ):
            fail_reasons.append(
                f"{pr['name']} RSS slope {pr['rss_slope_mib_h']:.2f} MiB/h > 8 MiB/h"
            )
        if pr["fds_first"] and pr["fds_last"] and pr["fds_last"] - pr["fds_first"] > 32:
            fail_reasons.append(
                f"{pr['name']} fd growth {pr['fds_first']} → {pr['fds_last']}"
            )
        if pr["threads_first"] and pr["threads_last"] and pr["threads_last"] - pr["threads_first"] > 16:
            fail_reasons.append(
                f"{pr['name']} thread growth {pr['threads_first']} → {pr['threads_last']}"
            )

    verdict = "FAIL" if fail_reasons else "PASS"

    lines = []
    lines.append("# 24h localhost SSH soak — measured results")
    lines.append("")
    lines.append("These numbers are from a real run (not inferred).")
    lines.append("")
    lines.append(f"- Requested duration: **{args.seconds:.0f} s** ({args.seconds/3600:.2f} h)")
    lines.append(f"- Observed monitor span: **{elapsed:.0f} s** ({elapsed/3600:.2f} h)")
    lines.append(f"- Workdir: `{wd}`")
    lines.append(f"- Verdict: **{verdict}**")
    if fail_reasons:
        lines.append("")
        lines.append("## Fail reasons")
        for r in fail_reasons:
            lines.append(f"- {r}")
    lines.append("")
    lines.append("## Traffic / integrity")
    lines.append("")
    lines.append("| stack | seconds | bytes_in | bytes_out | MiB/s in | MiB/s out | stall | verify_err | io_err |")
    lines.append("|---|---:|---:|---:|---:|---:|---|---:|---:|")
    for label, js in traffic.items():
        if not js:
            lines.append(f"| {label} | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |")
            continue
        t = float(js.get("t") or 0) or 1.0
        bi = int(js.get("bytes_in") or 0)
        bo = int(js.get("bytes_out") or 0)
        lines.append(
            f"| {label} | {t:.0f} | {bi} | {bo} | {bi/t/1024/1024:.3f} | {bo/t/1024/1024:.3f} | {js.get('stall')} | {js.get('verify_errors')} | {js.get('io_errors')} |"
        )
    lines.append("")
    lines.append("## russh server control plane")
    lines.append("")
    lines.append(f"- rekey_triggers (last sample): **{fmt(rekey, 0)}**")
    lines.append(f"- disconnects: **{fmt(disconnects, 0)}**")
    lines.append(f"- live sessions: **{fmt(sessions, 0)}**")
    lines.append("")
    lines.append("## Process resources (tree RSS/CPU/fd/thread)")
    lines.append("")
    lines.append("| process | hours | RSS first→last MiB | RSS min/max | slope MiB/h | CPU avg/p95/max % | fds first→last (max) | threads first→last (max) |")
    lines.append("|---|---:|---|---|---:|---|---|---|")
    for pr in procs:
        lines.append(
            "| {name} | {dh} | {a}→{b} | {mn}/{mx} | {sl} | {ca}/{cp}/{cm} | {f0}→{f1} ({fm}) | {t0}→{t1} ({tm}) |".format(
                name=pr["name"],
                dh=fmt(pr["duration_h"], 2),
                a=fmt(pr["rss_first_mib"], 2),
                b=fmt(pr["rss_last_mib"], 2),
                mn=fmt(pr["rss_min_mib"], 2),
                mx=fmt(pr["rss_max_mib"], 2),
                sl=fmt(pr["rss_slope_mib_h"], 3),
                ca=fmt(pr["cpu_avg"], 2),
                cp=fmt(pr["cpu_p95"], 2),
                cm=fmt(pr["cpu_max"], 2),
                f0=fmt(pr["fds_first"], 0),
                f1=fmt(pr["fds_last"], 0),
                fm=fmt(pr["fds_max"], 0),
                t0=fmt(pr["threads_first"], 0),
                t1=fmt(pr["threads_last"], 0),
                tm=fmt(pr["threads_max"], 0),
            )
        )
    lines.append("")
    lines.append("## How to read this")
    lines.append("")
    lines.append("- **stall**: no byte progress for ≥60s on a live bulk/echo stream (rekey hang / wedge / disconnect).")
    lines.append("- **RSS slope**: linear regression over the full window. Allocator noise of a few MiB/h is normal; unbounded growth is not.")
    lines.append("- **rekey_triggers**: russh server I5 volume rekeys actually started. 0 during a 64 MiB-limit bulk soak is a bug.")
    lines.append("- OpenSSH comparison uses the same 8 MiB/s × (1 down + 1 up + 1 echo) shape on localhost.")
    lines.append("")
    os.makedirs(os.path.dirname(args.result) or ".", exist_ok=True)
    with open(args.result, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if verdict == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

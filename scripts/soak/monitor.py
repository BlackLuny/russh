#!/usr/bin/env python3
"""Sample RSS/CPU/fds/threads for soak PIDs plus HTTP control stats."""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

CLK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
PAGESIZE = os.sysconf("SC_PAGESIZE")


def read_stat(pid: int) -> Optional[Tuple[int, int, int, int]]:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            s = f.read()
        rpar = s.rfind(")")
        fields = s[rpar + 2 :].split()
        utime = int(fields[11])
        stime = int(fields[12])
        vsize = int(fields[20])
        rss = int(fields[21]) * PAGESIZE
        return utime, stime, vsize, rss
    except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
        return None


def nthreads(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Threads:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ValueError):
        return 0
    return 0


def nfds(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except (FileNotFoundError, PermissionError):
        return 0


def ppid_map() -> Dict[int, int]:
    out: Dict[int, int] = {}
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            cpid = int(name)
            try:
                with open(f"/proc/{cpid}/stat", "r", encoding="utf-8") as f:
                    s = f.read()
                rpar = s.rfind(")")
                ppid = int(s[rpar + 2 :].split()[1])
                out[cpid] = ppid
            except (FileNotFoundError, ValueError, IndexError):
                continue
    except FileNotFoundError:
        pass
    return out


def descendants(root: int, ppids: Dict[int, int]) -> List[int]:
    kids = [pid for pid, ppid in ppids.items() if ppid == root]
    acc = list(kids)
    for k in kids:
        acc.extend(descendants(k, ppids))
    return acc


def sample_tree(root: int) -> Dict[str, int]:
    pids = [root] + descendants(root, ppid_map())
    rss = vsz = fds = threads = cpu_ticks = 0
    alive = 0
    for pid in pids:
        st = read_stat(pid)
        if not st:
            continue
        ut, stt, vsize, rs = st
        cpu_ticks += ut + stt
        rss += rs
        vsz += vsize
        fds += nfds(pid)
        threads += nthreads(pid)
        alive += 1
    return {
        "rss_bytes": rss,
        "vsz_bytes": vsz,
        "fds": fds,
        "threads": threads,
        "cpu_ticks": cpu_ticks,
        "procs": alive,
    }


def fetch_json(url: str) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def last_jsonl(path: str) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 8192))
            lines = f.read().decode("utf-8", "replace").strip().splitlines()
            if not lines:
                return None
            return json.loads(lines[-1])
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--targets", required=True, help="JSON list of {name,pid}")
    p.add_argument("--controls", default="[]", help="JSON list of {name,url}")
    p.add_argument("--traffic", default="[]", help="JSON list of {name,path}")
    p.add_argument("--out", required=True)
    p.add_argument("--interval", type=float, default=10)
    p.add_argument("--seconds", type=float, default=86400)
    args = p.parse_args()

    targets = json.loads(args.targets)
    controls = json.loads(args.controls)
    traffic = json.loads(args.traffic)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    fieldnames = [
        "t",
        "name",
        "rss_mib",
        "vsz_mib",
        "fds",
        "threads",
        "cpu_pct",
        "procs",
        "bytes_in",
        "bytes_out",
        "rekey_triggers",
        "sessions",
        "channels",
        "disconnects",
        "stall",
        "verify_errors",
        "io_errors",
    ]
    prev_ticks: Dict[str, Tuple[float, int]] = {}
    t0 = time.time()
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        f.flush()
        while time.time() - t0 < args.seconds:
            now = time.time()
            elapsed = now - t0
            rows_by_name = {}
            for t in targets:
                name, pid = t["name"], int(t["pid"])
                samp = sample_tree(pid)
                cpu_pct = 0.0
                key = name
                if key in prev_ticks:
                    pt, ptk = prev_ticks[key]
                    dt = now - pt
                    if dt > 0:
                        cpu_pct = 100.0 * (samp["cpu_ticks"] - ptk) / CLK / dt
                prev_ticks[key] = (now, samp["cpu_ticks"])
                rows_by_name[name] = {
                    "t": f"{elapsed:.3f}",
                    "name": name,
                    "rss_mib": f"{samp['rss_bytes'] / (1024 * 1024):.3f}",
                    "vsz_mib": f"{samp['vsz_bytes'] / (1024 * 1024):.3f}",
                    "fds": samp["fds"],
                    "threads": samp["threads"],
                    "cpu_pct": f"{cpu_pct:.2f}",
                    "procs": samp["procs"],
                    "bytes_in": "",
                    "bytes_out": "",
                    "rekey_triggers": "",
                    "sessions": "",
                    "channels": "",
                    "disconnects": "",
                    "stall": "",
                    "verify_errors": "",
                    "io_errors": "",
                }
            for ctl in controls:
                js = fetch_json(ctl["url"])
                row = rows_by_name.get(ctl["name"])
                if row and js:
                    row["bytes_in"] = js.get("bytes_in", "")
                    row["bytes_out"] = js.get("bytes_out", "")
                    row["rekey_triggers"] = js.get("rekey_triggers", "")
                    row["sessions"] = js.get("sessions", "")
                    row["channels"] = js.get("channels", "")
                    row["disconnects"] = js.get("disconnects", "")
            for tr in traffic:
                js = last_jsonl(tr["path"])
                row = rows_by_name.get(tr["name"])
                if row is None:
                    row = {
                        "t": f"{elapsed:.3f}",
                        "name": tr["name"],
                        "rss_mib": "",
                        "vsz_mib": "",
                        "fds": "",
                        "threads": "",
                        "cpu_pct": "",
                        "procs": "",
                        "bytes_in": "",
                        "bytes_out": "",
                        "rekey_triggers": "",
                        "sessions": "",
                        "channels": "",
                        "disconnects": "",
                        "stall": "",
                        "verify_errors": "",
                        "io_errors": "",
                    }
                    rows_by_name[tr["name"]] = row
                if js:
                    row["bytes_in"] = js.get("bytes_in", row["bytes_in"])
                    row["bytes_out"] = js.get("bytes_out", row["bytes_out"])
                    row["stall"] = js.get("stall", "")
                    row["verify_errors"] = js.get("verify_errors", "")
                    row["io_errors"] = js.get("io_errors", "")
            for row in rows_by_name.values():
                w.writerow(row)
            f.flush()
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

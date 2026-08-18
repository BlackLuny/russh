#!/usr/bin/env python3
"""OpenSSH client soak against russh inbound_tcp_proxy on loopback.

Topology (pure SSH proxy, OpenSSH client, loopback echo):

  traffic[i] --TCP--> ssh -L local_i:127.0.0.1:echo
                 --SSH multiplexed direct-tcpip--> russh inbound_tcp_proxy
                 --TCP--> echo server --echo back--> (same path reversed)

Runs 1-stream and/or 8-stream scenarios. Samples every `--sample-secs`.
Flags a stall if a stream makes no progress for `--stall-secs`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


CHUNK = 64 * 1024
PATTERN_SEED = 0xA5


def now() -> float:
    return time.time()


def fmt_mb(n: int) -> str:
    return f"{n / (1024 * 1024):.2f} MiB"


def fmt_mbps(bytes_delta: int, secs: float) -> str:
    if secs <= 0:
        return "n/a"
    return f"{(bytes_delta * 8) / secs / 1e6:.2f} Mbit/s"


def wait_tcp(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = now() + timeout
    last = None
    while now() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as e:
            last = e
            time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {host}:{port}: {last}")


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def echo_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_echo_server(host: str, port: int, stop: asyncio.Event) -> None:
    server = await asyncio.start_server(echo_client, host, port)
    async with server:
        await stop.wait()
        server.close()
        await server.wait_closed()


@dataclass
class StreamStats:
    idx: int
    bytes_tx: int = 0
    bytes_rx: int = 0
    last_progress: float = field(default_factory=now)
    mismatches: int = 0
    errors: list[str] = field(default_factory=list)
    stalled: bool = False
    dead: bool = False
    seq: int = 0


async def run_stream(
    host: str,
    port: int,
    stats: StreamStats,
    stop: asyncio.Event,
    stall_secs: float,
) -> None:
    backoff = 0.1
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
            backoff = 0.1
            writer.transport.set_write_buffer_limits(high=4 * CHUNK, low=CHUNK)
            pending: asyncio.Queue[bytes] = asyncio.Queue(maxsize=32)

            async def producer() -> None:
                while not stop.is_set():
                    stats.seq += 1
                    # Unique per-stream pattern: idx, seq, fill. Echo must round-trip intact.
                    header = stats.idx.to_bytes(2, "big") + stats.seq.to_bytes(6, "big")
                    payload = bytes(
                        (PATTERN_SEED ^ stats.idx ^ ((stats.seq + i) & 0xFF)) & 0xFF
                        for i in range(CHUNK - 8)
                    )
                    buf = header + payload
                    await pending.put(buf)
                    writer.write(buf)
                    await writer.drain()
                    stats.bytes_tx += len(buf)

            async def consumer() -> None:
                leftover = b""
                while not stop.is_set():
                    expected = await pending.get()
                    need = len(expected)
                    buf = leftover
                    while len(buf) < need:
                        if stop.is_set():
                            return
                        try:
                            chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
                        except asyncio.TimeoutError:
                            if stop.is_set():
                                return
                            idle = now() - stats.last_progress
                            if idle >= stall_secs:
                                stats.stalled = True
                                stats.errors.append(
                                    f"stall: no echo progress for {idle:.1f}s "
                                    f"tx={stats.bytes_tx} rx={stats.bytes_rx}"
                                )
                            continue
                        if not chunk:
                            if stop.is_set():
                                return
                            raise ConnectionError("echo peer closed")
                        buf += chunk
                    if len(buf) < need:
                        return
                    got, leftover = buf[:need], buf[need:]
                    if got != expected:
                        stats.mismatches += 1
                        stats.errors.append(
                            f"mismatch idx={stats.idx} got={len(got)} expected={need}"
                        )
                    stats.bytes_rx += len(got)
                    stats.last_progress = now()
                    stats.stalled = False

            prod = asyncio.create_task(producer())
            cons = asyncio.create_task(consumer())
            stop_wait = asyncio.create_task(stop.wait())
            done, _ = await asyncio.wait(
                {prod, cons, stop_wait}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in (prod, cons, stop_wait):
                t.cancel()
            for t in done:
                if t is not stop_wait and not t.cancelled():
                    exc = t.exception() if not t.cancelled() else None
                    if exc:
                        raise exc
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if stop.is_set():
                return
        except Exception as e:
            stats.dead = True
            stats.errors.append(f"stream error: {type(e).__name__}: {e}")
            if stop.is_set():
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 5.0)
            try:
                reader2, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=5.0
                )
                writer2.close()
                await writer2.wait_closed()
                stats.dead = False
            except Exception:
                pass


def start_proxy(example_bin: str, port_file: Path, log_file: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "russh=info")
    lf = open(log_file, "w")
    proc = subprocess.Popen(
        [
            example_bin,
            "--bind",
            "127.0.0.1:0",
            "--port-file",
            str(port_file),
        ],
        stdout=lf,
        stderr=subprocess.STDOUT,
        env=env,
    )
    deadline = now() + 60
    while now() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxy exited early: {log_file.read_text()[-4000:]}")
        if port_file.exists() and port_file.stat().st_size > 0:
            addr = port_file.read_text().strip()
            host, port_s = addr.rsplit(":", 1)
            wait_tcp(host, int(port_s), timeout=10)
            return proc
        time.sleep(0.05)
    raise RuntimeError("proxy did not write port file")


def start_ssh(
    ssh_port: int,
    identity: Path,
    forwards: list[tuple[int, int]],
    log_file: Path,
) -> subprocess.Popen:
    cmd = [
        "ssh",
        "-N",
        "-v",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"IdentityFile={identity}",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "BatchMode=yes",
        "-p",
        str(ssh_port),
        "-l",
        "soak",
    ]
    for local_port, echo_port in forwards:
        cmd.extend(["-L", f"127.0.0.1:{local_port}:127.0.0.1:{echo_port}"])
    cmd.append("127.0.0.1")
    lf = open(log_file, "w")
    return subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT)


def snapshot_streams(streams: list[StreamStats]) -> list[dict]:
    out = []
    for s in streams:
        idle = now() - s.last_progress
        out.append(
            {
                "idx": s.idx,
                "bytes_tx": s.bytes_tx,
                "bytes_rx": s.bytes_rx,
                "idle_secs": round(idle, 3),
                "mismatches": s.mismatches,
                "stalled": s.stalled or idle >= 30,
                "dead": s.dead,
                "error_count": len(s.errors),
                "last_error": s.errors[-1] if s.errors else None,
            }
        )
    return out


async def run_scenario(
    name: str,
    streams_n: int,
    duration: float,
    sample_secs: float,
    stall_secs: float,
    example_bin: str,
    out_dir: Path,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / f"{name}-samples.jsonl"
    tmp = Path(tempfile.mkdtemp(prefix=f"russh-soak-{name}-"))
    port_file = tmp / "proxy.port"
    key_path = tmp / "id_ed25519"
    subprocess.check_call(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-q"]
    )

    echo_port = pick_free_port()
    stop = asyncio.Event()
    echo_task = asyncio.create_task(run_echo_server("127.0.0.1", echo_port, stop))
    await asyncio.sleep(0.05)
    wait_tcp("127.0.0.1", echo_port)

    proxy = start_proxy(example_bin, port_file, out_dir / f"{name}-proxy.log")
    ssh_host, ssh_port_s = port_file.read_text().strip().rsplit(":", 1)
    ssh_port = int(ssh_port_s)

    local_ports = [pick_free_port() for _ in range(streams_n)]
    ssh = start_ssh(
        ssh_port,
        key_path,
        [(lp, echo_port) for lp in local_ports],
        out_dir / f"{name}-ssh.log",
    )
    try:
        for lp in local_ports:
            wait_tcp("127.0.0.1", lp, timeout=30)
    except Exception:
        ssh.poll()
        raise RuntimeError(
            f"ssh forwards not ready; ssh_rc={ssh.poll()} log=\n"
            + (out_dir / f"{name}-ssh.log").read_text()[-4000:]
        )

    streams = [StreamStats(idx=i) for i in range(streams_n)]
    workers = [
        asyncio.create_task(run_stream("127.0.0.1", local_ports[i], streams[i], stop, stall_secs))
        for i in range(streams_n)
    ]

    t0 = now()
    deadline = t0 + duration
    last_tx = [0] * streams_n
    last_rx = [0] * streams_n
    anomalies: list[dict] = []
    sample_i = 0

    print(
        f"[{name}] start streams={streams_n} duration={duration}s sample={sample_secs}s "
        f"ssh={ssh_host}:{ssh_port} echo={echo_port} locals={local_ports}",
        flush=True,
    )

    with samples_path.open("w") as sf:
        while now() < deadline:
            remaining = deadline - now()
            await asyncio.sleep(min(sample_secs, max(remaining, 0.1)))
            sample_i += 1
            elapsed = now() - t0
            proxy_alive = proxy.poll() is None
            ssh_alive = ssh.poll() is None
            snap = snapshot_streams(streams)
            tx = sum(s.bytes_tx for s in streams)
            rx = sum(s.bytes_rx for s in streams)
            dtx = tx - sum(last_tx)
            drx = rx - sum(last_rx)
            last_tx = [s.bytes_tx for s in streams]
            last_rx = [s.bytes_rx for s in streams]
            window = min(sample_secs, elapsed if sample_i == 1 else sample_secs)

            flags = []
            if not proxy_alive:
                flags.append("proxy_dead")
            if not ssh_alive:
                flags.append("ssh_dead")
            if any(s["stalled"] for s in snap):
                flags.append("stream_stall")
            if any(s["dead"] for s in snap):
                flags.append("stream_dead")
            if any(s["mismatches"] for s in snap):
                flags.append("mismatch")
            if dtx == 0 or drx == 0:
                flags.append("zero_window_throughput")

            rec = {
                "scenario": name,
                "sample": sample_i,
                "elapsed_secs": round(elapsed, 3),
                "proxy_alive": proxy_alive,
                "ssh_alive": ssh_alive,
                "ssh_pid": ssh.pid,
                "proxy_pid": proxy.pid,
                "bytes_tx": tx,
                "bytes_rx": rx,
                "delta_tx": dtx,
                "delta_rx": drx,
                "mbps_tx": (dtx * 8) / window / 1e6 if window else 0,
                "mbps_rx": (drx * 8) / window / 1e6 if window else 0,
                "flags": flags,
                "streams": snap,
            }
            sf.write(json.dumps(rec) + "\n")
            sf.flush()
            flag_s = ",".join(flags) if flags else "ok"
            print(
                f"[{name}] t={elapsed/60:.1f}min sample={sample_i} "
                f"tx={fmt_mb(tx)} rx={fmt_mb(rx)} "
                f"rate_tx={fmt_mbps(dtx, window)} rate_rx={fmt_mbps(drx, window)} "
                f"proxy={'up' if proxy_alive else 'DOWN'} ssh={'up' if ssh_alive else 'DOWN'} "
                f"flags={flag_s}",
                flush=True,
            )
            if flags:
                anomalies.append(rec)
            if not proxy_alive or not ssh_alive:
                # Connection is gone; keep sampling until duration so the report shows a hang,
                # but stop generating more traffic.
                stop.set()

    stop.set()
    await asyncio.wait(workers, timeout=10)
    echo_task.cancel()
    try:
        await echo_task
    except (asyncio.CancelledError, Exception):
        pass

    if ssh.poll() is None:
        ssh.send_signal(signal.SIGTERM)
        try:
            ssh.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ssh.kill()
    if proxy.poll() is None:
        proxy.send_signal(signal.SIGTERM)
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()

    shutil.rmtree(tmp, ignore_errors=True)

    total_tx = sum(s.bytes_tx for s in streams)
    total_rx = sum(s.bytes_rx for s in streams)
    elapsed = now() - t0
    summary = {
        "scenario": name,
        "streams": streams_n,
        "elapsed_secs": elapsed,
        "duration_requested_secs": duration,
        "sample_secs": sample_secs,
        "stall_secs": stall_secs,
        "bytes_tx": total_tx,
        "bytes_rx": total_rx,
        "avg_mbps_tx": (total_tx * 8) / elapsed / 1e6 if elapsed else 0,
        "avg_mbps_rx": (total_rx * 8) / elapsed / 1e6 if elapsed else 0,
        "mismatches": sum(s.mismatches for s in streams),
        "stream_errors": sum(len(s.errors) for s in streams),
        "anomaly_samples": len(anomalies),
        "proxy_exit": proxy.poll(),
        "ssh_exit": ssh.poll(),
        "ok": len(anomalies) == 0
        and sum(s.mismatches for s in streams) == 0
        and total_rx > 0
        and total_tx > 0,
        "per_stream": snapshot_streams(streams),
        "error_excerpts": [s.errors[-3:] for s in streams if s.errors],
    }
    (out_dir / f"{name}-summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[{name}] done ok={summary['ok']} anomalies={len(anomalies)} "
          f"tx={fmt_mb(total_tx)} rx={fmt_mb(total_rx)} "
          f"avg={fmt_mbps(total_tx, elapsed)}", flush=True)
    return summary


def find_example_bin() -> str:
    env = os.environ.get("INBOUND_TCP_PROXY_BIN")
    if env:
        return env
    candidates = [
        Path("target/release/examples/inbound_tcp_proxy"),
        Path("target/debug/examples/inbound_tcp_proxy"),
    ]
    for c in candidates:
        if c.exists():
            return str(c.resolve())
    raise SystemExit(
        "inbound_tcp_proxy binary not found; build with "
        "`cargo build -p russh --example inbound_tcp_proxy --release` "
        "or set INBOUND_TCP_PROXY_BIN"
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--duration-secs", type=float, default=7200)
    p.add_argument("--sample-secs", type=float, default=300)
    p.add_argument("--stall-secs", type=float, default=30)
    p.add_argument("--out", type=Path, default=Path("reports/openssh-proxy-soak"))
    p.add_argument(
        "--scenarios",
        default="1,8",
        help="comma-separated stream counts, e.g. 1,8",
    )
    p.add_argument("--parallel", action="store_true", default=True)
    p.add_argument("--no-parallel", action="store_false", dest="parallel")
    args = p.parse_args()
    example_bin = find_example_bin()
    args.out.mkdir(parents=True, exist_ok=True)
    scenarios = [int(x) for x in args.scenarios.split(",") if x.strip()]

    async def run_all() -> list[dict]:
        tasks = []
        for n in scenarios:
            name = f"{n}stream"
            coro = run_scenario(
                name,
                n,
                args.duration_secs,
                args.sample_secs,
                args.stall_secs,
                example_bin,
                args.out,
            )
            if args.parallel:
                tasks.append(asyncio.create_task(coro))
            else:
                tasks.append(await coro)  # type: ignore
        if args.parallel:
            return list(await asyncio.gather(*tasks))
        return tasks  # already results

    results = asyncio.run(run_all())
    report = {
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "git_describe": subprocess.check_output(
            ["git", "describe", "--always", "--dirty"], text=True
        ).strip(),
        "openssh": subprocess.check_output(["ssh", "-V"], stderr=subprocess.STDOUT, text=True).strip(),
        "duration_secs": args.duration_secs,
        "sample_secs": args.sample_secs,
        "results": results,
        "all_ok": all(r["ok"] for r in results),
    }
    (args.out / "REPORT.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"all_ok": report["all_ok"], "scenarios": [r["scenario"] for r in results]}, indent=2))
    return 0 if report["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""OpenSSH client soak against russh inbound_tcp_proxy on loopback.

Topology (pure SSH proxy, OpenSSH client, loopback echo):

  traffic[i] --TCP--> ssh -L local_i:127.0.0.1:echo
                 --SSH multiplexed direct-tcpip--> russh inbound_tcp_proxy
                 --TCP--> echo server --echo back--> (same path reversed)

Scenarios:
  1 / 8     long-lived streams
  churn     ~100 in-flight short connections (5-30s life, 5-10s cooldown)

Samples every `--sample-secs`. Flags stall / drop / socket-state blowup.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import errno
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


CHUNK = 64 * 1024
CHURN_CHUNK = 1024
PATTERN_SEED = 0xA5
# Expected TIME-WAIT ≈ conn_rate * tcp_fin_timeout (~60s). ~5-6 conn/s → a few hundred.
TIME_WAIT_WARN = 2000
FIN_WAIT_WARN = 200
EPHEMERAL_WARN = 20000


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


# /proc/net/tcp st field (hex) → ss-like names
_PROC_TCP_STATES = {
    "01": "ESTAB",
    "02": "SYN-SENT",
    "03": "SYN-RECV",
    "04": "FIN-WAIT-1",
    "05": "FIN-WAIT-2",
    "06": "TIME-WAIT",
    "07": "CLOSE",
    "08": "CLOSE-WAIT",
    "09": "LAST-ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _parse_proc_hex_port(addr: str) -> Optional[int]:
    # "0100007F:E4E3" or ipv6 "00000000000000000000000001000000:E4E3"
    if ":" not in addr:
        return None
    _ip, port_h = addr.rsplit(":", 1)
    try:
        return int(port_h, 16)
    except ValueError:
        return None


def iter_proc_tcp() -> list[tuple[str, int, int]]:
    """Yield (state, local_port, remote_port) from /proc/net/tcp{,6}."""
    rows: list[tuple[str, int, int]] = []
    for path in ("/proc/net/tcp",):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            lp = _parse_proc_hex_port(parts[1])
            rp = _parse_proc_hex_port(parts[2])
            st = _PROC_TCP_STATES.get(parts[3].upper(), parts[3])
            if lp is None or rp is None:
                continue
            rows.append((st, lp, rp))
    return rows


def wait_listen(port: int, timeout: float = 30.0) -> None:
    """Wait until something is LISTEN on port without completing a handshake."""
    deadline = now() + timeout
    while now() < deadline:
        for st, lp, _rp in iter_proc_tcp():
            if st == "LISTEN" and lp == port:
                return
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for LISTEN :{port}")


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def echo_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
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
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_echo_server(host: str, port: int, stop: asyncio.Event) -> None:
    server = await asyncio.start_server(
        echo_client,
        host,
        port,
        backlog=1024,
        reuse_address=True,
        start_serving=True,
    )
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
            wait_listen(int(port_s), timeout=10)
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
        "-o",
        "LogLevel=ERROR",
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


def tcp_state_counts(ports: set[int]) -> dict[str, int]:
    """Count TCP states whose local or remote port is in `ports`."""
    counts: dict[str, int] = collections.Counter()
    for st, lp, rp in iter_proc_tcp():
        if lp in ports or rp in ports:
            counts[st] += 1
    return dict(counts)


def sockstat_tcp() -> dict[str, int]:
    stats: dict[str, int] = {}
    try:
        text = Path("/proc/net/sockstat").read_text()
    except OSError:
        return stats
    for line in text.splitlines():
        if line.startswith("TCP:"):
            bits = line.split()
            kv = dict(zip(bits[1::2], bits[2::2]))
            for k, v in kv.items():
                try:
                    stats[k] = int(v)
                except ValueError:
                    pass
    return stats


async def interruptible_sleep(stop: asyncio.Event, secs: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=secs)
    except asyncio.TimeoutError:
        pass


async def close_cleanly(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """FIN then drain peer FIN. Avoids RST / lingering FIN_WAIT from half-close races."""
    try:
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
    except Exception:
        pass
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=3.0)
            if not chunk:
                break
    except Exception:
        pass
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
    except Exception:
        pass


@dataclass
class ChurnStats:
    inflight: int = 0
    connecting: int = 0
    opened: int = 0
    closed: int = 0
    bytes_tx: int = 0
    bytes_rx: int = 0
    mismatches: int = 0
    connect_fail: int = 0
    addr_in_use: int = 0
    timeouts: int = 0
    errors: list[str] = field(default_factory=list)
    inflight_max: int = 0
    last_progress: float = field(default_factory=now)

    def bump_inflight(self, delta: int) -> None:
        self.inflight += delta
        if self.inflight > self.inflight_max:
            self.inflight_max = self.inflight


def errno_eaddrnotavail() -> int:
    return getattr(errno, "EADDRNOTAVAIL", 99)


async def run_churn_worker(
    idx: int,
    host: str,
    port: int,
    stats: ChurnStats,
    stop: asyncio.Event,
    connect_sem: asyncio.Semaphore,
    life_min: float,
    life_max: float,
    cool_min: float,
    cool_max: float,
) -> None:
    await interruptible_sleep(stop, idx * 0.08 + random.random() * 0.05)
    while not stop.is_set():
        lifetime = random.uniform(life_min, life_max)
        stats.connecting += 1
        reader = writer = None
        try:
            async with connect_sem:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, local_addr=("127.0.0.1", 0)),
                    timeout=10.0,
                )
        except asyncio.TimeoutError:
            stats.connecting -= 1
            stats.timeouts += 1
            stats.errors.append(f"w{idx} connect timeout")
            if len(stats.errors) > 200:
                stats.errors = stats.errors[-100:]
            await interruptible_sleep(stop, 1.0)
            continue
        except OSError as e:
            stats.connecting -= 1
            stats.connect_fail += 1
            if e.errno == errno_eaddrnotavail():
                stats.addr_in_use += 1
            stats.errors.append(f"w{idx} connect {type(e).__name__}: {e}")
            await interruptible_sleep(stop, 1.0)
            continue
        stats.connecting -= 1
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        stats.opened += 1
        stats.bump_inflight(1)
        deadline = now() + lifetime
        seq = 0
        try:
            while not stop.is_set() and now() < deadline:
                seq += 1
                header = idx.to_bytes(2, "big") + seq.to_bytes(2, "big")
                payload = bytes(
                    (PATTERN_SEED ^ idx ^ ((seq + i) & 0xFF)) & 0xFF
                    for i in range(CHURN_CHUNK - 4)
                )
                buf = header + payload
                writer.write(buf)
                await writer.drain()
                stats.bytes_tx += len(buf)
                got = await asyncio.wait_for(reader.readexactly(len(buf)), timeout=10.0)
                if got != buf:
                    stats.mismatches += 1
                    stats.errors.append(f"w{idx} mismatch seq={seq}")
                stats.bytes_rx += len(got)
                stats.last_progress = now()
        except Exception as e:
            stats.errors.append(f"w{idx} io {type(e).__name__}: {e}")
        finally:
            if reader is not None and writer is not None:
                await close_cleanly(reader, writer)
            stats.bump_inflight(-1)
            stats.closed += 1
        if stop.is_set():
            return
        await interruptible_sleep(stop, random.uniform(cool_min, cool_max))


async def run_churn_scenario(
    name: str,
    duration: float,
    sample_secs: float,
    example_bin: str,
    out_dir: Path,
    inflight_target: int = 100,
    life_min: float = 5.0,
    life_max: float = 30.0,
    cool_min: float = 5.0,
    cool_max: float = 10.0,
) -> dict:
    """Keep ~inflight_target established short connections via one ssh -L.

    Duty cycle ≈ mean(life)/(mean(life)+mean(cool)) ≈ 17.5/25 = 0.7, so workers
    ≈ target / 0.7. Starts are staggered so they don't cooldown in lockstep.
    Connects are rate-limited; close is FIN+drain (no SO_LINGER/RST).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / f"{name}-samples.jsonl"
    tmp = Path(tempfile.mkdtemp(prefix=f"russh-soak-{name}-"))
    port_file = tmp / "proxy.port"
    key_path = tmp / "id_ed25519"
    subprocess.check_call(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-q"]
    )

    duty = ((life_min + life_max) / 2) / (
        ((life_min + life_max) / 2) + ((cool_min + cool_max) / 2)
    )
    workers_n = max(inflight_target + 8, int(round(inflight_target / max(duty, 0.1))))
    echo_port = pick_free_port()
    stop = asyncio.Event()
    echo_task = asyncio.create_task(run_echo_server("127.0.0.1", echo_port, stop))
    await asyncio.sleep(0.05)
    wait_listen(echo_port)

    proxy = start_proxy(example_bin, port_file, out_dir / f"{name}-proxy.log")
    _ssh_host, ssh_port_s = port_file.read_text().strip().rsplit(":", 1)
    ssh_port = int(ssh_port_s)

    local_port = pick_free_port()
    ssh = start_ssh(
        ssh_port,
        key_path,
        [(local_port, echo_port)],
        out_dir / f"{name}-ssh.log",
    )
    try:
        wait_listen(local_port, timeout=30)
    except Exception:
        raise RuntimeError(
            f"ssh forward not ready; ssh_rc={ssh.poll()} log=\n"
            + (out_dir / f"{name}-ssh.log").read_text()[-4000:]
        )

    stats = ChurnStats()
    connect_sem = asyncio.Semaphore(15)
    workers = [
        asyncio.create_task(
            run_churn_worker(
                i,
                "127.0.0.1",
                local_port,
                stats,
                stop,
                connect_sem,
                life_min,
                life_max,
                cool_min,
                cool_max,
            )
        )
        for i in range(workers_n)
    ]
    ports = {ssh_port, echo_port, local_port}
    t0 = now()
    deadline = t0 + duration
    last_tx = last_rx = last_opened = 0
    anomalies: list[dict] = []
    sample_i = 0

    print(
        f"[{name}] start workers={workers_n} target_inflight={inflight_target} "
        f"life={life_min}-{life_max}s cool={cool_min}-{cool_max}s duration={duration}s "
        f"ssh=127.0.0.1:{ssh_port} echo={echo_port} local={local_port}",
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
            tcp = tcp_state_counts(ports)
            sock = sockstat_tcp()
            dtx = stats.bytes_tx - last_tx
            drx = stats.bytes_rx - last_rx
            dopen = stats.opened - last_opened
            last_tx, last_rx, last_opened = stats.bytes_tx, stats.bytes_rx, stats.opened
            window = min(sample_secs, elapsed if sample_i == 1 else sample_secs)
            tw = tcp.get("TIME-WAIT", 0) + tcp.get("TIME_WAIT", 0)
            fw1 = tcp.get("FIN-WAIT-1", 0)
            fw2 = tcp.get("FIN-WAIT-2", 0)
            close_wait = tcp.get("CLOSE-WAIT", 0)
            estab = tcp.get("ESTAB", 0) + tcp.get("ESTABLISHED", 0)
            flags = []
            if not proxy_alive:
                flags.append("proxy_dead")
            if not ssh_alive:
                flags.append("ssh_dead")
            if stats.mismatches:
                flags.append("mismatch")
            if stats.addr_in_use:
                flags.append("eaddrnotavail")
            if tw > TIME_WAIT_WARN:
                flags.append("time_wait_high")
            if fw1 + fw2 > FIN_WAIT_WARN:
                flags.append("fin_wait_high")
            if elapsed > 60 and stats.inflight < inflight_target * 0.4:
                flags.append("inflight_collapse")
            if elapsed > 30 and dopen == 0:
                flags.append("no_new_connections")
            if now() - stats.last_progress >= 30:
                flags.append("no_echo_progress")

            rec = {
                "scenario": name,
                "sample": sample_i,
                "elapsed_secs": round(elapsed, 3),
                "proxy_alive": proxy_alive,
                "ssh_alive": ssh_alive,
                "inflight": stats.inflight,
                "connecting": stats.connecting,
                "inflight_max": stats.inflight_max,
                "opened": stats.opened,
                "closed": stats.closed,
                "opens_this_window": dopen,
                "bytes_tx": stats.bytes_tx,
                "bytes_rx": stats.bytes_rx,
                "delta_tx": dtx,
                "delta_rx": drx,
                "mismatches": stats.mismatches,
                "connect_fail": stats.connect_fail,
                "addr_in_use": stats.addr_in_use,
                "timeouts": stats.timeouts,
                "error_count": len(stats.errors),
                "last_error": stats.errors[-1] if stats.errors else None,
                "tcp_states": tcp,
                "estab": estab,
                "time_wait": tw,
                "fin_wait1": fw1,
                "fin_wait2": fw2,
                "close_wait": close_wait,
                "sockstat_tcp": sock,
                "flags": flags,
            }
            sf.write(json.dumps(rec) + "\n")
            sf.flush()
            flag_s = ",".join(flags) if flags else "ok"
            print(
                f"[{name}] t={elapsed/60:.1f}min sample={sample_i} "
                f"inflight={stats.inflight}/{inflight_target} opened={stats.opened} "
                f"estab={estab} tw={tw} fw1={fw1} fw2={fw2} cw={close_wait} "
                f"tx={fmt_mb(stats.bytes_tx)} rate={fmt_mbps(dtx, window)} "
                f"proxy={'up' if proxy_alive else 'DOWN'} ssh={'up' if ssh_alive else 'DOWN'} "
                f"flags={flag_s}",
                flush=True,
            )
            if flags:
                anomalies.append(rec)
            if not proxy_alive or not ssh_alive:
                stop.set()

    stop.set()
    await asyncio.wait(workers, timeout=40)
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

    elapsed = now() - t0
    summary = {
        "scenario": name,
        "workers": workers_n,
        "inflight_target": inflight_target,
        "inflight_end": stats.inflight,
        "inflight_max": stats.inflight_max,
        "elapsed_secs": elapsed,
        "duration_requested_secs": duration,
        "sample_secs": sample_secs,
        "opened": stats.opened,
        "closed": stats.closed,
        "bytes_tx": stats.bytes_tx,
        "bytes_rx": stats.bytes_rx,
        "mismatches": stats.mismatches,
        "connect_fail": stats.connect_fail,
        "addr_in_use": stats.addr_in_use,
        "timeouts": stats.timeouts,
        "anomaly_samples": len(anomalies),
        "proxy_exit": proxy.poll(),
        "ssh_exit": ssh.poll(),
        "error_excerpts": stats.errors[-10:],
        "ok": len(anomalies) == 0
        and stats.mismatches == 0
        and stats.addr_in_use == 0
        and stats.opened > 0
        and stats.bytes_rx > 0,
    }
    (out_dir / f"{name}-summary.json").write_text(json.dumps(summary, indent=2))
    print(
        f"[{name}] done ok={summary['ok']} anomalies={len(anomalies)} "
        f"opened={stats.opened} closed={stats.closed} inflight_max={stats.inflight_max} "
        f"tx={fmt_mb(stats.bytes_tx)} tw_fails={stats.addr_in_use}",
        flush=True,
    )
    return summary


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
        default="churn",
        help="comma-separated: integers (long-lived streams) and/or 'churn'",
    )
    p.add_argument("--inflight", type=int, default=100)
    p.add_argument("--parallel", action="store_true", default=True)
    p.add_argument("--no-parallel", action="store_false", dest="parallel")
    args = p.parse_args()
    example_bin = find_example_bin()
    args.out.mkdir(parents=True, exist_ok=True)
    scenarios = [x.strip() for x in args.scenarios.split(",") if x.strip()]

    async def run_all() -> list[dict]:
        tasks = []
        for spec in scenarios:
            if spec == "churn":
                coro = run_churn_scenario(
                    "churn",
                    args.duration_secs,
                    args.sample_secs,
                    example_bin,
                    args.out,
                    inflight_target=args.inflight,
                )
            else:
                n = int(spec)
                coro = run_scenario(
                    f"{n}stream",
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

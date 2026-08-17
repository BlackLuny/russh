#!/usr/bin/env python3
"""Localhost TCP echo/sink/source plus soak traffic generators."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import time
from typing import Optional

SOURCE_FILL = 0xAB
CHUNK = 32 * 1024


class Counters:
    def __init__(self) -> None:
        self.bytes_in = 0
        self.bytes_out = 0
        self.verify_errors = 0
        self.io_errors = 0
        self.stalls = 0
        self.channels_live = 0
        self.channels_opened = 0
        self.channels_closed = 0


def dump(c: Counters, t0: float, stall: bool) -> str:
    return json.dumps(
        {
            "t": round(time.time() - t0, 3),
            "bytes_in": c.bytes_in,
            "bytes_out": c.bytes_out,
            "verify_errors": c.verify_errors,
            "io_errors": c.io_errors,
            "stalls": c.stalls,
            "channels_live": c.channels_live,
            "channels_opened": c.channels_opened,
            "channels_closed": c.channels_closed,
            "stall": stall,
        },
        separators=(",", ":"),
    )


async def serve_echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve_sink(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while await reader.read(CHUNK):
            pass
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve_source(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    chunk = bytes([SOURCE_FILL]) * CHUNK
    try:
        while True:
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def run_backend(echo: int, sink: int, source: int, ready: str) -> None:
    e = await asyncio.start_server(serve_echo, "127.0.0.1", echo)
    s = await asyncio.start_server(serve_sink, "127.0.0.1", sink)
    o = await asyncio.start_server(serve_source, "127.0.0.1", source)
    with open(ready, "w", encoding="utf-8") as f:
        f.write(f"echo={echo}\nsink={sink}\nsource={source}\n")
    await asyncio.gather(e.serve_forever(), s.serve_forever(), o.serve_forever())


async def pump_down(host: str, port: int, c: Counters, stop: asyncio.Event, rate_bps: int) -> None:
    c.channels_opened += 1
    c.channels_live += 1
    started = time.time()
    got = 0
    try:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            while not stop.is_set():
                data = await asyncio.wait_for(reader.read(CHUNK), timeout=30)
                if not data:
                    c.io_errors += 1
                    break
                if any(b != SOURCE_FILL for b in data):
                    c.verify_errors += 1
                c.bytes_in += len(data)
                got += len(data)
                if rate_bps:
                    expected = got / rate_bps
                    lag = expected - (time.time() - started)
                    if lag > 0:
                        await asyncio.sleep(lag)
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        c.io_errors += 1
    c.channels_live -= 1
    c.channels_closed += 1


async def pump_up(host: str, port: int, c: Counters, stop: asyncio.Event, rate_bps: int) -> None:
    c.channels_opened += 1
    c.channels_live += 1
    chunk = bytes([SOURCE_FILL]) * CHUNK
    started = time.time()
    sent = 0
    try:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            while not stop.is_set():
                writer.write(chunk)
                await writer.drain()
                c.bytes_out += len(chunk)
                sent += len(chunk)
                if rate_bps:
                    expected = sent / rate_bps
                    lag = expected - (time.time() - started)
                    if lag > 0:
                        await asyncio.sleep(lag)
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        c.io_errors += 1
    c.channels_live -= 1
    c.channels_closed += 1


async def pump_echo(host: str, port: int, c: Counters, stop: asyncio.Event, rate_bps: int) -> None:
    c.channels_opened += 1
    c.channels_live += 1
    started = time.time()
    sent = 0
    seq = 0
    payload = bytearray(8 + 1024)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            while not stop.is_set():
                payload[:8] = seq.to_bytes(8, "little")
                payload[8] = seq & 0xFF
                writer.write(payload)
                await writer.drain()
                c.bytes_out += len(payload)
                sent += len(payload)
                buf = bytearray()
                while len(buf) < len(payload):
                    data = await asyncio.wait_for(reader.read(len(payload) - len(buf)), timeout=30)
                    if not data:
                        c.io_errors += 1
                        return
                    buf.extend(data)
                c.bytes_in += len(payload)
                if buf[:8] != payload[:8] or buf[8] != payload[8]:
                    c.verify_errors += 1
                seq = (seq + 1) & 0xFFFFFFFFFFFFFFFF
                if rate_bps:
                    expected = sent / rate_bps
                    lag = expected - (time.time() - started)
                    if lag > 0:
                        await asyncio.sleep(lag)
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        c.io_errors += 1
    finally:
        c.channels_live -= 1
        c.channels_closed += 1


async def run_client(args: argparse.Namespace) -> int:
    c = Counters()
    stop = asyncio.Event()
    t0 = time.time()
    tasks = []
    for _ in range(args.down):
        tasks.append(asyncio.create_task(pump_down(args.host, args.down_port, c, stop, args.rate_bps)))
    for _ in range(args.up):
        tasks.append(asyncio.create_task(pump_up(args.host, args.up_port, c, stop, args.rate_bps)))
    for _ in range(args.echo):
        tasks.append(asyncio.create_task(pump_echo(args.host, args.echo_port, c, stop, args.rate_bps)))

    if args.stats:
        os.makedirs(os.path.dirname(args.stats) or ".", exist_ok=True)

    last_in = last_out = 0
    last_progress = time.time()
    saw_stall = False
    deadline = t0 + args.seconds

    def on_stop(*_a) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, on_stop)
    signal.signal(signal.SIGINT, on_stop)

    while time.time() < deadline and not stop.is_set():
        await asyncio.sleep(1)
        if c.bytes_in > last_in or c.bytes_out > last_out:
            last_in, last_out = c.bytes_in, c.bytes_out
            last_progress = time.time()
        stall = (time.time() - last_progress) >= args.stall_secs
        if stall and not saw_stall:
            c.stalls += 1
            saw_stall = True
            print(f"SOAK_STALL detected after {time.time() - t0:.1f}s", flush=True)
        if not stall:
            saw_stall = False
        line = dump(c, t0, stall)
        print(line, flush=True)
        if args.stats:
            with open(args.stats, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if c.verify_errors > 0:
            break
        if all(t.done() for t in tasks) and time.time() < deadline:
            c.io_errors += 1
            print("SOAK_CHANNELS_DIED before duration elapsed", flush=True)
            break

    stop.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    print("SOAK_TRAFFIC_SUMMARY " + dump(c, t0, saw_stall), flush=True)
    if c.verify_errors or c.stalls or c.io_errors:
        return 2
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backend")
    b.add_argument("--echo-port", type=int, default=19000)
    b.add_argument("--sink-port", type=int, default=19001)
    b.add_argument("--source-port", type=int, default=19002)
    b.add_argument("--ready-file", required=True)

    c = sub.add_parser("client")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--down-port", type=int, required=True)
    c.add_argument("--up-port", type=int, required=True)
    c.add_argument("--echo-port", type=int, required=True)
    c.add_argument("--down", type=int, default=1)
    c.add_argument("--up", type=int, default=1)
    c.add_argument("--echo", type=int, default=1)
    c.add_argument("--seconds", type=int, default=86400)
    c.add_argument("--stall-secs", type=int, default=60)
    c.add_argument("--rate-bps", type=int, default=0)
    c.add_argument("--stats", default="")

    args = p.parse_args()
    if args.cmd == "backend":
        asyncio.run(run_backend(args.echo_port, args.sink_port, args.source_port, args.ready_file))
        return 0
    return asyncio.run(run_client(args))


if __name__ == "__main__":
    raise SystemExit(main())

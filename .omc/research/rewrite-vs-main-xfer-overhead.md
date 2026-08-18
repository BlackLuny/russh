# rewrite vs main：大流量传输 CPU / 内存开销评估

- 日期: 2026-08-18
- 对比: `origin/main` (`1c013cd`, S0+S1 已合入) vs `origin/russh-s2a-writer-task` (`5cb1f8a`, PR #3 S2–S8)
- 环境: 4 vCPU / 16 GiB，loopback，`release` + `RUSTFLAGS=-Ctarget-cpu=native`，AES-256-GCM，window 4 MiB，maxpkt 32 KiB，`nodelay=true`，**关闭 volume rekey**（只量热路径）
- 口径: 同一进程内 russh server + russh client；CPU 为 `CLOCK_PROCESS_CPUTIME_ID`（含两端加解密）；RSS 为进程 `VmRSS`。每个场景独立进程、warmup 8 MiB 后 3×1 GiB，取中位数。

---

## 结论（先看这个）

**内存：rewrite 不差，单连接峰值与 main 同量级，多 channel 下行甚至更省。** 长稳态由窗口/队列上界主导，不是任务数主导。PR #4 的 12.7h soak 也显示 RSS 升到约 52 MiB 后平台，无泄漏斜率。

**CPU：rewrite 在「服务端往对端灌大流」这条 zfc 热路径上更贵。** loopback CPU-bound 时：

| 场景 | main 吞吐 | rewrite 吞吐 | main CPU·s/GiB | rewrite CPU·s/GiB | CPU 相对 main |
|---|---:|---:|---:|---:|---:|
| 下行 1ch `ChannelStream`（zfc Path B） | 2948 MiB/s | 1677 MiB/s | 0.713 | 1.682 | **+136%** |
| 下行 1ch `Handle::data`（Path A） | 1566 MiB/s | 1625 MiB/s | 1.057 | 1.565 | **+48%** |
| 下行 8ch × 128 MiB | 2931 MiB/s | 2039 MiB/s | 0.843 | 1.289 | **+53%** |
| 上行 1ch `ChannelStream` | 2912 MiB/s | 3010 MiB/s | 0.658 | 0.771 | **+17%** |
| 上行 8ch × 128 MiB | 2873 MiB/s | 2927 MiB/s | 1.021 | 0.985 | **−3.5%** |

要点：

1. **回归集中在服务端推流（下行 Path B）。** rewrite 的 `ChannelStream` 不再快过 `Handle::data`（1677 ≈ 1625 MiB/s），而 main 上 Path B 几乎是 Path A 的 1.9 倍。这正好是代理场景 YouTube / speedtest 的方向。
2. **上行（客户端推、ReaderTask 拆包）几乎打平。** +17% CPU，吞吐还略高。三任务拆分没有在解密路径上变成负担。
3. **这不否定 PR #3 写的「P1 吞吐差 <1%」。** 那是对照 `e814204` 的 soak / 链路受限数字。10–100 MiB/s 的真机链路上，1.68 vs 0.71 CPU·s/GiB 只相当于 **0.07–0.17 核**，会被 RTT/窗口挡住，看不出。loopback 把 AES-GCM + 任务调度放到前台，才暴露出 Path B 的调度税。
4. **内存不是这条 rewrite 的风险面。** 单连接握手后 RSS ~10–28 MiB；8 条 4 MiB 窗下行峰值 main 204 MiB vs rewrite 104 MiB（首 trial）。OS 线程两边都是 6（tokio 4 worker + sampler 等），多出来的 Reader/Writer/Session/Executor 是任务不是线程。

---

## 1. 测了什么

两边同一份逻辑（API 只差 `Limits` vs `RekeyPolicy`）：

- Path B：`Channel::into_stream()` 写 32 KiB chunk（S7 / zfc 路径）
- Path A：`Handle::data(Bytes)`
- 上行：client `into_stream()` 写，server `into_stream()` 读
- 密码套件固定 AES-256-GCM，避免 cipher 协商差干扰

CPU 分辨率：1 GiB × 3 trial，`clock_gettime(PROCESS_CPUTIME)` 纳秒级（`/proc` tick 在 80 ms 传输上只有 ~17 个 10 ms 槽，不够用）。

本机无法用 `perf` / `/proc/self/sched`（容器未开），所以没有 cycles/指令计数，CPU 是进程 CPU 时间。

---

## 2. 原始中位数

### main `1c013cd`

| 场景 | MiB/s | CPU·s/GiB | 握手 RSS MiB | 峰值 RSS MiB |
|---|---:|---:|---:|---:|
| down_stream_1x1g | 2948.0 | 0.713 | 28.28 | 28.35 |
| down_handle_1x1g | 1565.7 | 1.057 | 18.39 | 18.51 |
| down_stream_8x128m | 2931.0 | 0.843 | 221.01¹ | 239.16¹ |
| up_stream_1x1g | 2911.8 | 0.658 | 13.25 | 15.05 |
| up_stream_8x128m | 2873.2 | 1.021 | 14.59 | 15.04 |

¹ 8ch 下行握手 RSS 已被 50 ms 预填窗口污染；**首 trial** 更干净：hs 157.6 / peak 203.5。

### rewrite `5cb1f8a`

| 场景 | MiB/s | CPU·s/GiB | 握手 RSS MiB | 峰值 RSS MiB |
|---|---:|---:|---:|---:|
| down_stream_1x1g | 1676.9 | 1.682 | 19.54 | 19.54 |
| down_handle_1x1g | 1624.8 | 1.565 | 21.64 | 21.64 |
| down_stream_8x128m | 2038.9 | 1.289 | 144.98¹ | 145.05¹ |
| up_stream_1x1g | 3010.3 | 0.771 | 19.38 | 19.43 |
| up_stream_8x128m | 2926.7 | 0.985 | 17.66 | 22.34 |

¹ 首 trial：hs 104.3 / peak 104.4。

---

## 3. 为什么下行 Path B 变贵

main 的 `ChannelTx`（`channels/io/tx.rs`）是 **本地预扣 window + fire-and-forget 进 session mpsc**。`poll_write` 返回即入队；加密/写 socket 在**同一个** session `select!` 任务里做。Path B 因此能把 32 KiB 块直接灌进 loop，几乎不跟控制面 ping-pong。Path A（`Handle::data`）每块还要 `oneshot` ack，所以 main 上 Path A 已经慢一截（1566 vs 2948）。

rewrite 的 server `ChannelTx` 打开了 `use_acked`：

- `start_acked_send` 每包 `Bytes::copy_from_slice` + `oneshot`
- `poll_write` 在 `acked_waiting` 上停，等 Session 侧 `window_size` notify
- SessionTask `dispatch_msg(ChannelDataAcked)` → `data()` → WriterTask `try_seal_payload` → 再 ack/wake

热路径从「1 个任务内加密」变成 **producer → SessionTask → WriterTask** 两跳，外加每 32 KiB 一次 ack 唤醒。结果是 Path B 退化成和 Path A 一类的开销（1677 ≈ 1625），相对 main Path B 多出约 **1.0 CPU·s/GiB**。

其余固定税（相对 AES-GCM 本体都是小头，但叠在 Path B 上）：

- 每连接 4 个任务（Reader / Writer / Session / HandlerExecutor）+ Supervisor 定时器
- 出站 1-packet ready-set 轮转（公平，但 loopback 上不如 main 的 gather/批量 flush）
- GlobalBudget / lane occupancy 原子账本（默认 4 TiB 预算，热路径是原子加减，不是分配）

上行不走这条 ack 链：client 仍是单 loop 加密，server 只是 Reader 解密 → inbound lane `Bytes`（payload 零拷贝切片）→ app 读。所以 CPU 只 +17%。

---

## 4. 内存结构对比

方案 G4 闭式上界（rewrite）比 main 更硬：

```
core 接管 ≤ Σ_chan(w_in + out_cap) + ctrl/kex 队列预算 + staging + 半包
```

| 项 | main (S0+S1) | rewrite (S2–S8) |
|---|---|---|
| 入站积压 | Scheme C 队列 + `max_pending_inbound_bytes`（默认 8×2 MB）+ `event_buffer` | 入站 lane：`window + maxpkt` 字节界 + 条数界 |
| 出站积压 | `pending_data` + `OUTBOUND_HIGH_WATERMARK` 128 KiB 软阈值 + Handle 16 MB 安全帽 | Writer 单账本 + per-channel out cap；ack 与窗口同一权威 |
| 任务栈 | 1 session loop | +Reader +Writer +Session +Executor（tokio 任务，非 OS 线程） |
| 固定协议预算 | 不明显 | ctrl 2 MiB + writer/kex 2 MiB **记账**（默认不预分配这么大块） |
| 全局 | 无 | `GlobalBudget` 默认 4 TiB / 4096 连接（部署要自己收紧） |
| rekey 暂存 | `pending_data` 在 `kex.active()` 时无限堆（事故源） | KEX 停 seal bulk；deadline 30s 拆连 |

实测与公式一致：**大流量峰值由 window×channel×两端 决定，不由任务拓扑决定。** 1ch 下行 ~20–28 MiB；8×4 MiB 窗可以把进程顶到一两百 MiB。rewrite 多 channel 下行更低，一部分是 Path B 更慢、50 ms 预填窗口填不满，一部分是 lane 不再另做 16 MB 级 Scheme C 缓冲。

长期：PR #3 2h soak RSS 斜率 0.66 MiB/h；PR #4 12.7h russh server 8.2→51.7 MiB 后平台。这是泄漏/碎片，不是每 GiB 线性涨。

---

## 5. 放到 zfc 代理场景怎么读

设计文档里的真机形状是「YouTube×2 + speedtest，同一 TCP 上共 ~1.42 **GiB 体积**」，不是 1.42 GiB/s。典型代理下行是几十到几百 Mbps。

粗算（只用下行 Path B CPU·s/GiB）：

| 链路 | main 核占用 | rewrite 核占用 | 差额 |
|---|---:|---:|---:|
| 100 Mbps ≈ 12 MiB/s | 0.008 | 0.020 | 0.012 核 |
| 500 Mbps ≈ 60 MiB/s | 0.042 | 0.098 | 0.056 核 |
| 1 Gbps ≈ 119 MiB/s | 0.083 | 0.195 | 0.11 核 |
| loopback 3 GiB/s | 把 4 核打满前 main 先到 ~2.9 GiB/s，rewrite ~1.7 GiB/s | | **吞吐墙** |

所以：

- **现网代理：CPU 开销可忽略，内存更可预期。** rewrite 的价值是 rekey/反压/拆连有界，不是打满万兆。
- **本机/LAN/测速环回：Path B 会先碰到 CPU 墙，吞吐少约 40%。** 若 zfc 要在高带宽 localhost 或同机 relay 上跑满，需要给 Path B 一条「入队即返回、窗口预扣」的快路径，接近 main 的 unacked `ChannelTx`。
- **不要用 Handle::data 灌大流。** 两边都比 Stream 贵；rewrite 上两者已经一样慢。

---

## 6. 和已有 soak 数字的对齐

| 来源 | 说了什么 | 和本次关系 |
|---|---|---|
| PR #3 Verification | 2h soak，相对 `e814204` P1 吞吐差 <1% | 链路/脚本受限；与本次 CPU-bound loopback **不矛盾** |
| PR #3 S7a | ignored loopback 基线，不进 CI | 本次补了 CPU·s/GiB 和 RSS，S7 当时只打了 MiB/s |
| PR #4 12.7h | russh RSS 8.2→51.7 MiB 平台；OpenSSH→sshd ~10 MiB/s | 内存有界得到实锤；10 MiB/s 看不到本次 Path B CPU 税 |

---

## 7. 建议（若要压 CPU）

按收益排序，都不否定 G1–G4：

1. **Path B 快路径：** server `ChannelTx` 在 Confirmed 且 Writer 有容量时，允许 unacked 入队（本地预扣 window，像 main），ack 只用于 Handle::data / 反压饱和。这是 1.68→~0.7 CPU·s/GiB 的主要杠杆。
2. **跨任务 gather：** Writer 已经有 1-packet 轮转；loopback 上连续 seal 多包再 `write` 能少几次任务切换（公平调度仍可按 quantum 切）。
3. **少一次 `Bytes::copy_from_slice`：** `poll_write` 的 `&[u8]` 来自 `vec![FILL;32K]`，可以让 `AsyncWrite` 上层直接交 `Bytes`。
4. 部署侧：`global_byte_budget` / `max_connections` 收紧到真实主机；默认 4 TiB 只是「测试不被误杀」，不是 DoS 上界。

非目标：为了 CPU 把 Reader/Writer 再并回单 loop——那正是这次 rewrite 要拆掉的死锁面。

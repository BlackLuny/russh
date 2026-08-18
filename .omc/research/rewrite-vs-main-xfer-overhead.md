# rewrite vs main：大流量传输 CPU / 内存开销评估

- 日期: 2026-08-18（第二轮复测）
- 对比:
  - `origin/main` `1c013cd`（S0+S1）
  - rewrite 优化前 `5cb1f8a`（PR #3 当时 HEAD）
  - rewrite 优化后 `a483cc2`（S9 P1–P6：acked credit window / seal reserve / gather fast path / writev）
- 环境: 4 vCPU / 16 GiB，loopback，`release` + `RUSTFLAGS=-Ctarget-cpu=native`，AES-256-GCM，window 4 MiB，maxpkt 32 KiB，`nodelay=true`，**关闭 volume rekey**
- 口径: 同一进程 russh server + russh client；CPU = `CLOCK_PROCESS_CPUTIME_ID`；RSS = `VmRSS`。每场景独立进程、warmup 8 MiB 后 3×1 GiB，取中位数。第二轮 main 与 `a483cc2` 同一会话连跑。

---

## 结论（`a483cc2` vs `main`，同一会话）

S9 优化**有效，但没有抹平 1ch 下行 Path B 对 main 的差距。**

| 场景 | main 吞吐 | rewrite `a483cc2` | vs 优化前 `5cb1f8a` | vs main CPU |
|---|---:|---:|---:|---:|
| 下行 1ch Path B（zfc） | 3054 MiB/s / **0.70** CPU·s/GiB | 1667 / **1.34** | CPU **−20%**，吞吐持平 | **+92%**（此前 +136%） |
| 下行 1ch Path A | 1570 / 1.00 | 1683 / 1.37 | CPU −13%，吞吐 +4% | +37% |
| 下行 8ch | 2821 / 0.83 | 2523 / 1.07 | CPU −17%，吞吐 **+24%** | +29% |
| 上行 1ch | 3163 / 0.67 | 3117 / 0.74 | CPU −4%，吞吐 +4% | +12% |
| 上行 8ch | 2932 / 1.00 | 3051 / 0.89 | CPU −10%，吞吐 +4% | **−11%**（rewrite 更省） |

怎么读：

1. **P1 credit window 打中了上次指出的 lockstep。** 每 channel 允许最多 K=8 包（256 KiB）未 ack，session 不再每 32 KiB 空转一轮。1ch 下行 CPU 从 1.68 降到 1.34；8ch 下行吞吐从 2039 拉到 2523（−11% vs main，此前 −30%）。
2. **1ch Path B 吞吐几乎没动（1677 → 1667）。** lockstep 烧掉的是空转 CPU，不是墙钟。墙钟仍约 0.61 s/GiB（main 0.33 s）。CPU/wall 从 2.8 核降到 2.2 核，说明更闲了，但每字节有效功仍约 main 的 1.9 倍（1.34 / 0.70），所以吞吐仍是 main 的 ~55%。
3. **上行已经可以视为打平**（1ch +12% CPU / 吞吐 −1.5%；8ch rewrite 还更省）。ReaderTask 不是问题。
4. **内存仍不是风险。** 1ch 峰值 ~20 MiB vs main ~26 MiB。8ch 下行因填窗更快，峰值从 145 升到 209，靠近 main 的 240——这是优化成功的副作用，不是泄漏。
5. **现网代理仍然感觉不到。** 1.34 CPU·s/GiB 在 100–500 Mbps 上是 0.016–0.078 核。差距只在 loopback / 高带宽 LAN 上变成吞吐墙。

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

### 第二轮（同一会话）main `1c013cd`

| 场景 | MiB/s | CPU·s/GiB | 握手 RSS MiB | 峰值 RSS MiB |
|---|---:|---:|---:|---:|
| down_stream_1x1g | 3054.0 | 0.697 | 24.91 | 26.44 |
| down_handle_1x1g | 1569.5 | 0.996 | 18.41 | 18.47 |
| down_stream_8x128m | 2821.4 | 0.828 | 215.95 | 240.04 |
| up_stream_1x1g | 3163.0 | 0.665 | 14.32 | 16.25 |
| up_stream_8x128m | 2931.6 | 0.996 | 15.27 | 16.62 |

### 第二轮 rewrite `a483cc2`（S9 P1–P6）

| 场景 | MiB/s | CPU·s/GiB | 握手 RSS MiB | 峰值 RSS MiB |
|---|---:|---:|---:|---:|
| down_stream_1x1g | 1667.1 | 1.339 | 19.88 | 19.88 |
| down_handle_1x1g | 1683.4 | 1.368 | 20.50 | 20.50 |
| down_stream_8x128m | 2522.8 | 1.068 | 209.16 | 209.20 |
| up_stream_1x1g | 3117.0 | 0.743 | 18.66 | 20.04 |
| up_stream_8x128m | 3051.2 | 0.886 | 18.08 | 21.62 |

### 第一轮 rewrite `5cb1f8a`（对照，同机器不同会话）

| 场景 | MiB/s | CPU·s/GiB | 峰值 RSS MiB |
|---|---:|---:|---:|
| down_stream_1x1g | 1676.9 | 1.682 | 19.54 |
| down_handle_1x1g | 1624.8 | 1.565 | 21.64 |
| down_stream_8x128m | 2038.9 | 1.289 | 145.05 |
| up_stream_1x1g | 3010.3 | 0.771 | 19.43 |
| up_stream_8x128m | 2926.7 | 0.985 | 22.34 |

第一轮 main 与第二轮相差 <5%（down Path B 2948 vs 3054），机器噪声可接受。

---

## 3. 热路径还差在哪

main Path B：本地预扣 window，fire-and-forget 进 **同一个** session 任务加密。可以把窗口（4 MiB）都堆在 loop 里。

`5cb1f8a` rewrite Path B：`use_acked` + 共享 `Notify`，每 32 KiB 一次 producer → Session → Writer → producer。Session 无法 batch，Writer 永远只有 1 包。

`a483cc2`（S9 P1）：每 channel 最多 K=`clamp(256KiB/maxpkt, 1, 8)` 个未 ack 包，每个包自己的 oneshot。P4 整包 reserve 少两次 memcpy；P5 单 chunk 聚包快路径；P6 `writev` 一次吐多包。这解释了 **CPU −20% 和 8ch 吞吐 +24%**。

1ch 下行吞吐仍卡住，是因为 K=8 只允许超前 256 KiB，而 main 可以超前整个 peer window。跨任务两跳（SessionTask 仍在数据面）和每包 ack 对象还在。剩下的 0.64 CPU·s/GiB 差额主要是：

- 数据面仍经 SessionTask，不是 producer → Writer
- 每包 oneshot + `Bytes::copy_from_slice`
- 三任务调度 / 公平 1-packet 轮转相对 main 单 loop gather

上行不走这条链，所以已经打平。

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

实测与公式一致：**大流量峰值由 window×channel×两端 决定，不由任务拓扑决定。** 1ch 下行 ~20–28 MiB。8ch 下行在 `a483cc2` 填窗更快后峰值从 145 升到 209 MiB，靠近 main 的 240——窗口被填满了，不是泄漏。

长期：PR #3 2h soak RSS 斜率 0.66 MiB/h；PR #4 12.7h russh server 8.2→51.7 MiB 后平台。这是泄漏/碎片，不是每 GiB 线性涨。

---

## 5. 放到 zfc 代理场景怎么读

设计文档里的真机形状是「YouTube×2 + speedtest，同一 TCP 上共 ~1.42 **GiB 体积**」，不是 1.42 GiB/s。典型代理下行是几十到几百 Mbps。

粗算（只用下行 Path B CPU·s/GiB）：

| 链路 | main 核占用 | rewrite `a483cc2` | 差额 |
|---|---:|---:|---:|
| 100 Mbps ≈ 12 MiB/s | 0.008 | 0.016 | 0.008 核 |
| 500 Mbps ≈ 60 MiB/s | 0.041 | 0.078 | 0.037 核 |
| 1 Gbps ≈ 119 MiB/s | 0.081 | 0.156 | 0.075 核 |
| loopback | main ~3.0 GiB/s，rewrite 1ch ~1.7 / 8ch ~2.5 | | **1ch 仍是墙；8ch 已接近** |

所以：

- **现网代理：CPU 开销可忽略。** S9 之后差额更小。
- **本机/LAN：1ch Path B 仍少约 45% 吞吐；8 条大流已经只少 ~11%。** 代理多 `direct-tcpip` 时，S9 的收益比单流测速更明显。
- **不要用 Handle::data 灌大流。** rewrite 上 Path A/B 仍然差不多；main 上 Path B 才是快路径。

---

## 6. 和已有 soak 数字的对齐

| 来源 | 说了什么 | 和本次关系 |
|---|---|---|
| PR #3 Verification | 2h soak，相对 `e814204` P1 吞吐差 <1% | 链路/脚本受限；与本次 CPU-bound loopback **不矛盾** |
| PR #3 S7a | ignored loopback 基线，不进 CI | 本次补了 CPU·s/GiB 和 RSS，S7 当时只打了 MiB/s |
| PR #4 12.7h | russh RSS 8.2→51.7 MiB 平台；OpenSSH→sshd ~10 MiB/s | 内存有界得到实锤；10 MiB/s 看不到本次 Path B CPU 税 |

---

## 7. 建议（若还要压 1ch Path B）

S9 P1/P4/P5/P6 已经把 lockstep、多余 memcpy、writev 收掉。下一档才是逼近 main 的 0.70 CPU·s/GiB：

1. **数据面旁路 SessionTask：** Confirmed channel 的 DATA 从 ChannelTx 直接进 Writer 出站车道（窗口仍由 Writer 权威记账）。ack/反压留给 Handle::data 和饱和情况。K=8 不够吃满 4 MiB 窗。
2. 或把 K 从 256 KiB 提到与 `channel_out_cap` / peer window 同阶——内存上界仍在 G4 里，但 1ch 可以超前得像 main。
3. `poll_write(&[u8])` 仍 `Bytes::copy_from_slice`；上层交 `Bytes` 能再削一刀。

非目标：为了 CPU 把 Reader/Writer 并回单 loop。

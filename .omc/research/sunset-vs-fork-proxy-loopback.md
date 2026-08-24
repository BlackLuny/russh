# sunset vs 本 fork：SSH 代理环回对比（吞吐 / CPU / RSS / 会不会挂死）

- 日期: 2026-08-18
- 机器: 4 vCPU / 16 GiB RAM，Linux x86_64，**纯本地 loopback**
- 本 fork: `main` `1c013cd`（S0+S1 单 loop + ConnSupervisor）
- sunset: [mkj/sunset](https://github.com/mkj/sunset) `0.6.0`（clone 当日 HEAD）
- 编译: `release` + `RUSTFLAGS=-Ctarget-cpu=native`
- 密码套件: 公平对比用 **chacha20-poly1305**（sunset 没有 AES-GCM）；本 fork 另附 AES-256-GCM（现网常见）
- CPU = `CLOCK_PROCESS_CPUTIME_ID`（同一进程里 SSH server + client）
- RSS = `/proc/self/status` `VmRSS`
- 断流判定: 5s 无字节进度 → `STALL`

压测代码：

- 本 fork: `russh/examples/proxy_loopback_bench.rs`（`direct-tcpip` 代理 + session 大流）
- sunset: `.omc/benches/sunset-loopback/`（sunset **没有 TCP forwarding**，数据面用 session channel 对照）

---

## 结论（先看这个）

**sunset 不能直接换成 zfc 这种「一条 SSH TCP 上多路 `direct-tcpip`」代理。** 环回实锤了三件硬缺口，吞吐数字是次要的。

1. **协议面：没有代理通道。** core 对 `ChannelOpenType::DirectTcpip` / `ForwardedTcpip` 直接 `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`；README 把 TCP forwarding 列在 *Desirable*。本 fork 的 `channel_open_direct_tcpip` 是现网路径。
2. **多 channel 会挂死。** sunset 文档写明「channel 必须读，否则整个 SSH session 阻塞」。环回 **slow-fast**（一条冻住不读 + 一条健康大流）在 stock 窗和 2 MiB 窗下都 **5s STALL**。本 fork 同样场景健康流跑完，连接不拆。
3. **硬上限 4 条 channel、默认窗 1000 字节。** `MAX_CHANNELS = 4`，`DEFAULT_WINDOW = 1000`，`DEFAULT_MAX_PACKET = 1000`。zfc 真机是 YouTube×2 + speedtest 同 TCP、单流 GiB 级。sunset 默认窗把 loopback 锁在 ~27 MiB/s；改到 2 MiB 窗才能接近本 fork 的 chacha 吞吐。

把窗改大之后，**单条健康大流** 的 loopback 吞吐可以和本 fork 的 chacha 打平（~430 vs ~440 MiB/s），RSS 更低（~4 MiB vs ~8–12 MiB）。这只说明 sunset 的固定缓冲/无分配 runner 在「一条已打开的 session 管道」上并不慢；**一旦出现慢消费者、第 5 条流、或真正的 TCP 转发，它就不是这个代理场景的候选。**

---

## 1. 架构对照（代理流量相关）

| | sunset | 本 fork (`1c013cd`) |
|---|---|---|
| 定位 | 嵌入式 / `no_std` / 无分配 SSH | Tokio 高性能 client+server，本 fork 面向 zfc 入站代理 |
| 任务模型 | 单 `Runner` + mutex；`progress()` 必须轮询 | 每连接一个 `select!` session loop（S0+S1）；rewrite 计划是 Reader/Session/Writer |
| 通道上限 | **硬编码 `MAX_CHANNELS=4`**，线性扫描 | 无 4 条硬顶；config 默认窗 2 MiB，本测用 4 MiB |
| 默认窗 / 最大包 | **1000 / 1000**（Pico 级） | 2 MiB / 32 KiB（测 4 MiB / 32 KiB） |
| TCP forwarding | **未实现，open 即拒** | `direct-tcpip` / `forward-tcpip` / streamlocal |
| 数据面反压 | 未读 channel 会堵住 **整条 session**（文档 + 实测） | Scheme C 入站按 channel 隔离；slow-fast 实测通过 |
| 密码 | chacha20-poly1305、aes256-ctr、hmac-sha256；**无 AES-GCM** | chacha + AES-GCM/CTR + aws-lc |
| 每会话 RAM（官方） | Pico W ~13 KiB / session | 本测 1ch 峰值 ~8–12 MiB（含 Tokio/两端窗） |
| rekey | ~30 GiB | 默认 1 GiB；本测关掉以免干扰吞吐 |

sunset 的 IO 缓冲是固定 `SSH_MAX_PACKET≈35 KiB` 的 in/out 各一块，所以 RSS 低是设计，不是漏测。

---

## 2. 环回吞吐 / CPU / 内存

两端都是「同一进程 server+client、loopback、无外网」。sunset 没有 `direct-tcpip`，所以 sunset 只跑 **session 下行**；本 fork 同时跑 session 和真正的 **origin TCP → `direct-tcpip` 代理**。

### 2.1 本 fork

cipher = chacha20-poly1305，window = 4 MiB，maxpkt = 32 KiB，`into_stream()`（zfc Path B）。1 GiB 把握手噪声压下去：

| 场景 | 体积 | MiB/s | CPU·s/GiB | 峰值 RSS MiB | 5s 断流 |
|---|---:|---:|---:|---:|---|
| session 下行 1ch | 1 GiB | 443 | 2.65 | 8.2 | 否 |
| proxy 下行 1ch AES-GCM | 1 GiB | **580** | **1.24** | 8.2 | 否 |
| proxy 下行 1ch chacha | 256 MiB | 195* | 2.73 | 8.0 | 否 |
| proxy 下行 4ch | 4×64 MiB | 194* | 3.76 | 8.8 | 否 |
| proxy 下行 8ch AES-GCM | 8×128 MiB | **592** | 2.06 | 9.3 | 否 |
| proxy 上行 1ch | 256 MiB | 194* | 3.24 | 11.6 | 否 |
| session 8ch | 8×32 MiB | 193* | 2.85 | 11.5 | 否 |

\* 256 MiB 档墙钟里握手占比大（约 1.3s 墙钟），吞吐被低估。1 GiB 档才是 CPU-bound 口径。AES-GCM 明显快于 chacha（aws-lc AES-NI）。

和此前 PR #7 的 ~3 GiB/s 不是同一条热路径口径（那次是 rewrite vs main、GCM、1 GiB warmup 矩阵）。**本次两端用同一套 harness，只用来和 sunset 比，不覆盖 PR #7 的绝对值。**

### 2.2 sunset

**出厂默认（窗 1000 / 包 1000 / 最多 4 ch）：**

| 场景 | 体积 | MiB/s | CPU·s/GiB | 峰值 RSS MiB | 结果 |
|---|---:|---:|---:|---:|---|
| session 下行 1ch | 16 MiB | **26.8** | **68.1** | 4.3 | 完成 |
| session 下行 4ch | 4×4 MiB | 28.7 | 68.1 | 4.3 | 完成（4 条也不加速，窗/单 runner 卡住） |

~27 MiB/s 就是 1000 字节窗在 loopback 上的天花板（每包还要 WINDOW_ADJUST）。CPU·s/GiB 高是包太碎，不是 AES 慢。

**代理向调参（只改 `DEFAULT_WINDOW=2MiB`、`DEFAULT_MAX_PACKET=32KiB`，`MAX_CHANNELS` 仍为 4）：**

| 场景 | 体积 | MiB/s | CPU·s/GiB | 峰值 RSS MiB | 结果 |
|---|---:|---:|---:|---:|---|
| session 下行 1ch | 64 MiB | **434** | 3.58 | 4.4 | 完成 |
| session 下行 4ch | 4×16 MiB | 353 | 4.01 | 4.3 | 完成（多 ch 没有线性加速） |

### 2.3 单条健康大流（chacha，调过大窗的 sunset vs fork）

| | MiB/s | CPU·s/GiB | RSS MiB |
|---|---:|---:|---:|
| sunset 调窗 1ch | 434 | 3.58 | **4.4** |
| 本 fork chacha 1ch 1 GiB | 443 | **2.65** | 8.2 |
| 本 fork AES-GCM 1ch 1 GiB | **580** | **1.24** | 8.2 |

单流：吞吐打平 chacha；fork GCM 更快；sunset 内存大约一半；fork CPU 更省。**这不是代理场景的决胜项。**

粗算放到 zfc 现网（几十到几百 Mbps，不是 loopback GiB/s）：

| 链路 | fork GCM 核占用 | sunset 调窗 chacha | 谁会先成为问题 |
|---|---:|---:|---|
| 100 Mbps ≈ 12 MiB/s | ~0.015 | ~0.042 | 都可忽略 |
| 500 Mbps ≈ 60 MiB/s | ~0.073 | ~0.21 | 仍很小 |
| 现网卡死 | 慢 channel 隔离 | **整条 SSH 冻住** | **sunset** |

---

## 3. 可靠性：多 channel、挂死、断流

场景定义：

- **slow-fast**：同一条 SSH 上两条下行。一条 client **永不 read**（窗耗尽），一条健康 drain。5s 无进度 = 挂死。这就是「YouTube 卡死连累 speedtest」的最小复现。
- **churn**：一条大流进行中，反复 open/close 其它 session。
- **8ch / 4ch**：多路同时灌。
- **direct-tcpip**：代理通道能不能开。

| 场景 | sunset | 本 fork |
|---|---|---|
| 1ch 大流跑完 | 通过（stock/调窗） | 通过 |
| 4ch 同时大流 | 通过，但总吞吐≈1ch | 通过，8ch 也可 |
| **8ch** | **做不到**（`MAX_CHANNELS=4`） | 通过，GCM ~592 MiB/s |
| **slow-fast 隔离** | **失败**：stock 与 2 MiB 窗都 5s STALL，健康流 0 字节 | **通过**：健康流跑完，session 不拆 |
| **churn** | **进程 abort**：`Channels::by_handle_mut` unwrap `BadChannel`（Opening 态读/写下标） | 通过（80 次额外 open/close） |
| **direct-tcpip** | **无 API + core 拒绝** | 通过，代理 1/4/8ch 都跑完 |
| 单 channel 自己停读 | 合法（窗=0）；但会堵住 **别的 channel** | 只堵住该 channel |

sunset 自己的 API 注释（`ChanInOut`）：

> This must be read, otherwise the SSH session will block.

环回不是文档吓唬人：**冻一条，另一条也停。** 加大 window 只是推迟 HoL，不能隔离。本 fork 的 Scheme C / 按 channel 入站队列就是为这个写的，slow-fast 对得上。

churn 的 `BadChannel` 说明 sunset 的 channel 生命周期对「确认前 IO / 额外 open」不宽容，库内部 `unwrap` 直接打崩进程。代理会频繁开闭 `direct-tcpip`，这种失败模式不可接受。

---

## 4. 怎么读到 zfc

设计文档里的真机形状是「YouTube×2 + speedtest，同一 TCP，共 ~1.42 GiB **体积**」，不是 1.42 GiB/s。第三方通用 SSH 客户端开多条 `direct-tcpip`。

sunset 要接这个场景需要至少：

1. 实现 `direct-tcpip`（现在是 TODO/直接拒绝）
2. 把 `MAX_CHANNELS` 从 4 提到几十～上百，并改掉线性扫描假设
3. 默认窗从 1 KiB 提到 MiB 级
4. **拆掉「未读 channel 阻塞整 session」**（否则一条慢 HTTP 仍会冻死同连接其它流）
5. 去掉 `by_handle_mut().unwrap()` 这类会 abort 的路径
6. 最好补 AES-GCM（很多客户端会协商到它）

这些已经是另一个库了。本 fork 在环回上已经具备：多 channel、代理通道、慢流隔离、8 路同灌不拆连。CPU/RSS 在 100–500 Mbps 上不是瓶颈；**可靠性才是。**

---

## 5. 复现

本 fork：

```bash
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --example proxy_loopback_bench -p russh -- \
  --scenario proxy-down-8ch --mib 32 --gcm
# 其它: proxy-down-1ch | session-down-1ch | slow-fast | churn
```

sunset bench（需 Rust 1.95；先 clone 到 `/tmp/ssh-proxy-cmp/sunset`）：

```bash
cd .omc/benches/sunset-loopback
RUSTFLAGS="-Ctarget-cpu=native" cargo +1.95.0 run --release -- --scenario session-down1ch --mib 16
# slow-fast 预期 STALL；direct-tcpip-reject 预期失败
```

调窗对照：改 sunset `src/config.rs` 的 `DEFAULT_WINDOW` / `DEFAULT_MAX_PACKET` 后重编。

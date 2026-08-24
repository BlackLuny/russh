# S2 拆解方案：WriterTask 提取

- 日期: 2026-08-12
- 状态: S2a GO（plan + 第一增量 + report）
- 前置: S0/S1 GO（分支 `russh-proxy-session-rewrite`）
- 方案锚点: §4.1 拓扑 / §4.3 WriterTask / §4.4 kex / §6 S2 行

## 1. 目标与非目标

### 整个 S2 完成门（§6）
close-with-backlog 全变体、NEWKEYS 出站半边、stop-discard-race、顺序矩阵绿。

### 本轮硬边界（禁止）
| 禁止 | 归属 |
|---|---|
| 删 Scheme C / `max_pending_inbound_bytes` | S5 |
| 删双账本 `WindowSizeRef` / `outbound_acks` | S5（本片最多桥接，不删） |
| Reader 独立 / 入站 epoch | S3 |
| HandlerExecutor / Session facade | S4 |
| 改 kex 状态机语义、channel 生命周期、窗口记账**口径** | 后续片 |
| 破坏 S1 supervisor 语义（两层看门狗、rekey/handshake deadline、单 grace、首因） | — |

### S2a 完成门（第一增量）
1. Writer **独立 tokio 任务**成立，独占 socket write half（`PacketWriter` 密封仍在 Session，S2b 迁走）  
2. Session→Writer **有序 bulk 通道**（密封 ciphertext 不得重排）+ **kex 控制队 cap=16 try_push**（Install/Shutdown；满→Cancelling）  
3. cancel-safe 写（`flush_into` 光标语义 + 进度）在 Writer 内  
4. NEWKEYS 出站半边：Session 本地 `newkeys()` + Writer `InstallAck{Outbound,gen}`  
5. `WriteProgress` **跨任务原子快照**（release-store / acquire-load）  
6. 全仓库编译 + 现有 9 tests + S0/S1 suite 全绿  

**S2a 序不变式**：Session 仍按 seqn 密封，Writer **禁止**用旁路队列把后密封的 kex 帧插到先密封 bulk 前面（会触发对端 `PacketSize` 垃圾长度）。真·kex 优先密封在 S2b PacketWriter 归属 Writer 后实现。

---

## 2. 目标拓扑（S2 末态 vs S2a）

```
S1（现状）:
  Session loop: read + seal(PacketWriter) + flush_into(socket) + supervisor

S2a（实际）:
  Session loop: read + kex/channel/handler + seal(PacketWriter still local)
       │ ordered bulk mpsc(256) try_send   │ kex control mpsc(16): Install/Shutdown
       ▼                                   ▼
  WriterTask: 独占 socket write half only
       select!(cancel, kex_ctrl, drain_writes, bulk)
       AtomicWriteProgress release-store
       InstallAck{Outbound,gen} → Session events

S2 末态（累计）:
  + per-channel 出站队列 / fence / ready-set / gather / boost
  + StopDiscard
  + 窗口记账权威在 Writer（与旧账本桥接，删除在 S5）
```

---

## 3. 子增量序列

### S2a — Writer 骨架 + epoch + kex 队 + NEWKEYS 出站 ACK + 原子进度  ✅ 本轮
| 项 | 内容 |
|---|---|
| 文件 | 新 `server/writer.rs`；改 `session.rs::run`、`supervisor.rs`（AtomicWriteProgress）、`mod.rs` export；必要时 `sshbuffer` 小补 |
| 通道 | `bulk: mpsc(256)`、`kex: mpsc(16)`、`event: unbounded`（InstallAck/错误）、`cancel: watch<bool>` |
| Writer 职责 | 独占 `PacketWriter`+write half；处理 `WithWriter` / `InstallOutboundEpoch` / `Shutdown`；优先 drain kex 队；`flush_into`+进度原子更新 |
| Session 职责 | spawn 后不再本地 `flush_into`；`flush`/kex 写经 `WriterHandle`；rekey Done 时 outbound 钥交 Writer 安装并等 ACK |
| 验收 | 全 suite 绿；S1 红用例首因不变；unit：kex try_push 满、InstallAck gen、AtomicWriteProgress 无撕裂 |
| 不包含 | fence/ready-set/StopDiscard/删双账本 |

### S2b — 出站项消息化（减少 WithWriter 闭包）
| 项 | 内容 |
|---|---|
| 内容 | 常见路径改为 `SealRaw(Bytes)` / `SealPayload` 显式消息，缩小 `WithWriter` 使用面 |
| 验收 | 行为不变 + 全绿 |

### S2c — per-channel 出站队列 + 队首 CONFIRMATION fence + 因果序
| 项 | 内容 |
|---|---|
| 内容 | I3 fence；OPEN_CONFIRMATION 队首；EOF/CLOSE 队尾；调度准入 fence 不看窗口 |
| 验收 | close-with-backlog / open-confirm-race 用例 |

### S2d — ready-set + gather + 配额 boost
| 项 | 内容 |
|---|---|
| 内容 | 1-packet 轮转、聚包上限、boost N=8 |
| 验收 | scheduler 对抗 / 老 bulk 最小服务率 |

### S2e — StopDiscard + 生命周期门闩
| 项 | 内容 |
|---|---|
| 内容 | peer CLOSE 时 StopDiscard；closing tombstone；CLOSE 后禁 ADJUST |
| 验收 | stop-discard-race |

### 明确不在 S2
- 双账本删除、permit 收口 → **S5**  
- Reader 独立、ADJUST 旁路 → **S3**  
- HandlerExecutor → **S4**  
- RekeyPolicy 包数界 → **S6**  

---

## 4. S2a 详细设计

### 4.1 任务与通道

```rust
// Session → Writer (bulk)
mpsc::channel::<WriterCmd>(256)

// Session → Writer (kex, priority)
mpsc::channel::<KexCmd>(16)  // try_send only; Full → Cancelling(PeerError or dedicated)

// Writer → Session
unbounded InstallAck / WriterFailed

// Cancel
watch::channel(false)  // true = Cancelling
```

### 4.2 WriterCmd / KexCmd

| 命令 | 队列 | 含义 |
|---|---|---|
| `WithWriter(Box<dyn FnOnce(&mut PacketWriter)+Send>)` | bulk 或 kex | 在 Writer 任务内独占访问 PacketWriter（seal 路径桥接） |
| `InstallOutboundEpoch { newkeys, generation }` | kex | 无 await 安装 outbound cipher/compress/seqn 策略；回 ACK |
| `Shutdown` | kex | 排空后结束 |

`WithWriter` 内嵌 oneshot 回传 `Result`，Session `await` 结果。kex 路径用 kex 队上的 `WithWriter` 以保证优先于 bulk。

### 4.3 NEWKEYS 出站半边

现路径（S1）在 Session 上 `common.newkeys(newkeys)` 同时装入站+出站。

S2a：
1. Session 保留 `remote_to_local` 安装（读侧仍在 Session）  
2. `local_to_remote` + compress 出站部分 → `InstallOutboundEpoch` 给 Writer  
3. Writer：`set_cipher` + compress 重置 +（strict 时）seqn 置 0；**同任务无 await**；`InstallAck{Outbound, gen}`  
4. Session 收到 ACK 后才认为出站半边完成；**双向 ACK+对端 NEWKEYS 齐才 clear rekey deadline** 的完整逻辑：S2a 在 rekey Done 时 **等待 outbound ACK** 再 `clear_rekey_deadline`（inbound ACK 待 S3，S2a 视 inbound 为即时完成以保持现语义）

诚实口径：S2a 的「完成判定」= outbound InstallAck ∧ 对端 NEWKEYS 已处理（现有 Done 路径已含对端 NEWKEYS）；inbound InstallAck 占位为同步 true，S3 接真 Reader。

### 4.4 AtomicWriteProgress

```rust
struct AtomicWriteProgress {
  // 单 Mutex 保护整个 WriteProgress 快照，store 时替换整结构；
  // load 时 clone 整结构 — 禁止分字段读
  inner: Mutex<WriteProgress>,
}
// Writer: lock; update all fields; unlock  (release)
// Session/watchdog: lock; copy snapshot; unlock (acquire)
```

S1 的 `WriteWatchdog` 改为从 `Arc<AtomicWriteProgress>` load 快照驱动 eligible/进度（或 Writer 直接更新 watchdog 输入字段，Session loop 只 load）。

S2a 采用：Writer 更新 `AtomicWriteProgress`；Session loop 的 WriteWatchdog 每轮 `progress.load()` 取 `wire_eligible_bytes` / drained delta。

### 4.5 与 S1 supervisor 的衔接

| S1 机制 | S2a |
|---|---|
| write watchdog | 仍在 Session loop；输入改原子快照 |
| rekey deadline | 仍在 Session；clear 时机加 outbound ACK |
| handshake deadline | 不变 |
| 单 grace teardown | Session 设 cancel；Writer Shutdown；grace 内 join Writer + drain read |
| 首因 slot | 不变 |

### 4.6 每步保绿策略

- 先原子快照 + Writer 骨架可测 unit，再切 run()  
- 初始 KEX（Writer spawn 前）仍用 Session 本地 PacketWriter + 一次 flush，与 S1 相同  
- Writer spawn 在 split 之后、主 loop 之前  
- client 侧：共享类型仅编译所需同改，不抽 Client Writer  

---

## 5. 风险与缓解

| 风险 | 缓解 |
|---|---|
| WithWriter 闭包死锁（Session 持锁等 Writer，Writer 等 Session） | Writer 永不回调 Session；oneshot 仅结果 |
| kex 队满 | try_push → Cancelling + 首因 |
| bulk 队满 | try_send 失败 → 背压/下轮重试或 Cancelling（S2a：主路径 await send，满则等） |
| rekey 装钥竞态 | Install 仅 Writer；Session 装 inbound cipher |
| 测试 flaky | 远程全 suite；不引入 sleep 竞态 |

---

## 6. 验收清单（S2a）

- [ ] `impl-S2-plan.md` 评审可读  
- [ ] Writer 独立任务 + 通道  
- [ ] kex 专队 cap 16 try_push  
- [ ] NEWKEYS 出站 InstallAck  
- [ ] AtomicWriteProgress  
- [ ] `cargo test -p russh --features _test_hooks` 全绿  
- [ ] `impl-S2-report.md`  

---

## 7. 后续（S2b+）一句话

S2b 消息化 seal → S2c fence → S2d scheduler → S2e StopDiscard；S5 删双账本。

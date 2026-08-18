# 完全用 rustls 式状态机实现 channel + session：可行性与成本

- 日期: 2026-08-18
- 范围: **分析 + 编译验证**，不改生产协议路径
- 验证代码: `russh/src/sm_feasibility.rs`（`#[cfg(test)]`，不进入发布产物）
- 对照: rustls `State::handle(self: Box<Self>) -> Box<dyn State>`；本仓库 kex `step(self)`；方案 v2.1 `.omc/plans/russh-proxy-session-rewrite.md`

## 0. 结论（先读这节）

| 问题 | 答案 |
|---|---|
| **完全**按 rustls 做一个覆盖 channel+session 的单一 consume-and-return SM，可行吗？ | **不可行。** 不是工程量问题，是模型不匹配。 |
| 成本高不高？ | 若强行做：与 S2–S8 同量级（~12k LOC 协议面重写）且**得不到** rustls 在 TLS 上的好处；若只做 rustls 真正适用的子集：中等成本、高收益。 |
| 推荐 | **分层组合，不要一个大 SM。** kex/auth 保持（并收紧）线性 SM；channel 用半关闭乘积枚举；session 是 `Handshake ⊗ Kex ⊗ Map<Id, Channel>`。这与方案 v2.1 的 Opening→Confirmed→Closing + Idle/InKex **同构**，不必另开架构。 |

rustls 自己在握手结束后也塌缩成一个 `ExpectTraffic`。TLS 只有一条字节流，所以那一态够用。SSH 在同一条 record 上流式复用 N 条 channel，还要正交地 rekey——把这些压进「一个 rustls SM」会组合爆炸（验证：8 channel → 131_072 态；128 channel → 溢出 `u128`）。

---

## 1. rustls 状态机实际是什么

生产 rustls（`common_state.rs`）的核心不是「凡协议都写成枚举」，而是三件套：

1. **Sans-I/O**：`read_tls` / `process_new_packets` / `write_tls`。状态机同步、无 async、不拥有 socket。
2. **Consume-and-return 握手**：
   ```text
   trait State<Data> {
       fn handle(self: Box<Self>, cx: &mut Context<Data>, msg: Message)
           -> Result<Box<dyn State<Data>>, Error>;
   }
   ```
   每个握手阶段一个类型；非法报文在该类型的 `handle` 里直接 `Err`。`Context` / `CommonState` 扛共享可变数据（密钥、发送缓冲）。
3. **握手后单态**：TLS 1.3 的 `ExpectTraffic` 处理 ApplicationData / KeyUpdate / Alert。KeyUpdate **不是**嵌套的第二台完整握手机。

`Box<dyn State>` 的动机是 TLS 1.2+1.3+扩展下握手态 *associated data 差异极大、数量多*（约数十个类型）。不是因为「枚举不够高级」。

### 1.1 本仓库已经有的 rustls 子集

| 层 | 现状 | 离 rustls 的距离 |
|---|---|---|
| Kex | `ClientKex::step(self) -> KexProgress<Self>` / `ServerKex::step`；内部 `Created → WaitingDh → WaitingForNewKeys` | **已经是** consume-self 线性 SM。`ServerKex::step` 因 `Handler` 而成 `async`——这是对 rustls 同步假设的第一处破裂。 |
| Auth / 加密后会话 | `EncryptedState` 四态枚举 | 线性、合适；但服务端 `process_packet` 对非法组合是 `_ => Ok(())` **静默丢弃**（`server/encrypted.rs`），与 rustls 的 fail-closed 相反。 |
| Channel | `ChannelParams { confirmed, pending_eof, pending_close }` 布尔积 | **不是** SM。8 种 bit 组合都可表示，其中若干非法（未 confirm 却 `pending_eof` 等）。本 fork 已为此修过 WrongChannel / close leak。 |
| I/O | 单任务 `select!` + Handler 内联 await | 与 rustls sans-I/O **相反**。方案 S2–S4 才是在抽 I/O。 |

---

## 2. 为什么「完全 rustls」套不上 SSH

SSH 会话不是一条线性报文序列，而是**正交状态的张量积**：

```text
Session  =  Transport(banner/kex/keys)
         ⊗  Auth(service/userauth/authenticated)
         ⊗  Kex(Idle | InKex)          ← 认证后仍可插入，双向独立 NEWKEYS
         ⊗  ∏_{id} Channel(id)
              Channel = Opening | (WriteHalf ⊗ ReadHalf) × Credit(window)
```

TLS 对应关系：

| 维度 | TLS / rustls | SSH / russh |
|---|---|---|
| 握手 | 线性，rustls 的主场 | kex+auth，同样线性 |
| 握手后 | 一条 ApplicationData 流 | RFC 4254 多路 channel |
| 密钥更新 | `KeyUpdate`，同态内处理 | 完整二次握手，且与 bulk **车道/因果**纠缠（方案 I3/I5） |
| 反压 | 记录层缓冲 | 每 channel 双向窗口；**合法** peer-window=0（G2） |
| 应用回调 | 无（纯库） | `Handler` 全是 async，可阻塞 |

把「session 实现成 rustls SM」若字面理解为 **一个** `Box<dyn State>` 吃所有报文：

- 认证前：可行，等价于收紧 `EncryptedState`。
- 认证后：`ExpectTraffic` 必须再 dispatch 到 N 个 channel 机 + 一个 kex 机。此时外层已经不是 rustls 握手机，而是**路由器**。再把 N 个 channel 展平进外层枚举，态数是 `2 × 4^N`（kex × 半关闭积）。

验证（`sm_feasibility::LinearChannel::flattened_session_states`）：

| N channels | 展平态数 |
|---|---|
| 1 | 8 |
| 4 | 512 |
| 8 | 131_072 |
| 128（方案默认 `max_channels`） | 溢出 u128 |

所以：**不是「可以但贵」，是「展平在数学上不成立」。** rustls 从未面对这个问题。

### 2.1 Channel 也不是线性的

RFC 4254 §5.3：一端 EOF 后，另一端仍可发 DATA。半关闭是**乘积**，不是链：

```text
WriteHalf ∈ {Open, EofSent, CloseSent}
ReadHalf  ∈ {Open, EofRecv, CloseRecv}
```

线性编码必须手写 `LocalEof` / `RemoteEof` / `BothEof`，每个事件处理函数复制一份。窗口是 **credit**，不是生命周期态——把它做成变体会让「zero-window」看起来像协议阶段，看门狗会误杀（方案 G2 / `zero-window-legit`）。验证见 `window_is_credit_not_a_state`。

`Box<dyn State>` **每个 channel 一个 trait object** 更差：

- 128 channel × 堆分配 + vtable，热路径（DATA）多一跳。
- 增加一种报文时没有穷尽性检查（rustls 用 trait object 就是牺牲了这一点）。
- Channel 各态 associated data 几乎同构（id、窗、队列），枚举才是对的。TLS 握手态差异大，才需要 trait object。

### 2.2 Async 与 sans-I/O

rustls SM **不能** `.await`。russh 的 `Handler::channel_open_session` / `auth_*` / `data` 全是 async；`ServerKex::step` 已经因此异步化。

要把 session 做成纯 rustls SM，必须先把 Handler 移出协议机——这正是方案 **S4 HandlerExecutor + Session facade**。它是 rustls 模式的**前置条件**，不是 rustls 模式的替代实现。在现有单 loop 里塞 `Box<dyn State>`，每次 `handle` 仍要 await Handler，会得到「看起来像 rustls、运行时仍是现在这套死锁面」的混合体。

### 2.3 现有病灶不是「缺少 trait object」

方案 P1–P9 里，kex 屏障、车道混用、双账本、Handler 内联，没有一项会被 `Box<dyn State>` 自动修好：

- `kex.active()` 闸住所有 arm：是**任务/车道**问题，不是 handshake 变体不够。
- `confirmed && pending_eof && pending_close`：要修的是 channel **乘积枚举 + fence**（方案 I3），不是 session 级 trait object。
- 服务端 auth 对未知报文 `_ => Ok(())`：收紧 match 即可，不必换表示。

---

## 3. 分层之后，哪些部分 *应该* 学 rustls

可行且划算的子集（与 v2.1 对齐，不是新架构）：

| 层 | 做法 | 相对 rustls | 成本（侵入性） |
|---|---|---|---|
| **Kex** | 保持 `step(self)`；按方案 §4.4 补 ACK/gen/deadline，不要改成 `Box<dyn State>` | 已经是更好的 SSH 编码（枚举、穷尽） | S6 已排；**不要**为 rustls 外形重写 |
| **Auth / EncryptedState** | 非法报文 fail-closed（对齐 rustls）；`InitCompression` 可并入邻态 | 线性枚举足够 | 小：改 `process_packet` 的 `_` 臂 + 恶意客户端用例 |
| **Channel 生命周期** | `Opening \| Established { write, read } \| Dead`；窗留在 `Credit`；fence 项不耗窗 | **不是** rustls，是 RFC 乘积机 | 中：S2 Writer 生命周期门闩的核心，约替换 `ChannelParams` 布尔字段 + 迁 ~20 处 `confirmed`/`pending_*` |
| **Session 外壳** | 认证后就是 dispatcher：报文 → kex 层或 `channels[id]` | 对应 rustls `ExpectTraffic`，但内部是 Map | 随 S3/S4；**不要**再包一层 `Box<dyn SessionState>` |
| **Sans-I/O** | Reader/Writer/Session 三任务 | rustls 的真正架构遗产 | **高**，但方案已因死锁/rekey 独立论证，不因「学 rustls」而增加 |

明确 **不要** 做的：

- 每个 channel `Box<dyn ChannelState>`。
- 把 rekey 编进 channel 变体（会重建 `kex.active()` 全连接屏障；验证 `composed_session_keeps_rekey_orthogonal_to_channels`）。
- 在抽出 I/O / Handler 之前，把现 loop 改成 rustls trait。
- 用 typestate（`Channel<Open>` vs `Channel<Eof>` 作公开 API）——公开 `Channel` 跨 await、被 `HashMap` 持有，typestate 会把 API 撕碎；内部枚举即可。

---

## 4. 成本（按改动面，不按日历）

协议相关约 **11.7k LOC**（`session.rs` + 双端 `session`/`encrypted`/`kex` + `channels` + `pending_inbound` + supervisor）。

| 方案 | 改动面 | 风险 | 与 v2.1 关系 |
|---|---|---|---|
| A. 单一 rustls SM 覆盖 channel+session | 几乎整表；另造任务模型仍要做一遍 | 态爆炸；async 无法进 `handle`；热路径 vtable；与 G5 API 冲突 | **另开炉灶**，否定三任务拆分，不采纳 |
| B. 只把现有枚举改成 `Box<dyn State>` | kex + EncryptedState 表示层 | 丢失穷尽性；零语义收益 | 纯成本，不采纳 |
| C. 推荐子集（§3） | ChannelParams → 乘积枚举；auth fail-closed；kex 保持枚举 | 中：与 Writer fence / StopDiscard 同一批不变量 | **叠在 S2/S3 上**，不是新切片 |
| D. 先抽 sans-I/O 再考虑 SM 外形 | 即 S2–S4 | 已评审 | SM 是协议合法性层，挂在 SessionTask/Writer 内 |

C 的量级：新类型 + 迁移 `confirmed`/`pending_eof`/`pending_close`/`is_established_channel` 调用点（双端 encrypted/session、flush、close_discarding_pending）。不碰公开 `Channel`/`Handler` 签名（G5）。

相对收益：C 能在类型上消灭「未 confirm 就 data / fence 被窗锁死」这类已经出过 bug 的组合；A/B 不能加速 S2，反而拖住 Writer 提取。

---

## 5. 验证了什么

`russh/src/sm_feasibility.rs` 编译进 `cargo test -p russh`，断言：

1. 线性握手 SM 在 auth 前拒绝 `ChannelData`（rustls 适用区）。
2. Channel 半关闭是乘积：本地 EOF 后仍可收 DATA。
3. 窗口是 credit：peer-window 0→4096 不改变变体（G2）。
4. 今日三布尔 flag 表示 8 态，合法 live 只有 4。
5. 展平 SM：`2×4^N` 在 N=8 已五位数，N=128 爆。
6. 组合 session 里 rekey 不改变 channel 变体。

额外的编译期证据：spike 第一版把 `CloseSent` 留在 `WriteHalf` 里，`rustc` 以 `E0004` 拒绝 `CloseSent × Eof` 未覆盖。布尔 `pending_close && pending_eof` 不会报这个错——这正是枚举 SM 相对 flag 的收益。随后把 CLOSE 收成 channel 级 `Dead`，半关闭只保留 `{Open,Eof}²`。

生产路径未改。本文件不替代 S2 拆解方案。

---

## 6. 对后续切片的含义

- **S2 Writer**：按 v2.1 做 Opening→Confirmed→Closing 时，用 §3 的 `WriteHalf ⊗ ReadHalf` 枚举落地，而不是再引入 `Box<dyn State>`。
- **S3 Reader**：入站合法性走同一套 channel 枚举；不要第三套 flag。
- **S4**：HandlerExecutor 才使 session 协议机可以接近 rustls 那样同步；在那之前不要为「像 rustls」改 EncryptedState 的控制流。
- **Auth `_ => Ok(())`**：小修复，可挂在任意切片的恶意报文用例上，不阻塞 S2。

**一句话**：学 rustls 要学的是 **sans-I/O + 线性阶段 fail-closed + 共享 Context**；不要学「整个连接一个 trait object」。SSH 的 session/channel 必须是组合机。完全 rustls 化不可行，成本高且方向错；按层采用则可行、成本中等、且已在 v2.1 里。

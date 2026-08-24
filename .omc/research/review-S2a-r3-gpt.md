# S2a 终审（r3，窄口径）

## 判决：CONDITIONAL

r2 的 Writer panic、cancel sender-drop 饥饿、grace 后 abort+await、`notify_one` 丢边沿和假测试均已实质修正；但还剩两项会阻止 GO 的必修，以及一个提交前必须处理的交付项：

1. **总 teardown grace 仍叠加。** Writer 使用一个绝对 `grace_at` 后，read drain 又从更晚的 `now` 启动最多 1s 的新预算；默认最坏仍是 5s + 1s，违反 S1“单一 grace 不叠加”：`russh/src/server/session.rs:1434-1464`，默认值与契约见 `russh/src/server/mod.rs:135-137,176`。
2. **暂存首因仍有一个 early-return 绕过窗口。** Install 失败写入 `pending_supervisor_cause` 后，`reply()` 末尾仍执行 fallible `session.flush()?`；若它失败，run loop 进入 `Err(e) => return Err(e)`，不会读取暂存 cause：`russh/src/server/mod.rs:1274-1315,1342-1356`，`russh/src/server/session.rs:1290-1301,1551-1561`。
3. **交付项：核心新文件尚未被 git 跟踪。** `pub mod writer` 已由跟踪文件引用，但实现文件仍显示 `?? russh/src/server/writer.rs`；若漏入 changeset，提交态不能构建：`russh/src/server/mod.rs:61-66`，`russh/src/server/writer.rs:1-529`。

最小修法：read drain 直接复用 `grace_at`（只消费 Writer 剩余预算）；run loop 在检查 `reply_result` 的 Err 之前先 `take()`/`record_cause`，若 cause 已暂存则保留它为首因并走统一 teardown，Err 只作为次因记录；补一条“暂存 cause + reply 尾部错误仍记录首因”的确定性测试。提交时把 `russh/src/server/writer.rs` 纳入 changeset。

## 1. panic 路径：YES

select 前退出和四臂 enable 谓词可化为：

- 提前退出：`S && !O`，其中 `S=shutting_down`，`O=current.is_some() || !out_q.is_empty()`：`russh/src/server/writer.rs:252-296`。
- cancel：`C=poll_cancel`：`russh/src/server/writer.rs:305-322`。
- kex：`K=!S`：`russh/src/server/writer.rs:324-341`。
- drain：`D=O`：`russh/src/server/writer.rs:343-358`。
- bulk：`B=!S && !bulk_closed && out_q.len() < OUT_Q_SOFT_CAP`：`russh/src/server/writer.rs:298-300,360-374`。

穷举结果：

| 状态 | select 前/臂状态 | 结论 |
|---|---|---|
| `S && !O` | select 前 sweep；仍空则 `shutdown()`、ACK、`break` | 不进入 select |
| `S && O` | `D=true` | 至少 drain 臂启用 |
| `!S`（任意 `O/bulk_closed/poll_cancel`） | `K=true` | 至少 kex 臂启用 |

因此 `bulk_closed + shutting_down + has_out` 由 drain 臂覆盖；drain 即使一次 poll 内把队列写空并立即返回，也只是回到外层 loop，下一轮命中提前退出，不会在同一次 select 中变成“全臂禁用”：`russh/src/server/writer.rs:343-358,385-437`。kex 臂只在 `S=true` 时禁用，此时分别由提前退出或 drain 覆盖。

新测确实复现原调度：current-thread runtime 中 `spawn_writer` 后、任何 `yield/await` 前立刻 `cancel_tx.send(true)`，且 bulk/out_q/current 均空；同时把 JoinError 作为失败而非成功接受：`russh/src/server/writer.rs:481-496`。

## 2. cancel 饥饿：YES

`cancel.changed()` 的 `Err` 分支同一轮设置 `shutting_down=true` 与 `poll_cancel=false`；此后 guard 永久关闭该臂：`russh/src/server/writer.rs:305-320`。其它所有把 `poll_cancel` 置 false 的路径也同时进入 shutdown：`russh/src/server/writer.rs:229-246,331-339,363-371`。

`biased` 下没有另一条永久立即 Ready、却不改变状态的生产路径：关闭的 kex/bulk receiver 各只会被消费一次并转入 shutdown；`cancel.changed() -> Ok(false)` 消费当前版本后会重新 Pending；drain 的 Ready 与真实写入/队列清空绑定，清空后下一轮提前退出。优先级也把 cancel、kex 放在 drain 前：`russh/src/server/writer.rs:302-375`。

## 3. grace、abort 与 guard：NO（Writer helper 本身 YES；总 teardown 回归）

`stop_writer_task` 使用调用者给出的单一绝对 `grace_at`。到点后调用 `abort()`，禁用 timer 臂并继续 await 同一个 JoinHandle，直到 join 返回；`is_cancelled`、`is_panic` 和其它 JoinError 分开处理：`russh/src/server/writer.rs:137-183`。生产测试现在直接调用该 helper，`HangWrite` 的 write/flush/shutdown 永久 Pending：`russh/src/server/writer.rs:446-478`。

guard 也已保持 armed 到 helper join 完成之后才 disarm：`russh/src/server/session.rs:1066-1085,1434-1444`。若外部取消并 drop 整个 run future，`stop_writer_task` 的局部 JoinHandle 会被 detach，但仍 armed 的 guard 随栈析构发送 cancel 并用独立 AbortHandle abort Writer，能兜住任务泄漏：`russh/src/server/session.rs:1066-1082`。外层 future 已被 drop 时无法再 await join，这不否定正常 teardown 的 abort+await 保证。

但 Writer join 后又创建新的 `read_grace_at = now + min(teardown_grace, 1s)`，没有复用 `grace_at` 的剩余预算：`russh/src/server/session.rs:1436-1464`。默认 `teardown_grace=5s`，所以永久阻塞 Writer + read drain 的最坏总时长是约 6s；这是 S1 单一 grace 的实质回归：`russh/src/server/mod.rs:135-137,176`。

最小修法：删除 `read_grace_at`，对 `read_drain` 使用同一个 `timeout_at(grace_at, ...)`；Writer 已耗尽预算时 read drain 应立即超时。

## 4. `notify_one`：YES

所有容量进度/队空/Writer 退出通知均已改为 `notify_one()`：`russh/src/server/writer.rs:378,385-386,402-425,430-433`。这里仅有 Session 一个容量消费者；多个 drain 通知合并成一个 permit 是正确语义，因为一次唤醒就会在 loop 顶重新读取权威 `pending_bytes`/`sealed_backlog`：`russh/src/server/session.rs:1131-1146,1367-1370`。

“旧 permit 被无关 notified 消费”不会重新制造丢边沿：消费旧 permit 后会立刻重算 backlog；若仍需等待，新的 `notified()` waiter 会接住之后的真实 drain。若 select 的其它臂获胜，被取消但已获 `notify_one` 的 waiter 会把单通知转交/保留，不等同于 `notify_waiters` 的无 permit 广播。通知仅由真实 write、队空或退出触发，permit 又会合并，最多多一次重算，不会反向永久忙唤醒：`russh/src/server/writer.rs:396-435`。

新测先 enqueue，等待 `pending_bytes==0`，之后才创建 `cap.notified()`，并要求 200ms 内消费先存 permit；在 current-thread runtime 中 Writer 从原子减到 0 至紧随其后的同步 `notify_one()` 之间没有调度让出，因此确实构造 notify 先于 waiter：`russh/src/server/writer.rs:499-524`。

## 5. 首因收口：NO

直接 Install 失败分支的映射本身正确：

- kex queue Full/Closed：暂存 `PeerError`：`russh/src/server/mod.rs:1274-1281`。
- 缺失 deadline：fail closed 为 `PeerError`，不存在无界 ACK fallback：`russh/src/server/mod.rs:1283-1290`。
- ACK channel/Writer error：暂存 `PeerError`：`russh/src/server/mod.rs:1291-1305`。
- ACK timeout：暂存 `RekeyTimeout`：`russh/src/server/mod.rs:1298-1311`。

正常 `reply() -> Ok` 时，run loop 会 `take()` 并用统一 `record_cause` 记录 first cause、置 disconnected：`russh/src/server/session.rs:1290-1296`。无界 ACK fallback 确已删除。

但传递并非“所有退出都无遗漏”：暂存 cause 后仍会执行 `session.flush()?`，而 `Session::flush` 自身包含 `enc.flush(...)?` 和 `begin_rekey()?`；一旦这里报错，`reply_result` 为 Err，run loop 在读取 pending cause 的分支之外直接 return，只触发硬 abort guard：`russh/src/server/mod.rs:1342-1356`，`russh/src/server/session.rs:1290-1301,1551-1561`。因此首因契约尚未形式闭合。

最小修法：`reply(...).await` 返回后，无论 Result 是 Ok/Err，都先读取并记录 `pending_supervisor_cause`；有 staged cause 时走统一 Cancelling/teardown，随后错误只作次因。应为该组合补确定性测试；现有 case1 在 rekey 完成前由 rekey deadline 触发，未覆盖 InstallAck timeout/Full/Closed 的暂存路径：`russh/tests/test_malicious_client_s0.rs:114-125`。

## 6. 回归实跑：YES（记录一次无关既有测试抖动）

先单独运行三个 Writer 测试：

```text
cargo test -p russh --features _test_hooks server::writer::tests:: -- --nocapture

running 3 tests
test server::writer::tests::writer_empty_queue_shutdown_no_panic ... ok
test server::writer::tests::capacity_notify_before_waiter_is_not_lost ... ok
test server::writer::tests::writer_join_finishes_after_grace_abort ... ok
test result: ok. 3 passed; 0 failed; 176 filtered out
```

完整命令第二轮真实 exit 0：

```text
cargo test -p russh --features _test_hooks

running 179 tests
test server::writer::tests::capacity_notify_before_waiter_is_not_lost ... ok
test server::writer::tests::writer_empty_queue_shutdown_no_panic ... ok
test server::writer::tests::writer_join_finishes_after_grace_abort ... ok
test result: ok. 179 passed; 0 failed

running 10 tests
test s0_incident_repro_rekey_stall_client_initiated ... ok
test s0_talk_no_read ... ok
test s0_write_stall_during_rekey ... ok
test s0_zero_window_legit ... ok
test result: ok. 10 passed; 0 failed; finished in 8.51s

Doc-tests russh
test result: ok. 3 passed; 0 failed; 8 ignored
```

G2、case1、case2、case4 的断言位置分别为 `russh/tests/test_malicious_client_s0.rs:312-323,114-126,238-253,373-399`，本轮均绿。

为完整披露：完整命令首轮在未改动的 ssh-agent 测试连接刚创建的 Unix socket 时一次 `ConnectionRefused`，结果是 lib 178/179；失败点为 `russh/src/keys/mod.rs:1251-1266`。该单测立即独立复跑 1/1 通过，随后上述第二轮完整 suite exit 0。它与本轮 S2a 改动无 diff 交集，不改变本次 CONDITIONAL 的代码判决，但说明该既有测试有启动竞态抖动。

## GO 前必修清单

1. read drain 复用 Writer 的同一个绝对 `grace_at`，不得另起最多 1s 的尾段：`russh/src/server/session.rs:1436-1464`。
2. 无论 `reply_result` 为 Ok/Err，都先消费并记录 `pending_supervisor_cause`，消除暂存后 `flush()?` 的 early-return 绕过，并补组合测试：`russh/src/server/mod.rs:1274-1356`，`russh/src/server/session.rs:1290-1301`。
3. 将核心 `russh/src/server/writer.rs:1-529` 纳入最终 changeset；当前它仍是未跟踪文件，而 `russh/src/server/mod.rs:61-66` 已依赖它。

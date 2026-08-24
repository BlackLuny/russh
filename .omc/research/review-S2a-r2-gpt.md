# S2a 复审（第 2 轮，窄口径）

- 基线：`HEAD e814204`，评审对象为当前未提交 S2a 工作树
- 日期：2026-08-12
- 范围：仅复核上轮三条必修、P2 修复及直接副作用

## 判决：NO-GO

三条必修没有真闭合：

1. **P0-1 NO**：主 cancel=true 饥饿已修，但 sender-drop/false 仍可重复 Ready；更严重的是生产 teardown 的外层绝对 grace 会先取消内层 `stop_writer`，此时 JoinHandle 已被 `take()`，abort 没执行且后置检查也看不到 handle。另有 shutdown 空队列时 `select!` 全臂禁用 panic，已独立复现。
2. **P0-2 NO**：总 backlog 口径已收敛，10 用例连续 4 轮均绿；但 Writer 用的是 `notify_waiters()`，不是带单 permit 的 `notify_one()`。Writer 在 Session 注册 `notified()` 前 drain 的边沿仍会永久丢失，原停摆存在可达竞态窗。
3. **P1 NO**：ACK timeout 已有界且 mid-session rekey 的 deadline 在生产路径已注册；但 timeout、kex queue Full/Closed 都只从 `reply()` 返回 `Err`，随后 `run()` 直接 early-return，没有进入 supervisor Cancelling/统一 teardown，也没有写 first-cause slot。

P2 的字节行为已修对；G2 与 case1/2/4 本轮实跑均保持契约。

## 重要机制更正

**接受更正。** 上轮所写“`drain_writes()` pending 时外层 `select!` 不能运行其他臂”是错误的；`tokio::select!` 会并发 poll 各臂，cancel/kex Ready 可以取消 pending 的 drain future。连续 drain 不应拆回单次 write。

本轮 P0 否决依据不是该旧机制，而是下面三个独立问题：sender-drop/false 饥饿、嵌套 grace 丢 abort、空队列全臂禁用 panic。

## P0-1：NO

### 1. cancel 臂是否还可能反复 Ready 饿死写臂：NO（仍有一条路径）

- cancel 值变成 `true` 的正常路径已修：顶部 `borrow_and_update()` 令 `shutting_down=true`，之后 `poll_cancel=false`，不会继续 poll `changed()`：`russh/src/server/writer.rs:204-212,249-264`。
- 但 `cancel.changed()` 的返回值被完全忽略。若最后一个 sender 在值仍为 `false` 时 drop，`changed()` 每轮立即返回 `Err`；分支内 `borrow_and_update()` 仍是 false，`shutting_down` 不变，`poll_cancel` 下轮仍为 true。由于 `biased`，该臂会持续抢占 drain/bulk：`russh/src/server/writer.rs:253-264`。

最小修法：显式 match `cancel.changed().await`；`Err(_)` 也只消费一次并进入 shutdown（或至少永久关闭该臂）。保留连续 `drain_writes()`。

### 2. `WriterTeardownGuard` 是否覆盖全部 `run()` 退出路径：NO

- Writer spawn 后的普通 `?`/`return Err` 和 panic unwind 会 drop guard；Drop 只做同步 `watch::send(true)` 与 `AbortHandle::abort()`，**没有 await，也没有阻塞 I/O**：`russh/src/server/session.rs:1052-1083`。这一部分是 YES。
- 但正常 teardown 在任何 await 之前先把 guard disarm：`russh/src/server/session.rs:1450-1453`。此后若 `run()` future 被取消/drop，或者外层 grace 取消 teardown future，guard 不再 abort Writer。故“全部退出路径”整体为 NO：`russh/src/server/session.rs:1451-1487`。

最小修法：在确认 Writer 已终止并 await 完 abort 结果之前保持 guard armed；最后才 disarm。

### 3. grace 到期是否必然 abort 并 drop write half：NO

生产路径存在确定的 deadline 次序错误：

1. 外层先计算 `grace_at = now + teardown_grace`：`russh/src/server/session.rs:1452`。
2. 稍后进入 `stop_writer(..., teardown_grace)`；内部又从更晚的时刻启动一个完整相对 grace：`russh/src/server/session.rs:1453-1461,1118-1123`。
3. 因此外层 `timeout_at(grace_at, teardown)` 必然早于内层 `timeout(grace, join)` 到期。外层先取消 `stop_writer`，而 JoinHandle 已在 `join.take()` 中被移入被取消的 future：`russh/src/server/session.rs:1118-1119,1476`。
4. 被取消 future drop JoinHandle 只会 detach Writer，不会 abort；同时原 Option 已是 None，后面的 `writer_join.is_some()` 为 false，1ms 兜底不运行：`russh/src/server/session.rs:1477-1487`。
5. guard 又已在第 1 步前 disarm。因此永久 pending 的 socket write 可以越过 grace 存活，write half 不保证被 drop。

最小修法：只用一个绝对 `grace_at`；等待时借用 `JoinHandle`，不要提前 `take()`。外层超时后在 future 外执行 `join.abort(); let _ = join.await;`，确认 write half 所在任务已 drop，再 disarm guard。不要嵌套两个同长度、起点不同的 timeout。

### 4. graceful shutdown 是否排空已接受的 bulk 密文：YES（该子项本身）

- 进入 shutdown 后会用 `bulk_rx.try_recv()` 把 mpsc 中已接受的 `WireBytes` 搬入 `out_q`：`russh/src/server/writer.rs:228-247`。
- 写空后还有一次最终 bulk sweep，发现新项则继续写：`russh/src/server/writer.rs:316-340`。
- `request_shutdown()` 仅做 kex/bulk `try_send`，不再 await 满队列：`russh/src/server/writer.rs:147-155`。

这修掉了上轮的“shutting_down 后直接遗弃 bulk mpsc”问题，但不能抵消上述 grace/abort 漏洞。

### 5. 新增 writer grace 测试是否有效：NO（阻塞构造真实，生产证明无效）

`HangWrite` 的 write/flush/shutdown 确实永久 `Pending`：`russh/src/server/writer.rs:431-447`。但测试没有调用生产 `stop_writer`，也没有走 Session 的嵌套 timeout；它只是 sleep 50ms 后由测试代码直接 `join.abort()`，再证明 Tokio 的手工 abort 返回 JoinError：`russh/src/server/writer.rs:450-474`。

所以“socket 永久阻塞”构造是真的，“grace 到期生产代码必然 abort”是假证明。

### 6. 新洞：shutdown 空队列会 panic（已独立复现）

当 Writer 第一次被 poll 前 cancel 已为 true、且 bulk/out_q/current 为空时：顶部置 `shutting_down=true`，随后 `poll_cancel=false`、kex recv disabled、`has_out=false`、`can_pull_bulk=false`；`select!` 四臂全部 disabled 且没有 `else`：`russh/src/server/writer.rs:204-212,249-256,259-313`。

独立 current-thread 复现（`spawn_writer(tokio::io::sink())` 后在首次 poll 前 send cancel）真实输出：

```text
thread 'main' panicked at russh/src/server/writer.rs:256:13:
all branches are disabled and there is no else branch
writer join: Ok(Err(JoinError::Panic(...)))
```

生产 `stop_writer` 又把 `Ok(Err(JoinError))` 匹配为笼统 `Ok(_)`，会把 Writer panic 当正常结束：`russh/src/server/session.rs:1118-1123`。

最小修法：在进入 `select!` 前处理 `shutting_down && !has_out` 的最终 bulk sweep/`shutdown()`/ACK/退出；同时检查 JoinError，不能把 panic 当成功。

## P0-2：NO

### 1. `sealed_backlog` 是否唯一权威：YES

- `WriterHandle.pending_bytes` 在 `try_send_wire` 接受前增加，Full/Closed 回滚，socket 每次成功 write 后减少，因此覆盖 bulk mpsc + `out_q` + `current`：`russh/src/server/writer.rs:84-87,90-118,369-411`。
- Session 唯一 HWM 判定是 `PacketWriter.pending_bytes + WriterHandle.pending_bytes`，并同时把同一总数交给 watchdog：`russh/src/server/session.rs:1153-1168,1207-1209`。
- 全仓搜索没有残留以 `PacketWriter` 单独值或 `AtomicWriteProgress.wire_eligible_bytes` 判 HWM 的路径。`queue_eligible()` 结果在 Writer 中被丢弃，不参与 HWM：`russh/src/server/writer.rs:197-202,352-365`。

三处字节口径已实质收敛；死的 `queue_eligible` 建议删除，但它本身不改变判决。

### 2. Notify 是否会丢边沿：NO（仍会丢）

- Writer 在进度与退出时调用的是 `notify_waiters()`：`russh/src/server/writer.rs:344-345,384-387,410-411`。
- Session 到 `select!` 内才创建 `capacity_notify.notified()`：`russh/src/server/session.rs:1258,1383-1386`。
- `notify_waiters()` 只唤醒当时已经注册的 waiter，不保存 permit。竞态为：Session 先用旧 `sealed_backlog` 判定 HWM、Writer 随后 drain 并在 Session 注册前 notify、Session 再进入 select；若此时无读包/定时器/Writer event，便可睡到长 supervisor timer，原停摆重现。

最小修法：单消费者这里改用 `notify_one()`，利用它“无 waiter 时保留一个 permit、多个通知合并”的语义；Session 下一次 `notified()` 会立即消费 permit 并重算 backlog。不要改回单次 write。

### 3. 会不会反向忙唤醒：当前没有无限空转证据，但实现选择不对

当前每个成功 write 都 `notify_waiters()`，可能造成高频调度，但通知与真实 drain 进度绑定，不是无条件 Ready 的永久自旋。改成 `notify_one()` 后 permit 会合并，至多留下一个未消费 permit；消费一次并重算后不会凭空永久 Ready，因此不会引入反向忙循环。

### 4. 两个原失败用例及新增用例稳定性：YES（观测层面）

- 完整套件一轮 10/10；随后 `test_malicious_client_s0` 连续独立复跑 3 轮，均 10/10，三轮耗时分别 8.50s、8.49s、8.49s。
- 原两例断言分别位于 `russh/tests/test_malicious_client_s0.rs:173-180,592-603`；新增跨 HWM 连续 6 次增长断言位于 `russh/tests/test_malicious_client_s0.rs:716-740`。

这证明常见调度下恢复稳定，但不能证明 `notify_waiters()` 的 lost-edge 窗不存在；该竞态可由 API 语义直接判定。

## P1：NO

### 1. ACK 等待点的 rekey deadline 是否已注册：YES（生产 mid-session invariant）；缺失时会无界

- 所有生产 mid-session rekey 都经 `begin_rekey()`；当 `common.encrypted.is_some()` 时先递增 generation 并 register 绝对 deadline：`russh/src/server/session.rs:2200-2227`。
- InstallAck 只在 `common.encrypted.is_some()` 的 Done 分支等待，所以该生产路径上 `remaining()` 已注册：`russh/src/server/mod.rs:1252-1274`。
- `remaining()` 已过期返回 `Some(Duration::ZERO)`，未注册返回 `None`：`russh/src/server/supervisor.rs:404-411`。当前 `None` 分支会直接 `wait.await`，确会退化为无期限：`russh/src/server/mod.rs:1287-1299`。

在当前生产 invariant 下 None 分支不可达，但最小硬化应删除无界 fallback：缺 deadline 应 fail closed/internal invariant error，不能无限等。

### 2. ACK timeout 是否干净拆连并记录 `RekeyTimeout`：NO

- timeout 会返回 typed `Error::RekeyTimeout(outbound_gen)`，不会 panic：`russh/src/server/mod.rs:1287-1295`。
- 但 `reply()` 的 Err 在 run-loop 中直接 `return Err(e)`；只触发 RAII abort，绕过 `record_cause` 和统一 graceful teardown：`russh/src/server/session.rs:1312-1317`。
- 因而 first-cause slot 不会记录 `DisconnectCause::RekeyTimeout`，也不会发送 best-effort supervisor DISCONNECT。它是“typed error + early hard drop”，不是要求的 Cancelling 状态收口。

### 3. `try_install_outbound_epoch` Full/Closed 是否进入 Cancelling 并记首因：NO

- `try_install_outbound_epoch` 把 Full/Closed 都折叠成 `Error::SendError`：`russh/src/server/writer.rs:121-133`。
- caller 仅日志后 `return Err`：`russh/src/server/mod.rs:1273-1279`；run 随后走上述 early-return：`russh/src/server/session.rs:1312-1317`。
- `WriterEvent::KexQueueFull` 仍没有发送点，只有接收处理臂：定义/处理分别为 `russh/src/server/writer.rs:70-76`、`russh/src/server/session.rs:1360-1369`。

连接最终会因 run 返回而被拆掉，错误没有被吞；但它没有进入 supervisor Cancelling、没有记录 first cause，故契约未闭合。

最小修法：ACK timeout 与 try-push Full/Closed 必须先把原因送回 Session 主循环（或写入 Session 的 pending supervisor cause），由主循环调用同一 `record_cause`、置 disconnected，并走统一 teardown。timeout 记 `RekeyTimeout`；Full/Closed 至少记现有枚举中的 `PeerError`。不要在 `reply()` 内直接 early-return 绕过收口。

## P2：YES

`take_pending_wire_bytes()` 先取 buffer，再显式删除 `[0..flush_cursor)`，最后清 cursor：`russh/src/sshbuffer.rs:420-441`；restore 只恢复未写 bytes 并保持 cursor=0：`russh/src/sshbuffer.rs:444-463`。行为上不会重复上线已写前缀。

`debug_assert` 实际检查的是 cursor 不越界，而不是“cursor 必须为 0”：`russh/src/sshbuffer.rs:429-434`。注释略不准确，但显式 skip 已使 P2 闭合，不单列为必修。

## 新副作用与首因契约

- **G2 zero-window：YES。** peer SSH window=0 的数据仍停在未 seal 的 channel pending_data，不进入 sealed backlog/watchdog；实跑断言 session 存活且 cause=None 通过：`russh/tests/test_malicious_client_s0.rs:257-323`。
- **case1：YES。** first cause=`RekeyTimeout` 断言通过：`russh/tests/test_malicious_client_s0.rs:114-126`。
- **case2：YES。** first cause=`WriteStalled` 断言通过：`russh/tests/test_malicious_client_s0.rs:238-253`。
- **case4：YES。** first cause=`WriteStalled` 断言通过：`russh/tests/test_malicious_client_s0.rs:373-399`。
- `WriterTeardownGuard::drop` 无 await/阻塞；问题是 disarm 时机和未 await abort 完成，而不是 Drop 内阻塞：`russh/src/server/session.rs:1064-1077,1451`。

## 独立回归实跑

命令：

```text
cargo test -p russh --features _test_hooks
```

真实关键输出（exit 0）：

```text
running 177 tests
test server::writer::tests::writer_join_finishes_after_grace_abort ... ok
test result: ok. 177 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Running tests/test_kex_shared_secret.rs
running 4 tests
test test_kex_done_on_rekey ... ok
test result: ok. 4 passed; 0 failed

Running tests/test_malicious_client_s0.rs
running 10 tests
test s2a_healthy_continuous_read_grows_past_hwm ... ok
test s0_incident_repro_rekey_stall_negative_no_rekey ... ok
test s1_rekey_stall_other_connection_unaffected ... ok
test s0_zero_window_legit ... ok
test result: ok. 10 passed; 0 failed; finished in 8.50s

Doc-tests russh
test result: ok. 3 passed; 0 failed; 8 ignored
```

完整命令中的其余 integration test binaries 也全部通过。首次追加复跑在受限沙箱内因本地端口 bind 返回 `PermissionDenied (Operation not permitted)` 环境失败；按原命令在允许本地 TCP 的执行环境重跑后，连续三轮均为：

```text
test result: ok. 10 passed; 0 failed; finished in 8.50s
test result: ok. 10 passed; 0 failed; finished in 8.49s
test result: ok. 10 passed; 0 failed; finished in 8.49s
```

## GO 前最小必修

1. 修复 Writer sender-drop/false 的 `changed() -> Err` 饥饿；在 shutdown 空队列时于 `select!` 前正常退出，且不要吞 JoinError panic。
2. teardown 只保留一个绝对 grace；不要 `take()` 后把 JoinHandle 放进会先被外层取消的 timeout。超时后必须 abort **并 await join 完成**，guard 在此之前保持 armed。
3. capacity wake 改为可保留单 permit 的 `notify_one()`（或等价 watch/version），补一个确定性“notify 先于 waiter 注册”测试。
4. ACK timeout 与 try-install Full/Closed 先记录 supervisor first cause，再走统一 Cancelling/teardown；去掉 deadline=None 时的无界 ACK fallback。
5. 把 `writer_join_finishes_after_grace_abort` 改为调用生产 teardown helper，断言它对永久 Pending writer 自动在 grace 后 abort，而不是测试代码手工 abort。

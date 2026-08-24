# S2a 对抗评审：WriterTask 骨架（出站半边）

- 基线：`git HEAD = e814204`（S0+S1 GO）
- 评审对象：当前未提交 S2a 工作树
- 日期：2026-08-12

## 判决：NO-GO

序完整性本身成立，ACK-only 在当前 S2a 切分下也没有制造“旧钥继续 seal”的假绿；但有三项必须修复的实质问题：

1. Writer 的 socket write 不可被 cancel/kex 打断，单一 `grace_at` 到期后又没有 abort Writer；任务和 write half 可越过 grace 存活，正常 shutdown 还会丢弃尚在 bulk mpsc 的已接收密文。
2. Session 在 HWM/队满后没有订阅 Writer 的 drain/capacity 边沿；健康下行会在 Writer 已排空后仍睡眠，现有恶意客户端套件已稳定出现两个吞吐停摆回归。
3. kex 控制面实际不是“cap16 try-push、满即 Cancelling”，并且 InstallAck 在 `reply()` 内无期限等待；Writer 若卡在 bulk `write().await`，rekey deadline 本身也无法被 Session 轮询。

上述任一项都足以否决；这不是 S2b 才需解决的 epoch 迁移问题。

## 必修项

### P0 — teardown/grace 不再保证 Writer 终止或 write half 被关闭

**依据：**

- Writer 进入 `drain_writes()` 后，真正的 `w.write(...).await` 在内部循环中执行；外层 `select!` 的 cancel/kex 分支在该 future 返回前无法运行：`russh/src/server/writer.rs:260-299,352-398`。
- cancel/Shutdown 一旦令 `shutting_down=true`，`can_pull_bulk` 立即变 false；Writer 不再读取 bulk mpsc，却只用 `current/out_q` 是否为空决定 shutdown，因此已经被 `try_send` 接受但仍在 mpsc 中的密文会被丢弃：`russh/src/server/writer.rs:253-258,307-327`。
- Session 把 `writer_join.await` 放进 `timeout_at(grace_at, teardown)`，超时后只丢弃等待 future，没有调用 `writer_join.abort()`；丢弃 Tokio `JoinHandle` 不会终止任务：`russh/src/server/session.rs:1381-1403`。
- 多个 run-loop 错误路径会在统一 teardown 代码之前直接 `return Err`，例如读失败和 handler/reply 失败：`russh/src/server/session.rs:1201-1205,1252-1255`。这些路径也没有 RAII cancel+abort 收口。
- kex `Shutdown` 满时退回 `bulk_tx.send().await`；但 Writer 在 `shutting_down` 后不再 pull bulk，这个 fallback 可一直等到外层 grace 被取消，之后仍没有 abort：`russh/src/server/writer.rs:175-186,258,308`。

**最小修法：**

1. 让 `writer_join` 在 grace future 之外仍可控；`timeout_at` 失败后必须 `abort()`，并 await abort 完成，确保 write half 被 drop。
2. 每个 socket `write/flush/shutdown` 用同一绝对 `grace_at`/cancel 做 `select!`；不能把连续 drain 作为一个不可打断的 select arm。
3. 所有 `run()` 退出路径经统一 cleanup 或 RAII guard 发送 cancel；不要让 `?`/`return Err` 绕过 Writer 收口。
4. 明确区分 graceful drain 与 forced cancel：graceful Shutdown 必须处理所有已接受的 bulk mpsc 项；forced cancel 到期则立即 abort/drop，不能既停止 pull 又声称“drain 后 ACK”。

### P1 — HWM 后无 drain 唤醒，健康连接吞吐停摆；总 backlog 也漏算 bulk mpsc

**依据：**

- `try_send_wire` 的 `pending_bytes` 统计 bulk mpsc + Writer 内未写字节：`russh/src/server/writer.rs:105-128,165-168,383-388`。
- 但 ship HWM 看的是 `AtomicWriteProgress.wire_eligible_bytes`：`russh/src/server/session.rs:1440-1447`；该值只由 `current + out_q` 重算，不含仍在 bulk mpsc 的最多 256 项：`russh/src/server/writer.rs:203-226,337-349`。
- PacketWriter 达 HWM 后，Session 禁用 outbound receiver：`russh/src/server/session.rs:1150-1152,1320`。Writer 的成功写只改 Mutex 快照，不向 Session 发事件；Session 的 `select!` 没有 progress/capacity watch 分支：`russh/src/server/session.rs:1295-1331`。因此 Writer 排空后，Session 仍不会及时重试 `ship_sealed_to_writer`。
- 实测 `cargo test -p russh --features _test_hooks`：lib **176/176** 通过，但 `test_malicious_client_s0` **7/9**，以下两个健康流量断言失败：
  - `s0_incident_repro_rekey_stall_negative_no_rekey`：4.03s 内 `start_bytes == end_bytes == 3,866,624`；断言位于 `russh/tests/test_malicious_client_s0.rs:173-181`。单测单独复跑仍失败（exit 101）。
  - `s1_rekey_stall_other_connection_unaffected`：健康连接 B 在 A teardown 后字节数不增长；断言位于 `russh/tests/test_malicious_client_s0.rs:592-603`。

这不是合法 zero-window 背压：两个失败用例的客户端在持续读取，预期是健康下行继续流动。

**最小修法：**

1. 用一个权威的“全部 sealed-but-not-written bytes”计数覆盖 bulk mpsc、`out_q/current` 和 PacketWriter staging；ship/intake HWM 按总字节而非仅 item 数/当前 Writer staging 判断。
2. Writer 在成功 drain、队列从满转可写或总量跌破 HWM 时，通过 `watch`/`Notify` 唤醒 Session；Session `select!` 收到边沿后立即重试 ship，并重新开放 outbound intake。
3. 加一个“静默但持续读的健康客户端、跨 HWM 后仍持续增长”的定向回归；现有两个失败用例必须恢复。

### P1 — kex 控制/ACK 可能被 bulk write 无限期压住，rekey deadline 也救不了

**依据：**

- 生产路径 `install_outbound_epoch()` 使用 `kex_tx.send().await`，并继续无期限等待 oneshot ACK；声明的非阻塞 `try_install_outbound_epoch()` 没有调用点，`WriterEvent::KexQueueFull` 也没有发送点：`russh/src/server/writer.rs:75-80,134-163`；唯一生产调用在 `russh/src/server/mod.rs:1270-1276`。
- Writer 若已进入 `drain_writes()` 的 `w.write().await`，不能处理 kex queue 或 cancel：`russh/src/server/writer.rs:260-299,375`。
- Session 在处理 rekey Done 的 `reply()` 内直接 await InstallAck：`russh/src/server/mod.rs:1252-1276`。握手完成后 `reply()` 不受 timeout 包裹：`russh/src/server/session.rs:1226-1251`；而 rekey deadline 只在主循环顶部轮询：`russh/src/server/session.rs:1119-1125`。因此 ACK wait 卡住时，`RekeyTimeout` 不会触发。

**最小修法：**

1. Writer 每个 write 点必须可被 kex/cancel 抢占，同时保留 `current+cursor` 的密文字节顺序。
2. Install 生产路径改成 `try_send`；Full/Closed 立即进入 Cancelling 并记录首因，不得 await 队列容量。
3. ACK 等待移入 Session 的显式 rekey 子状态，由主 `select!` 同时轮询 ACK 与同一绝对 rekey deadline；或至少用该 generation 已注册的绝对 deadline 包住 ACK wait并正确记录 `RekeyTimeout`。

## 重点证伪逐条结论

### 1. 序完整性：YES

- `take_pending_wire_bytes()` 原子取走当前整个 Vec，失败恢复时把原 bytes prepend 到后来可能存在的 buffer 前：`russh/src/sshbuffer.rs:420-447`。
- `ship_sealed_to_writer()` 从 take 到同步 `try_send`/restore 之间没有 `.await`；Session 单任务不可能在中间再次 seal：`russh/src/server/session.rs:1432-1465`。
- 成功项全部走同一 bulk mpsc，Writer `push_back`/`pop_front`，socket partial write 用 `current+flush_cursor`：`russh/src/server/writer.rs:203-204,307-310,337-398`。

所以顺序为：已成功 ship 的旧字节 → 本次失败后恢复的字节 → 同轮以后新 seal 的字节；逐字节不倒序。这里没有密文流损坏洞。

### 2. teardown / 取消是否仍由单一 grace 兜住：NO

见 P0。Writer 可越过 grace 悬挂；正常 Shutdown 会忽略 bulk mpsc 中已接受的帧；kex 队满 fallback 也会阻塞。Session 退出后 Writer **不必然**终止。

### 3. 看门狗 Mutex 长锁 / lost update：长锁 NO，lost update NO；整体 eligible 口径 NO

- `note_write`/`store_eligible` 只在同步字段更新期间持 `std::sync::Mutex`，锁不跨 `write().await` 或整个 drain：`russh/src/server/supervisor.rs:133-152`。
- 两个更新均在同一 Writer 任务串行发生；Session 的 `observe_eligible` 更新的是本地 `WriteWatchdog`，不是 `AtomicWriteProgress`：`russh/src/server/session.rs:1104-1112`。因此没有题述的互相覆盖 lost update。
- 但快照的 `wire_eligible` 漏掉 bulk mpsc，不能代表“全部已 seal 可写字节”；它会低估 HWM/rekey 前队深。该口径错误造成的是 P1 的 backlog 与活性问题，而非 Mutex 撕裂。
- SSH peer-window=0 的数据仍留在 `pending_data`、未 seal，不进入 eligible；G2 语义本身未被误杀，且对应测试通过：`russh/tests/test_malicious_client_s0.rs:260-323`。

### 4. HWM 双闸活性代价：NO（当前实现会误伤健康读者）

“TCP 不写时 eligible 不降、ship 永停”本来是预期的有界背压，并应由 WriteStalled 结束；“SSH peer-window=0 未 seal”也应保持 G2。实际问题是健康 TCP 已 drain 后没有 capacity wake，Session 仍停在旧 HWM 状态。两个运行时失败已直接证明吞吐塌方，不只是理论性能担忧。

### 5. rekey 延迟是否与 S1 等价：NO

S1 的 intake gate观察同一个 PacketWriter 总 pending（允许一次 batch overshoot）；S2a 额外加入 256-item bulk mpsc，而 ship gate不计这 256 项。KEXINIT/NEWKEYS 密文保持 FIFO 是正确的，但它们现在可排在额外的、非 HWM 字节界的 mpsc backlog 后：`russh/src/server/writer.rs:37-38,105-111`，`russh/src/server/session.rs:1440-1452`。

最小修法是按总 sealed bytes 施加 S1 级别的字节界并增加 drain wake；不能重新引入 kex wire 优先队列，否则会再次破坏 seqn。

### 6. ACK-only InstallAck 是否是假信号：NO（但等待路径本身有 P1）

Writer ACK 确实是 no-op：`russh/src/server/writer.rs:239-243,273-276`；但当前真实 outbound cipher 已先由 Session 的 `common.newkeys(newkeys)` 安装：`russh/src/server/mod.rs:1257-1267`。事件接收臂只记录日志，不清 deadline、不恢复 bulk：`russh/src/server/session.rs:1295-1300`。rekey deadline 是在同步请求的 oneshot ACK 返回、Done 路径完成并置 Idle 时才清：`russh/src/server/mod.rs:1270-1304`。

因此它在 S2a 是冗余活性握手，不会让旧 epoch 被当成新 epoch。真正的问题是它可能永远等不到，且等待期间 deadline 不运行；见上一 P1。

### 7. 回归与首因：NO（套件非全绿；已通过的首因正确）

命令：`cargo test -p russh --features _test_hooks`

- lib：176 passed。
- `test_kex_shared_secret`：4 passed，含 `test_kex_done_on_rekey`。
- `test_malicious_client_s0`：**7 passed / 2 failed**，失败为健康无 rekey 连续流和他连隔离连续流，见 P1。
- case1 通过其 `RekeyTimeout` 断言：`russh/tests/test_malicious_client_s0.rs:114-126`。
- case2 通过其 `WriteStalled` 断言：`russh/tests/test_malicious_client_s0.rs:238-253`。
- case4 通过其 `WriteStalled` 断言：`russh/tests/test_malicious_client_s0.rs:385-399`。
- G2 zero-window 通过：`russh/tests/test_malicious_client_s0.rs:302-323`。
- `InitCompression | Authenticated` 判定仍在 `russh/src/server/session.rs:1086-1096`，且 auth-success-idle 测试通过其 3s idle/no-cause 断言：`russh/tests/test_malicious_client_s0.rs:618-669`。

注意：case2/4 的首因槽在 grace 前已经写入；它们通过不能证明 Writer task 在 grace 后已结束，故不抵消 P0。

## GO 前最小验收

1. 修复 Writer 可中断 I/O、统一退出收口、grace 超时 abort/drop half，并新增“Writer join 在 grace 内结束”的测试。
2. 总 sealed backlog 纳入同一字节 HWM，Writer drain/capacity 唤醒 Session；上述 2 个失败用例恢复。
3. kex control 使用 try-push fail-closed，ACK wait 与同一 generation 的绝对 rekey deadline 并行受监督。
4. 重跑 `cargo test -p russh --features _test_hooks`，要求全部通过且 case1=`RekeyTimeout`、case2/4=`WriteStalled`、G2 无 cause。

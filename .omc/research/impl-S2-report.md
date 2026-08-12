# S2a 实现报告（含 r2 NO-GO 修复）

- 实现者: grok-4.5
- 日期: 2026-08-12
- Brief: `.omc/plans/impl-S2-brief.md` + fix-brief + **review-S2a-r2-gpt.md**
- 分支: `russh-proxy-session-rewrite`

---

## 0. 评审历程

| 轮次 | 判决 | 关键 |
|---|---|---|
| 初审 | NO-GO | 7/9 健康流停摆等 |
| 第 1 轮修复 | 用例绿但机制未闭合 | 报告误称全绿已更正 |
| **r2** | **NO-GO** | 空队列 panic、嵌套 grace 丢 abort、notify 丢边沿、首因未记、假测试 |
| **本轮** | 按 r2 §GO 最小必修 5 条闭合 | 见 §2 + §6 实跑 |

---

## 1. r2 最小必修闭合

### 1. 空队列 panic + JoinError

- **修**: `shutting_down && !has_out` 时在 **`select!` 之前** 做最终 bulk sweep → `shutdown()` → ACK → `break`。
- **cancel `Err`**: `match cancel.changed()`；`Err(_)`（sender drop）只消费一次并 `poll_cancel=false`。
- **`stop_writer_task`**: 不把 `Ok(Err(JoinError))` 当成功；`is_panic()` 打 warn。

### 2. 单一绝对 grace + abort await

- 删除外层 `timeout_at` 套内层相对 grace。
- `stop_writer_task(grace_at)`：`&mut JoinHandle` 等；超时 `abort()` 后**继续 await join**。
- Guard 在 join 完成**之后**才 disarm。

### 3. `notify_one` + 先于 waiter 测试

- 全部改为 `notify_one()`（单消费者 permit）。
- 测试 `capacity_notify_before_waiter_is_not_lost`。

### 4. 首因契约

- Install Full/Closed / 缺 deadline → `pending_supervisor_cause = PeerError`。
- ACK timeout → `RekeyTimeout`。
- **不** `return Err` 绕过；`reply` Ok 后 run 取 cause → `record_cause` + `disconnected` → 统一 teardown。
- 删除 `remaining()=None` 无界 ACK fallback。

### 5. 生产 teardown 测试

- `writer_join_finishes_after_grace_abort` 调用 **`stop_writer_task`**（非手写 abort）。
- `writer_empty_queue_shutdown_no_panic`：cancel 先于首 poll、空队列，2s 内 `Ok(())`。

### 其它

- 删除死代码 `queue_eligible`。
- P2 注释改为：assert 只检查 cursor **in-bounds**，skip 前缀。

**未改**: 连续 `drain_writes`；Scheme C；Reader/HandlerExecutor；kex/窗口口径。

---

## 2. 关键代码

| 路径 | 变更 |
|---|---|
| `server/writer.rs` | 空队列 pre-select 退出；cancel Err；`notify_one`；`stop_writer_task`；3 unit tests |
| `server/session.rs` | 单一 grace teardown；`pending_supervisor_cause`；guard 晚 disarm |
| `server/mod.rs` | Install 失败 stage cause + install_ok 门控 |
| `sshbuffer.rs` | P2 注释校正 |

---

## 3. 真实门禁输出（远程，必须保留）

命令：

```text
cargo test -p russh --features _test_hooks -- --test-threads=4
```

task_id: `t-01KZSZS88F1DDQEMZRRNP5A6VE`（全 suite success）

### Writer 确定性测试（单独）

```text
cargo test -p russh --features _test_hooks --lib writer:: -- --nocapture
running 3 tests
test server::writer::tests::writer_empty_queue_shutdown_no_panic ... ok
test server::writer::tests::capacity_notify_before_waiter_is_not_lost ... ok
test server::writer::tests::writer_join_finishes_after_grace_abort ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 176 filtered out; finished in 0.05s
```

task_id: `t-01KZSZRD7AC19JF3YEZ5GHESCR`

### malicious_client + kex（全 suite 摘录）

```text
Running tests/test_kex_shared_secret.rs
running 4 tests
test test_kex_done_on_rekey ... ok
test result: ok. 4 passed; 0 failed; finished in 0.63s

Running tests/test_malicious_client_s0.rs
running 10 tests
test s0_write_stall_during_rekey ... ok
test s0_talk_no_read ... ok
test s0_incident_repro_rekey_stall_client_initiated ... ok
test s0_incident_repro_rekey_stall_negative_no_rekey ... ok
test s1_auth_success_idle_survives_handshake_deadline ... ok
test s1_rekey_stall_other_connection_unaffected ... ok
test s2a_healthy_continuous_read_grows_past_hwm ... ok
test s1_trickle_read_min_drain_on ... ok
test s1_trickle_read_min_drain_off ... ok
test s0_zero_window_legit ... ok
test result: ok. 10 passed; 0 failed; finished in 10.95s
```

全 suite 各 binary 均为 `test result: ok`（exit 0）。

### 首因抽查（10/10 内）

| 用例 | 期望 | 结果 |
|---|---|---|
| case1 rekey-stall | RekeyTimeout | ok |
| case2 talk-no-read | WriteStalled | ok |
| case4 write-stall-during-rekey | WriteStalled | ok |
| G2 zero-window | 无 cause | ok |

---

## 4. r3 CONDITIONAL 两处小修（闭合即 GO）

1. **单一 grace**：read drain 复用同一个绝对 `grace_at`（`timeout_at(grace_at, read_drain)`），不再 `now + min(teardown_grace, 1s)` 叠加。
2. **首因窄窗**：`reply_result` 无论 Ok/Err，**先** `take`+`record_cause(pending_supervisor_cause)`，再处理 Err。

### r3 实跑（task `t-01KZT0HZH8KMJPPBKKHG5TA5Y8` / lib `t-01KZT0NPYAH0P6KJ9SZ1N6YHTW`）

```text
cargo test -p russh --features _test_hooks -- --test-threads=4
# exit 0

test_malicious_client_s0: ok. 10 passed; 0 failed; finished in 10.95s
test_kex_shared_secret:   ok. 4 passed (含 test_kex_done_on_rekey)
lib:                      ok. 179 passed; 0 failed; finished in ~15s
```

本轮未复现 `test_sign_request_cert_missing_key_returns_agent_failure` 的 ConnectionRefused flaky。

---

## 5. 后续

S2b PacketWriter→Writer / 真 epoch；S2c–e 车道；S3 Reader；S4 HandlerExecutor；S5 双账本删除。

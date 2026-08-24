# S2a 终审(第 3 轮,窄口径):验证 r2 的 5 条必修是否真闭合

你上轮判 NO-GO(`.omc/research/review-S2a-r2-gpt.md`),grok 已修。
**本轮只验那 5 条 + 修复副作用,判 GO / CONDITIONAL(列必修)/ NO-GO。**
只报会改变判决的实质项,每条 file:line。

## 硬性纪律(上轮越界,本轮必须遵守)
- **只准写 `.omc/research/review-S2a-r3-gpt.md` 这一个文件。**
- **禁止删除或修改仓库中任何其它文件**(上轮你执行了
  `rm -rf .claude AGENTS.md CLAUDE.md`——那是用户仓库,不在你职权内;所幸均非 git 跟踪文件,无损失)。
  看到不认识的文件就在报告里指出,不要动手。
- 禁止改任何 `russh/src/**` 或测试代码;只读 + 跑测试。

## grok 自称的修法(勿默认采信)
| # | r2 必修 | 自称修法 |
|---|---|---|
| 1 | 空队列全臂禁用 panic | `shutting_down && !has_out` 时在 **select 之前** 完成 sweep→`shutdown()`→ACK→`break` |
| 1b | cancel sender-drop 饥饿 | `match cancel.changed()`:`Err` 只消费一次并永久关 `poll_cancel` |
| 1c | JoinError 当成功 | `stop_writer_task` 区分 `is_cancelled` / `is_panic` |
| 2 | 嵌套 grace 丢 abort | **单一绝对** `grace_at`;超时 `abort()` 后 **await join**;guard 在 join 完成后才 disarm |
| 3 | `notify_waiters` 丢边沿 | 改 `notify_one` + 新测 `capacity_notify_before_waiter_is_not_lost` |
| 4 | 首因绕过 | Install 失败写 `pending_supervisor_cause`,run loop 里 `record_cause`;删无界 ACK fallback |
| 5 | 假测试 | `writer_join_finishes_after_grace_abort` 改调生产 `stop_writer_task` |
| + | — | 新测 `writer_empty_queue_shutdown_no_panic`;删死代码 `queue_eligible` |

自称实跑:Writer 3 个确定性测试绿、lib 179 passed、`test_malicious_client_s0` 10 passed、全 suite exit 0。

## 请独立判定(每条 YES/NO + 依据)
1. **panic 路径是否真消失**:除 `shutting_down && !has_out` 外,还有没有**其它**能让 `select!` 四臂全禁的组合
   (例如 `bulk_closed` + `shutting_down` + `has_out` 为真但 drain 立刻返回、或 kex 臂禁用后的边角)?
   请把 select 前的提前退出与四个臂的 enable 谓词做**穷举组合**核对。新测 `writer_empty_queue_shutdown_no_panic`
   是否真复现原复现场景(首次 poll 前 cancel 已 true)?
2. **cancel 饥饿是否彻底**:`Err(_)` 只消费一次的实现,在 sender drop 后是否**永久**不再 poll 该臂?
   还有没有其它每轮立即 Ready 的臂能在 `biased` 下饿死 drain?
3. **grace 与 abort**:`stop_writer_task` 是否**必然**在 grace 到期后 `abort()` **并 await 到 join 返回**
   (write half 确实 drop)?`writer_guard` 现在在 join 完成后才 disarm——那么在 `stop_writer_task` 内部
   被外部取消(run future 被 drop)时,guard 是否仍能兜住?
   ⚠️ **我发现一处可能的新副作用请你判定**:teardown 现在是
   `stop_writer_task(grace_at = now + teardown_grace)` **之后**又起
   `read_grace_at = now + teardown_grace.min(1s)`(`session.rs:1436-1464`)——这是**两段 grace 叠加**
   (默认最坏 5s + 1s = 6s),而 S1 的验收项之一正是「单一 grace 不叠加」。
   请判定这是否构成回归(若是,最小修法应是 read drain 复用同一个 `grace_at` 的剩余预算)。
4. **`notify_one` 是否真解决丢边沿**:permit 语义用对了吗?会不会出现「permit 被无关的一次 `notified()` 消费掉,
   而真正需要唤醒的那次没醒」?新测是否真构造了「notify 先于 waiter 注册」?有无反向忙唤醒。
5. **首因是否真收口**:`pending_supervisor_cause` 从 `reply()`/Install 失败点到 run loop `record_cause`
   的传递路径是否**无遗漏**(所有失败分支都会经过那个读取点吗?还有没有 early-return 绕过)?
   ACK timeout 是否记 `RekeyTimeout`、Full/Closed 是否记 cause?无界 ACK fallback 是否真删掉?
6. **回归**:**自己实跑** `cargo test -p russh --features _test_hooks`,贴真实输出(含 3 个新 Writer 测试)。
   确认 G2 与 case1/2/4 首因契约仍绿。

## 输出
`.omc/research/review-S2a-r3-gpt.md`:判决 + 各条 YES/NO + 新洞定位与最小修法。

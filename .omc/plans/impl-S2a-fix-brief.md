# S2a 评审结论:NO-GO —— 必修 3 项(+1 潜伏隐患)

评审:gpt-5.6-sol high(`.omc/research/review-S2a-gpt.md`,含独立交叉审)+ Claude。**先读那份报告。**

**首先一条硬事实:你报告里的「全 suite 绿」不成立。** 评审实跑
`cargo test -p russh --features _test_hooks` → lib 176/176 绿,但
**`test_malicious_client_s0` 只有 7/9**,失败两例都是「健康连接应持续流动」:
- `s0_incident_repro_rekey_stall_negative_no_rekey`:4.03s 内字节数**纹丝不动**(`start==end==3,866,624`),断言 `tests/test_malicious_client_s0.rs:173-181`,单独复跑仍 exit 101。
- `s1_rekey_stall_other_connection_unaffected`:健康连接 B 在 A teardown 后不再增长,断言 `:592-603`。

以后**不要在没实跑目标 suite 的情况下写「全绿」**。门禁自证必须贴真实运行输出。

---

## P0-1 Writer 永不退出 + 100% CPU 空转 + write half 泄漏(Claude 诊断,机制以此为准)

`server/writer.rs:260-268` 的 select 是 `biased`,第一臂 `_ = cancel.changed()` **无条件启用**。

> ⚠️ gpt 报告里「Writer 卡在 `w.write().await` 时外层 select 的 cancel/kex 臂无法运行」这一**机制描述是错的** ——
> `tokio::select!` 会并发轮询所有臂,pending 的 `drain_writes` 可以被 cancel/kex 抢占。**不要**为此把连续 drain
> 拆回「每次 select 只写一次」,那正是你之前修掉的吞吐塌方。真正的机制是下面这个:

teardown 时 `run()` 先 `cancel_tx.send(true)`;之后 `cancel.changed()` **每次立即 Ready**
(cancel 已置位后语义如此;`run()` 返回、`cancel_tx` 被 drop 后 `changed()` 返回 `Err` 同样立即 Ready)。
`biased` 下它永远第一个命中 → **写臂 `drain_writes` 再也轮不到**。此时若 `out_q` 非空,
底部 `break` 的前提(`current.is_none() && out_q.is_empty()`)永不成立:

- Writer 任务**永不退出**且**100% CPU 空转**;
- 它独占的 socket write half **不被 drop**(S1 靠 `run()` 返回时 drop halves 砍掉挂死 IO,这条保护没了);
- 最后那份 DISCONNECT / 残留密文**永远写不出去**;
- `session.rs:1381-1403` 的 `writer_join.await` 超 grace 后**只是丢弃 future,没有 `abort()`** —— tokio 丢 JoinHandle 不终止任务,任务泄漏到进程结束。

teardown 时 `out_q` 非空是**常态**(退出前刚 `flush()`+`ship_sealed_to_writer()` 过 DISCONNECT)。测试仍能过只是因为进程退出掩盖了泄漏。

**最小修法**
1. cancel 臂加 `if !shutting_down` 守卫(或改 `borrow_and_update()`),使 cancel 只触发一次,之后让位给 drain。
2. grace `timeout_at` 到期后**必须** `writer_join.abort()`(并 await abort 完成),确保 write half 被 drop。
3. `run()` 的**所有**提前 `return Err` 路径(读失败 `session.rs:1201-1205`、handler/reply 失败 `:1252-1255` 等)
   都要经统一 cleanup / RAII guard 发 cancel + abort,别让 `?` 绕过 Writer 收口。
4. 区分 graceful drain 与 forced cancel:`shutting_down` 后 `can_pull_bulk` 立刻变 false
   (`writer.rs:253-258,307-327`),于是**已被 `try_send` 接受、仍在 bulk mpsc 里的密文被静默丢弃**,
   却仍声称「drain 完成后 ACK」。graceful 路径必须把 mpsc 里已接受的项排空;forced 路径到期直接 abort,不要两头不靠。
5. `WriterHandle::shutdown` 在 kex 队满时回退到 `bulk_tx.send().await`(`writer.rs:175-186`),
   而 `shutting_down` 后 Writer 不再 pull bulk → 这个 fallback 会一直等到 grace 被取消。修掉。

## P0-2 HWM 后没有 drain 唤醒 → 健康连接吞吐停摆(**这就是那两个失败用例**)

- ship 闸看 `AtomicWriteProgress.wire_eligible_bytes`(`session.rs:1440-1447`),但该值只由 Writer 的
  `current + out_q` 重算(`writer.rs:203-226,337-349`),**不含仍在 bulk mpsc 的最多 256 项**;
  而 `try_send_wire` 的 `pending_bytes` 又是另一套口径(`writer.rs:105-128,165-168,383-388`)。口径分裂。
- PacketWriter 达 HWM 后 Session 关掉 outbound intake(`session.rs:1150-1152,1320`);
  Writer 写成功只改 Mutex 快照,**不发事件**,Session 的 `select!` 里**没有 progress/capacity 臂**
  (`session.rs:1295-1331`)→ Writer 排空后 Session 仍在睡,不会重试 ship。**健康下行就此停摆。**

**最小修法**
1. 收敛成**唯一权威的「已 seal 未上线总字节」计数**,覆盖 PacketWriter staging + bulk mpsc + `out_q/current`;
   ship/intake 两个 HWM 都按**总字节**判(恢复 S1 的字节界口径),不要按 item 数或只看 Writer staging。
2. Writer 在「成功 drain / 队列由满转可写 / 总量跌破 HWM」时用 `watch` 或 `Notify` **唤醒 Session**;
   Session `select!` 加一臂,收到边沿立即重试 `ship_sealed_to_writer` 并重新开放 intake。
3. 补一个定向回归:静默但**持续读**的健康客户端,跨过 HWM 后字节数必须**持续增长**。
   上述 2 个现有失败用例必须恢复绿。

## P1 kex 控制面不是「try-push 失败即 Cancelling」,且 InstallAck 无期限等待

- `install_outbound_epoch()` 用的是 `kex_tx.send().await` + 无期限等 oneshot ACK(`writer.rs:134-163`);
  你声明的非阻塞 `try_install_outbound_epoch()` **没有任何调用点**,`WriterEvent::KexQueueFull` **没有发送点**(死代码)。
- 唯一生产调用在 `server/mod.rs:1270-1276`,位于 `reply()` 内;握手完成后 `reply()` **不受 timeout 包裹**
  (`session.rs:1226-1251`),而 rekey deadline **只在主循环顶部轮询**(`session.rs:1119-1125`)。
  ⇒ ACK 卡住时 `RekeyTimeout` **永远不会触发**,S1 的 rekey 兜底在此失效。

**最小修法**:Install 生产路径改 `try_send`,Full/Closed 立即进 Cancelling 并记首因;
ACK 等待要么移入 Session 的显式 rekey 子状态、由主 `select!` 与**同 generation 的绝对 rekey deadline** 一起轮询,
要么至少用该绝对 deadline 包住 ACK wait 并正确记 `RekeyTimeout`。

## P2(潜伏,现在不可达,但 S2b 必踩)— `take_pending_wire_bytes` 忽略 `flush_cursor`

`sshbuffer.rs:420-447` 把整个 buffer 取走却**不跳过 `[0..flush_cursor)` 已写前缀**,`restore` 还把 cursor 清零。
今天唯一的 Session 侧 `flush_into`(初始 KEX,`session.rs:1014`)超时即 `HandshakeTimeout` 返回、成功即清空,
所以摸不到;但 S2b 迁 PacketWriter 时会**重复上线已写字节 → 密文流不可恢复损坏**。
现在就加 `debug_assert!(self.flush_cursor == 0)` 或显式跳过前缀。

---

## 评审已确认**没问题**的部分(别乱动)

- **密文字节顺序:严格保持**(take→try_send→restore 之间无 `.await`,失败项 prepend,单一 FIFO)。**不要**重新引入 kex wire 优先队列。
- Mutex 无长持锁、无 lost update;G2(peer-window=0)语义未被误杀,对应用例绿。
- ACK-only 不是假信号(真钥已由 Session `newkeys()` 装),只是冗余握手 + 上面的活性洞。
- `InitCompression | Authenticated` 握手判定完好,auth-idle 回归绿;case1=`RekeyTimeout`、case2/4=`WriteStalled` 首因正确。

## GO 门(必须全部满足,并贴真实运行输出)

1. `cargo test -p russh --features _test_hooks` **全部通过**(含现在失败的 2 例),case1=`RekeyTimeout`、case2/4=`WriteStalled`、G2 无 cause。
2. 新增「Writer join 在 grace 内结束」的测试(证明无泄漏/无空转)。
3. 新增「健康持续读客户端跨 HWM 后字节持续增长」的定向回归。
4. 仍不得删 Scheme C / 双账本,不得动 Reader / HandlerExecutor,不得改 kex/窗口口径,S1 supervisor 语义保持。

改完更新 `.omc/research/impl-S2-report.md`(逐条闭合说明 + **真实**测试输出)。

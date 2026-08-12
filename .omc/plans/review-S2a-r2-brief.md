# S2a 复审(第 2 轮,窄口径):验证 NO-GO 三条必修是否真闭合

你上轮判 NO-GO(`.omc/research/review-S2a-gpt.md`),grok 已修。
**本轮只验这三条是否真闭合 + 修复有无新副作用,判 GO / CONDITIONAL(列必修)/ NO-GO。**
避免过度设计:只报会改变判决的实质项,每条给 file:line。

## 先看一条重要更正(我在 fix-brief 里对你上轮的机制判断做了纠正)
你 P0 的依据之一「Writer 进入 `drain_writes()` 后,外层 `select!` 的 cancel/kex 分支在该 future 返回前无法运行」
**是错的**:`tokio::select!` 并发轮询所有臂,pending 的 `drain_writes` 可被 cancel/kex 抢占。
真因是 **`biased` + cancel 置位后 `changed()` 每轮立即 Ready → 饿死写臂**(sender drop 后返回 Err 同样立即 Ready)。
因此**不接受**把连续 drain 拆回「每次 select 只写一次」的修法(那会重新引入吞吐塌方)。
请以此口径复核 —— 若你仍认为原机制成立,请给出可复现的依据。

## grok 自称的修法(勿默认采信)
- **P0-1**:cancel 只进一次 graceful;shutdown 后用 `try_recv` 排空 bulk mpsc;grace 到期 `writer_join.abort()`;
  新增 `WriterTeardownGuard` 兜住 `?`/early return;`request_shutdown` 改为仅 `try_send`。
- **P0-2**:统一 `sealed_backlog = PacketWriter.pending + writer.pending`;`Notify` 唤醒 Session 重试 ship / 重开 intake;
  新增用例 `s2a_healthy_continuous_read_grows_past_hwm`。
- **P1**:改用 `try_install_outbound_epoch` + `timeout(rekey_deadline.remaining())`,超时记 `RekeyTimeout`。
- **P2**:`take_pending_wire_bytes` 跳过 `flush_cursor` 前缀 + `debug_assert`。
- 自称实跑:`test_malicious_client_s0` 10 passed / 0 failed;lib 177 passed;
  含新测 `writer_join_finishes_after_grace_abort`、`test_kex_done_on_rekey` 绿。

## 请独立判定(每条 YES/NO + 依据)
- **P0-1 是否真闭合**:cancel 臂现在还会不会在某条路径上反复 Ready 饿死写臂?
  `WriterTeardownGuard` 是否**覆盖全部** `run()` 退出路径(含 `?` 传播、panic unwind)?
  grace 到期后 `abort()` 是否**必然**执行并 drop write half(不是只在 happy path)?
  graceful shutdown 是否真把**已被 `try_send` 接受、仍在 bulk mpsc 的密文**写出去(不再静默丢弃)?
  新测 `writer_join_finishes_after_grace_abort` 是否真复现「socket 永久阻塞」场景,还是走了 happy path 的假证明?
- **P0-2 是否真闭合**:`sealed_backlog` 是否**唯一权威**(三处口径 PacketWriter / bulk mpsc / out_q+current 是否已收敛,
  有无残留旧口径判 HWM)?`Notify` 唤醒有无**丢边沿**(Writer 在 Session 进入 select 之前 notify → 永久错过 → 停摆重现)?
  `Notify::notify_one` 的 permit 语义是否被正确利用?会不会反向**忙唤醒**空转?
  两个原失败用例恢复绿是否稳定(能否复跑数次)?
- **P1 是否真闭合**:`rekey_deadline.remaining()` 在 ACK 等待点是否**一定**已注册(未注册时 remaining 是什么?
  可能退化成无期限或 0)?超时后是否干净拆连并记 `RekeyTimeout`(不 panic、不半状态)?
  `try_install_outbound_epoch` 的 Full/Closed 是否**真进 Cancelling 并记首因**,还是只返回 Err 被吞?
- **新副作用**:`sealed_backlog` 口径变化会不会**误杀合法 zero-window 背压**(G2 必须仍绿)或
  **漏武装**看门狗(事故场景 case1/2/4 首因必须仍为 RekeyTimeout / WriteStalled)?
  `WriterTeardownGuard` 的 Drop 里若有 await/阻塞需特别指出。
- **回归**:请**自己实跑** `cargo test -p russh --features _test_hooks`,贴真实输出;
  不接受转述。确认 10/10 + lib 全绿 + 首因契约。

## 输出
`.omc/research/review-S2a-r2-gpt.md`:判决 + 上述各条 YES/NO + 新洞定位与最小修法。
先读 `russh/src/server/writer.rs` 全文、`server/session.rs` 的 teardown/HWM/ship 段与新增 guard、
`server/mod.rs` 的 install/ACK 路径、`sshbuffer.rs` take/restore、新增测试。

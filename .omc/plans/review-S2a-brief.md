# S2a 对抗评审:WriterTask 骨架(出站半边)

grok 已交付 S2a(工作树未 commit,基线 = `git HEAD` = `e814204` S0+S1 GO)。
**判 GO / CONDITIONAL(列必修)/ NO-GO。避免过度设计:只报会改变判决的实质项,每条给 file:line 依据。**

- 方案:`.omc/plans/russh-proxy-session-rewrite.md` §4.1/§4.2/§4.3/§4.4
- 本片 brief:`.omc/plans/impl-S2-brief.md`;拆解:`.omc/research/impl-S2-plan.md`;报告:`.omc/research/impl-S2-report.md`
- 代码:`russh/src/server/writer.rs`(新 399 行)+ `server/{session,mod,supervisor}.rs`、`sshbuffer.rs` 的 `git diff`

## S2a 自称做了什么(勿默认采信)
1. Writer 独立 tokio 任务,独占 socket write half;**`PacketWriter` 密封仍在 Session**(S2b 再迁 epoch)。
2. 所有密文走**单一有序 bulk 通道**(cap 256);kex 专队(cap 16)只承载 `InstallOutboundEpoch`/`Shutdown` 控制面。
   —— 因为踩过坑:kex 优先 wire 队把后密封的 KEXINIT 插到先密封 bulk 前,chacha20 seqn 序被打乱 → 对端 `PacketSize` 垃圾。
3. NEWKEYS 出站半边:Session 本地 `newkeys()`,Writer 回 `InstallAck{Outbound,gen}`(**S2a 为 ACK-only,不真装钥**)。
4. `AtomicWriteProgress`:自称 release-store/acquire-load,**实为 `Mutex<WriteProgress>` 整结构**;`note_write(n)` 同步 `wire_eligible -= n`。
5. HWM 双闸:intake(`can_receive_outbound`)只看 `packet_writer.pending_bytes()`;
   ship(`ship_sealed_to_writer`)在 `wire_eligible >= HWM` 时停,密文留在 PacketWriter;
   ship 用 `try_send`,满则 `restore_pending_wire_bytes` 写回 PacketWriter(避免 Session 阻塞在 send 上读不到入站 WINDOW_ADJUST)。
6. Writer 写臂内**连续 drain**(不是每次 select 只写一次)。

## 请重点证伪(每条 YES/NO + 依据)
- **序完整性**:`take_pending_wire_bytes`/`restore_pending_wire_bytes` 的取-塞回路径,在
  「取出 N 字节 → try_send 失败 → 写回」和「部分 ship 成功」交错时,wire 字节顺序是否**逐字节严格保持**?
  有无可能与 Session 同轮新密封的字节交错/倒序?一旦错序即密文流损坏(不可恢复)。
- **teardown / 取消**:Writer 现在持有 write half —— S1 的**单一 `grace_at`** 是否仍**真正兜住** flush+shutdown
  (Writer 任务内的 drain 是否受同一绝对期限约束,还是可能超出 grace 继续写/悬挂)?Session 退出后 Writer 任务
  是否必然终止(无泄漏、无 socket half 悬挂)?`Shutdown` 走 kex 队 cap16,满了怎么办?
- **看门狗保真**:`Mutex<WriteProgress>` 是否可能被 Writer 在**长 drain 期间持锁**,致 supervisor 读进度被阻塞/看到陈旧值?
  `note_write` 里 `wire_eligible -= n` 与 Session 侧 `observe_eligible` 的写入是否互相覆盖(lost update)导致
  eligible 虚低 → **看门狗漏武装**(事故场景漏杀)或虚高 → **误杀**合法 zero-window 背压(G2 必须仍绿)。
- **HWM 双闸的活性代价**:ship 在 `wire_eligible>=HWM` 停 —— 健康高吞吐 flood 下是否引入**吞吐塌方**或
  与 bulk cap 256 的组合下产生**死等**(eligible 只由 note_write 减,若 Writer 因对端零窗口长期不写,eligible 不降,
  ship 永停 —— 这是期望行为还是会误伤合法慢读者?与 S1 的 G2 语义是否一致)?
- **rekey 延迟**:kex 密文现在排在 bulk FIFO 尾部,饱和下行时 KEXINIT/NEWKEYS 的排队延迟相对 S1 是否**变差**
  (S1 是单个 PacketWriter 缓冲,也 FIFO —— 请判定是否真等价,还是 S2a 多出 256 项通道深度使 rekey deadline 更易触发)。
- **ACK-only InstallAck 是否是假信号**:S2a 不真装钥,那这个 ACK 有没有被任何地方当作「出站 epoch 已就绪」而
  提前注销 rekey deadline / 提前恢复 bulk?若有 → 假绿。
- **回归**:现有 lib tests + `test_malicious_client_s0` 全 9 是否仍绿且**首因正确**(case1=RekeyTimeout、case2/4=WriteStalled)?
  可远程 `cargo test -p russh --features _test_hooks` 抽验。S1 的 `InitCompression|Authenticated` 握手完成判定有无被本片改坏?

## 输出
`.omc/research/review-S2a-gpt.md`:判决 + 上述各条 YES/NO + 任何新洞的定位与**最小**修法。
先读 `russh/src/server/writer.rs` 全文、`server/session.rs` 的 `run` loop 与 `ship_sealed_to_writer`、
`server/supervisor.rs` 的 `AtomicWriteProgress`、`sshbuffer.rs` 的 take/restore。

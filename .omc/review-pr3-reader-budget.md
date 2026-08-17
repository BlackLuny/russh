# Adversarial review: Reader / inbound lane / GlobalBudget / WINDOW_ADJUST

**Repo:** BlackLuny/russh  
**HEAD:** `5cb1f8a` (PR https://github.com/BlackLuny/russh/pull/3)  
**Scope:** `russh/src/server/reader.rs`, `inbound_lane.rs`, `global_budget.rs`, inbound WINDOW_ADJUST / grant / deferred adjust in `session.rs`  
**Excluded (known fixed, not rediscovered):** S9 F2 `channel_gens` (`66060fb`), S9 F3 50 ms deferred grant poll (`5093e50`), S4d D28 ceiling ledger (`4720e8e`), D29 `Handler::adjust_window` occupancy raise (`0475106`)

---

## Overall verdict: **FIX-FIRST**

Two production defects are enough to block ship: (1) saturated lane-pump skips peer `WINDOW_ADJUST` apply (outbound stall / cross-effect HOL), (2) `CtrlMsg::Overflow` tears down a channel without `release_channel_global` (per-connection GlobalBudget + map leak). A third defect completes the D29 hole on multi-channel sessions when `adjust_window` grows the session-wide target.

Reader inbound-epoch install and ctrl fail-closed mechanics look sound for healthy peers; remaining issues there are lower severity or theoretical.

---

## Findings

### F1 — P1 — `more_lanes` continue skips `apply_pending_peer_credit` (outbound stall / HOL)

**Category:** inbound stall / lost WINDOW_ADJUST credit; cross-channel HOL  
**Files:** `session.rs` ~3207–3244, 2345–2362, 3751–3753; `reader.rs` ~939–963; `inbound_lane.rs` `PeerCreditBoard`

**Mechanism**

Confirmed inbound `CHANNEL_WINDOW_ADJUST` bypasses ctrl and posts to `PeerCreditBoard` (`reader.rs` 954–958). Session drains that board only via `apply_pending_peer_credit` at the pre-select site (`session.rs` 3241–3244). The credit select arm is explicitly wake-only (`3751–3753`).

After `pump_reader_lanes`, if the 64-item quantum is exhausted:

```3232:3244:russh/src/server/session.rs
            if more_lanes && !self.common.disconnected {
                continue;
            }
            // Aggregation board drain: always here (or, under the pin hook,
            // after the batch drain). Never in the notify arm.
            ...
                if let Err(e) = self.apply_pending_peer_credit(handler.as_mut()).await {
```

`continue` jumps to loop-top and **never** runs `apply_pending_peer_credit`, and **never** enters `select!` (so `credit_notified` cannot help).

**Failure scenario**

1. Default `window_size` is 2 MiB (`mod.rs` Config default). Peer uploads steadily on channel A; app buffer accepts promptly.
2. Reader keeps ≥64 lane items ready → every `pump_reader_lanes` returns `more_lanes == true`.
3. Concurrently the peer sends `CHANNEL_WINDOW_ADJUST` (same or other channel) to open server→client send window; Reader `credit.post`s it.
4. Session spins pump → flush → pump… indefinitely. Board entries sit until the inbound flood dips below one quantum.
5. Outbound `pending_data` stays window-blocked: upload/shell output stalls for the duration of a saturated download. Multi-channel: B’s credit is starved by A’s inbound pump (cross-channel HOL).

**Why this is not the known F3/D30 bug:** F3 fixed *grant* (server→peer inbound window) deferred on GlobalBudget; this loses *peer→server* outbound credit apply.

**Fix direction:** Always drain `PeerCreditBoard` before `more_lanes` continue (or apply credit inside the continue path / before pump). Do not rely on select wake alone.

**Verdict:** **REAL — must fix**

---

### F2 — P1 — `CtrlMsg::Overflow` never calls `release_channel_global`

**Category:** GlobalBudget leak; channel-churn / long-lived connection accounting; process refusal under tight budgets  
**Files:** `session.rs` 1768–1783 vs 2569–2600 / 1065–1069

**Mechanism**

Normal close path: `finalize_close` → `release_channel_global` (takes `channel_global_held` / `channel_window_covered`, refunds `ConnAccount`).

Overflow path:

```1768:1783:russh/src/server/session.rs
            CtrlMsg::Overflow { id, .. } => {
                log::warn!("reader lane overflow on {id:?}; StopDiscard");
                self.discard_channel_outbound(id).map_err(|e| e.into())?;
                self.teardown_inbound_channel(id);
                ...
                self.channels.remove(&id);
                if let Some(r) = &self.reader {
                    r.close_lane(id, r.lane_gen(id).unwrap_or(0));
                }
                Ok(true)
            }
```

`discard_channel_outbound` removes `enc.channels` and clears deferred grants, but **does not** release global held. `release_channel_global` is only referenced from `finalize_close` (and OPEN_FAILURE paths that manually refund `slot.reserved`). Overflow never reaches `finalize_close`.

**Failure scenario**

1. Channel hits `LanePush::Overflow` (malicious peer, or multi-channel D29 hole in F3 below, or occupancy mis-size).
2. Session StopDiscards: app `channels` + lane + enc entry gone; `channel_global_held` still holds `window_size + OUTBOUND_CAP_ESTIMATE` (~2 MiB+).
3. Repeat on a long-lived connection → `held`/`used` ratchet up; `channel_global_held` map grows one entry per overflowed id (ids not reused until `u32` wrap, so the map leaks historical ids).
4. Under a real `global_byte_budget` / floor (not the default 4 TiB toy ceiling): later `try_reserve` for OPEN or ceiling growth fails → `OPEN_FAILURE` / deferred grants; connection appears “full” after churn that should have refunded.

Connection drop still refunds via `ConnAccount::Drop`, so this is **per-connection** until teardown, not a permanent process-wide leak after the socket dies — but it matches the “whole-process channel refusal after large transfers” class when many connections share a tight ledger and one connection’s unreclaimed excess eats the shared remainder.

**Verdict:** **REAL — must fix** (call `release_channel_global` / `finalize_close` on Overflow)

---

### F3 — P1 — Session-global `target_window_size` + per-channel `align_lane_occupancy_caps` (D29 incomplete for multi-channel)

**Category:** inbound stall / Overflow after `Handler::adjust_window` growth  
**Files:** `session.rs` 2142–2150, 2235–2247; default window 2 MiB; D29 raised caps only for the granting id

**Mechanism**

After a grant:

```2142:2150:russh/src/server/session.rs
            let old_target = self.target_window_size;
            let w = self
                .dispatch_adjust_window(handler, id, old_target)
                .await;
            if w > 0 {
                self.target_window_size = w;
            }
            if w > old_target {
                self.align_lane_occupancy_caps(id, w);
            }
```

`target_window_size` is **one field for the whole Session**. Occupancy raise runs **only for `id`**. Default `adjust_window` returns `current` unchanged; any handler that grows the target (the D29 / `test_s8c_adjust_window` Grow mode) publishes that target to every channel’s subsequent `planned_grant_delta`.

**Failure scenario**

1. Channels A and B open with `byte_cap = window + max_packet` at construction.
2. Traffic on A; handler returns a larger target; A’s lane caps are raised; `target_window_size` becomes e.g. 1 MiB.
3. Grants on B use the new target, emit large `WINDOW_ADJUST`, but B’s `byte_cap` stays at the open-time bound.
4. Peer fills B up to the advertised window → `try_push` Overflow → StopDiscard (and then F2 budget leak).

Single-channel D29 gates stay green; multi-channel + growing `adjust_window` does not.

**Verdict:** **REAL — must fix** for any deployment that overrides `adjust_window` upward with >1 channel (raise all live lanes, or make target per-channel)

---

### F4 — P2 — `CloseDropped` treats `generation == 0` as “always live” (ABA after id wrap)

**Category:** channel slot/generation reuse  
**Files:** `reader.rs` 1056–1090; `session.rs` 1785–1807; `inbound_lane.rs` 363–366

**Mechanism**

On `CHANNEL_CLOSE`, Reader snapshots `generation = lane_gen.unwrap_or(0)` — **0 if no lane**. `CloseDropped` stale check:

```1796:1802:russh/src/server/session.rs
                let live = self.reader.as_ref().and_then(|r| r.lane_gen(id));
                if live.is_some_and(|g| generation != 0 && g != generation) {
                    ...
                    return Ok(true);
                }
```

If `generation == 0` and a **new** lane exists for that id, the check does not fire → `dispatch_close` + `finalize_close` kills the replacement.

**Failure scenario**

Ghost/late CLOSE while lane absent queues `CloseDropped { generation: 0 }`. After `last_channel_id` wraps (`Wrapping<u32>` in `new_channel_id`) and reuses that id, a delayed ctrl `CloseDropped` finalizes the new channel.

Practical rate: needs ~2³² opens on one connection **or** extreme ctrl delay across wrap. `WireClose` also ignores generation (`1757`), same wrap class.

**Verdict:** **REAL but rare** — fix by rejecting `generation == 0` when a live lane exists (and/or tagging WireClose with gen checks). Not a 24 h thousands-of-channels soak bug by itself.

---

### F5 — P2 — Lane pump fairness: `HashMap::iter().find` sticky head + quantum

**Category:** soft cross-channel HOL  
**Files:** `inbound_lane.rs` 427–447 (`peek_gated`), 383–392; `session.rs` `LANE_PUMP_QUANTUM = 64`

**Mechanism**

Ready-lane selection walks `HashMap` iteration order and returns the first match. A channel that sorts first and stays non-empty can consume an entire 64-pop quantum every turn. Combined with F1’s `more_lanes` continue, other channels’ lane heads and credit apply are delayed for as long as the busy channel stays saturated.

Backpressure (`hold_all`) correctly isolates a stuck app buffer; this finding is about a *fast* consumer monopolizing the pump.

**Verdict:** **REAL fairness defect**; severity rises to P1 when paired with F1. Prefer round-robin / `sched_next`-style cursor (outbound already has one).

---

### F6 — P3 — Ctrl fail-closed vs saturated pump (secondary)

**Category:** ctrl queue fail-closed killing connections  
**Files:** `reader.rs` `try_push_ctrl` / `INBOUND_CTRL_BUDGET`; `session.rs` F1 continue path; `CtrlFull` → `PeerError` (3835–3837)

**Mechanism**

Ctrl full intentionally Cancelling. During F1’s pump spin, Session does not recv ctrl. Steady bulk DATA does not use ctrl (ADJUST→board; DATA→lanes), so a healthy bulk transfer alone should not fill 2 MiB. Risk rises if OPEN/GLOBAL/kex/`!confirmed` ADJUST arrive during a long `more_lanes` spin.

**Verdict:** **Latent** — fix F1 first; then reassess whether ctrl drain needs a progress guarantee under load. Not an accidental healthy-path kill by itself for confirmed bulk.

---

### Cleared / not shipping blockers in this pass

| Concern | Assessment |
|--------|------------|
| Reader mid-packet epoch install | Sound: install only after NEWKEYS at packet boundary; mid-read never `recv`s install (`reader.rs` 1392–1416, 1536–1585). Cap-1 Full → Cancelling is intentional protocol violation / stuck Reader. |
| `PeerCreditBoard` map growth | Membership filter + `take_all` + established gate; TOCTOU stale entries O(in-flight teardowns) as documented. Not a 24 h leak if F1 is fixed so `take_all` runs. |
| GlobalBudget cumulative grant (D28) | Ceiling/`grant_reserve_need` path present; not re-opened. F2 is a different release hole. |
| Deferred grant cross-conn (D30/F3) | 50 ms poll present (`3436–3443`). |
| `channel_gens` unbounded (F2/66060fb) | Replaced by `next_channel_gen`. |
| D29 single-channel occupancy | Fixed for the granting id; multi-channel hole is F3 above. |
| `ConnAccount` double-release | `release` caps by `held`; Drop is once via `live` flag. OK. |
| Lane `generation == 0` close wildcard | Session passes live gen when lane exists; single-threaded Session avoids open/close TOCTOU between the two locks. |

---

## Severity summary

| ID | Severity | Ship impact |
|----|----------|-------------|
| F1 | P1 | Outbound stall under saturated inbound pump |
| F2 | P1 | GlobalBudget + map leak on Overflow teardown |
| F3 | P1 | Multi-channel Overflow after growing `adjust_window` |
| F4 | P2 | ABA finalize after id wrap |
| F5 | P2 | Unfair lane scheduling (amplifies F1) |
| F6 | P3 | CtrlFull under F1 + ctrl flood |

---

## Recommended fix order

1. **F1:** Drain peer credit (and ideally poll ctrl) even when `more_lanes` continues.  
2. **F2:** Overflow → `release_channel_global` (prefer sharing `finalize_close` cleanup).  
3. **F3:** Per-channel targets or raise occupancy for all live lanes when session target grows.  
4. **F5 / F4:** Fair peek cursor; harden gen-0 CloseDropped / WireClose.

**Overall: FIX-FIRST** — do not ship PR3 Reader/budget surface until F1–F3 are fixed or explicitly waived with tests that pin the failure classes above.

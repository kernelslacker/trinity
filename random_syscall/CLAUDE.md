# random_syscall/ — Pick, Substitute, Dispatch: the Per-Iteration Hot Path

The core "choose a syscall and run it" loop. Every fuzzed syscall in trinity — fresh, chain-replayed, chain-biased, or redqueen re-exec — funnels through `set_syscall_nr()` and then `dispatch_step()` in this directory. Nothing else in the codebase is on the critical path as often: this runs once (or twice, with re-exec) per syscall, for every child, for the life of the run.

## Files (18 files + 2 internal headers, ~7,907 LOC)

The picker (`pickers.c`), the dispatch tail (`dispatch.c`) and the post-dispatch
attribution helpers (`strategy-accounting.c`) have each been split one concern
per translation unit; the chain executor that used to live in the root
`sequence.c` was folded in here as the `chain-*.c` cluster.

Picker arms and their shared plumbing:

| File | Lines | Role |
|---|---|---|
| pick-common.c | 644 | Shared picker plumbing: `choose_syscall_table()` (32/64-bit table select), `load_active_syscall_count()`, the validation success/failure deactivation counters, `expensive_accept()` (adaptive EXPENSIVE-syscall accept-rate gate), the cost-pool selector shadow/live/predraw observers, `syscall_in_group()` |
| pick-frontier.c | 590 | STRATEGY_COVERAGE_FRONTIER arm: `set_syscall_nr_coverage_frontier()` — uniform draw plus biased acceptance against the per-syscall frontier-edge weight |
| pick-frontier-weight.c | 514 | Weight helpers for the frontier silent-regime accept gate: `frontier_cold_weight()` (plateau fallback when the frontier ring goes silent) and `cmp_frontier_weight()` (CMP-weighted alternate) |
| pick-heuristic.c | 417 | STRATEGY_HEURISTIC arm: `set_syscall_nr_heuristic()` — uniform draw from `active_syscalls`, then the layered biases (group affinity, kcov cold-skip) |
| pick-random.c | 246 | STRATEGY_RANDOM arm: `set_syscall_nr_random()` — uniform draw with no further biasing, plus the anti-prior plateau intervention |
| pickers.c | 141 | `set_syscall_nr()`, the top-level dispatcher that reads `shm->current_strategy` and routes to one of the three arms |

Dispatch and chain substitution:

| File | Lines | Role |
|---|---|---|
| dispatch-step.c | 1280 | `dispatch_step()`: the actual `do_syscall()` call plus all post-call bookkeeping (kcov/cmp collection, minicorpus save, cmp_hints credit, strategy attribution), and the CMP RedQueen greedy re-exec tail (`redqueen_pin_slot`, `redqueen_pin_field`, `redqueen_reexec_step`) |
| dispatch-wrappers.c | 278 | The four public entry points that converge on `dispatch_step()`: `random_syscall`, `random_syscall_step`, `random_syscall_step_biased`, `replay_syscall_step` |
| chain-subst.c | 269 | `apply_chain_substitution()`: splices a prior chain step's retval into one arg slot of the current call, gated by argtype safety and protected-fd/pid checks |

Post-dispatch attribution, carved out of `strategy-accounting.c` and sharing
`random_syscall/strategy-accounting-internal.h`:

| File | Lines | Role |
|---|---|---|
| strategy-rotate.c | 441 | `maybe_rotate_strategy()`: the SR_* rotation gate — window expiry, atomic switch claim, bandit feed, next-arm select, fleet publish |
| per-syscall-edges.c | 420 | `account_reexec_ab_cohort`, `account_per_syscall_new_edges`, `account_pc_edge_only`, `account_transition_reward` — per-dispatch cohort denominators and per-syscall edge attribution |
| warm-reserve.c | 286 | `account_warm_reserve` (SHADOW deep-but-warm probe) and `account_cold_overflow_would_save` (SHADOW cold/corpus-absent overflow-tail probe) |
| remote-adaptive.c | 254 | `remote_adaptive_decide()`: adaptive KCOV_REMOTE disposition, consulted before the raw call to override the static `remote_mode` |
| fd-group.c | 165 | `account_fd_and_group()`: fd-leak counters, live-fd ring push, the `group_bias`-gated `last_group` stamp, and the F-RSEQ group-pin damper state machine |
| strategy-accounting-internal.h | 52 | Cross-file declarations private to the accounting cluster |

Chain executor and its corpus, sharing `random_syscall/chain-internal.h`:

| File | Lines | Role |
|---|---|---|
| chain-persist.c | 651 | Chain-corpus on-disk persistence and mid-run snapshot cadence: versioned, arch- and release-tagged save/load with an atomic rename |
| chain-exec.c | 633 | `run_sequence_chain()`: draws a chain source (fresh vs corpus replay), dispatches each step, records the outcome (corpus admission + per-resource-kind pair credit) |
| chain-restype.c | 342 | Resource-type dependency table for `--chain-resource-typing`: one row per fd-family with a producer/consumer split, measured via `chain_restype_replay_win[]` |
| chain-corpus.c | 336 | The in-memory ring of admitted chains plus init / save / pick; a single fleet-wide ring of inline `chain_entry` slots, lockless on the pick path |
| chain-internal.h | 42 | Cross-file declarations private to the `chain-*.c` cluster |

Cross-cluster private declarations live in `include/random-syscall-internal.h` (the 14 non-chain files here include it; the chain cluster uses `chain-internal.h` instead). Public entry points are split across `include/child-api.h` (the four dispatch-step wrappers), `include/sequence.h` (the chain executor and its corpus API) and `include/syscall.h` (`set_syscall_nr_random`, `compute_numeric_substitute_mask`, `choose_syscall_table`).

## How a syscall gets picked

`set_syscall_nr()` (pickers.c) is the single top-level entry. It:
1. Clears `child->frontier_pick_regime` to NONE.
2. Explorer-pool children bypass the bandit entirely and always run `set_syscall_nr_random()` — the always-on uniform baseline that keeps the bandit's reward signal honest even when its winning arm stalls.
3. Otherwise reads `shm->current_strategy` (ACQUIRE) and stamps it into `child->strategy_at_pick` *before* dispatching, so post-call reward attribution credits the arm that actually picked the syscall even if a rotation lands mid-call.
4. Routes to one of three arms:
   - **`set_syscall_nr_heuristic`** (STRATEGY_HEURISTIC, the default): uniform draw from the active-syscall prefix, then layered biases — 70% same-group-as-last-call, kcov cold-skip (probabilistic skip of syscalls that stopped finding edges, scaling 50%→90% with staleness), `--cred-throttle`, and several SHADOW-only observability gates (wall-lever, F-RSEQ group-pin damper) that record what a future live gate *would* do without changing selection.
   - **`set_syscall_nr_random`** (STRATEGY_RANDOM): uniform draw with only correctness gates (active/EXPENSIVE/validate/cred-throttle), plus an anti-prior accept gate during plateau interventions that inverts the bandit's learned pick-rate distribution.
   - **`set_syscall_nr_coverage_frontier`** (STRATEGY_COVERAGE_FRONTIER): rejection-sampled against a per-syscall frontier-edge weight (`frontier_recent_count`), with a "silent ring" plateau fallback (`frontier_cold_weight`/`cmp_frontier_weight`) that steers toward under-explored or CMP-productive syscalls when the frontier ring has decayed to zero everywhere.

All three arms share the same skeleton: `choose_syscall_table()` picks 32 vs 64-bit once per call (not per retry), then a `retry:` loop applies EXPENSIVE early-out (`expensive_accept`), `validate_specific_syscall_silent()` (with a 3-consecutive-failure deactivation counter), and strategy-specific biasing, bounded by a 10000-iteration outer retry budget. `pick-common.c` supplies the machinery all three retry loops depend on.

## How chain substitution works

`apply_chain_substitution()` (chain-subst.c) runs after `generate_syscall_args()` fills `rec->a1..a6` and before dispatch. With `CHAIN_SUBST_PCT` (30%) probability, it overwrites one arg slot with the previous chain step's return value (fd, pid, or other small integer). Safety is enforced three ways:
- A per-syscall-entry bitmask (`entry->numeric_substitute_mask`, computed once at table-init by `compute_numeric_substitute_mask()`) restricts substitution to argtypes that legitimately accept a numeric value (fds, lengths, modes, pids, etc.) — never pointer/struct/address argtypes, which would produce a wild pointer and crash the renderer or the kernel.
- If the substitute value equals `mainpid`, ARG_PID slots are masked out (protects against accidentally sending SIGKILL-class syscalls to trinity's own main process).
- If the substitute value is a protected fd (kcov PC/cmp fd, stderr capture memfd), fd-typed slots are masked out (protects against `dup2`/`close_range` closing trinity's own instrumentation fds).
- The eligible slot is chosen via an explicit popcount + rank walk over the bitmask, not `ctz`, specifically to keep the draw uniform (a raw ctz pick would bias 2:1 toward low-numbered slots).

Called identically from the fresh-args path (`random_syscall_step`), the bias path (`random_syscall_step_biased`), the replay path (`replay_syscall_step`), and the redqueen re-exec pin (via `redqueen_pin_slot`/`redqueen_pin_field`, a related but separate single-slot/single-field override mechanism in dispatch-step.c).

## How dispatch works

`dispatch_step()` (dispatch-step.c) is the shared tail all four public entry points converge on. Sequence, per call:
1. Stamp `rec->entry`, clear `rec->validator_rejected`.
2. Decide `child->kcov.remote_mode` (KCOV_REMOTE_ENABLE for softirq/kthread/workqueue-deferred coverage) via a static rate (`KCOV_REMOTE_RATIO`/`_HEAVY`) or, for redqueen A/B arm B, an adaptive decision from `remote_adaptive_decide()`.
3. `do_syscall()` — the actual syscall invocation (in dispatch/syscall.c, outside this cluster).
4. Collect coverage: `kcov_collect()` (PC mode, kcov/collect.c) or `kcov_collect_cmp()` (CMP mode, kcov/collect-fanout.c). New-edge and new-CMP-novelty counts are per-call authoritative out-params, not global-counter diffs (which would race concurrent sibling children).
5. Credit cmp_hints feedback (`cmp_hints_feedback_credit_*`, cmp_hints/credit.c) and typed-hypothesis stash entries.
6. Save to minicorpus (`minicorpus_save_with_reason`) on any novelty signal (PC edge OR CMP bloom novelty — the OR is deliberate, documented as breaking a "PC-plateau → no-saves → no-mutator-wins" self-reinforcing loop).
7. Run the accounting-cluster helpers (`account_per_syscall_new_edges`, `account_pc_edge_only`, `account_transition_reward` from per-syscall-edges.c; `account_warm_reserve`, `account_cold_overflow_would_save` from warm-reserve.c; `account_fd_and_group` from fd-group.c) — per-syscall/per-strategy reward and diagnostic bookkeeping.
8. Push to `child_syscall_ring` and `pre_crash_ring` for crash-forensics.
9. Enqueue combined stats (`stats_ring_enqueue_call_complete`).
10. Bump per-arm completion counters (mirrors the pick-time `strategy_picks[]` bump).
11. **CMP RedQueen greedy re-exec tail**: if the parent call is CMP-mode, redqueen-enabled, not already mid-reexec/mid-chain-step, produced new CMP novelty, and has staged `reexec_pending` attribution entries, drain *all* of them (bounded by `MAX_REEXEC_PENDING`) through `redqueen_reexec_step()` — each one regenerates fresh args, pins a single learned-constant slot or struct field, and recursively calls `dispatch_step()` again (guarded by `child->in_reexec` against runaway recursion). Gate disposition is tracked with a mutually-exclusive per-gate skip counter for measurement.
12. `maybe_rotate_strategy()` — cheap end-of-call check for the bandit/round-robin window boundary.

The four public wrappers differ only in how `rec` gets populated before calling `dispatch_step()`:
- `random_syscall_step` — calls `set_syscall_nr()`, `generate_syscall_args()`, then `apply_chain_substitution()`.
- `random_syscall` — trivial wrapper: `random_syscall_step(child, false, 0, NULL, NULL, NULL)`.
- `random_syscall_step_biased` — skips `set_syscall_nr()` for a chain-executor-supplied NR (resource-typed consumer pick), still generates fresh args.
- `replay_syscall_step` — replays a saved `(nr, do32bit, args)` chain step through `minicorpus_mutate_args()` (shared mutator engine) instead of fresh generation.

Bias and replay paths both set `child->strategy_at_pick = -1` so their novelty doesn't get misattributed to whatever bandit arm happens to be current.

## What the accounting cluster tracks

- **`maybe_rotate_strategy()`** (strategy-rotate.c): the bandit/round-robin rotation gate. Reads a fleet-wide op-count mirror (`shm_published->fleet_op_count`), tightens the rotation window during a detected coverage plateau, CAS-claims the switch, computes per-strategy call/edge/CMP-novelty/WARN-fire deltas for the just-finished window, feeds them to `bandit_record_pull()`, ticks the frontier-ring and cmp_hints chaos-mode windows, and picks the next strategy via `select_next_strategy()` (strategy/strategy.c).
- **`remote_adaptive_decide()`** (remote-adaptive.c): per-syscall promote/demote/force policy for KCOV_REMOTE sampling, using cross-multiplied rate comparisons (no floating point, overflow-checked) against lifetime remote vs. local edge-yield counters. Runs its shadow-counter bumps unconditionally so both A/B arms contribute to the same denominator even when only one arm's decision is live.
- **`account_reexec_ab_cohort`**: A/B cohort denominators (enabled vs. control) for CMP-mode redqueen lift measurement.
- **`account_per_syscall_new_edges`**: splits new-edge counts into explorer vs. bandit-pool buckets; separately tracks frontier-yield "kill-list feedstock" (productive-win / live-miss streaks per syscall) keyed on the picker's `frontier_pick_regime` stamp.
- **`account_warm_reserve`**: SHADOW "deep-but-warm" candidate detection — calls that found no novelty but walked unusually many PCs relative to the syscall's running mean, or nearly saturated the kcov trace buffer. Feeds a not-yet-built STAGE B reserve+replay consumer.
- **`account_cold_overflow_would_save`**: SHADOW measurement of syscalls that would benefit from corpus save under CMP-plateau conditions but currently don't get one.
- **`account_pc_edge_only`**: PC-edge-exclusive bookkeeping — minicorpus snapshot cadence, per-strategy edge-reward attribution, and random-rescue classification during forced-plateau windows.
- **`account_transition_reward`**: per-strategy transition-edge (new PC-ordering, not new PC) reward, capped per-call to prevent one pathological trace from dominating the bandit's window delta.
- **`account_fd_and_group`**: fd-leak counters, live-fd ring push for arg-generation reuse, and the F-RSEQ group-pin damper's streak/coverage-watermark bookkeeping.

Nearly everything in the accounting cluster is dual-mode: a SHADOW/observability half that always runs and bumps counters, and a much smaller live-behavior-changing half gated behind a mode enum and a per-child A/B arm flag, so new selection logic can be measured on real fleets before it's allowed to touch the picker's output distribution.

## Integration points

Callers into this cluster's public entry points:
- `child/child.c` — per-child main loop; its default `CHILD_OP_SYSCALL` path falls through to `run_sequence_chain()` (child.c:782), which is what reaches the dispatch wrappers
- `childops/misc/sched-cycler.c` — an alt-op childop that calls `random_syscall(child)` from inside its own inner loop (flagged via `child->in_childop` so dispatch-step.c's `syscalls_in_childops` vs `syscalls_random` split attributes correctly)
- `chain-exec.c` — the chain executor (in this directory since the root `sequence.c` was folded in); calls `random_syscall_step()` for fresh chain steps, `random_syscall_step_biased()` for resource-typed consumer picks (`--chain-resource-typing=live`), and `replay_syscall_step()` for corpus-replay chain steps

Calls out from dispatch-step.c to the rest of the tree:
- `dispatch/syscall.c` — `do_syscall()` (the actual syscall invocation); `args/arg-decoder.c` — `output_syscall_prefix/postfix()`; `dispatch/syscall-return.c` — `handle_syscall_ret()`
- `args/generate-args.c` — `generate_syscall_args()` (arg generation, called before chain substitution)
- `args/cmp_hint_inject.c` — invoked transitively during arg generation to splice cmp_hints pool values into args
- `kcov/collect.c` / `kcov/collect-fanout.c` — `kcov_collect()` / `kcov_collect_cmp()`, the PC/CMP coverage collection that drives nearly every downstream accounting decision
- `cmp_hints/credit.c` — `cmp_hints_feedback_credit_{pc,cmp_novelty,transition,corpus_save}()`, `cmp_hints_feedback_reset_stash()`
- `persist/minicorpus-*.c` — `minicorpus_save_with_reason()` (minicorpus-save.c), `minicorpus_mutate_args()` (minicorpus-splice.c), `minicorpus_maybe_snapshot()` (minicorpus-snapshot.c), `minicorpus_mut_attrib_{set_cmp_source,commit}()` (minicorpus-accounting.c)
- `strategy/strategy-bandit.c` — `bandit_record_pull()`; `strategy/strategy.c` — `select_next_strategy()` (both called from `maybe_rotate_strategy()`)
- `strategy/strategy-frontier.c` — `frontier_record_transition_edge()`, `frontier_recent_count()`; `strategy/strategy-frontier-window.c` — `frontier_window_advance()`; `strategy/strategy-frontier-cool.c` — `frontier_satcool_spare()`, `frontier_live_cool_spare()`
- `strategy/strategy-rescue.c` — `classify_random_rescue()`; `strategy/strategy-plateau.c` — `plateau_rescue_bias_active_for()`, `plateau_anti_prior_active/accept()`
- `tables/table-meta.c` — `validate_specific_syscall_silent()`, `get_syscall_entry()`; `tables/table-activate.c` — `deactivate_syscall_locked()`
- `health/pre_crash_ring.c`, `child/child.c` (`child_syscall_ring_push`) — crash-forensics ring pushes
- `child/cred_throttle.c` — `cred_throttle_should_reject()`

## Areas of attention

1. **`set_syscall_nr_coverage_frontier()` and its two weight helpers (`frontier_cold_weight`, `cmp_frontier_weight`) are the most complex control flow in the cluster** — pick-frontier.c:94-590 and pick-frontier-weight.c:106-454 / 455-514. `frontier_cold_weight()` alone computes an OLD weight, a BLENDED weight (three disjoint ilog2-scaled novelty terms), an A/B arm selection between them, and then a further reach-band adjustment (HIGH-band boost / MID-band demote), all before the caller does its own live/silent regime split with two more SHADOW decay predicates (`frontier_satcool_spare`, `frontier_errno_plateau_should_decay`) each with their own A/B live-reject roll. Six or seven independently-gated mode enums (`reach_band_mode`, `cmp_frontier_mode`, `frontier_group_antilock_mode`, per-child arm-b flags for blend/silent-decay/errno-decay/live-cool) all interact at this single call site. Correctness here depends on every SHADOW-only branch genuinely being byte-identical-when-OFF — that invariant is documented at every call site but is unverified by any test in this view.
2. **`dispatch_step()` is a single ~720-line function (dispatch-step.c:167-885) doing coverage collection, cmp_hints credit, minicorpus save, six `account_*` calls, crash-ring pushes, stats enqueue, and the redqueen re-exec tail** — it is the busiest function in the fuzzer by call count and its correctness ordering is load-bearing in non-obvious ways: e.g. `account_cold_overflow_would_save()` must run *before* `minicorpus_save_with_reason()` or its "was this the first admission" snapshot races the save it's trying to measure (documented at warm-reserve.c:245-252).
3. **Recursive re-exec**: `redqueen_reexec_step()` calls back into `dispatch_step()` (dispatch-step.c:1172), guarded only by the `child->in_reexec` flag checked at the dispatch_step tail gate. If that guard were ever bypassed, this is an unbounded-recursion path; the per-window cap (`REDQUEEN_REEXEC_WINDOW_CAP`) and per-call cap (drain loop bounded by `MAX_REEXEC_PENDING`) are the only backstops.
4. **`rec` field-level publish/restore discipline**: the dispatch and picker files thread `srec_publish_begin/end()` brackets carefully around every multi-field `rec` mutation so an out-of-band reader (watchdog, pre_crash_ring decoder) never observes a torn `(nr, do32bit, aN)` tuple. `redqueen_reexec_step()` additionally snapshots and restores six `rec` fields plus retval/errno/post_state around its inner dispatch call (dispatch-step.c:1082-1090, 1268-1276) — a missed field in that snapshot/restore pair would silently corrupt what the chain-corpus save sees after the parent call returns.
5. **Chain substitution's protected-fd/pid masking (chain-subst.c:192-219) is a narrow, easy-to-regress safety net**: it depends on `fd_is_protected()` and `is_fdarg()` staying in sync with whatever fd classes trinity considers instrumentation-critical; a new protected-fd class added elsewhere without updating this masking would silently reopen the "chain-substitute closes trinity's own kcov fd" bug class this code exists to prevent.
6. **Every hot-path helper takes pains to be RNG-stream-identical when its owning mode is OFF** (`expensive_accept`, `cost_pool_selector_shadow_note`, `remote_adaptive_decide`, the frontier blend/decay predicates) — this is a strong implicit invariant across the whole cluster (any new mode must preserve pick-stream byte-identity under its OFF setting for reproducible fuzzing runs), but it is enforced only by code comments, not by any automated check visible in this directory.

## Summary

`set_syscall_nr()` picks a syscall via one of three bandit-selected arms (heuristic/random/coverage-frontier), each layering probabilistic accept/retry gates on top of a uniform draw from the active-syscall table. `apply_chain_substitution()` optionally splices a prior chain step's retval into a safe arg slot. `dispatch_step()` then runs the syscall, collects PC/CMP coverage, credits cmp_hints and mutator feedback, saves novel calls to the minicorpus, attributes rewards back to the picking strategy via the accounting cluster's `account_*` helpers, and — for CMP-mode redqueen — greedily re-executes with a learned constant pinned into the slot that produced it. `maybe_rotate_strategy()` closes the loop by feeding the window's reward deltas back into the bandit that drives the next `set_syscall_nr()` call.

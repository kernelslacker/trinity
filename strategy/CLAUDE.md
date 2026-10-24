# strategy/ — Multi-Strategy Syscall-Picker Orchestration

High-level adaptive layer that decides which "arm" (heuristic / random / coverage-frontier) each
fuzzer window runs under, learns from edge-discovery yield via a discounted UCB1 bandit, detects
coverage plateaus and classifies their cause, and drives targeted interventions (forced-random
rescue, anti-prior bias, frontier-weighted picking) to break the fleet out of stalls.

## Key design decisions

3. **Discounted UCB1 (D-UCB)** — `recent_pulls_x1000[]`/`recent_reward_x1000[]` are EMA-decayed
   (alpha=0.05, ~13.5-window half-life) rather than lifetime sums, so the picker tracks
   non-stationary kernel-coverage yield (easy edges mined out early, late-run degradation)
   instead of a stale 2024-mean. Exploit term normalized by max observed mean-reward across arms
   to stay comparable to the sqrt(ln N/n) explore term.
4. **Plateau hypothesis classifier (5 rules)** — driven from a per-plateau entry snapshot diffed
   against the current tick (`plateau_snapshot_capture/delta`), not tick-over-tick, so rules
   requiring sustained signal don't race noisy per-tick deltas.
5. **Plateau Intervention Mode (PIM) rotation** — round-robins among 4 modes (RRC_BIASED,
   ANTI_PRIOR, COVERAGE_FRONTIER, UNIFORM_RANDOM) via a fetch-add counter that only advances
   during plateau windows, so a fresh plateau resumes where the last left off. PIM_COVERAGE_FRONTIER
   is skip-substituted with PIM_UNIFORM_RANDOM when `frontier_max_weight_cached == 0` (deep
   plateau, empty rings) — a real run showed the frontier slot demoting childops via the canary
   gate with zero payoff in that state.
6. **Anti-prior accept gate** — precomputed per-syscall acceptance weights (`ANTI_PRIOR_MAX_BOOST
   = 8`) invert the picker's learned call-count distribution during an intervention window: cold
   syscalls (few calls) get boosted acceptance, hot syscalls get suppressed, capped so a single
   "genuinely broken in this kernel" syscall can't be boosted to monopolize the rotation.
8. **Frontier decay ring** — `FRONTIER_DECAY_WINDOWS` (=8, power-of-two, statically asserted)
   slots per syscall; `frontier_window_advance()` clears-then-publishes (age out the retiring
   slot under a CAS loop before bumping the visible slot index) specifically to avoid a
   documented underflow bug where the old bump-then-clear order could wrap the cached sum to
   near-UINT32_MAX and blow up the frontier roulette wheel.
9. **CMP-novelty bloom** — independent per-(syscall, arch) 1024-bit two-hash bloom (separate from
   cmp_hints' own dedup bloom) with lazy per-entry decay keyed to a global window counter; feeds
   a bandit reward term (`cmp_term`) so arms that surface novel comparison constants (even
   without an immediate PC-edge win) get partial credit.
10. **Many features are SHADOW_ONLY-gated and unwired** — saturation-cooldown
    (`frontier_satcool_spare`), LIVE-regime cooldown discriminator (`frontier_live_cool_spare`),
    floored-barren demote, group-antilock damper, cost-pool selector, and context-pool
    classifier all default OFF and compute-but-don't-act under SHADOW_ONLY, accumulating shadow
    counters for validation against real runs before a future COMBINED mode wires them into
    live selection. None of the six has a COMBINED value yet and the parser rejects `combined`.
    The blended edge-count bandit reward follows the same ramp, but its COMBINED mode is wired.
    This is a deliberate, consistently-applied ramp discipline across the whole directory, not
    ad hoc dead code.

## Integration points

- `random_syscall/strategy-rotate.c` — `maybe_rotate_strategy()` is the CAS-serialized
  rotation site: This is the
  single point where strategy/ meets the hot dispatch path.
- `random_syscall/pick-frontier.c` — `set_syscall_nr_coverage_frontier()` consumes
  `frontier_recent_count()` / `frontier_max_weight_cached` as its roulette-wheel weights; the
  silent-regime accept site calls `frontier_errno_plateau_should_decay()`,
  `frontier_satcool_spare()`, and reads `plateau_anti_prior_accept()` / `plateau_rescue_bias_active_for()`.
- `random_syscall/dispatch-step.c` — calls `maybe_rotate_strategy()` once per dispatch step;
  `classify_random_rescue()` is invoked from the rescue-attribution block
  (`random_syscall/per-syscall-edges.c:344`) after a plateau-forced call lands a new edge.
- `kcov/plateau.c` — `kcov_plateau_check()` calls `strategy_plateau_response()` on the plateau
  rising edge (arms the hypothesis-entry snapshot, forces an immediate rotation) and reads
  `strategy_plateau_hypothesis_current/name()` for its own stats line.
- `kcov/collect.c` — calls `frontier_record_new_edge()` on the new-edge branch;
  `kcov/collect-fanout.c` calls `bandit_cmp_observe()` on the CMP-trace ingestion path (feeds
  the novelty bloom and bandit CMP reward term); `random_syscall/dispatch-step.c` calls
  `frontier_record_transition_edge()`.
- `main/stats.c` — ticks `strategy_plateau_hypothesis_tick()` once per stats interval
  (parent-only, no locking needed) and renders the current hypothesis / per-hypothesis fire
  counts.
- `stats/dump/strategy.c` — calls `dump_strategy_stats()` at end-of-run.
- `main/params/coverage.c` — owns `--strategy` (round-robin/bandit) and the six OFF/SHADOW_ONLY mode
  flags (`--frontier-saturation-cooldown`, `--frontier-live-cooldown-mode`,
  `--frontier-barren-demote`, `--frontier-group-antilock`, `--cost-pool-selector`,
  `--context-pool`); writes `picker_mode_arg` before `init_shm()` runs.  `--explorer-children` is
  parsed in `main/params/childop.c`.
- `cmp_hints/` (see cmp_hints/CLAUDE.md) — cross-references this directory heavily: the
  `CMP_RISING_PC_FLAT` plateau hypothesis reads `kcov_shm->hints_flat.cmp_hints_unique_inserts`;
  `RRC_CMP_DERIVED` rescue classification reads `cmp_hints_pool_safe_count()`; the two-tier
  picker in cmp_hints/get.c samples the recent ring first during a plateau.
- `child.c` / `child-altop-*.c` — read frontier record hooks' side effects (childop-driven
  productive-event bookkeeping mirrors `frontier_window_advance()`'s clear-then-publish
  ordering); `strategy.h` included for the plateau/frontier declarations.
- `include/strategy.h` / `include/strategy-internal.h` — shared enums (`strategy_t`,
  `plateau_hypothesis`, `plateau_intervention_mode`, `random_rescue_class`, the six
  OFF/SHADOW_ONLY mode enums, `bandit_reward_edge_count_mode`) and the cross-file function
  declarations; internal header separates truly-private helpers used only within strategy/.

## Areas of attention

1. **The frontier cluster is the largest concern here (5 files, ~1,524 LOC)** doing at least 4
   distinct jobs: the decay-ring producer/consumer (strategy-frontier.c), the errno-plateau
   predicate, two near-duplicate shadow discriminators (`frontier_satcool_spare` /
   `frontier_live_cool_spare`, both wrapping the shared `frontier_spare_lane_decide()` in
   strategy-frontier-spare.c), and the topology-pair shadow ring. The shared lane-decide
   function is good reuse, and the cluster is split per concern like strategy.c,
   strategy-bandit.c and strategy-plateau.c.
2. **Heavy load-bearing comments over terse code** — nearly every function carries multi-
   paragraph rationale (ordering/race justification, historical bug postmortems e.g. the
   frontier underflow story in `frontier_window_advance()`, strategy-frontier-window.c). This is valuable but means the
   real logic-to-comment ratio is low; a reader has to track which comments describe current
   behavior vs. future (COMBINED) behavior.
3. **Proliferation of mode enums** (six independent OFF/SHADOW_ONLY ones:
   `frontier_saturation_cooldown_mode`, `frontier_live_cooldown_mode`,
   `frontier_barren_demote_mode`, `frontier_group_antilock_mode`, `cost_pool_selector_mode`,
   `context_pool_mode`, plus the OFF/SHADOW_ONLY/COMBINED `bandit_reward_edge_count_mode`) —
   each with its own shadow-counter family. The six have no COMBINED value, only comments
   about the live follow-up that would add one. Consistent pattern, but the surface area for
   dead/half-live code is large; several of these have been sitting at OFF/SHADOW_ONLY long
   enough that the directory carries meaningfully more branches than the live decision tree
   actually uses.
4. **3 of 6 random-rescue classes are permanently unreachable** — `RRC_UNUSUAL_FD_PRODUCER`,
   `RRC_WRONG_TYPE_FD`, `RRC_PERSONA_GATED` are scanned in `dominant_rescue_class()` and named in
   `random_rescue_class_name()` but `classify_random_rescue()` can never return them (the comment
   says the detection infrastructure doesn't exist yet); dead enum values kept live for a future
   wiring.
5. **Atomic-ordering discipline is dense and easy to get wrong on modification** — several
   functions (`plateau_rescue_bias_active_for`, `plateau_anti_prior_active`,
   `wall_lever_should_suppress_shadow`) rely on a specific ACQUIRE-load-then-RELAXED-read
   sequence to piggyback on an unrelated RELEASE store (`current_strategy`) elsewhere in
   random_syscall/ for cross-field visibility. Any future refactor of the rotation site's
   store ordering would silently break these gates without a compiler error.

# strategy/ — Multi-Strategy Syscall-Picker Orchestration

High-level adaptive layer that decides which "arm" (heuristic / random / coverage-frontier) each
fuzzer window runs under, learns from edge-discovery yield via a discounted UCB1 bandit, detects
coverage plateaus and classifies their cause, and drives targeted interventions (forced-random
rescue, anti-prior bias, frontier-weighted picking) to break the fleet out of stalls.

## Files (7 files, ~3,700 LOC)

| File | Lines | Role |
|---|---|---|
| strategy.c | 462 | Glue + plateau-intervention dispatch: `--strategy` parsing, arm/mode name tables, `select_next_strategy()` (bandit vs. intervention dispatch), rescue-classifier-driven `amplified_intervention_arm()`, PIM rotation (`select_plateau_intervention_strategy`) |
| strategy-bandit.c | 587 | UCB1/D-UCB learner: `bandit_record_pull()` reward attribution (call-count + CMP-novelty + transition + edge-count terms, EMA-discounted), `ucb1_score()`, `pick_next_strategy()` (cold-start + round-robin + UCB1 dispatch) |
| strategy-frontier.c | 1103 | Per-syscall frontier-edge decay ring: `frontier_record_new_edge/transition_edge`, `frontier_window_advance()` (ring rotation + F4 LIVE-cooldown halving), errno-plateau decay predicate, saturation-cooldown and LIVE-cooldown shadow discriminators, topology-pair (setup-op → productive-event) shadow ring |
| strategy-plateau.c | 824 | Plateau-intervention machinery: hypothesis classifier (5 rules: CMP-rising/PC-flat, childop-dominant, remote-dominant, frontier-cold, single-group-dominant), anti-prior accept-weight computation, "wall-lever" shadow suppression, snapshot/delta helpers |
| strategy-cmp-novelty.c | 180 | Per-syscall CMP-constant novelty bloom filter (`bandit_cmp_observe()`): two-hash 1024-bit bloom per (syscall, arch) with lazy window-based decay, feeds bandit CMP-reward term |
| strategy-rescue.c | 87 | Random-rescue classifier: `classify_random_rescue()` attributes a plateau-forced STRATEGY_RANDOM win to a class (COLD_SKIP, CMP_DERIVED, or UNKNOWN; 3 placeholder classes not yet wired) |
| strategy-stats-dump.c | 457 | End-of-run operator summary: picker mode, plateau-forced cohort, intervention-mode distribution, rescue-class distribution, explorer-vs-bandit "edge race", per-arm pulls/reward/exposure/reason/chaos breakdowns |

## Key design decisions

1. **Two-layer picker** — `select_next_strategy()` (strategy.c) is the top-level entry: if
   `kcov_shm->plateau_active` and picker mode is bandit, it hands off to
   `select_plateau_intervention_strategy()` (an intervention layer that bypasses the learner
   entirely); otherwise it defers to `pick_next_strategy()` (strategy-bandit.c), the pure
   UCB1/round-robin policy. Round-robin mode never gets plateau-intervened (its own cycling
   already visits RANDOM).
2. **Forced windows excluded from learner history** — `SR_PLATEAU_FORCE` windows are recorded in
   diagnostic by-reason matrices (`bandit_pulls_by_reason[]`) but never bumped into the live
   learner series (`bandit_pulls[]`, `recent_pulls_x1000[]`) — an intervention rescue is
   structurally different from a policy-chosen pick and folding it in would contaminate the
   reward history.
3. **Discounted UCB1 (D-UCB)** — `recent_pulls_x1000[]`/`recent_reward_x1000[]` are EMA-decayed
   (alpha=0.05, ~13.5-window half-life) rather than lifetime sums, so the picker tracks
   non-stationary kernel-coverage yield (easy edges mined out early, late-run degradation)
   instead of a stale 2024-mean. Exploit term normalized by max observed mean-reward across arms
   to stay comparable to the sqrt(ln N/n) explore term.
4. **Plateau hypothesis classifier (5 rules)** — driven from a per-plateau entry snapshot diffed
   against the current tick (`plateau_snapshot_capture/delta`), not tick-over-tick, so rules
   requiring sustained signal don't race noisy per-tick deltas. Rules: CMP climbing/PC flat,
   childop-dominant (2:1 call-count ratio), remote-KCOV-dominant, frontier-cold (bandit pulled
   frontier arm but the picker's weighted-accept gate rejected every candidate), single-group
   dominant (>70% of edge delta in one syscall group).
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
7. **Random-rescue classification** — a plateau-forced RANDOM call that lands a new edge is
   attributed to a class (`classify_random_rescue`) using pre-existing evidence (heuristic's
   cold-skip probability snapshot before the call; cmp_hints pool occupancy) so future
   interventions can amplify the most productive rescue shape (`amplified_intervention_arm`:
   COLD_SKIP → STRATEGY_HEURISTIC with cold-skip suppressed; CMP_DERIVED →
   STRATEGY_COVERAGE_FRONTIER). Amplification only engages once a class clears both a minimum
   count floor and a lead-over-runner-up ratio.
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
    group-antilock damper, cost-pool selector, and blended edge-count bandit reward all default
    OFF/compute-but-don't-act, accumulating shadow counters for validation against real runs
    before a future COMBINED mode wires them into live selection. This is a deliberate,
    consistently-applied ramp discipline across the whole directory, not ad hoc dead code.

## Integration points

- `random_syscall/strategy-accounting.c` — `maybe_rotate_strategy()` is the CAS-serialized
  rotation site: computes per-window deltas, calls `bandit_record_pull()`, then
  `select_next_strategy()` for the next arm, then `frontier_window_advance()`. This is the
  single point where strategy/ meets the hot dispatch path.
- `random_syscall/pickers.c` — `set_syscall_nr_coverage_frontier()` consumes
  `frontier_recent_count()` / `frontier_max_weight_cached` as its roulette-wheel weights; the
  silent-regime accept site calls `frontier_errno_plateau_should_decay()`,
  `frontier_satcool_spare()`, and reads `plateau_anti_prior_accept()` / `plateau_rescue_bias_active_for()`.
- `random_syscall/dispatch.c` — calls `maybe_rotate_strategy()` once per dispatch step;
  `classify_random_rescue()` is invoked from the rescue-attribution block (line ~1011 of
  strategy-accounting.c) after a plateau-forced call lands a new edge.
- `kcov/plateau.c` — `kcov_plateau_check()` calls `strategy_plateau_response()` on the plateau
  rising edge (arms the hypothesis-entry snapshot, forces an immediate rotation) and reads
  `strategy_plateau_hypothesis_current/name()` for its own stats line.
- `kcov/collect.c` — calls `frontier_record_new_edge()` / `frontier_record_transition_edge()` on
  the new-edge/new-transition branches, and `bandit_cmp_observe()` on the CMP-trace ingestion
  path (feeds the novelty bloom and bandit CMP reward term).
- `main/stats.c` — ticks `strategy_plateau_hypothesis_tick()` once per stats interval
  (parent-only, no locking needed) and renders the current hypothesis / per-hypothesis fire
  counts.
- `stats/dump.c` — calls `dump_strategy_stats()` at end-of-run.
- `params.c` — owns `--strategy` (round-robin/bandit), `--explorer-children`, and the four
  SHADOW_ONLY mode flags (`--frontier-saturation-cooldown`, `--frontier-live-cooldown-mode`,
  `--frontier-group-antilock`, `--cost-pool-selector`); writes `picker_mode_arg` before
  `init_shm()` runs.
- `cmp_hints/` (see cmp_hints/CLAUDE.md) — cross-references this directory heavily: the
  `CMP_RISING_PC_FLAT` plateau hypothesis reads `kcov_shm->cmp_hints_unique_inserts`;
  `RRC_CMP_DERIVED` rescue classification reads `cmp_hints_pool_safe_count()`; the two-tier
  picker in cmp_hints/get.c samples the recent ring first during a plateau.
- `child.c` / `child-altop.c` — read frontier record hooks' side effects (childop-driven
  productive-event bookkeeping mirrors `frontier_window_advance()`'s clear-then-publish
  ordering); `strategy.h` included for the plateau/frontier declarations.
- `include/strategy.h` / `include/strategy-internal.h` — shared enums (`strategy_t`,
  `plateau_hypothesis`, `plateau_intervention_mode`, `random_rescue_class`, the four
  SHADOW/COMBINED mode enums) and the cross-file function declarations; internal header
  separates truly-private helpers used only within strategy/.

## Areas of attention

1. **strategy-frontier.c is 1103 LOC in one file** doing at least 4 distinct jobs: the decay-ring
   producer/consumer, the errno-plateau predicate, two near-duplicate shadow discriminators
   (`frontier_satcool_spare` / `frontier_live_cool_spare`, both wrapping the shared
   `frontier_spare_lane_decide()`), and the topology-pair shadow ring. The shared lane-decide
   function is good reuse, but the file would benefit from the same per-concern split
   strategy.c/strategy-bandit.c/strategy-plateau.c already went through.
2. **Heavy load-bearing comments over terse code** — nearly every function carries multi-
   paragraph rationale (ordering/race justification, historical bug postmortems e.g. the
   frontier underflow story in `frontier_window_advance()`). This is valuable but means the
   real logic-to-comment ratio is low; a reader has to track which comments describe current
   behavior vs. reserved/future (COMBINED) behavior.
3. **Proliferation of SHADOW_ONLY/COMBINED mode pairs** (4 independent enums:
   `frontier_saturation_cooldown_mode`, `frontier_live_cooldown_mode`,
   `frontier_group_antilock_mode`, `cost_pool_selector_mode`, plus
   `bandit_reward_edge_count_mode`) — each with its own shadow-counter family and its own
   "COMBINED reserved, not wired yet" comment. Consistent pattern, but the surface area for
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
   random-syscall.c for cross-field visibility. Any future refactor of the rotation site's
   store ordering would silently break these gates without a compiler error.

## Summary

strategy/ implements a two-tier control loop over the syscall-picking arms: a discounted UCB1
bandit continuously reallocates windows toward whichever arm (heuristic/random/coverage-frontier)
is yielding new edges fastest, while an independent plateau-detection and classification layer
(fed by kcov's stall signal) periodically overrides the bandit with a targeted intervention —
forced random, anti-prior bias, or frontier-weighted picking — chosen by rotating through modes
and, within the RANDOM intervention, further biased by a rescue classifier that reads cmp_hints
pool occupancy and the heuristic's own cold-skip probability. A large fraction of the directory
(shadow discriminators, blended reward modes) is instrumented-but-inert scaffolding for future
live-mode graduation rather than currently active decision logic.

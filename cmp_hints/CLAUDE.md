# cmp_hints/ — KCOV Comparison-Operand Hint System

Fuzzer intelligence layer for Trinity. Collects constants the kernel compares syscall-derived values against (KCOV_TRACE_CMP), feeds them back into arg generation to bias inputs toward values likely to pass kernel validation gates.

## Files (14 files, ~6,964 LOC)

| File | Lines | Role |
|---|---|---|
| cmp_hints.c | 332 | Entry point: SHM allocation, strip-installation, chaos-mode gating |
| collect.c | 1158 | KCOV ingestion: cmp_hints_collect() walks raw trace_cmp buffer (its once-per-call scan setup is `cmp_attribution_prestage()`), cmp_hint_apply_transform() normalizes values, cmp_hints_stash_consumed() records consumed hints for credit |
| pool.c | 1042 | Pool primitives: lock wrappers, corruption gates, dedup + LRU eviction, bloom filter, recent ring, batch flush |
| get.c | 633 | Consumer tier: two-tier picker (recent ring first during plateaus, durable pool otherwise), A/B live-pick policy, weighted draw |
| credit.c | 413 | Feedback loop: per-entry credit drain (wins/misses), outcome classification (PC win, CMP novelty, transition, corpus save) |
| persist.c | 855 | Warm-start persistence: on-disk snapshot/load with kallsyms SHA-256 fingerprinting, KASLR-base validation, CRC32 integrity |
| shadow_promote.c | 304 | Measure-only shadow-arm promotion evaluator: walks a registry of shadow arms each stats tick, emits one promotion-criterion line. Writes no generation path. |
| childop_consume.c | 66 | Consume-side resolver for the childop CMP path (`--childop-cmp-harvest`); shadow-scores what a live consume would return, always returns "no hint" |

### Typed hypothesis store (`hyp-*.c`)

The typed hypothesis store — 5 kind lanes (EXACT, BITMASK, ENUM_FAMILY,
RANGE, BOUNDARY), the OBSERVED→PROMOTED/DEMOTED→RETIRED state machine, and
the live inject arm — is split one lane per translation unit. Helpers a lane
exports to a sibling lane, but not to the public `cmp_hints.h`, live in
`cmp_hints/hyp-internal.h`.

| File | Lines | Role |
|---|---|---|
| hyp-pool.c | 188 | Pool primitives: `cmp_hyp_find()` / alloc / range-identity. Writers run under the matching durable `cmp_hint_pool` lock. |
| hyp-observe.c | 256 | Observe path: the five kind-lane inference rules |
| hyp-credit.c | 436 | Credit path: `cmp_hyp_find_for_credit()`, per-outcome selectors, `cmp_hyp_credit_outcome()` / `cmp_hyp_credit_consume()` |
| hyp-pick.c | 261 | Picker: `cmp_hyp_would_pick_locked()` pool walk, specificity ordering, state-aware preference within a kind |
| hyp-derive.c | 791 | Derive ladder: `cmp_hyp_derive_value()` plus the pow2/alignment, bitmask FULL_OR/ANDNOT_TOGGLE and sign-switch probe classes |
| hyp-live.c | 229 | LIVE inject arm: `cmp_hyp_try_live_inject()` and its three gating channels (plateau-amplified A, always-on bootstrap B, PROMOTED-bypass C) |

## Data model

Shared memory (`cmp_hints_shm`):
- `pools[MAX_NR_SYSCALL][2]` — per-syscall, per-arch durable pools; `entries[CMP_HINTS_PER_SYSCALL]` = {value, cmp_ip, size, last_used, wins, misses}; LRU eviction (lowest last_used evicted)
- `recent_pools[MAX_NR_SYSCALL][2]` — circular buffer of latest N inserts
- `childop_recent_pools[...]` — child-sourced recent ring (`--childop-cmp-harvest`)
- `hyp_pools[MAX_NR_SYSCALL][2]` — typed hypothesis store, parallel to durable pools

Per-child:
- `cmp_hints_seen[2]` — per-arch bloom filter (dedup within a bloom window)
- `cmp_hints_consumed_stash[]` — ring of consumed hints for credit drain at dispatch end

## Key design decisions

1. **Lock-free consumption** — `cmp_hints_try_get_ex()` does a lockless ACQUIRE load on `pool->count` then indexes into `entries[]`. Torn reads from concurrent LRU eviction yield either the pre- or post-eviction value, both valid.
2. **Two-tier picker** — during the `CMP_RISING_PC_FLAT` plateau, the recent ring is sampled first for fresh constants; steady state queries only the durable LRU pool.
3. **A/B live-pick policy** — each child gets arm A (uniform random draw) or arm B (weighted: `FLOOR + wins*4 - misses`, floored). Arm B consumes SHADOW feedback scores from the credit drain; arm A is the control.
4. **Typed hypothesis inference (`hyp-*.c`)** — on every new constant, 5 parallel lanes observe it: EXACT (per-value identity), BITMASK (single-bit-only values), ENUM_FAMILY (all values at a cmp_ip, accumulating lo/hi/mask), RANGE (synthesized from ENUM_FAMILY at ≥3 hits, span 2..32), BOUNDARY (per-(cmp_ip, width) strict-inequality summary, N-1/N+1). State machine: OBSERVED → first win → PROMOTED; 8+ misses no wins → DEMOTED → sustained misses → RETIRED. PROMOTED gets higher injection probability via the Promoted-Bypass channel (~1.6%).
5. **Chaos mode** — every 8th window (~12.5%) suppresses hint injection to let random-arg generation explore invalid-combination space.
6. **Persistence (persist.c)** — warm-start with 5-version schema evolution: v1→v2 pool capacity 32→16, v2→v3 last_used widened to uint64_t, v3→v4 arch dimension added, v4→v5 KASLR canonicalization. Validity gates: magic, version, max_syscall, per_syscall count, entry_size, payload_bytes, CRC32, kallsyms SHA-256 fingerprint, KASLR-base mode agreement.
7. **Corruption defense** — every pool accessor checks `cmp_hints_pool_corrupted()`: validates `count <= CAP`, probes canary sentinels flanking the pool (before entries[], after entries[], after lock). Stomped pool is latched corrupted to prevent OOB access; wild-write detection bumps per-channel counters for forensics.

## Integration points

- `args/cmp_hint_inject.c` — commits a `cmp_hints_try_get_ex()` hint to a produced syscall arg; the actual injection point downstream of get.c's picker
- `blob_mutator.c` — `cmp_hints_try_get_sized()` for width-preserving splat into opaque buffers (CMPDICT mode)
- `child/child-init-*.c` — per-child bloom filter reset and consumed stash clearing on fork
- `main/trinity-warmstart.c` — warm-start load on boot, save on shutdown, snapshot tick in main loop
- `main/params/runtime.c` — `--no-cmp-hints-warm-start` toggle, blob-mutator mode description
- `health/signals-fault-handler.c` — recovery point for field-scoped timespec deref SEGV
- `strategy.c`, `strategy-plateau.c`, `strategy-cmp-novelty.c`, `strategy-bandit.c`, `strategy-frontier.c`, `strategy-rescue.c`, `stats_ring.h` — plateau hypothesis coordination, CMP-novelty outcome classification, bandit/frontier scoring, stats ring counters
- `random_syscall/chain-persist.c`, `objects/prop_ring.c` — mid-run snapshot triggers and injection-rate mirroring analogous to the cmp_hints gate

## Areas of attention

1. **Largest files** — collect.c (1,158), pool.c (1,042), persist.c (855), hyp-derive.c (791). The hypothesis store's responsibilities (inference, state machine, picker, derive, credit outcomes, live inject) sit one per `hyp-*.c` lane file, but `cmp_hyp_derive_value()` (hyp-derive.c:497–791) is still ~295 lines with deep nesting. `cmp_hints_collect()` (collect.c:236–970) is still a ~735-line function: its per-record loop (collect.c:392–923, ~530 lines, with the RedQueen attribution scan nested in it) stays whole on purpose, and only the once-per-call scan setup lives apart, in `cmp_attribution_prestage()`. The post-loop counter flush stays inline: it publishes thirteen same-typed accumulators that the loop increments by name, so a helper would take them as a long positional list or need a struct that rewrites every increment in the loop.
2. **Complex credit resolution** — `cmp_hyp_find_for_credit()` walks all 5 hypothesis kinds in specificity order (EXACT > ENUM_FAMILY > BITMASK > RANGE > BOUNDARY) on every consume and every outcome credit.
3. **Timespec-pin safety depends on `range_readable_user()`** (`cmp_field_match_timespec()` in collect.c) — checks VMA readability before dereferencing the dispatch-time buffer; a missed page-fault race is recovered through the sigsetjmp point in health/signals-fault-handler.c.

## Summary

Core loop: collect CMP constants → store in LRU pools → re-inject into args → observe outcomes (PC edge / novelty / transition / corpus save) → credit hypotheses → promote converting ones. The typed hypothesis layer adds semantic structure on top of raw constant replay (N-1/N+1 for boundaries, individual bits for masks, lo/hi/midpoint for ranges).

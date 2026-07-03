# cmp_hints/ — KCOV Comparison-Operand Hint System

Fuzzer intelligence layer for Trinity. Collects constants the kernel compares syscall-derived values against (KCOV_TRACE_CMP), feeds them back into arg generation to bias inputs toward values likely to pass kernel validation gates.

## Files (8 files, ~5,950 LOC)

| File | Lines | Role |
|---|---|---|
| cmp_hints.c | 358 | Entry point: SHM allocation, strip-installation, chaos-mode gating |
| collect.c | 1042 | KCOV ingestion: cmp_hints_collect() walks raw trace_cmp buffer, cmp_hint_apply_transform() normalizes values, cmp_hints_stash_consumed() records consumed hints for credit |
| pool.c | 482 | Pool primitives: lock wrappers, corruption gates, dedup + LRU eviction, bloom filter, recent ring, batch flush |
| get.c | 559 | Consumer tier: two-tier picker (recent ring first during plateaus, durable pool otherwise), A/B live-pick policy, weighted draw |
| credit.c | 419 | Feedback loop: per-entry credit drain (wins/misses), outcome classification (PC win, CMP novelty, transition, corpus save) |
| hyp.c | ~1600 | Typed hypothesis store: inference engine with 5 kind lanes (EXACT, BITMASK, ENUM_FAMILY, RANGE, BOUNDARY), state machine (OBSERVED→PROMOTED/DEMOTE→RETIRED), live inject arm |
| field.c | ~663 | Field-scoped attribution pool: maps kernel CMP constants to specific struct fields via struct catalog walking |
| persist.c | 835 | Warm-start persistence: on-disk snapshot/load with kallsyms SHA-256 fingerprinting, KASLR-base validation, CRC32 integrity |

## Data model

Shared memory (`cmp_hints_shm`):
- `pools[MAX_NR_SYSCALL][2]` — per-syscall, per-arch durable pools; `entries[CMP_HINTS_PER_SYSCALL]` = {value, cmp_ip, size, last_used, wins, misses}; LRU eviction (lowest last_used evicted)
- `recent_pools[MAX_NR_SYSCALL][2]` — circular buffer of latest N inserts
- `childop_recent_pools[...]` — child-sourced recent ring (`--childop-cmp-harvest`)
- `field_pools[CMP_FIELD_POOL_BUCKETS]` — hash-based field-scoped attribution pool
- `hyp_pools[MAX_NR_SYSCALL][2]` — typed hypothesis store, parallel to durable pools

Per-child:
- `cmp_hints_seen[2]` — per-arch bloom filter (dedup within a bloom window)
- `cmp_hints_consumed_stash[]` — ring of consumed hints for credit drain at dispatch end

## Key design decisions

1. **Lock-free consumption** — `cmp_hints_try_get_ex()` does a lockless ACQUIRE load on `pool->count` then indexes into `entries[]`. Torn reads from concurrent LRU eviction yield either the pre- or post-eviction value, both valid.
2. **Two-tier picker** — during the `CMP_RISING_PC_FLAT` plateau, the recent ring is sampled first for fresh constants; steady state queries only the durable LRU pool.
3. **A/B live-pick policy** — each child gets arm A (uniform random draw) or arm B (weighted: `FLOOR + wins*4 - misses`, floored). Arm B consumes SHADOW feedback scores from the credit drain; arm A is the control.
4. **Typed hypothesis inference (hyp.c)** — on every new constant, 5 parallel lanes observe it: EXACT (per-value identity), BITMASK (single-bit-only values), ENUM_FAMILY (all values at a cmp_ip, accumulating lo/hi/mask), RANGE (synthesized from ENUM_FAMILY at ≥3 hits, span 2..32), BOUNDARY (per-(cmp_ip, width) strict-inequality summary, N-1/N+1). State machine: OBSERVED → first win → PROMOTED; 8+ misses no wins → DEMOTED → sustained misses → RETIRED. PROMOTED gets higher injection probability via the Promoted-Bypass channel (~1.6%).
5. **Field-scoped attribution (field.c)** — walks cataloged struct arguments, checks if a field value matches CMP arg2, records the constant against that struct::field tuple for precise re-injection at the right arg slot.
6. **Chaos mode** — every 8th window (~12.5%) suppresses hint injection to let random-arg generation explore invalid-combination space.
7. **Persistence (persist.c)** — warm-start with 5-version schema evolution: v1→v2 pool capacity 32→16, v2→v3 last_used widened to uint64_t, v3→v4 arch dimension added, v4→v5 KASLR canonicalization. Validity gates: magic, version, max_syscall, per_syscall count, entry_size, payload_bytes, CRC32, kallsyms SHA-256 fingerprint, KASLR-base mode agreement.
8. **Corruption defense** — every pool accessor checks `cmp_hints_pool_corrupted()`: validates `count <= CAP`, probes canary sentinels flanking the pool (before entries[], after entries[], after lock). Stomped pool is latched corrupted to prevent OOB access; wild-write detection bumps per-channel counters for forensics.

## Integration points

- `args/cmp_hint_inject.c` — commits a `cmp_hints_try_get()` hint to a produced syscall arg; the actual injection point downstream of get.c's picker
- `blob_mutator.c` — `cmp_hints_try_get_sized()` for width-preserving splat into opaque buffers (CMPDICT mode)
- `child-init.c` — per-child bloom filter reset and consumed stash clearing on fork
- `trinity.c` — warm-start load on boot, save on shutdown, snapshot tick in main loop
- `params.c` — `--no-cmp-hints-warm-start` toggle, blob-mutator mode description
- `signals.c` — recovery point for field-scoped timespec deref SEGV
- `strategy.c`, `strategy-plateau.c`, `strategy-cmp-novelty.c`, `strategy-bandit.c`, `strategy-frontier.c`, `strategy-rescue.c`, `stats_ring.h` — plateau hypothesis coordination, CMP-novelty outcome classification, bandit/frontier scoring, stats ring counters
- `deferred-free.c` — recovers real allocation length for field-scoped pool scans; parallel recent-entry walk order
- `sequence.c`, `prop_ring.c` — mid-run snapshot triggers and injection-rate mirroring analogous to the cmp_hints gate

## Areas of attention

1. **hyp.c size** (~1600 LOC) does inference, state machine, picker, derive logic, credit outcomes, and live inject — 5–6 responsibilities. `cmp_hyp_derive_value()` (lines 1168–1431) alone is ~260 lines with deep nesting.
2. **Complex credit resolution** — `cmp_hyp_find_for_credit()` walks all 5 hypothesis kinds in specificity order (EXACT > ENUM_FAMILY > BITMASK > RANGE > BOUNDARY) on every consume and every outcome credit.
3. **Field-scan safety depends on `range_readable_user()`** (field.c:424) — checks VMA readability before dereferencing struct buffers; a missed page-fault race SEGVs the child (recovery point in signals.c).

## Summary

Core loop: collect CMP constants → store in LRU pools → re-inject into args → observe outcomes (PC edge / novelty / transition / corpus save) → credit hypotheses → promote converting ones. The typed hypothesis layer adds semantic structure on top of raw constant replay (N-1/N+1 for boundaries, individual bits for masks, lo/hi/midpoint for ranges).

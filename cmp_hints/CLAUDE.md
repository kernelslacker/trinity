# cmp_hints/ — KCOV Comparison-Operand Hint System

Fuzzer intelligence layer for Trinity. Collects constants the kernel compares syscall-derived values against (KCOV_TRACE_CMP), feeds them back into arg generation to bias inputs toward values likely to pass kernel validation gates.

## Key design decisions

1. **Lock-free consumption** — `cmp_hints_try_get_ex()` does a lockless ACQUIRE load on `pool->count` then indexes into `entries[]`. Torn reads from concurrent LRU eviction yield either the pre- or post-eviction value, both valid.
5. **Chaos mode** — every 8th window (~12.5%) suppresses hint injection to let random-arg generation explore invalid-combination space.
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

1. **Largest files** — The hypothesis store's responsibilities (inference, state machine, picker, derive, credit outcomes, live inject) sit one per `hyp-*.c` lane file; `cmp_hyp_derive_value()` keeps the kind switch and the census tail, with the EXACT and BOUNDARY ladders in `derive_exact()` / `derive_boundary()`. `cmp_hints_collect()` is still a ~735-line function: its per-record loop stays whole on purpose, and only the once-per-call scan setup lives apart, in `cmp_attribution_prestage()`. The post-loop counter flush stays inline: it publishes thirteen same-typed accumulators that the loop increments by name, so a helper would take them as a long positional list or need a struct that rewrites every increment in the loop.
3. **Timespec-pin safety depends on `range_readable_user()`** (`cmp_field_match_timespec()` in collect.c) — checks VMA readability before dereferencing the dispatch-time buffer; a missed page-fault race is recovered through the sigsetjmp point in health/signals-fault-handler.c.

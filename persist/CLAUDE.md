# persist/ — Persistence & Corpora

Coverage-guided argument retention plus the deferred-free temporal-overlap queue — state that survives across iterations so productive inputs can be replayed and frees can be safely delayed.

The chain corpus does *not* live here: it is a chain *executor* whose corpus is
a secondary feature, distinct from minicorpus's per-syscall arg snapshots, so it
sits in `random_syscall/` beside `chain-subst.c` as `chain-corpus.c` /
`chain-persist.c`.

## Files (10 files, ~4,875 LOC)

| File | Lines | Role |
|---|---|---|
| deferred-free.c | 2343 | Deferred-free queue: hold a tracked free for a TTL window so a temporally-overlapping later syscall can still touch the buffer, with the bad-free/UAF safety machinery. |

Coverage-guided argument retention — snapshot the args of a syscall that found
a new edge, re-inject them into later iterations — is split across
`minicorpus-*.c`, sharing `persist/minicorpus-internal.h`:

| File | Lines | Role |
|---|---|---|
| minicorpus-field-mutate.c | 631 | Per-arg mutator engine: weighted case picker (Beta(1,1)-prior posterior mean over historical trials/wins), structure-aware neighbour ops for ARG_LIST / ARG_OP / ARG_RANGE, and the 1..STACK_MAX stacking wrapper |
| minicorpus-file.c | 521 | On-disk warm-start format: fixed header (magic, version, kernel major.minor, syscall-number space) followed by fixed-size entries |
| minicorpus-accounting.c | 370 | Mutate accept-reject accounting: per-process attribution stashes drained into fleet-wide trials/wins on post-syscall commit; baseline gate, source-age histogram, per-tag rules |
| minicorpus-select.c | 213 | Replay entry point: picks a saved snapshot from the per-syscall ring (uniform normally, K-newest-window under the CMP-rising-PC-flat plateau), then runs the splice-and-mutate driver |
| minicorpus-core.c | 197 | Core primitives: shm allocation + init, per-ring lock bracket, replayability predicate, wp-canary sweep, mutator kill-switch |
| minicorpus-xprop.c | 173 | Cross-syscall value propagation: with low probability override a target arg with a value pulled from a *different* syscall's corpus pool |
| minicorpus-save.c | 169 | Save path: capture per-syscall arg snapshots into the ring after a productive coverage signal (`minicorpus_save()` / `minicorpus_save_with_reason()`) |
| minicorpus-splice.c | 152 | Splice-and-mutate driver: walks the six saved arg slots applying cross-arg splice, xprop pull and the weighted-stack mutator chain, with a final fd-safety scrub |
| minicorpus-snapshot.c | 106 | Periodic mid-run snapshot trigger: `minicorpus_maybe_snapshot()` called by every child after each kcov edge event, armed pre-fork by `minicorpus_enable_snapshots()` |

## Key invariants
- **minicorpus snapshot on new edge** — only args that produced a fresh KCOV edge are retained; replay threads them into later iterations.
- **deferred-free TTL** — a freed-but-tracked buffer survives ~5–50 ticks (batched by 16 → ~80–800 effective) before the real free; opt-in `alloc_track` tracking gates what's eligible, so untracked pointers can't be bad-freed.
- **deferred-free is correctness-critical** — the ring/hash lock-step, same-mprotect-bracket size-slot zeroing, and PROT_READ steady state are the UAF/double-free defenses; changes need ASAN validation (and the TU-split of this file is held for that reason).

## Interactions
- Gated by **`kcov/`** + **`cmp_hints/`** (the coverage signal that decides what to retain).
- deferred-free is called from **`args/`**, csfu, valresult, and the object/childop free paths.

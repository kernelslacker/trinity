# persist/ — Persistence & Corpora

Coverage-guided argument retention plus the deferred-free temporal-overlap queue — state that survives across iterations so productive inputs can be replayed and frees can be safely delayed.

`sequence.c` (the chain corpus) is the last file still at repo root — under active rework in the resource-typing lane. It moves to `random_syscall/` (beside `chain-subst.c`, its executor sibling), not here, once that settles: it's a chain *executor* whose corpus is a secondary feature, distinct from minicorpus's per-syscall arg snapshots.

## Files (2 files, ~4,450 LOC)

| File | Lines | Role |
|---|---|---|
| minicorpus.c | 2327 | Coverage-guided argument retention: snapshot the args of a syscall that found a new edge, re-inject them into later iterations. |
| deferred-free.c | 2120 | Deferred-free queue: hold a tracked free for a TTL window so a temporally-overlapping later syscall can still touch the buffer, with the bad-free/UAF safety machinery. |

## Key invariants
- **minicorpus snapshot on new edge** — only args that produced a fresh KCOV edge are retained; replay threads them into later iterations.
- **deferred-free TTL** — a freed-but-tracked buffer survives ~5–50 ticks (batched by 16 → ~80–800 effective) before the real free; opt-in `alloc_track` tracking gates what's eligible, so untracked pointers can't be bad-freed.
- **deferred-free is correctness-critical** — the ring/hash lock-step, same-mprotect-bracket size-slot zeroing, and PROT_READ steady state are the UAF/double-free defenses; changes need ASAN validation (and the TU-split of this file is held for that reason).

## Interactions
- Gated by **`kcov/`** + **`cmp_hints/`** (the coverage signal that decides what to retain).
- deferred-free is called from **`args/`**, csfu, valresult, and the object/childop free paths.

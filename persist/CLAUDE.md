# persist/ — Persistence & Corpora

Coverage-guided argument retention plus the deferred-free temporal-overlap queue — state that survives across iterations so productive inputs can be replayed and frees can be safely delayed.

The chain corpus does *not* live here: it is a chain *executor* whose corpus is
a secondary feature, distinct from minicorpus's per-syscall arg snapshots, so it
sits in `random_syscall/` beside `chain-subst.c` as `chain-corpus.c` /
`chain-persist.c`.

## Key invariants
- **minicorpus and chain corpus zero saved fd and pointer slots** — each argtype's replay class (keep, zero or refuse) is set on its `argtype_table[]` row, and an argtype whose row sets none is refused; save and load both zero every slot whose argtype is an fd, an address, or a struct, time, mask, pool-buffer or socketinfo pointer (`corpus_argtype_stale_on_replay()`; the chain corpus applies it per step by that step's own ABI, in `chain_zero_stale_args()`); ARG_UNDEFINED slots and kernel-validated ids (key serial, timer, SysV, aio) stay raw by design; a syscall with an iovec, pathname, sockaddr, mmap or pid argument (`corpus_argtype_refused()`), or with no arguments at all, is refused whole by `corpus_args_replayable()`.  The chain corpus's `chain_is_replay_safe()` asks the same `corpus_argtype_refused()`, but admits a step with no arguments.
- **minicorpus rings are keyed by nr alone** — on biarch the i386 and x86_64 syscalls at one nr are unrelated but share the ring, so each entry carries `do32bit`: replay only takes entries of the record's ABI, and the warm-start loader judges each entry by the matching table.  The shadow corpus-absent probe asks `minicorpus_ring_has_abi()` rather than reading the ring's count, which both ABIs share.
- **deferred-free TTL** — a freed-but-tracked buffer survives ~5–50 ticks (batched by 16 → ~80–800 effective) before the real free; opt-in `alloc_track` tracking gates what's eligible, so untracked pointers can't be bad-freed.
- **deferred-free is correctness-critical** — the ring/hash lock-step, same-mprotect-bracket size-slot zeroing, and PROT_READ steady state are the UAF/double-free defenses; changes need ASAN validation.

## Interactions
- Gated by **`kcov/`** + **`cmp_hints/`** (the coverage signal that decides what to retain).
- deferred-free is called from **`args/`** (csfu and valresult included), `objects/`, `fds/`, `utils/`, `mm/` and the syscall handlers' free paths.

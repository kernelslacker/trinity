# childops/mm/ — Memory-Management Childops

Scripted VM/memory stress workloads: mapping lifecycle, protection-boundary splits, madvise patterns, memory locking, NUMA migration, userfaultfd, and pagecache/vDSO edge cases. One workload per file, dispatched by symbol via `op_dispatch[]` generated from `include/childop.def` (X-macro registry).

## Files (16) <!-- Update this count when adding files -->
- `mmap-lifecycle` / `vma-split-storm` — mapping create/teardown + VMA-split pressure.
- `mprotect-split` — protection-boundary splits within a mapping.
- `madvise-pattern-cycler` — madvise advice cycling over a mapping.
- `mlock-pressure` / `memory-pressure` — locked-memory + committable-memory pressure.
- `numa-migration-churn` — NUMA page migration.
- `uffd-churn` — userfaultfd register / fault / resolve cycle.
- `vdso-mremap-race` — vDSO remap race.
- `pagecache-canary-check` — pagecache integrity canary.
- `thp-split-ref-race` — THP split / folio-ref race; 16 MiB mincore-OOB arm uses a `CLONE_VM` sibling racing `walk_pud_range()` alongside `folio_try_get()` / deferred-split queue paths.
- `mremap-merge-matrix` — adjacent anon-VMA merge identities under mremap; drives FIXED_MOVE, DONTUNMAP, GROW, and SHRINK shapes to exercise `vma_merge_copied_range()` and `dup_anon_vma()`.
- `mseal-transition-matrix` — three-VMA arena (fully-sealed / partially-sealed / unsealed) mseal prohibited-transition coverage; canary oracle re-verifies page contents after every prohibited-op attempt, with a concurrent fault thread racing the VMA-lock path.
- `map-shared-stress` — MAP_SHARED writeback + coherence: concurrent shared writeback, MADV_DONTFORK vs fork COW with adjacent MAP_SHARED regions, and O_APPEND vs mmap ordering on a shared pagecache.
- `memfd-secret-lifecycle` — full memfd_secret(2) lifecycle with a cross-process content-confidentiality oracle using `process_vm_readv` and `/proc/<pid>/mem`, plus a concurrent `ftruncate` thread.
- `uffd-fault-move` — UFFD fault + UFFDIO_MOVE/swap-cache race: fault-resolve matrix (COPY/ZEROPAGE/POISON/WP rotation with DONTWAKE), UFFDIO_MOVE racing MADV_PAGEOUT-induced swap-cache pages, and teardown race against a pending fault.

# childops/mm/ — Memory-Management Childops

Scripted VM/memory stress workloads: mapping lifecycle, protection-boundary splits, madvise patterns, memory locking, NUMA migration, userfaultfd, and pagecache/vDSO edge cases. One workload per file, dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c`.

## Files (11)
- `mmap-lifecycle` / `vma-split-storm` — mapping create/teardown + VMA-split pressure.
- `mprotect-split` — protection-boundary splits within a mapping.
- `madvise-pattern-cycler` — madvise advice cycling over a mapping.
- `mlock-pressure` / `memory-pressure` — locked-memory + committable-memory pressure.
- `numa-migration-churn` — NUMA page migration.
- `uffd-churn` — userfaultfd register / fault / resolve cycle.
- `vdso-mremap-race` — vDSO remap race.
- `pagecache-canary-check` — pagecache integrity canary.
- `thp-split-ref-race` — deterministic THP folio split / folio-ref race (folio_split, folio_try_get, deferred-split queue).

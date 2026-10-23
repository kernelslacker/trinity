# mm/ — Memory-Management Fuzzing-Target Subsystem

Owns the fuzzed process's synthetic VMA pools (anon/file/testfile mmap objects), deliberate page-fault injection (read and write), mlock/memlock accounting, initial-mapping and image-segment bookkeeping, and hugepage size-encoding helpers. This is the layer that hands out addresses/lengths for ARG_ADDRESS/ARG_MMAP args and then actively touches the memory behind them to trigger kernel fault paths.

## Files (11 files + internal header, ~3,133 LOC)

| File | Lines | Role |
|---|---|---|
| maps-pick.c | 645 | Pool pick + validate + refill: `pick_mmap_pool_type()`, the three corruption guards (`obj_ptr_in_user_va_band`, `obj_pool_slot_check`, `map_size_in_range`), `get_map_handle`/`validate_map_handle`, `get_map`/`get_map_with_prot`, `addr_in_local_runtime_map`, `maybe_refill_local_anon_pool` |
| maps-lifecycle.c | 589 | Destructors and pool cloning: `map_destructor` (OBJ_LOCAL) / `map_destructor_shared` (OBJ_GLOBAL), `map_dump`, `clone_global_mmap_pool`, `init_child_mappings`, `mmap_fd()` (fd-backed mmap producer) |
| maps-proc.c | 208 | `proc_maps_check()`: reads `/proc/self/maps` and verifies the presence/absence and prot bits of a VMA covering `[addr, addr+len)` |
| maps-arg.c | 115 | `common_set_mmap_ptr_len()` — arg-plumbing for mincore/mremap/madvise/mlock/etc., plus the pool type-resolution walk |
| maps-dirty.c | 96 | `dirty_mapping()` / `dirty_random_mapping()`: assorted write patterns over a mapping trinity created |
| maps-internal.h | 18 | Cross-file declarations private to the `maps-*.c` cluster |
| maps-initial.c | 241 | Startup-only: `setup_initial_mappings()` creates the OBJ_GLOBAL ANON pool (every prot x flags combination x mapping_sizes[9]) plus best-effort MAP_HUGETLB entries before fork; `setup_mapping_sizes()` gates 1GB mappings on free memory and a 1-in-100 roll |
| fault-read.c | 384 | `random_map_readfn()`: 5 read-walk strategies (whole/every-other/reverse/random/last-page) capped at 32 pages/call, wrapped in a SIGSEGV/SIGBUS handler that longjmps past TOCTOU races (sibling munmap, hole-punch) |
| fault-write.c | 376 | `random_map_writefn()`: same 5 strategies for writes (mprotect RW + store), plus 2 single-page variants; same SIGSEGV/SIGBUS longjmp guard, mirrored per-file statics |
| mlock-state.c | 191 | Per-child `__thread` mlock accounting: RLIMIT_MEMLOCK-aware budget tracking (`mlock_state_clamp_len`), (start,len) bucket picker for mlock/munlock args, 8-entry recently-locked ring for biasing munlock toward real locked ranges |
| image-segments.c | 117 | One-shot at startup: `register_loaded_image_segments()` walks `dl_iterate_phdr()` and registers every writable PT_LOAD segment (main exe + every DSO's data/BSS) with `shared_regions[]` so fuzzed mmap/munmap/mprotect can't touch trinity's own static state |
| hugepages.c | 166 | `pick_random_huge_size_encoding()`: probes `/sys/kernel/mm/hugepages/` for supported sizes, encodes a random one into the shared MAP_HUGE_*/MFD_HUGE_*/SHM_HUGE_* bitfield shift (bits 26-31) |

## Key design decisions

1. **Two-tier pool model (OBJ_GLOBAL vs OBJ_LOCAL)** — `setup_initial_mappings()` builds one shared/global ANON snapshot pre-fork; `init_child_mappings()` clones it (by-pointer, COW-backed) into each child's OBJ_LOCAL pool. FILE/TESTFILE pools are lazily cloned the same way (`clone_global_mmap_pool`). Runtime mmap()/munmap() by a child only ever mutates its own OBJ_LOCAL pool.
2. **Pool-type masking (maps-pick.c `pick_mmap_pool_type`)** — a per-child `mmap_pool_nonempty_mask` restricts the uniform 1-of-3 draw to non-empty OBJ_LOCAL pools, avoiding guaranteed-miss draws once FILE/TESTFILE drain; OBJ_GLOBAL (parent-side) keeps the plain uniform pick since it has no occupancy shadow.
3. **Layered corruption defense on every pool pick** (`get_map_handle`) — three independent guards run before any deref: user-VA-band check on the obj pointer (`obj_ptr_in_user_va_band`), pool-slot validity via `objpool_check` (`obj_pool_slot_check`; validates obj->obj_type against the pool the draw landed on -- same gate the sibling `addr_in_local_runtime_map` / `invalidate_mmap_pool_range` walks use), and a size sanity cap at GB(4) (`map_size_in_range`). Each has a dedicated per-type stats counter; failing any retries up to 1000 times, then triggers `maybe_refill_local_anon_pool`.
4. **Destructor split by scope** — `map_destructor` (OBJ_LOCAL, libc strdup/malloc names, plain `free`) vs `map_destructor_shared` (OBJ_GLOBAL, shared-heap names via `alloc_shared_str`/`free_shared_str`). Both re-validate `ptr`/`extent` against the VA band and GB(4) cap before `munmap`/`untrack_shared_region`, since a scribbled map struct could otherwise drive a wild unmap of trinity's own bookkeeping.
5. **tracked_size vs size split** — `map->size` is the consumer-walkable, fstat-clamped extent (never past real file EOF); `map->tracked_size` is the actual VMA extent the kernel mapped, used for `track_shared_region`/`untrack_shared_region` and `munmap` so a clamp-for-safety on `size` doesn't leak the tail of the VMA in the shared-region tracker.
6. **Live TOCTOU handling in the fault injectors** — both `random_map_readfn`/`random_map_writefn` snapshot the map, re-`fstat` file-backed extents to clamp against a shrinking file, then install a scoped SIGSEGV/SIGBUS handler (`sigsetjmp`/`siglongjmp`) that only intercepts faults whose `si_addr` falls inside the active walk range; a fault outside it, or a signal the child sent itself (`SI_USER`/`SI_TKILL` with its own pid), is passed through to the normal `child_fault_handler` crash path, and whatever a sibling or `F_SETSIG` could have sent is ignored (`fault_signal_is_real()`, which trusts `si_pid` only under those two codes; `tests/child_fault_test.c`). Handler state is per-file `volatile` statics, matching the guard in `childops/mm/pagecache-canary-check.c`.
7. **Per-call fault-walk cap (32 pages)** — both fault-read and fault-write cap the pages touched per call to bound the mprotect-driven TLB-shootdown IPI storm on large mappings; offset/index selection stays uniform over the full mapping, only the iteration count is capped.
8. **mlock budget accounting is `__thread`, not per-process** — tracks cumulative locked bytes against `RLIMIT_MEMLOCK` so repeated mlock draws don't uniformly ENOMEM once the cap is exhausted; deliberately returns `page_size` rather than 0 when over budget so the call still exercises the kernel's rlimit-check path instead of no-op'ing on `len=0`.
9. **Image-segment registration is a startup one-shot** — `dl_iterate_phdr()` runs once before `fork_children()`; only PT_LOAD segments with `PF_W` are tracked (read-only text/rodata mprotect strips just SIGSEGV on next fetch, already handled by the fault machinery). No re-scan on hypothetical future `dlopen()`.
10. **Hugepage shift probing is lazy and cached** — `/sys/kernel/mm/hugepages/` is scanned once per process; falls back to a fixed architecture-agnostic shift list (2MB/32MB/256MB/1GB/8GB) if the sysfs directory is absent, deliberately allowing -EINVAL as a fuzzable outcome.

## Integration points

- `args/gen_arg_scalar.c`, `rand/random-address.c` — draw addresses from `get_map()`/`get_map_handle()` for ARG_ADDRESS-shaped syscall args
- `syscalls/mm/munmap.c`, `mprotect.c`, `madvise.c`, `mremap.c`, `mincore.c`, `mlock.c`, `munlock.c`, `mbind.c`, `msync.c`, `remap_file_pages.c`, `syscalls/hardware/getrandom.c` — sanitisers call `common_set_mmap_ptr_len()` to plumb a picked map's (ptr,len) into `rec->a1`/`a2`
- `syscalls/mm/mmap.c` calls `dirty_random_mapping()`/pool APIs directly and pulls hugepage encodings from `pick_random_huge_size_encoding()` (shared with `syscalls/mm/memfd/memfd_create.c`)
- `syscalls/fs/ftruncate.c`, `fallocate.c`, `madvise.c`, `fds/testfiles.c` — call `invalidate_obj_mmap_in_range`/`invalidate_obj_mmap_by_fd` to soft-invalidate pool entries whose backing extent changed (hole-punch, truncate)
- `syscalls/mm/mmap.c`, `munmap.c`, `mprotect.c` — use `proc_maps_check()` to verify VMA invariants after a syscall
- `child/child.c`, `child/child-init-freeze.c`, `child/child-periodic.c`, `syscalls/process/fork.c` — call `init_child_mappings()`/`dirty_random_mapping()`/fault injectors during child bootstrap and `periodic_work()`
- `fds/sockets.c`, `ioctls/userfaultfd.c`, `syscalls/syslog.c`, `syscalls/ipc/sysv/shmat.c`, `syscalls/mm/numa/move_pages.c`, `syscalls/fs/truncate.c`, `objects/registry-lifecycle.c`, `stats/dump/corruption.c`, `stats/periodic/counter-rates.c` — other consumers of the map pool API (`get_map`/`get_map_with_prot`/`get_map_handle`)
- `syscalls/mm/mlock/mlock.c`, `munlock.c`, `munlockall.c` — the only callers of `mlock_state_*`; munlockall calls `mlock_state_reset()` after a real kernel `munlockall()` clears every VM_LOCKED VMA
- `main/trinity.c` — calls `register_loaded_image_segments()` once before `fork_children()`; `main/trinity-warmstart.c` calls `setup_initial_mappings()` during startup, and each child calls `init_child_mappings()` during child init
- `fds/files.c`, `fds/testfiles.c`, `syscalls/mm/mmap.c` — call `mmap_fd()` to seed OBJ_GLOBAL/OBJ_LOCAL FILE/TESTFILE pool entries from an already-open fd
- `dispatch/syscall-arena.c` — `addr_in_local_runtime_map()` is the live-mapping check in the arena-pointer liveness probe

## Areas of attention

1. **The maps cluster is the bulk of the directory (6 `.c` files, ~1,900 LOC)** — pool pick/validate/refill (maps-pick.c, 645), destructor pairs and cloning (maps-lifecycle.c, 589), `/proc/self/maps` checking (maps-proc.c), and arg-plumbing (maps-arg.c) now sit in separate TUs sharing `maps-internal.h`. The corruption-defense layer (obj-ptr band check, alloc-track lookup, size cap) is still duplicated inline across `get_map_handle`, `map_destructor`, and `map_destructor_shared` rather than factored into one shared validator.
2. **`common_set_mmap_ptr_len`'s type-resolution walk is O(n) over all three pools** on every call that needs `out_type` (used by `post_munmap`'s WHOLE-destroy path) — a linear scan comparing `obj` pointers, with its own scan-length stats counters acknowledging the cost.
3. **Fault-injection signal handlers are duplicated near-verbatim** between fault-read.c and fault-write.c (armed flag, lo/hi range, sigsetjmp/siglongjmp dance) — the comments in both note that `childops/mm/pagecache-canary-check.c` carries the same pattern a third time. `-Wclobbered`/volatile requirements make hoisting nontrivial but three independent copies is a real drift risk.
4. **`/proc/self/maps` parsing appears in two places** (`maps-proc.c::proc_maps_check`, `stats/periodic/vma.c::count_proc_maps_lines`) with different failure semantics — a shared parser deliberately was not built to avoid include-surface entanglement, so fixing a `/proc/self/maps` line-format edge case requires touching both files.

## Summary

mm/ supplies both the raw material (VMA pools seeded pre-fork, cloned per-child, refilled lazily) and the active fault-injection machinery (read/write walkers with TOCTOU-safe signal recovery) that the rest of trinity uses to exercise page-fault, mmap/mprotect/mlock, and hugepage kernel paths. Everything here is defensive by construction: pool consumers assume a fuzzed syscall may have scribbled any pointer/size field, and every pick/destroy path re-validates before dereferencing. image-segments.c exists purely to keep trinity's own memory unmolested while the fuzzed syscalls run.

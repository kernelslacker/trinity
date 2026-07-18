# utils/ — General-Purpose Runtime Support

Grab-bag of infrastructure Trinity's fuzz loop depends on but that doesn't
belong to any one subsystem: shared-memory allocation, locking, resource
limits, namespace/cgroup isolation, crash/debug diagnostics, and small
pointer-sanity/range helpers consumed from syscalls/, mm/, kcov/, and
cmp_hints/.

## Files (23 files, ~9,181 LOC)

| File | Lines | Role |
|---|---|---|
| shared_mem.c | 1364 | Core shared-memory allocator: `alloc_shared()`/`free_shared()`, region tracking (`shared_regions[]` + overflow tail), 2 MiB-granularity bitmap accelerator, size-bucket freelists, per-object `CONFIG_GUARD_SHARED` guard-page mode |
| self_cgroup.c | 1245 | cgroup v2 self-containment: parent/children sub-cgroup split, memory.high/max caps, OOM-group isolation, clone-into-cgroup, delegation checks, event (memory.high/max) polling |
| range_overlap.c | 801 | `range_overlaps_shared()`/`range_in_tracked_shared()` — mm-syscall sanitiser oracle: bitmap prefilter + exact linear-scan confirm; `CONFIG_GUARD_SHARED` audit path (`range_overlaps_shared_audited`) cross-checks fast vs. slow verdicts |
| heap_bounds.c | 787 | glibc brk-arena bounds tracking from `/proc/self/maps`; `is_in_glibc_heap()`, `range_overlaps_libc_heap()` guard mm-syscalls against clobbering the malloc arena |
| corrupt_ptr.c | 524 | `looks_like_corrupted_ptr()` heuristic (NULL-ish/pid-shaped/kernel-VA/misaligned bands) plus per-child attribution rings (by syscall, by callsite PC, by rejection site) for the cluster-1/2/3 SIGSEGV triage |
| locks.c | 485 | `lock_t` primitive: `trylock`/`lock`/`unlock`, dead-owner reaping via (pid, start_time) fingerprint, `check_all_locks()` periodic sweep across shm/children/cmp_hints/minicorpus/chain_corpus lock families, reserved-bit scribble recovery |
| debug.c | 489 | Backtraces, `BUG()`/panic path, child crash dump (`dump_child_bug`, `dump_child_fault_beacon`, `dump_childdata`), list-corruption assertions, `debugf`/`syslogf` |
| isolation.c | 392 | Parent-side one-shot namespace provisioning: `unshare(CLONE_NEWNET\|CLONE_NEWNS)`, hand-rolled netlink RTM_NEWLINK/RTM_NEWADDR to bring up lo+loopback addrs, MS_PRIVATE remount; publishes `net_ready`/`mnt_ready` latches to shm |
| post_state.c | 429 | Ownership table for post-handler state snapshots (`rec->post_state`) hung off zmalloc'd structs — guards against a sibling's value-result write redirecting the pointer into another syscall's chunk |
| pc_format.c | 343 | `pc_to_string()`: renders a code pointer as "binary+0xOFFSET" via `dl_iterate_phdr`/link_map bias, addr2line-friendly for both PIE and EXEC builds |
| utils.c | 281 | Misc: `sizeunit()`, `kill_pid()`, `sanitize_inherited_fds()`, `get_num_fds()`, `cached_online_cpus()` |
| proc-status.c | 288 | `/proc/self/status` seq_file-safe reader (loops read() to EOF) plus field parsers (uint, uid/gid quad, hex sigmask, ns-last-uint) |
| rlimit-safe.c | 244 | Per-resource "safe" (cur,max) pair dictionaries for fuzzing the rlimit family without self-DoS (RLIMIT_NICE encoding, RTPRIO range, etc.) |
| shm.c | 474 | `create_shm()`/`init_shm()` orchestrator: shm sizing, sentinel stamping (netns_fd=-1, scratch_block=-1), phased init (debug/start-time, self-exe snapshot, strategy-rotation state, children[] + fd/stats ring allocation, mprotect(PROT_READ) lockdown, subsystem singleton bring-up) |
| post_snapshot.c | 135 | `range_readable_user()` (VMA-readability gate before deref) and safe struct-copy helpers used by field-scoped attribution and post handlers |
| sysv-shm.c | 114 | SysV shared-memory object type: create/dump/destructor, integrates with `objects/` and shared-region tracking |
| rlimits.c | 128 | Startup rlimit caps: raise RLIMIT_MEMLOCK to infinity (needs CAP_SYS_RESOURCE), cap NOFILE/NPROC/AS as OOM-cascade defense-in-depth |
| uid.c | 139 | `drop_privs()`, `init_uids()`, `check_uid()` — privilege-drop-to-nobody spine |
| writer-watch.c | 139 | `--writer-watch=<addr>`: arms a hardware WRITE breakpoint (perf_event_open) per child for pinpointing a wild writer's exact RIP |
| log-load-bases.c | 102 | Logs PIE/libc/ld-linux/vDSO load bases via `dl_iterate_phdr()` at startup so post-mortem crash IPs can be resolved offline |
| output.c | 107 | `output()`/`outputerr()`/`outputstd()` verbosity-gated logging, `should_route_to_stdout()` (stdout reserved for `--stats-json`) |
| persist-util.c | 107 | `persist_sweep_stale_tmp()`: sweeps orphaned `<path>.tmp.<pid>` staging files left by a killed writer, shared by minicorpus/cmp_hints/kcov-bitmap persistence |
| zmalloc.c | 64 | `__zmalloc()`/`__zmalloc_tracked()`: zeroing malloc wrapper with mlockall-retry-on-ENOMEM and brk-cache refresh tick |

## Key design decisions

1. **Two-tier shared-region tracking (shared_mem.c, range_overlap.c)** — every `alloc_shared()` call registers into `shared_regions[]` (+ overflow tail) *and* marks a 2 MiB-granularity bitmap (`shared_region_bitmap`) plus a size-bucket bitmap (`tracked_size_bm`). `range_overlaps_shared()` uses the bitmaps as a fast negative prefilter (O(1) empty-fleet check, O(chunks) word scan) and only falls through to the exact linear scan on a bitmap hit — this is the primary defense keeping fuzzed mm-syscalls (munmap/mremap/mprotect/madvise/mseal/mbind) from clobbering Trinity's own shared state.
2. **`CONFIG_GUARD_SHARED` dual-mode audit** — when enabled, `guard_pages_alloc()` wraps allocations in PROT_NONE leading/trailing pages (byte-precise overflow trapping) and `range_overlaps_shared_audited()` cross-checks the fast bitmap path against a from-scratch slow scan, logging to a per-child ring on divergence. This is a debug/investigation mode (kcov trace-buffer corruption hunt), not the production default path.
3. **Lock recovery via (pid, start_time) fingerprint (locks.c)** — a bare `pid_alive()` check is insufficient because PIDs recycle over a long fuzz run; every dead-owner reclaim (`check_lock`, `try_release_dead_holder`, `force_bust_lock`) additionally compares `owner_start_time` against `/proc/<pid>/stat` field 22 to rule out a recycled-pid false match before releasing.
4. **`check_all_locks()` held_count fast-path + recalibration** — per-family (cmp_hints pools, minicorpus rings) atomic `held_count` counters let the periodic parent sweep skip the full per-syscall walk when nothing is held; a `zombies_reaped` counter bump forces one full recalibration pass to resync `held_count` after a dead-child leak, since acquire/release pairing can desync the fast-path gate.
5. **Startup namespace provisioning is parent-side and best-effort (isolation.c)** — `setup_startup_isolation()` runs once pre-fork as root, using hand-rolled NETLINK_ROUTE messages (no libc netns helpers) to bring `lo` up and assign 127.0.0.1/8 + ::1/128 before children fork and inherit via COW. `net_ready` and `mnt_ready` latch independently; any failure degrades silently to the pre-existing per-child `unshare()` path — never fatal.
6. **cgroup parent/children split (self_cgroup.c)** — `trinity-<pid>/parent/` (generous `memory.high`, `oom.group=0`) is kept separate from `trinity-<pid>/children/` (`oom.group=1`, capped `memory.max`) so an OOM in the fuzz workload kills the whole worker pool atomically without also killing the orchestrating parent process.
7. **`looks_like_corrupted_ptr()` heuristic bands (corrupt_ptr.c)** — rejects pointers that are `< 0x10000` (PID/small-int shaped), `>= 1<<47` (non-canonical/kernel-VA), or misaligned (`& 0x7`, since every Trinity allocator returns 8-byte-aligned memory). Deliberately over-rejects (false positive = benign leak) rather than under-rejects (false negative = the SIGSEGV class it exists to kill).
8. **shm init is a strict ordered phase list (shm.c)** — `init_shm()` runs debug/start-time seed → self-exe snapshot → strategy-rotation state → children[]/ring allocation → per-child ring init → publish+mprotect+subsystem bring-up. The mprotect(PROT_READ) lockdown of `children[]` must run after the mirror-page publish and before per-child-ring-dependent subsystem init; comments in the file document this as load-bearing ordering, not incidental.
9. **rlimit caps are defense-in-depth, not security boundaries (rlimits.c)** — NOFILE/NPROC/AS caps bound a runaway fuzz process from starving the whole host; NPROC is skipped under `--dry-run` (no fork-storm childops fire) and AS is skipped on ASAN builds (shadow memory needs unlimited VA).

## Integration points

- `syscalls/*.c` (mbind.c, madvise.c, mseal.c, mmap-lifecycle.c, mprotect-split.c, mlock-pressure.c, futex_wait.c, remap_file_pages.c, process_madvise.c, set_mempolicy_home_node.c, and dozens more) — call `range_overlaps_shared()` / `looks_like_corrupted_ptr()` before honoring a fuzzed address/pointer argument; this is the widest fan-out from utils/, spanning nearly every mm-adjacent syscall handler plus most post handlers that free or deref a value-result pointer.
- `mm/maps.c`, `mm/maps-initial.c`, `mm/image-segments.c`, `rand/random-address.c` — consume `range_overlaps_shared()`, `range_in_tracked_shared()`, `is_in_glibc_heap()` when picking or validating candidate addresses for fuzzed syscall args.
- `kcov/lifecycle.c`, `stats/corrupt_ptr.c` — kcov trace-buffer setup consults `range_overlaps_shared()`; `stats/corrupt_ptr.c` aggregates the corrupt_ptr.c per-child attribution shards for reporting.
- `deferred-free.c` — the deferred-free ring uses `looks_like_corrupted_ptr()` before freeing a stashed pointer, and recovers real allocation length via `shared_region_size_for()`; `range_overlaps_shared()` protects the ring's own mprotect'd region.
- `cmp_hints/*.c`, `minicorpus.c`, `kcov-bitmap` writers — call `persist_sweep_stale_tmp()` at the top of their warm-start load paths, and use `lock_t`/`trylock`/`unlock` for their pool/ring locking; `check_all_locks()` in locks.c walks their lock families by name (cmp_hints pools, minicorpus rings, chain_corpus ring).
- `trinity.c` — `create_shm()`/`init_shm()` run at startup before fork; `init_rlimits()`, `log_load_bases()`, and (as root) `setup_startup_isolation()` all run from the same pre-fork init sequence in trinity.c.
- `child.c`, `child-init.c`, `main/loop.c`, `main/spawn.c`, `fds/scratch_block.c` — drive `self_cgroup_setup()`/`self_cgroup_fork_into_workload()`/`self_cgroup_cleanup()` around the fork boundary.
- `signals.c` — `child_fault_handler()` calls `guard_pages_classify()` (async-signal-safe, plain array reads only) to identify a guard-page trap, and consults `range_readable_user()` in the post_snapshot.c recovery path for field-scoped struct dereferences.
- `objects/` — `sysv-shm.c` implements the SysV shm object type (`create_sysv_shms`, dump, destructor) plugged into the generic object-lifecycle framework.

## Areas of attention

1. **self_cgroup.c (1245 LOC) does five jobs in one file** — size-arg parsing/validation, cgroup v2 filesystem manipulation (mkdir/write/rmdir across parent+children sub-cgroups), delegation/capability probing (`scope_can_delegate`, `already_capped`), fork-into-workload orchestration, and `memory.events` polling. `setup_split()`/`setup_single()` (lines ~400-683) are the split/fallback cgroup-layout logic and are the densest part.
2. **shared_mem.c mixes three independent allocator concerns** — the plain bump/freelist allocator, the bitmap+size-bucket region tracker, and the `CONFIG_GUARD_SHARED` guard-page subsystem all live in one 1364-line file. The guard-page code (`guard_pages_alloc`, `guard_pages_classify`, `guard_pages_derive_span`) is compiled conditionally but interleaves with the always-on allocator, raising the file's effective complexity even when the feature is off.
3. **isolation.c hand-rolls netlink wire encoding** — `privnet_bring_link_up()` and `privnet_add_loopback_addr()` build `nlmsghdr`/`ifinfomsg`/`ifaddrmsg`/`nlattr` byte layouts directly into fixed 128-byte stack buffers with manual `NLMSG_ALIGN`/`NLA_ALIGN` offset arithmetic. This is inherently fiddly (any off-by-one in the attribute offset math corrupts the netlink request) though the surface is small and self-contained; runs once pre-fork as root, so a bug here is a startup-isolation regression rather than an exploitable runtime path.
4. **Lock recovery has several independent dead-owner paths that must stay in lock-step** — `check_lock()`, `try_release_dead_holder()`, and `force_bust_lock()` each reimplement the (pid, start_time) fingerprint comparison and CAS-on-sampled-state pattern independently rather than sharing one helper; a future fix to the ABA-recycle logic must be applied in all three call sites.
5. **corrupt_ptr.c's heuristic is inherently probabilistic** — the NULL-ish/pid-shaped/kernel-VA/misaligned bands are tuned against observed crash signatures (documented inline as a specific 2026-05-02 triage), not a formal invariant; false negatives (a scribbled value that happens to look like a plausible heap pointer) remain possible by construction, and the file's own comments flag the per-site attribution counters as evidence the aggregate corrupt_ptr counter conflates distinct rejection paths (structural validators vs. genuine scribbles).

## Summary

utils/ is the substrate the rest of Trinity builds on: `shared_mem.c` + `range_overlap.c` give every subsystem a shared-memory arena with corruption/overlap defenses; `locks.c` gives it a crash-tolerant locking primitive; `shm.c` orchestrates bringing all of it up in the right order before fork. `isolation.c`, `self_cgroup.c`, `rlimits.c`, and `uid.c` handle sandboxing the fuzzer process tree itself (namespaces, cgroup memory caps, resource limits, privilege drop) — orthogonal to the fuzz loop but load-bearing for running unprivileged and safely at scale. The remaining files are narrowly-scoped diagnostic/safety helpers (`corrupt_ptr.c`, `heap_bounds.c`, `post_state.c`, `post_snapshot.c`, `pc_format.c`, `debug.c`, `writer-watch.c`) consumed piecemeal by syscall/post handlers across the whole tree, plus small persistence and formatting utilities (`persist-util.c`, `proc-status.c`, `zmalloc.c`, `output.c`).

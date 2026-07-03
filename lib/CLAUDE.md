# lib/ — Generic Reusable Primitives

Small grab-bag of standalone helpers with no dependency on each other. Each was
extracted to kill copy-pasted logic that had drifted across several call sites
(cmsg builders, id-map writers, ring buffers). No shared header, no shared
state — this is a directory of convenience, not a subsystem.

## Files (7 files, ~1,457 LOC)

| File | Lines | Role |
|---|---|---|
| cmsg_build.c | 678 | Builds `msghdr.msg_control` ancillary-data blocks for send/sendmsg fuzzing: 16 cmsg kinds (SCM_RIGHTS, SCM_CREDENTIALS, SO_TIMESTAMPING, PACKET_AUXDATA, UDP_GSO, IP/IPv6 pktinfo/tos/ttl/retopts/rthdr, SCM_TXTIME, TLS_SET_RECORD_TYPE) plus a multi-cmsg packer |
| userns-bootstrap.c | 255 | `userns_run_in_ns()`: fork a transient grandchild, enter an identity-mapped user namespace (+ optional secondary namespaces), run a callback, exit — never touches the persistent child's credentials |
| publish_resource.c | 221 | `publish_resource()`: single typed entry point that stamps a freshly minted kernel handle (fd, aio ctx, key serial, pkey, timerid, pid, sysv id) into the OBJ_LOCAL object pool, replacing ~70 hand-rolled `alloc_object()`/`add_object()` call sites |
| spsc-ring.c | 129 | Lock-free single-producer/single-consumer ring buffer primitive: `spsc_ring_init/try_enqueue/drain/overwrite_enqueue`, acquire/release atomics, power-of-two slot count, caller owns storage |
| numa.c | 84 | Parses `/sys/devices/system/node/online` cpulist syntax into a NUMA node pool; `init_numa_nodes()` / `random_numa_node()` for `ARG_NUMA_NODE` generation |
| fd.c | 55 | `write_all()` / `read_all()`: EINTR-retrying full-buffer read/write loops shared by every on-disk persistence format |
| jsonl.c | 35 | Dependency-free JSON-Lines sink (`jsonl_open`/`jsonl_write`): raw open/write/close only, no reliance on trinity's output/shm/logging so it can run before those are up |

(numa.c and cmsg_build.c are the two largest by responsibility; userns-bootstrap.c is the highest-risk for correctness due to privilege semantics.)

## Key design decisions

1. **cmsg_build.c — richness lever preserves RNG-stream identity.** `pick_cmsg_kind()` has two paths gated by `cmsg_richness_mode` (atomic, `__ATOMIC_RELAXED`): OFF does a single `rnd_modulo_u32(NR_CMSG_KINDS_BASE)` over the original 5 kinds so a build without the lever draws byte-identical RNG state; ON adds a family-gated pool (per-AF_UNIX/PACKET/INET/INET6 eligible kinds) plus a `ONE_IN(4)` chance of `CMSG_KIND_MULTI`.
2. **cmsg_build.c — multi-cmsg packer sizes by SUM, not max.** `build_cmsg_multi()` samples 2-3 distinct kinds via Fisher-Yates from a per-family pool of fixed-size entries (variable-length kinds like IP_RETOPTS/IPV6_RTHDR are excluded to keep size accounting trivial), allocates `SUM(CMSG_SPACE(plen))` across chosen entries, and walks `CMSG_FIRSTHDR`→`CMSG_NXTHDR` — this is required for the kernel parser to actually advance past the first header.
3. **userns-bootstrap.c — transient-grandchild pattern, never touches the persistent child.** `unshare(CLONE_NEWUSER)` happens in a short-lived fork()ed grandchild that `_exit()`s when the callback returns; the persistent trinity child keeps host credentials so privileged syscalls keep reaching privileged kernel paths. Order is fixed: unshare(NEWUSER) → write uid_map → write setgroups=deny → write gid_map → optional secondary unshare(target_ns_flags) → run callback. `setns()` is never called — no path back into the host namespace stack.
4. **userns-bootstrap.c — geteuid/getegid captured before unshare, not getuid/getgid.** After `unshare(CLONE_NEWUSER)` the effective ids read as the overflow id (65534) until mapped; the unprivileged single-line idmap rule requires the mapped outside id to equal the *effective* id in the parent ns at write time. Real uid can diverge from effective uid in a child that fuzzed setreuid/setresuid/setfsuid, making getuid() racy — geteuid()/getegid() are the only tautologically correct choice.
5. **userns-bootstrap.c — per-errno exit code buckets.** Grandchild exit codes distinguish EPERM/EINVAL/other at each id-map write site (`map_write_exit_code()`) so post-mortem stats can diagnose "policy rejected" (EPERM: hardened `unprivileged_userns_clone=0`) vs "malformed request" (EINVAL) vs opaque failures, without a stats schema remap — the historical single "MAP_WRITE_FAIL" value is kept as the OTHER bucket.
6. **publish_resource.c — two-phase stamp with explicit unsupported-type gate.** `publish_resource_type_supported()` runs *before* `alloc_object()` so rejected types never leave an orphaned object for the caller's legacy fallback path to trip over. Primary handle stamp (`publish_resource_stamp_primary`) and secondary metadata stamp (`publish_resource_stamp_metadata`) are separate switches — FD types route through the shared `set_object_fd()`; non-fd id-only types (aio_ctx, key_serial, pkey, timerid, pid, sysv_sem/msg) get one-line inline assignment. Types with pool-specific shapes the union can't represent (mmap, sockinfo, watch_queue, pipe, epoll, kvm_vm/vcpu, futex, sysv_shm) are intentionally excluded — callers fall back to hand-rolled `alloc_object()`/`add_object()`.
7. **spsc-ring.c — acquire/release pairing is the whole contract.** Producer publishes `head` with RELEASE, consumer's ACQUIRE load of `head` in `spsc_ring_drain()` pairs with it (slot bytes visible before read); consumer publishes `tail` with RELEASE, producer's ACQUIRE load of `tail` in `try_enqueue()` pairs with it (slot free before reuse). `overflow` is RELAXED — it's a stat counter, not part of the data-visibility handshake. `spsc_ring_overwrite_enqueue()` deliberately leaves `head` unmasked/monotonic (no tail consultation, no fullness check) so a snapshot reader can distinguish "empty" from "wrapped once."
8. **numa.c — cpulist parser, not a NUMA topology library.** Hand-parses `/sys/devices/system/node/online`'s `"0-1,3,5-7"` syntax with `strtol`; any parse failure (malformed range, negative, `hi < lo`) or missing file falls back to a single node {0} rather than failing the fuzzer.
9. **jsonl.c is deliberately dependency-free** — direct `open`/`write`/`close` only, because it is the first telemetry pipe brought up during a fuzz run and cannot assume trinity's shm/logging/output() are initialized yet.
10. **fd.c treats a 0-byte `write()` as an error** (not a legal short write) but treats a 0-byte `read()` as EOF, returning the partial count — matches POSIX semantics for each syscall rather than symmetric handling.

## Integration points

- **cmsg_build.c**: `syscalls/send.c` calls `pick_cmsg_kind()` + `cmsg_build()` to attach ancillary data to sendmsg/sendmmsg; `params.c` exposes the `cmsg_richness_mode` toggle; declared in `include/cmsg_build.h`, `include/cmsg-richness.h`.
- **userns-bootstrap.c**: `userns_run_in_ns()` has the widest fan-out in the directory — ~29 callers under `childops/` (mount-churn.c, fs-lifecycle.c, netns-teardown-churn.c, vxlan-encap.c, xfrm-churn.c, nftables-churn.c, bridge-*.c, tc-*.c, and more), each wrapping a namespace-scoped operation in a transient grandchild. Stats counters (`shm->stats.userns_bootstrap_*`) declared in `include/stats.h`, shm struct in `include/shm.h`.
- **publish_resource.c**: called from `fds/fs_ctx.c`, `fds/mount.c`, `childops/bpf-lifecycle.c`, `pids.c`, and directly from ~15 syscall post-handlers (`syscalls/eventfd.c`, `pidfd_open.c`, `memfd_create.c`, `timerfd_create.c`, `signalfd.c`, `userfaultfd.c`, `fanotify_init.c`, `inotify_init.c`, `io_setup.c`, `io_uring_setup.c`, `bpf.c`, `keyctl.c`, `timer_create.c`, `pkey.c`, `msgget.c`, `semget.c`, `landlock_create_ruleset.c`, `fsconfig.c`).
- **spsc-ring.c**: embedded as the header of two typed rings — `fd-event.c`'s fd-event ring and `stats/stats-ring.c`'s stats ring (both use init/try_enqueue/drain), and `pre_crash_ring.c` uses `spsc_ring_overwrite_enqueue()` for its rolling-history snapshot buffer. Declared in `include/spsc-ring.h`, `include/pre_crash_ring.h`, `include/stats.h`.
- **numa.c**: `trinity.c` calls `init_numa_nodes()` at startup; `args/gen_arg_scalar.c` calls `random_numa_node()` for `ARG_NUMA_NODE` generation.
- **fd.c**: `write_all`/`read_all` shared by every on-disk persistence format — `sequence.c`, `minicorpus.c`, `cmp_hints/persist.c`, `kcov/persist.c`.
- **jsonl.c**: declared in `include/jsonl.h`; consumer is the diag-ring drain (per grep, currently only referenced from its own header — a narrow/early-stage integration point).

## Areas of attention

1. **userns-bootstrap.c is privilege-boundary code with a wide, security-relevant contract.** Get the fork/exit-code/errno-bucket plumbing wrong and either (a) the persistent fuzz child accidentally loses privilege (defeats the whole point of the cap-drop oracle design) or (b) a caller misreads -EPERM vs -EAGAIN and latches out of testing a real kernel policy gate incorrectly. The comment block is unusually detailed for a reason — this is the one file in the directory where a subtle bug has correctness implications beyond the fuzzer itself.
2. **cmsg_build.c mixes two levels of abstraction in one file** — the richness-mode dispatcher/family-eligibility logic (`pick_cmsg_kind`, `build_multi_pool`) and 16 near-identical per-kind builders that repeat the same buf/memset/msg_control/cmsg_len boilerplate. Each `build_*` function is ~15-20 lines of copy-pasted structure; a small `build_one()` helper (already partially factored as `build_one_int`) could absorb more of them.
3. **spsc-ring.c correctness is entirely dependent on correct memory-order annotations at call sites** — the primitive itself is correct, but a caller that adds a second producer or second consumer to a ring silently breaks the lock-free contract (no assertion enforces single-producer/single-consumer beyond code review).

## Summary

Seven independent utility modules, each solving one narrow problem that had (or would have) been duplicated across multiple call sites: cmsg construction for socket fuzzing, namespace-scoped privilege sandboxing for childops, typed object-pool publishing, a lock-free ring-buffer primitive, NUMA node enumeration, robust fd I/O loops, and a minimal JSON-lines writer. No file depends on another in this directory; grouping is purely "small and reusable," not architectural.

# syscalls/ — Per-Syscall Descriptor Table

Largest directory in the codebase: 363 `.c` files (14 directly here, 342
grouped into 28 by-family subdirectories, 7 arch-specific under `x86/`),
plus 6 headers, ~65,600 LOC in `.c` files alone. One file per Linux syscall
Trinity fuzzes (`accept.c`, `access.c`, `acct.c`, ... `write.c`), each defining a
single `struct syscallentry syscall_<name>` descriptor consumed by
`tables/` at init time. This directory has no control flow of its own — it
is a declarative catalog: argument shapes, generator hooks, and per-syscall
constraint knowledge, one TU per syscall.

## Files

Files are grouped by family into subdirectories — `fs/` (83), `process/`
(35), `mm/` (26), `signal/` (22), `cred/` (18), `sched/` (18), `socket/`
(15), `ipc/` (14), `xattr/` (14), `clock/` (11), `concurrency/` (10),
`poll/` (8), `timer/` (8), plus 15 smaller ones — with 14 files left
directly in `syscalls/`. Do not enumerate all 363 files individually — they
follow one of two shapes:

**Bulk (232 of the 356 non-arch files are under 200 LOC): pure descriptor pattern.**
A `struct syscallentry syscall_X = { ... }` initializer with `.name`,
`.num_args`, `.argtype[6]`, `.argname[6]`, `.group`, `.rettype`, optional
`.flags`, and optionally a `static void sanitise_X(struct syscallrecord *rec)`
wired via `.sanitise`. Examples at the simple end:
- `acct.c` (14 lines) — no sanitise at all, pure declarative: 1 arg
  (`ARG_PATHNAME`), `GROUP_VFS`, `NEEDS_ROOT` flag.
- `access.c` (76 lines) — one `sanitise_access()` that repoints the pathname
  arg at a real trinity-testfile inode 50% of the time, `REEXEC_SANITISE_OK`
  flag opting into CMP RedQueen re-exec.

85 of the 356 non-arch files have no `.sanitise` at all (pure table-driven
generic arg generation off `argtype[]`); 271 define at least one
`static void sanitise_X()`; 209 define a `.post` handler; only 12 define
`.cleanup`, 3 explicitly call `generic_sanitise`.

**Outliers: syscalls with substantial standalone logic (>400 LOC).** By line
count: `process/prctl.c` (1246), `socket/setsockopt.c` (986, +
`setsockopt-internal.h`), `perf/perf_event_open-pmu-discovery.c` (860),
`io_uring/io_uring_register-payloads.c` (830), `fs/fcntl.c` (810),
`socket/recv.c` (808), `xattr/listxattr.c` (789), `socket/send.c` (775),
`fs/stat/stat.c` (749), `bpf.c` (713, gated `#ifdef USE_BPF`),
`keyctl/keyctl.c` (650), `mm/mmap.c` (576), `concurrency/futex.c` (571),
`fs/mount/mount.c` (567), `fs/mount/statmount.c` (544),
`fs/stat/statfs.c` (541), `io_uring/io_uring_register.c` (532, +
`io_uring_register-internal.h`), `ipc/sysv/ipc.c` (498),
`timer/timer_create.c` (492), `fs/open.c` (491), `fs/readlink.c` (484),
`process/execve.c` (478), `fs/stat/file_getattr.c` (470),
`fs/stat/newfstat.c` (466), `socket/getpeername.c` (463),
`keyctl/add_key.c` (460), `xattr/listxattrat.c` (448),
`fs/stat/fstatfs.c` (447), `socket/getsockname.c` (446),
`process/prlimit64.c` (441), `fs/mount/listmount.c` (432), `fs/write.c`
(426), `signal/sigaction.c` (423), `sched/sched_getattr.c` (412),
`process/ptrace.c` (410), `xattr/getxattr.c` (405). These carry their own
static tables (opcode lists, sockopt validity matrices, PMU sysfs
enumeration), multi-op dispatch switches, and often a `.post`/`.cleanup`
pair managing a heap allocation stashed in `rec->post_state`.

**Arch-specific subdirectories** (compiled conditionally by `Makefile`'s
`SYSCALLS_ARCH` variable, keyed off `$(CC) -dumpmachine`):
`x86/{ioperm,iopl,modify_ldt}.c`, `x86/i386/{vm86,vm86old}.c`,
`x86/x86_64/{arch_prctl,uretprobe}.c`. Small (12-343 lines), single-syscall,
same descriptor pattern.

**Headers**: `syscalls.h` (437 lines) — `extern struct syscallentry
syscall_X;` forward declarations for every descriptor, included by
`include/syscalls-*.h` (one per arch) to build the `struct syscalltable[]`
literals `tables/` copies into shared memory. `clock-common.h` — shared
POSIX-clock-encoding helpers for the `clock_*`/`timer_*` family.
`bpf-internal.h`, `io_uring_register-internal.h`,
`perf_event_open-internal.h`, `setsockopt-internal.h` — private declarations splitting a large syscall's
builder/table logic into a second TU compiled in parallel with the
sanitise/post/dispatch logic that stays in the main `.c` (documented at the
top of each header as private to that pair of TUs).

## Key design decisions

1. **The descriptor is the whole contract.** `struct syscallentry` (defined
   once in `include/syscall.h:534`, not here) is what every file in this
   directory populates: `.argtype[6]` (an `enum argtype` — `ARG_FD`,
   `ARG_PATHNAME`, `ARG_STRUCT_PTR_IN/OUT/INOUT`, `ARG_LIST`, `ARG_RANGE`,
   typed-fd variants like `ARG_FD_BPF_MAP`, etc.) drives generic argument
   generation with zero per-syscall code; `.sanitise` is an escape hatch for
   syscalls whose args need semantic coupling (a length that must match a
   buffer, a command opcode that gates which union member is valid).
2. **Sanitise is optional and additive, not mandatory.** 85 files rely
   entirely on the generic `argtype[]`-driven generator (`acct.c`); the rest
   layer a `sanitise_X()` on top that mutates `rec->aN` after generic
   generation has already populated it (see `access.c`'s comment on why it
   repoints only half the time — keeping the ENOENT reject arm alive).
3. **`.post`/`.cleanup` split for allocation lifetime, not for logic.**
   `.post` is a conditional successful-result inspector (gated on
   `state == AFTER`); `.cleanup` runs unconditionally after `.post` regardless
   of success/failure/validator-reject/dry-run, and is where sanitiser-owned
   heap buffers stashed in `rec->post_state` get freed (`ptrace.c`,
   `mount_setattr` in `mount.c`). The magic-cookie pattern
   (`#define X_POST_STATE_MAGIC ...` + a small struct with `magic` as first
   field) recurs across `execve.c`, `ptrace.c`, and others to defend
   `rec->post_state` derefs against sibling-syscall stomps between dispatch
   and post/cleanup.
4. **Object pools cross-pollinate related syscalls.** `keyctl.c` registers a
   `key_serial_destructor` via `REG_GLOBAL_OBJ` and exposes
   `get_random_key_serial()`/`register_key_serial()` consumed by
   `add_key.c`/`request_key.c` so those three syscalls exercise real live
   key serials instead of dead-on-arrival random integers — the same
   producer/consumer object-pool pattern recurs for fds, mount IDs, and
   BPF map/prog fds across the directory.
5. **Big syscalls get an internal split, not a rewrite.** `io_uring_register`,
   `perf_event_open`, and `setsockopt` each split into a main `.c` (sanitise,
   post, dispatch switch, `syscallentry`) plus a payload/table `.c` sharing
   a private `-internal.h`, so the per-opcode builder families compile as a
   separate TU without exposing that boundary to the rest of the codebase.
6. **Arch conditionality is file-selection, not `#ifdef` fan-out.** Arch-only
   syscalls (`ioperm`, `iopl`, `modify_ldt`, `arch_prctl`, `vm86`/`vm86old`)
   live in arch subdirectories and are only added to the build's `SRCS` via
   `Makefile`'s `SYSCALLS_ARCH` glob for the matching `$(CC) -dumpmachine` —
   no dead arch code is compiled or linked on non-matching machines. (`bpf.c` is the one exception using
   in-file `#ifdef USE_BPF` gating instead, since it's not arch-specific but
   config-specific.)
7. **`GROUP_*` tagging is coarse and mostly VFS/PROCESS-weighted.** Of ~424
   group tags across the directory, GROUP_VFS (155) and GROUP_PROCESS (105)
   dominate; GROUP_BPF has exactly one member (`bpf.c` itself). Groups drive
   `-g`/targeting selection in `tables/`, not generation behavior.

## Integration points

- `tables/tables.c` `copy_syscall_table()` — the sole consumer that reads
  every `struct syscallentry` here at init, memcpy's it into a shared-memory
  copy, and stamps derived fields (`is_mmap2`, `address_scrub_mask`,
  `syscall_category`, etc.) the descriptors themselves never set. See
  `tables/CLAUDE.md` for the full registration pipeline.
- `include/syscalls-*.h` (one per arch, e.g. `syscalls-x86_64.h`) — compile-time
  `struct syscalltable[]` literals of `{ .entry = &syscall_X }` built from the
  `extern` declarations in `syscalls.h`; selected via `include/arch-syscalls.h`.
- `random_syscall/dispatch-step.c`, `random_syscall/pickers.c` — runtime consumers
  that pick a syscall number and call `get_syscall_entry()` (in `tables/`) to
  resolve the descriptor defined here, then dispatch `.sanitise` →
  kernel call → `.post` → `.cleanup`.
- `args/generate-args.c`, `args/argtype_table.c` — read `entry->argtype[]` to drive
  generic per-arg generation before `.sanitise` runs; `blanket_address_scrub()`
  consults the precomputed `address_scrub_mask`/`nested_address_scrub_mask`.
- `results.c` — reads `.rettype`, `entry->results[6]` scoreboards
  (`success_fds`/`failed_fds`/`len_score`) updated per-call from these entries.
- `fds/files.c`, `fds/testfiles.c` — path/fd helper consumers referenced by
  name from several syscall files (e.g. `access.c`'s `get_testfile_path()`).
- `struct_catalog/` — supplies shared struct-shape tables (`bpf_prog_types`,
  `bpf_map_types`) that `bpf.c` and `struct_catalog/bpf.c` both reference to keep
  vocabulary in sync across the catalog and the raw syscall arg generator.
- `objects/registry.c` / `lib/publish_resource.c` — object-pool registration
  (`register_key_serial`, fd publication) that lets one syscall's successful
  result feed a later syscall's argument generation.
- `cmp_hints/`, `kcov/` — indirectly, via `MAX_NR_SYSCALL`-sized per-syscall
  pools keyed by the `number`/`active_number` `tables/` stamps onto each
  entry defined here.

## Areas of attention

1. **Security-sensitive descriptors carry the most custom logic.**
   `process/execve.c` (478 lines) fabricates argv/envp arrays with a
   post-state snapshot to survive sibling-stomp between syscall return and
   post handling; `process/ptrace.c` (410 lines) tracks a 32-request
   allocation matrix (only 4 of 32 `PTRACE_*` ops allocate a freeable
   buffer) behind a magic-cookie-guarded `post_state`; `keyctl/keyctl.c`
   (650 lines) and its sibling `add_key.c`/`request_key.c` share a live
   key-serial object pool whose destructor issues a real
   `KEYCTL_INVALIDATE` at pool teardown; `bpf.c` (713 lines, `#ifdef
   USE_BPF`) builds both classic and eBPF programs and drives
   `BPF_PROG_LOAD`/`BPF_MAP_CREATE`-shaped `union bpf_attr` payloads.
   `fs/mount/mount.c` (567 lines) maintains its own sacrificial-mount-path pool with
   a constructor/destructor pair (`make_sacrificial_mount_paths`,
   `cleanup_sacrificial_mount_paths`, `sweep_dead_sacrificial_mount_paths`)
   and a bounded-copy `pick_sacrificial_target()` (recent hardening commit
   `9568f984e`) — mount namespace/target confusion is an ongoing area of
   care here.
2. **The five largest files (`process/prctl.c`, `socket/setsockopt.c`,
   `perf/perf_event_open-pmu-discovery.c`,
   `io_uring/io_uring_register-payloads.c`, `fs/fcntl.c`) each exceed 800
   LOC and embed their own opcode/option dispatch tables** (`sockopt_table[]` in
   `setsockopt.c`, PMU sysfs enumeration in
   `perf_event_open-pmu-discovery.c`) — effectively small sub-interpreters
   living inside a single syscall's TU. Changes to kernel-side opcode/option
   sets require hand-syncing these tables; there is no generation from
   kernel headers.
3. **`setsockopt.c` maintains cross-call state** (`sso_history[]`, a
   fixed-size per-fd ring recording the last `(level, optname)` pair) so a
   later `setsockopt` on the same fd can pair with a preceding call
   (`try_paired_setsockopt`) — stateful behavior that's easy to overlook
   since most files in this directory are stateless per-call generators.
4. **Four internal-header clusters (`bpf`, `io_uring_register`,
   `perf_event_open`, `setsockopt`) intentionally break the "one syscall,
   one file" convention** — `perf_event_open` is spread over six `.c` files.
   A reader expecting the whole descriptor in one file needs to know to also
   check the paired `-payloads.c`/`-pmu-discovery.c`/`-internal.h` files.

## Summary

363 files, one `struct syscallentry` per Linux syscall Trinity fuzzes,
consumed exclusively by `tables/copy_syscall_table()` at startup. The
overwhelming majority are small declarative descriptors —
`argtype[]` plus an optional `sanitise_X()`/`post_X()`/`cleanup_X()` triplet
for semantic arg coupling and heap-lifetime management. A handful of
syscalls with genuinely complex kernel ABIs (`prctl`, `setsockopt`,
`perf_event_open`, `io_uring_register`, `fcntl`, `bpf`, `mount`, `execve`,
`ptrace`, `keyctl`) carry hundreds to over a thousand lines of dedicated opcode
tables, dispatch logic, and cross-call state, some split into a second TU
via a private `-internal.h`. Arch-specific syscalls live in the `x86/`
subdirectory, compiled in only for the matching target via `Makefile`'s
`SYSCALLS_ARCH` glob.

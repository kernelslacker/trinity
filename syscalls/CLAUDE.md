# syscalls/ — Per-Syscall Descriptor Table

Largest directory in the codebase: 348 top-level `.c` files + 12 arch-specific
`.c` files under `ppc/`, `s390x/`, `sh/`, `sparc/`, `x86/` (361 total), plus 5
headers, ~56,400 LOC in `.c` files alone. One file per Linux syscall Trinity
fuzzes (`accept.c`, `access.c`, `acct.c`, ... `writev.c`), each defining a
single `struct syscallentry syscall_<name>` descriptor consumed by
`tables/` at init time. This directory has no control flow of its own — it
is a declarative catalog: argument shapes, generator hooks, and per-syscall
constraint knowledge, one TU per syscall.

## Files

Do not enumerate all 361 files individually — they follow one of two shapes:

**Bulk (~330 files, mostly under 200 LOC): pure descriptor pattern.**
A `struct syscallentry syscall_X = { ... }` initializer with `.name`,
`.num_args`, `.argtype[6]`, `.argname[6]`, `.group`, `.rettype`, optional
`.flags`, and optionally a `static void sanitise_X(struct syscallrecord *rec)`
wired via `.sanitise`. Examples at the simple end:
- `acct.c` (14 lines) — no sanitise at all, pure declarative: 1 arg
  (`ARG_PATHNAME`), `GROUP_VFS`, `NEEDS_ROOT` flag.
- `access.c` (76 lines) — one `sanitise_access()` that repoints the pathname
  arg at a real trinity-testfile inode 50% of the time, `REEXEC_SANITISE_OK`
  flag opting into CMP RedQueen re-exec.

91 of the ~348 top-level files have no `.sanitise` at all (pure table-driven
generic arg generation off `argtype[]`); 257 define at least one
`static void sanitise_X()`; 189 define a `.post` handler; only 10 define
`.cleanup`, 9 explicitly call `generic_sanitise`.

**Outliers: syscalls with substantial standalone logic (>400 LOC).** By line
count: `perf_event_open.c` (1283, + `perf_event_open-internal.h` 71 lines),
`bpf.c` (1203, gated `#ifdef USE_BPF`), `prctl.c` (987), `setsockopt.c`
(922, + `setsockopt-internal.h` 62 lines), `io_uring_register-payloads.c`
(802), `perf_event_open-pmu-discovery.c` (801), `recv.c` (791),
`listxattr.c` (769), `send.c` (737), `fcntl.c` (696), `mount.c` (578),
`futex.c` (565), `stat.c` (540), `mmap.c` (537), `keyctl.c` (534),
`io_uring_register.c` (494, + `io_uring_register-internal.h` 62 lines),
`readlink.c` (483), `statmount.c` (478), `execve.c` (474), `statfs.c`
(465), `ipc.c` (464), `getpeername.c` (464), `open.c` (448),
`getsockname.c` (447), `listmount.c` (433), `newfstat.c` (429), `write.c`
(426), `listxattrat.c` (416), `timer_create.c` (401). These carry their own
static tables (opcode lists, sockopt validity matrices, PMU sysfs
enumeration), multi-op dispatch switches, and often a `.post`/`.cleanup`
pair managing a heap allocation stashed in `rec->post_state`.

**Arch-specific subdirectories** (compiled conditionally by `Makefile`'s
`SYSCALLS_ARCH` variable, keyed off `$(CC) -dumpmachine`):
`x86/{ioperm,iopl,modify_ldt}.c`, `x86/i386/{vm86,vm86old}.c`,
`x86/x86_64/arch_prctl.c`; `s390x/{runtime_instr,s390_guarded_storage,
s390_pci_mmio,s390_sthyi}.c`; `ppc/rtas.c`; `sh/cacheflush.c`;
`sparc/kern_features.c`. Small (12-365 lines), single-syscall, same
descriptor pattern.

**Headers**: `syscalls.h` (445 lines) — `extern struct syscallentry
syscall_X;` forward declarations for every descriptor, included by
`include/syscalls-*.h` (one per arch) to build the `struct syscalltable[]`
literals `tables/` copies into shared memory. `clock-common.h` — shared
POSIX-clock-encoding helpers for the `clock_*`/`timer_*` family.
`io_uring_register-internal.h`, `perf_event_open-internal.h`,
`setsockopt-internal.h` — private declarations splitting a large syscall's
builder/table logic into a second TU compiled in parallel with the
sanitise/post/dispatch logic that stays in the main `.c` (documented at the
top of each header as private to that pair of TUs).

## Key design decisions

1. **The descriptor is the whole contract.** `struct syscallentry` (defined
   once in `include/syscall.h:410`, not here) is what every file in this
   directory populates: `.argtype[6]` (an `enum argtype` — `ARG_FD`,
   `ARG_PATHNAME`, `ARG_STRUCT_PTR_IN/OUT/INOUT`, `ARG_LIST`, `ARG_RANGE`,
   typed-fd variants like `ARG_FD_BPF_MAP`, etc.) drives generic argument
   generation with zero per-syscall code; `.sanitise` is an escape hatch for
   syscalls whose args need semantic coupling (a length that must match a
   buffer, a command opcode that gates which union member is valid).
2. **Sanitise is optional and additive, not mandatory.** 91 files rely
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
   syscalls (`modify_ldt`, `s390_pci_mmio`, `rtas`, `cacheflush`,
   `kern_features`, `arch_prctl`, `vm86`/`vm86old`) live in arch subdirectories
   and are only added to the build's `SRCS` via `Makefile`'s `SYSCALLS_ARCH`
   glob for the matching `$(CC) -dumpmachine` — no dead arch code is compiled
   or linked on non-matching machines. (`bpf.c` is the one exception using
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
- `random_syscall/dispatch.c`, `random_syscall/pickers.c` — runtime consumers
  that pick a syscall number and call `get_syscall_entry()` (in `tables/`) to
  resolve the descriptor defined here, then dispatch `.sanitise` →
  kernel call → `.post` → `.cleanup`.
- `args/generate-args.c`, `args/fill_arg.c` — read `entry->argtype[]` to drive
  generic per-arg generation before `.sanitise` runs; `blanket_address_scrub()`
  consults the precomputed `address_scrub_mask`/`nested_address_scrub_mask`.
- `results.c` — reads `.rettype`, `entry->results[6]` scoreboards
  (`success_fds`/`failed_fds`/`len_score`) updated per-call from these entries.
- `fds/files.c`, `fds/testfiles.c` — path/fd helper consumers referenced by
  name from several syscall files (e.g. `access.c`'s `get_testfile_path()`).
- `struct_catalog/` — supplies shared struct-shape tables (`bpf_prog_types`,
  `bpf_map_types`) that `bpf.c` and `struct_catalog.c` both reference to keep
  vocabulary in sync across the catalog and the raw syscall arg generator.
- `objects/registry.c` / `publish_resource.c` — object-pool registration
  (`register_key_serial`, fd publication) that lets one syscall's successful
  result feed a later syscall's argument generation.
- `cmp_hints/`, `kcov/` — indirectly, via `MAX_NR_SYSCALL`-sized per-syscall
  pools keyed by the `number`/`active_number` `tables/` stamps onto each
  entry defined here.

## Areas of attention

1. **Security-sensitive descriptors carry the most custom logic.**
   `execve.c` (474 lines) fabricates argv/envp arrays with a post-state
   snapshot to survive sibling-stomp between syscall return and post
   handling; `ptrace.c` (330 lines) tracks a 32-request allocation matrix
   (only 4 of 32 `PTRACE_*` ops allocate a freeable buffer) behind a
   magic-cookie-guarded `post_state`; `keyctl.c` (534 lines) and its sibling
   `add_key.c`/`request_key.c` share a live key-serial object pool whose
   destructor issues a real `KEYCTL_INVALIDATE` at pool teardown; `bpf.c`
   (1203 lines, `#ifdef USE_BPF`) builds both classic and eBPF programs and
   drives `BPF_PROG_LOAD`/`BPF_MAP_CREATE`-shaped `union bpf_attr` payloads.
   `mount.c` (578 lines) maintains its own sacrificial-mount-path pool with
   a constructor/destructor pair (`make_sacrificial_mount_paths`,
   `cleanup_sacrificial_mount_paths`, `sweep_dead_sacrificial_mount_paths`)
   and a bounded-copy `pick_sacrificial_target()` (recent hardening commit
   `9568f984e`) — mount namespace/target confusion is an ongoing area of
   care here.
2. **The five largest files (`perf_event_open.c`, `bpf.c`, `prctl.c`,
   `setsockopt.c`, `io_uring_register-payloads.c`) each exceed 800 LOC and
   embed their own opcode/option dispatch tables** (`sockopt_table[]` in
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
4. **Two internal-header pairs (`io_uring_register`, `perf_event_open`,
   `setsockopt`) intentionally break the "one syscall, one file" convention.**
   A reader expecting the whole descriptor in one file needs to know to also
   check the paired `-payloads.c`/`-pmu-discovery.c`/`-internal.h` files.

## Summary

353-plus files, one `struct syscallentry` per Linux syscall Trinity fuzzes,
consumed exclusively by `tables/copy_syscall_table()` at startup. The
overwhelming majority (~330 files) are small declarative descriptors —
`argtype[]` plus an optional `sanitise_X()`/`post_X()`/`cleanup_X()` triplet
for semantic arg coupling and heap-lifetime management. A handful of
syscalls with genuinely complex kernel ABIs (`perf_event_open`, `bpf`,
`prctl`, `setsockopt`, `io_uring_register`, `mount`, `execve`, `ptrace`,
`keyctl`) carry hundreds to over a thousand lines of dedicated opcode
tables, dispatch logic, and cross-call state, some split into a second TU
via a private `-internal.h`. Arch-specific syscalls live in `ppc/`,
`s390x/`, `sh/`, `sparc/`, `x86/` subdirectories, compiled in only for the
matching target via `Makefile`'s `SYSCALLS_ARCH` glob.

# syscalls/ — Per-Syscall Descriptor Table

## Files

**Bulk (235 of the 357 non-arch files are under 200 LOC): pure descriptor pattern.**
A `struct syscallentry syscall_X = { ... }` initializer with `.name`,
`.num_args`, `.argtype[6]`, `.argname[6]`, `.group`, `.rettype`, optional
`.flags`, and optionally a `static void sanitise_X(struct syscallrecord *rec)`
wired via `.sanitise`. Examples at the simple end:
- `fs/mount/pivot_root.c` (14 lines) — no sanitise at all, pure declarative: 2 args
  (`ARG_PATHNAME`), `GROUP_VFS_MOUNT`, `NEEDS_ROOT` flag.
- `fs/path/access.c` (83 lines) — one `sanitise_access()` that repoints the pathname
  arg at a real trinity-testfile inode 50% of the time, `REEXEC_SANITISE_OK`
  flag opting into CMP RedQueen re-exec.

**Headers**: `syscalls.h` — `extern struct syscallentry
syscall_X;` forward declarations for every descriptor, included by
`include/syscalls-*.h` (one per arch) to build the `struct syscalltable[]`
literals `tables/` copies into shared memory.

## Key design decisions

1. **The descriptor is the whole contract.** `struct syscallentry` (defined
   once in `include/syscall.h:548`, not here) is what every file in this
   directory populates: `.argtype[6]` (an `enum argtype` — `ARG_FD`,
   `ARG_PATHNAME`, `ARG_STRUCT_PTR_IN/OUT/INOUT`, `ARG_LIST`, `ARG_RANGE`,
   typed-fd variants like `ARG_FD_BPF_MAP`, etc.) drives generic argument
   generation with zero per-syscall code; `.sanitise` is an escape hatch for
   syscalls whose args need semantic coupling (a length that must match a
   buffer, a command opcode that gates which union member is valid).
2. **Sanitise is optional and additive, not mandatory.** 84 files rely
   entirely on the generic `argtype[]`-driven generator (`pivot_root.c`); the rest
   layer a `sanitise_X()` on top that mutates `rec->aN` after generic
   generation has already populated it (see `access.c`'s comment on why it
   repoints only half the time — keeping the ENOENT reject arm alive).
   Every `.sanitise` also has to say what the CMP RedQueen re-exec step does
   with it: `REEXEC_SANITISE_OK` or `AVOID_REEXEC` in the entry's flags, or a
   `Not REEXEC_SANITISE_OK: <reason>` comment inside it.
   `scripts/check-static/check-reexec-coverage.sh` fails an entry with none;
   an op-multiplexed sanitiser that sets `REEXEC_OK` per call is listed in
   its baseline instead.
   A slot the sanitiser writes on every path, without reading the
   generated value, can go in `.sanitiser_owned_mask`: `generic_sanitise()`
   then leaves it zeroed instead of building a value (for a struct pointer,
   an allocation plus schema fill plus deferred-free enqueue) that the
   sanitiser would replace.  A prop_ring value or CMP hint drawn into such
   a slot is thrown away yet still counted as injected, so a scalar slot
   qualifies as much as a struct pointer.  `sanity_check_tables()` refuses
   a mask on an entry with no `.sanitise` or with a bit at or past
   `num_args`.  `tests/sanitiser_owned_mask_test.c` lists the entries that
   set it, once their TU links into the test binary, and runs each one's
   sanitiser to check that every slot the mask names is written on every
   path.
   A sanitiser that sizes a byte count to the buffer before it, for a call
   that writes as far as its source lets it (read() from /dev/zero, for
   one), names the count's slot in `.buf_count_slot`: `validate_arg_coupling()`
   then cuts a rewritten count (chain substitution, a RedQueen pin) that
   would run the write past the buffer into trinity's own regions, and
   `sanity_check_tables()` refuses a slot with no address argtype before it.
   A count whose buffer the sanitiser made of a pool mapping is held to how
   far the mapping runs from that buffer by the entry's `.vet_final` hook
   instead (`socket/recv.c`).
   A rule the sanitiser's vetting rests on, which a rewrite after it
   (chain substitution, a RedQueen pin) could undo, goes in `.vet_final`:
   `validate_arg_coupling()` runs it once on the slots the kernel is about
   to read, ahead of its generic rules, and hands it the entry the
   dispatcher passed: a hook names the call and tells a shared variant
   apart by that, never by `rec->entry`, which a stray write to the record
   can repoint.  It may repair a slot in place and
   refresh the call's own `post_state` snapshot, and a non-zero return
   refuses the call (`fs/close_range.c` refuses a range other than the
   one its sanitiser vetted).
   A compat call's kernel reads each pointer slot as its low 32 bits, and
   the writable pool lies past 4 GiB, so `get_writable_address()` and its
   siblings draw a compat call's buffers from the MAP_32BIT low pool,
   going by the ABI of `this_child()`'s record, which the sanitiser builds
   the call in (`rand/CLAUDE.md`).
3. **`.post`/`.cleanup` split for allocation lifetime, not for logic.**
   `.post` runs for every record in `state == AFTER` — an errno'd failure and
   `--dry-run`'s synthesized `-1`/`ENOSYS` included; the dispatcher skips it
   only after rejecting a RET_FD or RET_ZERO_SUCCESS retval, and never gates
   it on `-1`.  A handler that judges the return value must stand down on the
   failure itself (`syscall_errno_failure()` for a "cannot fail" oracle, `-1UL`
   left out of a range check), and one that reads a kernel-written out-param
   must test for the success return first.  `.cleanup` runs unconditionally
   after `.post` regardless of success/failure/validator-reject/dry-run, and
   is where sanitiser-owned heap buffers stashed in `rec->post_state` get
   freed (`ptrace.c`, `mount_setattr` in `mount.c`). The magic-cookie pattern
   (`#define X_POST_STATE_MAGIC ...` + a small struct with `magic` as first
   field) recurs across `execve.c`, `ptrace.c`, and others to defend
   `rec->post_state` derefs against sibling-syscall stomps between dispatch
   and post/cleanup.  A descriptor a sanitiser opens for the call is owned
   the same way: `sanitiser_own_fd()` records it in the snapshot and
   `cleanup_sanitiser_fd()` closes it from `.cleanup` (`process/setns.c`,
   `fs/path/fchdir.c`, `fchroot.c`), never read back from the arg slot,
   which may hold a pool fd or a chain splice.
4. **Object pools cross-pollinate related syscalls.** `keyctl.c` registers a
   `key_serial_destructor` via `REG_GLOBAL_OBJ` and exposes
   `get_random_key_serial()`/`register_key_serial()` consumed by
   `add_key.c`/`request_key.c` so those three syscalls exercise real live
   key serials instead of dead-on-arrival random integers — the same
   producer/consumer object-pool pattern recurs for fds, mount IDs, and
   BPF map/prog fds across the directory.
6. **Arch conditionality is file-selection, not `#ifdef` fan-out.** Arch-only
   syscalls (`ioperm`, `iopl`, `modify_ldt`, `arch_prctl`, `vm86`/`vm86old`
   under `x86/`; `riscv_hwprobe` and `riscv_flush_icache` under `riscv/`,
   which also carry an in-file `__riscv_xlen == 64` guard)
   live in arch subdirectories and are only added to the build's `SRCS` via
   `Makefile`'s `SYSCALLS_ARCH` glob for the matching `$(CC) -dumpmachine` —
   no dead arch code is compiled or linked on non-matching machines. (`bpf.c` is the one exception using
   in-file `#ifdef USE_BPF` gating instead, since it's not arch-specific but
   config-specific.)

## Integration points

- `tables/table-copy.c` `copy_syscall_table()` — the sole consumer that reads
  every `struct syscallentry` here at init, memcpy's it into a shared-memory
  copy, and stamps derived fields (`is_mmap2`, `address_scrub_mask`,
  `syscall_category`, etc.) the descriptors themselves never set. See
  `tables/CLAUDE.md` for the full registration pipeline.
- `include/syscalls-*.h` (one per arch, e.g. `syscalls-x86_64.h`) — compile-time
  `struct syscalltable[]` literals of `{ .entry = &syscall_X }` built from the
  `extern` declarations in `syscalls.h`; selected via `include/arch-syscalls.h`.
- `random_syscall/pick-common.c` and the `pick-*.c` arms,
  `random_syscall/dispatch-step.c` — runtime consumers
  that pick a syscall number and call `get_syscall_entry()` (in `tables/`) to
  resolve the descriptor defined here, then dispatch `.sanitise` →
  kernel call → `.post` → `.cleanup`.
- `args/generate-args.c`, `args/argtype_table.c` — read `entry->argtype[]` to drive
  generic per-arg generation before `.sanitise` runs; `blanket_address_scrub()`
  consults the precomputed `address_scrub_mask`/`nested_address_scrub_mask`.
- `dispatch/results.c` — reads `.rettype`, `entry->results[6]` scoreboards
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
   `process/execve.c` (473 lines) fabricates argv/envp arrays with a
   post-state snapshot to survive sibling-stomp between syscall return and
   post handling; `process/ptrace.c` (410 lines) tracks a 34-request
   allocation matrix (only 6 of 34 `PTRACE_*` ops allocate a freeable
   buffer) behind a magic-cookie-guarded `post_state`; `keyctl/keyctl.c`
   (655 lines) and its sibling `add_key.c`/`request_key.c` share a live
   key-serial object pool whose destructor issues a real
   `KEYCTL_INVALIDATE` at pool teardown; `bpf.c` (609 lines, `#ifdef
   USE_BPF`) builds both classic and eBPF programs and drives
   `BPF_PROG_LOAD`/`BPF_MAP_CREATE`-shaped `union bpf_attr` payloads.
   `fs/mount/mount.c` (567 lines) maintains its own sacrificial-mount-path pool
   under trinity's tmp dir: `make_sacrificial_mount_paths()` (the `.init`
   hook of both mount and move_mount, sweeping dead runs' dirs with
   `sweep_dead_pid_dirs()` first), an atexit
   `cleanup_sacrificial_mount_paths()`, and a bounded-copy
   `pick_sacrificial_target()` —
   mount namespace/target confusion is an ongoing area of care here.
2. **Several of the largest files (`process/prctl.c`, `socket/setsockopt.c`,
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
   one file" convention** — `perf_event_open` is spread over six `.c` files, and `bpf` over seven (the `bpf.c` aggregator plus `bpf-{prog,map,btf,link,common,fallback}.c`).
   A reader expecting the whole descriptor in one file needs to know to also
   check the paired `-payloads.c`/`-pmu-discovery.c`/`-internal.h` files.
   `bpf-common.c` draws the fourth and fifth arguments of `bpf()`, a
   `struct bpf_common_attr` and its size, which the kernel reads only when
   the command carries `BPF_COMMON_ATTRS`; the two slots are the sanitiser's
   (`.sanitiser_owned_mask`) and most calls leave them 0.

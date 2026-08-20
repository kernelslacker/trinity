# struct_catalog/ — Kernel Struct Layout Catalog

Static data + lookup layer describing the field-level shape of kernel-facing
structs (offset, size, semantic tag, constraints). Consumed by `args/` to
schema-fill, mutate and scrub struct-pointer syscall arguments, and by
`cmp_hints/field.c` to attribute KCOV-CMP-learned constants to a specific
struct field rather than a coincidentally-same-width slot. This directory is
pure data-plus-resolution: it contains no fill/mutate logic of its own (that
lives in `args/struct_fill.c`, `args/struct_mutate.c`, `args/struct_validate.c`,
`args/scrub.c`).

## Files (50 .c files, ~10,619 LOC)

The registration table and the union-bpf_attr tables have each been split: the
per-domain registration arrays live under `struct_catalog/registry/` and the
per-cmd BPF field tables under `bpf-*.c`.

| File | Lines | Role |
|---|---|---|
| sockaddr-af.c | 792 | `sockaddr_storage_fields`/`_variants` tagged union (dispatch on `ss_family`) + per-AF field arrays (UNIX/INET/INET6/NETLINK/PACKET/TIPC/QIPCRTR/NFC + optional VSOCK/CAIF/CAN/RXRPC/X25/PHONET/AX25/ROSE/ATM/LLC/MCTP/IF_ALG/XDP) |
| catalog.c | 748 | `struct_catalog[]` — the struct_desc array itself (name/size/fields/variants per SC_X slot), local shims for structs missing from older kernel headers (`open_how`, `ns_id_req`, `lsm_ctx`), `struct_catalog_lookup()` by name |
| io_uring_register.c | 695 | io_uring_setup params fields + `io_uring_register_variants[]` (one variant per IORING_REGISTER_* opcode) |
| sctp.c | 587 | 20+ SCTP setsockopt optval field tables (rtoinfo, assocparams, sndinfo, paddrparams, etc.), gated `USE_SCTP` |
| perf.c | 572 | `perf_event_attr_fields` + per-PERF_TYPE_* variant field arrays and vocab pools |
| bpf-link.c | 493 | BPF_LINK_* family field tables: BPF_LINK_UPDATE / BPF_LINK_DETACH plus the nested LINK_CREATE sub-variant fan-out (BASE, ITER, PERF_EVENT, TRACING, TRACING_MULTI, KPROBE_MULTI, UPROBE_MULTI, NETFILTER, TCX, NETKIT, CGROUP) |
| bpf.c | 478 | union bpf_attr spine: the remaining per-cmd field tables plus `bpf_attr_variants[]` tagged-union dispatch (one variant per bpf(2) cmd), aggregating the sibling `bpf-*.c` tables |
| registry.c | 374 | Registration composition root + (nr, arg) lookup: `syscall_struct_arg_groups[]`, the `slot_binding` pool + `desc_by_nr_64/32[]` fast nr-indexed lookup, `struct_arg_lookup`/`_two_key`/`_by_name`, `struct_catalog_init()` |
| bpf-prog.c | 297 | BPF_PROG_* command family field tables |
| variant.c | 260 | Generic discriminator resolution: `read_rec_arg`, `discrim_key_matches`, `discrim_key2_matches` (shared with registry.c's rec-based lookup), `struct_desc_resolve_variant`, `struct_desc_resolve_nested_variant` |
| time.c | 231 | timex, itimerspec, timespec, itimerval, utimbuf, timeval, timezone field tables |
| signal.c | 231 | sigevent, sigaction, stack_t, siginfo_t (+ `_rt`/`_kill` tagged-union variants), sigset_t |
| fcntl.c | 203 | flock, f_owner_ex, open_how, file_handle field tables + fcntl cmd vocab |
| validate.c | 189 | Init-time slot-shape guard: BUGs if a registration row's arg_idx lands on a non-struct-shaped argtype (catches the arg_idx off-by-one class of bug) |
| sockaddr-mcast.c | 171 | ip_mreqn, ip_mreq_source, ipv6_mreq + well-known multicast-address vocab pools |
| quota.c | 171 | if_dqblk, if_dqinfo, fs_disk_quota (quotactl/quotactl_fd) |
| ptrace_regs.c | 171 | Per-arch ptrace register-set structs for PTRACE_{GET,SET}REGS and the iovec-wrapped PTRACE_{GET,SET}REGSET; attribution-only (the sanitiser hand-rolls the iovec / raw pointer itself) |
| address.c | 158 | (per-family leaf; address-shaped field tables) |
| bpf-map.c | 155 | BPF_MAP_* command family field tables |
| sockaddr-sockopt.c | 150 | linger, packet_mreq, group_req, group_source_req |
| landlock.c | 150 | landlock_ruleset_attr, landlock_path_beneath_attr, landlock_net_port_attr |
| cmp.c | 146 | `struct_field_for_cmp()` — reservoir-sampled heuristic mapping a KCOV-CMP constant to the most likely field (prefers FT_ENUM/FT_FLAGS/FT_VERSION_MAGIC "gate" fields over same-width FT_RAW) |
| keyctl.c | 138 | keyctl payload per-cmd field tables, dispatched off `rec->a1` in the same tagged-union shape as bpf.c; attribution-only (bespoke `sanitise_keyctl()` owns every live fill) |
| mount.c | 134 | mount_attr, mnt_id_req, ns_id_req (+ local `ns_id_req` shim for pre-6.8 headers) |
| ipc.c | 122 | sembuf, mq_attr, msqid_ds, shmid_ds, msgbuf |
| socket.c | 118 | iovec, msghdr, mmsghdr |
| futex.c | 115 | robust_list_head, rseq, futex_waitv |
| uffdio.c | 102 | userfaultfd ioctl argument structs; attribution-only, and reached by name rather than through the registration table (ioctl args don't resolve that way) |
| xattr.c | 98 | xattr_args (gated `USE_XATTR_ARGS`), file_attr |
| bpf_classic.c | 95 | sock_filter (cBPF insn word), sock_fprog (seccomp/setsockopt/prctl cBPF install) |
| aio.c | 95 | iocb + IOCB_CMD_* opcode vocab (io_cancel) |
| bpf-task-storage.c | 85 | Task / iter / stats / token / raw-tracepoint cmd families: BPF_TASK_FD_QUERY, BPF_ENABLE_STATS, BPF_ITER_CREATE, BPF_RAW_TRACEPOINT_OPEN, BPF_TOKEN_CREATE |
| poll.c | 83 | pollfd, epoll_event |
| lsm.c | 80 | lsm_ctx (fixed 4-u64 head only; flexible ctx[] tail not cataloged) |
| bpf-btf.c | 70 | BTF family: BPF_BTF_LOAD and the generic BPF_OBJ_GET_INFO_BY_FD info-query slot |
| sched.c | 61 | sched_attr, clone_args, sched_param |
| resource.c | 48 | rlimit, cachestat_range |
| kexec.c | 48 | kexec_segment |
| ldt.c | 45 | user_desc (modify_ldt write arm, X86-only) |
| crypto.c | 45 | `af_alg_iv` — the AF_ALG `ALG_SET_IV` control-message payload; attribution-only |
| cap.c | 35 | user_cap_header, user_cap_data |
| tcp.c | 33 | tcp_repair_opt (gated `USE_TCP_REPAIR_OPT`) |

`struct_catalog/registry/` holds the per-domain registration arrays that
`registry.c` composes into `syscall_struct_arg_groups[]`:

| File | Lines | Role |
|---|---|---|
| registry/fs.c | 503 | Filesystem / VFS rows: file / dir / mount / xattr / quota / poll / io syscalls, the landlock attrs, the fcntl / landlock_add_rule / quotactl / quotactl_fd discriminator-aware rows and their pools, the iovec fanout, and the sigset_t rows on signalfd/ppoll/epoll_pwait |
| registry/net.c | 470 | Network rows: sockaddr / msghdr / mmsghdr on the socket calls, plus the setsockopt / getsockopt (level, optname) two-key rows and their discriminator vocabularies |
| registry/process.c | 236 | Process / signal / rlimit / futex rows: clone3, rlimits, perf_event_open, the sigaction / siginfo / sigaltstack / sigqueue rows, capset / capget, keyctl, rseq, set_robust_list, process_vm_{read,write}v, the futex family, and (X86) modify_ldt |
| registry/misc.c | 125 | Catch-all rows for syscalls with no clean fs / net / io_uring / sched / time / process / bpf bucket — POSIX mqueue, SysV IPC, and friends |
| registry/time.c | 85 | Time / timer rows: adjtimex, clock_*, timer_*, timerfd_*, nanosleep, settimeofday, setitimer, timer_create. Timeout-taking syscalls whose primary domain is elsewhere keep their timespec rows in that domain's file. |
| registry/bpf.c | 75 | BPF / seccomp rows: the bpf(2) attr union, `seccomp(SECCOMP_SET_MODE_FILTER)`, and its `prctl(PR_SET_SECCOMP)` legacy sibling |
| registry/sched.c | 28 | sched_setattr / sched_getattr → sched_attr; sched_setparam / sched_setscheduler → sched_param |
| registry/io_uring.c | 25 | io_uring setup and register paths only — io_uring_enter's opcode-dispatched SQE bodies resolve through their own opcode table |

`catalog.c` additionally `#include`s six `catalog-*.inc` fragments (~296 LOC) —
blocks of `struct_catalog[]` designated initializers for the bpf, ptrace_regs,
setsockopt, sctp, uffdio and AF_ALG slots, each wrapped in its own feature guard.

`sockaddr.o` build artifact present in the directory listing is stale/ignored
(no matching `.c`).

## Data model

- **`struct struct_field`** (include/struct_catalog.h): one field = name,
  `offsetof`/`sizeof` (via `FIELD()`/`FIELDX()` macros), an `enum field_tag`
  (FT_RAW default, FT_ENUM, FT_RANGE/FT_SRANGE, FT_FLAGS, FT_PTR_BYTES/
  FT_PTR_ARRAY/FT_PTR_STRUCT + FT_LEN_BYTES/FT_LEN_COUNT pairing, FT_FD,
  FT_MAGIC/FT_VERSION_MAGIC, FT_ADDRESS, FT_TAGGED_UNION, FT_BPF_PROGRAM,
  FT_VOCAB, FT_PICKER), a `mutate_weight`, and a tagged union carrying the
  per-tag constraint payload (range bounds, flag mask, vocab pool, sibling
  length-field name, element struct name, picker function pointer, etc).
- **`struct struct_desc`**: name, `struct_size`, `fields[]`/`num_fields`, plus
  optional tagged-union plumbing — either `discrim_arg_idx` (read a syscall
  arg off `rec`) or `buffer_discrim_offset`/`_size` (read from a fixed offset
  in the just-filled buffer, e.g. `sockaddr_storage.ss_family`) selects one of
  `variants[]` (`struct union_variant`: discriminator value(s), field subset,
  optional `effective_size`, optional nested sub-variants for two-level
  dispatch like BPF's LINK_CREATE).
- **`struct syscall_struct_arg`** (rows in `registry/<domain>.c`): `(syscall_name, 1-based
  arg_idx) → struct_desc*`, with an independent, orthogonal discriminator
  axis for selecting *which descriptor* a slot resolves to (packed
  shift/mask extraction, single value or value-list, optional second key for
  two-key dispatch like `setsockopt(level, optname)`). This selects the
  descriptor; `struct_desc->variants` then selects the field subset *within*
  it — a slot can use both axes at once (e.g. `landlock_add_rule`'s a3
  resolves to a different desc per rule_type; `fcntl`'s a3 resolves to
  `flock` or `f_owner_ex` per cmd).
- Each per-family `.c` file is a leaf TU defining `static`→`const` field
  arrays; `struct_catalog-internal.h` centralizes `extern` declarations (with
  compile-time-checked `_N` array-size constants) so `catalog.c`'s
  designated-initializer references to e.g. `futex_waitv_fields` resolve
  across TUs, and a leaf/spine size mismatch is a build error rather than a
  runtime corruption.
- `catalog.c`'s `struct_catalog[]` is indexed by a stable `enum
  struct_catalog_idx` (`SC_TIMEX`, `SC_BPF_ATTR`, ...) using C99 designated
  initializers, so `#ifdef`-gated slots (USE_BPF, USE_SCTP, X86, ...) don't
  shift other indices; a `_Static_assert` locks `ARRAY_SIZE(struct_catalog)
  == SC_NR_ENTRIES` at compile time, and `struct_catalog_init()` additionally
  scans for zero-initialized "holes" (a missing `[SC_X] = {...}` designator)
  at runtime init.

## Registration and lookup flow

1. Each per-family `.c` defines field tables and (where applicable) variant
   tables; `catalog.c` assembles them into `struct_catalog[SC_X]` entries.
2. Each `registry/<domain>.c` defines a NULL-terminated array of
   `(syscall_name, arg_idx, desc, discriminator...)` rows, hand-written per
   syscall (~165 rows across the eight files); `registry.c` composes those
   arrays into `syscall_struct_arg_groups[]`, walked via
   `FOR_EACH_SYSCALL_STRUCT_ARG()`. A row's identity is (syscall_name,
   arg_idx) plus any discriminator keys, so group order does not matter.
   Many rows are explicitly "attribution-only": the
   syscall's `argtype[]` is not `ARG_STRUCT_PTR_*` (a bespoke `.sanitise`
   callback owns the live fill), and the catalog row exists solely so
   `struct_field_for_cmp()` can name the right field for CMP steering instead
   of guessing off width alone.
3. `struct_catalog_init()` (called after `select_syscall_tables()`) walks
   every registration group, resolves each `syscall_name` against the active
   syscall table(s) via `search_syscall_table()`, and populates
   `desc_by_nr_64/32[nr][arg_idx-1]` — a `slot_binding` holding one optional
   default descriptor plus up to `DISCRIM_VARIANTS_PER_SLOT_MAX` (32)
   discriminated variants in registration order. Both `SLOT_POOL_MAX` (256)
   and the per-slot cap BUG() on overflow rather than silently dropping
   mappings.
4. Runtime consumers call `struct_arg_lookup(nr, arg_idx, do32bit, rec)` —
   O(1) table lookup, then a short linear scan of that slot's discriminator
   variants (reading sibling args off `rec` via `read_rec_arg`/
   `discrim_key_matches`) — falling back to the slot's default descriptor.
   `struct_arg_lookup_two_key()` supports callers (setsockopt) that must
   resolve before the picked (level, optname) reach `rec`. Once a descriptor
   is chosen, `struct_desc_resolve_variant()` (variant.c) further narrows to
   a specific `union_variant` for tagged-union structs.
5. `validate_syscall_struct_args()` runs once at init: for every row, checks
   `entry->argtype[arg_idx-1]` is one of an allow-list of pointer-bearing
   argtypes (`ARG_STRUCT_PTR_*`, `ARG_ADDRESS`, `ARG_IOVEC*`, `ARG_SOCKADDR`,
   time-shaped types, `ARG_UNDEFINED`); a non-struct slot (e.g. `ARG_PATHNAME`,
   `ARG_FD`, `ARG_LEN`) is a BUG. This was added specifically to catch a
   1-based/0-based `arg_idx` off-by-one class of bug found in a 2026-06-11
   audit where 6 of 8 new rows silently mis-mapped.

## Key design decisions

1. **Data/logic separation from consumers.** This directory holds only the
   catalog (struct_desc/field tables) and resolution primitives
   (lookup-by-nr, lookup-by-name, variant resolution, CMP field attribution).
   The actual schema-aware fill (`struct_field_fill_schema_aware`), post-fill
   mutation (`struct_field_mutate_one`), and address-scrubbing walkers live
   in `args/struct_validate.c`, `args/struct_fill.c`, `args/struct_mutate.c`,
   `args/scrub.c` — those files declare the functions whose *prototypes* live
   in `struct_catalog.h` and call back into this directory's lookup/resolve
   API.
2. **Attribution-only vs. live-fill rows.** The majority of the `registry/`
   rows exist purely so CMP-learned constants land on the correctly named
   field even though a bespoke per-syscall `.sanitise()` remains the sole
   writer of the buffer. This is a deliberate two-speed design: bespoke
   generators keep full control of semantically tricky fills (BPF program
   generation, iovec arrays, sized buffers with bucketed distributions)
   while still getting precise CMP steering.
3. **Two independent discriminator axes.** A registration row's
   discriminator picks *which descriptor* a slot resolves to (driven by a
   sibling syscall arg, e.g. fcntl's cmd or setsockopt's (level, optname));
   `struct_desc->variants` picks a *field subset within* an already-chosen
   descriptor (driven by an arg or an in-buffer discriminator like
   `ss_family`). Both can compose on one slot.
4. **Packed/shifted discriminators.** `discrim_shift`/`discrim_mask` support
   syscalls that pack a sub-command into part of a word (quotactl's
   `QCMD(subcmd, type)`), extracting the meaningful bits before matching.
5. **Two-key dispatch** (`discrim2_arg_idx`) exists specifically for
   `setsockopt(level, optname)`, where optname values are only unique within
   a level (e.g. `IPV6_TCLASS == IP_TOS == 1`); a single-key match would
   catastrophically misattribute.
6. **Hard-fail over silent drop.** Every capacity limit in the registry path
   (`SLOT_POOL_MAX`, `DISCRIM_VARIANTS_PER_SLOT_MAX`, catalog holes, slot-shape
   violations) is a `BUG()` at init, not a graceful degrade — a
   misconfiguration is treated as a build-time-class error surfaced at first
   run rather than a silently wrong fuzzing target.
7. **CMP field attribution prefers "gate" fields.** `struct_field_for_cmp()`
   (cmp.c) does a single-pass reservoir sample over candidate fields, ranked:
   same-width FT_ENUM/FT_FLAGS/FT_VERSION_MAGIC fields > any same-width field
   > any wider-fitting field. Gate fields are preferred because the kernel
   more plausibly compared against real ABI vocabulary than against an
   opaque same-width ID.
8. **Config-driven catalog shape.** Optional kernel features (`USE_BPF`,
   `USE_SCTP`, `USE_XATTR_ARGS`, `USE_TCP_REPAIR_OPT`, `X86`-only `user_desc`,
   many `USE_<AF>` sockaddr families) gate both catalog entries and their
   `SC_X` enum slots identically, so a disabled feature can't leave a
   dangling reference; `struct_catalog-internal.h` mirrors the same guards on
   its `_N` size constants and externs.

## Integration points

- `args/struct_validate.c` — defines `struct_field_fill_schema_aware()`
  (three-pass scalar/pointer/length fill driven by field tags), the primary
  consumer of `struct_desc`/`struct_field`.
- `args/struct_fill.c` — nested `FT_PTR_STRUCT`/`FT_PTR_ARRAY` fill,
  resolving `struct_catalog_lookup()` by name for sub-structs and array
  elements.
- `args/struct_mutate.c` — `struct_field_mutate_one()` post-fill mutator plus
  `struct_desc_has_address_field()` reachability checks used to decide
  whether nested address-scrub must run every dispatch.
- `args/scrub.c` — mirrors the fill traversal to scrub/rewrite address-shaped
  fields; calls `struct_arg_lookup()` directly for top-level dispatch.
- `args/gen_arg_struct_ptr.c` — the `ARG_STRUCT_PTR_IN/OUT/INOUT` arg
  generator: `struct_arg_lookup()` → `struct_field_fill_schema_aware()` →
  `struct_field_mutate_one()` per dispatch.
- `args/gen_arg_time.c` — direct `struct_catalog_lookup("timespec")` for
  time-shaped scalar args.
- `cmp_hints/field.c` — calls `struct_arg_lookup()` to resolve the live
  struct for a dispatch, then walks its fields to match KCOV-CMP constants
  against specific field offsets (the consumer this catalog was originally
  built for; see `cmp_hints/CLAUDE.md`).
- `syscalls/bpf.c` — `struct_catalog_lookup("bpf_attr")` +
  `struct_desc_resolve_variant()` + `struct_field_fill_schema_aware()` in the
  default per-cmd arm, letting most bpf(2) cmds fall through to schema fill
  rather than a hand-rolled generator.
- `syscalls/socket/setsockopt.c` — `struct_arg_lookup_two_key("setsockopt", 4, level,
  optname)` resolves the optval struct before the picked (level, optname)
  values are published to `rec`.
- `syscalls/sched/sched_getattr.c` — `struct_arg_lookup()` fallback sizing cap when
  no catalog entry matches.
- `persist/minicorpus-accounting.c` — per-tag mutation trial counters keyed by
  `enum field_tag` (`minicorpus_struct_field_attrib()`), fed by
  `struct_field_mutate_one()`.
- `include/struct_catalog.h` / `include/struct_catalog-internal.h` — the
  public API surface and the leaf-TU extern/size-constant registry,
  respectively.

## Areas of attention

1. **`registry/` is ~1,547 lines of near-entirely declarative data** (comments
   plus initializer literals) spread over eight per-domain files, which is
   appropriate for a registration table but means any structural change to the
   row shape (e.g. a third discriminator key) touches all of them at once. The
   lookup logic itself (`struct_arg_lookup*`, `slot_binding_attach`,
   `struct_catalog_init`) is isolated in `registry.c`.
2. **Silent runtime tolerance vs. init-time strictness.** `validate.c`'s own
   comment notes the dispatcher "tolerates" an arg_idx mismatch at runtime —
   it just steers CMP attribution at the wrong bytes rather than crashing.
   All the safety here is front-loaded into `struct_catalog_init()`
   (BUG-on-violation); there is no runtime assertion if `struct_catalog[]`
   and the registration rows drift after init (they don't, since both are
   `const` static tables, but any future dynamic-registration path would
   reopen this gap).
3. **Two-level nested variants are explicitly capped at depth 2**
   (`struct_desc_resolve_nested_variant()` rejects a nested entry whose own
   `nested_variants` is non-NULL). BPF's `LINK_CREATE` opcode is the only
   consumer of this today; a future third-level dispatch need would require
   revisiting the cap rather than just adding data.
4. **`struct_field_for_cmp()`'s reservoir sample runs on every CMP hit** — a
   full O(num_fields) scan per call with no caching. Fine at current struct
   sizes (max ~22 fields), but would need revisiting if per-cmd bpf_attr-style
   variants grow substantially larger.
5. **The catalog is hand-maintained against kernel UAPI headers**, including
   inline fallback struct definitions (`open_how`, `ns_id_req`, `lsm_ctx`) for
   hosts with older kernel-headers packages. These shims are duplicated
   between `catalog.c` (for `sizeof()`) and the owning leaf TU (for
   `offsetof()`), with comments flagging that a future UAPI header bump
   growing the struct requires updating both copies — an easy place for the
   two to silently drift if only one side is edited.

## Summary

A static, hand-curated description of kernel struct layouts (field name,
offset, size, semantic tag, and tag-specific constraints), registered against
syscall argument slots with an optional two-axis discriminator system
(descriptor-selection via sibling args, then field-subset-selection via
tagged-union variants). The catalog itself does no filling or mutation — it
is read by `args/` to schema-fill and mutate struct-pointer arguments
correctly, and by `cmp_hints/field.c` to attribute learned kernel comparison
constants to the exact field that produced them. Safety is front-loaded into
one-time init validation (slot-shape checks, catalog-hole detection,
capacity BUGs); per-dispatch lookups are O(1) table hits with a short
discriminator scan.

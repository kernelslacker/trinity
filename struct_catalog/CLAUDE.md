# struct_catalog/ — Kernel Struct Layout Catalog

Static data + lookup layer describing the field-level shape of kernel-facing
structs (offset, size, semantic tag, constraints). Consumed by `args/` to
schema-fill, mutate and scrub struct-pointer syscall arguments. This directory is
pure data-plus-resolution: it contains no fill/mutate logic of its own (that
lives in `args/struct_fill.c`, `args/struct_mutate.c`, `args/struct_validate.c`,
`args/scrub.c`).

## Registration and lookup flow

1. Each per-family `.c` defines field tables and (where applicable) variant
   tables; `catalog.c` assembles them into `struct_catalog[SC_X]` entries.
2. Each `registry/<domain>.c` defines a NULL-terminated array of
   `(syscall_name, arg_idx, desc, discriminator...)` rows, hand-written per
   syscall; `registry.c` composes those
   arrays into `syscall_struct_arg_groups[]`, walked via
   `FOR_EACH_SYSCALL_STRUCT_ARG()`. A row's identity is (syscall_name,
   arg_idx) plus any discriminator keys, so group order does not matter.
   A row is read by the struct-pointer generators (`ARG_STRUCT_PTR_*` slots,
   including the paired-size lookup behind `ARG_STRUCT_SIZE`), by the
   nested-address scrub, by `sanitise_sched_getattr()`, or by the setsockopt
   two-key lookup. An `ARG_STRUCT_PTR_IN` slot the entry lists in
   `.sanitiser_owned_mask` (clone3, mount_setattr, open_tree_attr,
   perf_event_open) never gets the schema fill: `generic_sanitise()` skips it
   and the sanitiser's own buffer goes to the kernel, so its row serves only
   the paired-size lookup and the scrub.
3. `struct_catalog_init()` (called after `select_syscall_tables()`) walks
   every registration group, resolves each `syscall_name` against the active
   syscall table(s) via `search_syscall_table()`, and populates
   `desc_by_nr_64/32[nr][arg_idx-1]` — a `slot_binding` holding one optional
   default descriptor plus up to `DISCRIM_VARIANTS_PER_SLOT_MAX` (64)
   discriminated variants in registration order. Both `SLOT_POOL_MAX` (192)
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
   (lookup-by-nr, lookup-by-name, variant resolution).
   The actual schema-aware fill (`struct_field_fill_schema_aware`), post-fill
   mutation (`struct_field_mutate_one`), and address-scrubbing walkers live
   in `args/struct_validate.c`, `args/struct_fill.c`, `args/struct_mutate.c`,
   `args/scrub.c` — those files declare the functions whose *prototypes* live
   in `struct_catalog.h` and call back into this directory's lookup/resolve
   API.
5. **Hard-fail over silent drop.** Every capacity limit in the registry path
   (`SLOT_POOL_MAX`, `DISCRIM_VARIANTS_PER_SLOT_MAX`, catalog holes, slot-shape
   violations) is a `BUG()` at init, not a graceful degrade — a
   misconfiguration is treated as a build-time-class error surfaced at first
   run rather than a silently wrong fuzzing target.
6. **Config-driven catalog shape.** Optional kernel features (`USE_BPF`,
   `USE_SCTP`, `USE_TCP_REPAIR_OPT`, many `USE_<AF>` sockaddr families) gate
   both catalog entries and their `SC_X` enum slots identically, so a disabled feature can't leave a
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

1. **`registry/` is near-entirely declarative data** (comments plus
   initializer literals) spread over per-domain files, which is
   appropriate for a registration table but means any structural change to the
   row shape (e.g. a third discriminator key) touches all of them at once. The
   lookup logic itself (`struct_arg_lookup*`, `slot_binding_attach`,
   `struct_catalog_init`) is isolated in `registry.c`.
2. **Silent runtime tolerance vs. init-time strictness.** `validate.c`'s own
   comment notes the dispatcher "tolerates" an arg_idx mismatch at runtime —
   it just describes the wrong slot rather than crashing.
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
4. **The catalog is hand-maintained against kernel UAPI headers.** A UAPI
   bump that grows a cataloged struct needs the matching field table updated
   by hand.
5. **`struct_catalog` rows: verify the arg index against the syscall's real
   (1-indexed) signature**, and skip op-multiplexed args (e.g. `futex` a4 is a
   timespec only for the WAIT ops) unless discriminated.

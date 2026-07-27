# Heavyweight debug options

Companion to `main/params/help.c`.  These options are targeted
corruption-hunt and self-corruption-detection tools; every one of
them is **default off** and only worth enabling for a specific
investigation.  The `--help` output carries only a one-line contract
per option; the two-stage workflow, the perf_event_open() plumbing,
and the byte-identical `off` guarantee live here.

## --self-corrupt-canary

Deeper self-corruption detector, companion to the always-on gate
loggers in kcov / mm / dispatch.  At every dispatch, checksum a
bounded signature of the child's critical self-state
(`child->local_stats`, `child->objects`,
`child->kcov.trace_buf` / `cmp_trace_buf` / `dedup` pointers, and a
64-byte trinity-heap sentinel filled with `SELF_CORRUPT_CANARY_MAGIC`)
before `do_syscall`; recompute after; on mismatch,
`log_self_corrupt_culprit` names the syscall whose dispatch clobbered
the state.  Catches mid-struct scribbles (glibc-heap family aborts,
wrong-offset writes) that leave the tracked-pointer VA bands intact
and slip past the always-on gates.

`off` short-circuits before any signature computation and before the
sentinel is allocated at `init_child`, so a fixed-seed `--dry-run`
stderr md5 stays byte-identical to a build without this row.  Default
off.

## --writer-pin-sweep

Stage-1 detector for the writer-pinning canary.  At every
post-syscall validate phase, sweep the shared minicorpus rings for a
stomped `wp_canary` or `count > 32` invariant violation.  On the
first hit, emit one `SUSPECT` line naming the observer context (NOT
the wild writer) and the stomped address.

The address is the deliverable for the Stage-2
`--writer-watch=<addr>`, which IS the synchronous writer-namer.
Default-off path is byte-identical to a build without this row (one
branch-predicted `if` test).  Default off; heavyweight tool -- only
enable for a targeted corruption hunt.

## --writer-pin-stride

Throughput escape hatch for `--writer-pin-sweep`: only sweep every
Nth post-syscall validate phase.

- Default `1` = sweep every syscall, which keeps the writer-attribution
  window at one op.
- Values `> 1` widen the window past one op and degrade the sweep to
  "some recent writer" -- documented escape hatch only; the
  writer-namer is Stage-2 `--writer-watch`, not the sweep.

## --writer-watch

Stage-2 writer-namer for the writer-pinning canary.  Arm a
`perf_event_open` hardware WRITE breakpoint (`PERF_TYPE_BREAKPOINT`,
`HW_BREAKPOINT_W`, `bp_len=8`, `exclude_kernel=0`) on the given
8-byte address per-child after fork.

A write to that address traps synchronously in the writing child at
the exact instruction; the `SIGTRAP` handler dumps `writer_pc` (raw,
resolve offline against `[load-bases]`), syscall nr, childop name,
`op_nr`, `pid` -- the exact WILD WRITER, with no race.  Up to 4
watchpoints are supported by hardware; this code arms ONE.

Argument is a hex address (with or without `0x` prefix), typically
the `bad_addr` surfaced by a prior `--writer-pin-sweep` run.  Default
off; heavyweight tool -- only enable for a targeted corruption hunt.

## --guard-shared

Guard shared `mmap` regions with `PROT_NONE` guard pages to catch
out-of-bounds writes.  Requires a `GUARD_SHARED=1` build; otherwise
accepted but warns to rebuild.

- `off`: no guard pages.
- `pools` (default when given bare): focused scope -- kcov_shm,
  shared str/obj heap, childdata.
- `all`: every `alloc_shared` region -- may need a `vm.max_map_count`
  bump to avoid `mprotect`-split ENOMEM.

## --redqueen-pending-pick

Retained for compatibility; no-op.  The RedQueen re-exec consumer at
the `dispatch_step` tail now drains every staged `reexec_pending[]`
entry per parent dispatch, so the `random` vs `first` selection no
longer alters behaviour.

Still parsed (accepts `random` or `first`) so existing invocations do
not break; per-pending-index success counters
(`kcov_shm->reexec_pending_hist.reexec_pending_pick_success[]`) are
still bumped at each entry's true index inside
`redqueen_reexec_step()`, so per-slot / per-index re-exec lift
remains directly readable.

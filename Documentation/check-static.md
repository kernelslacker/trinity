# check-static

`make check-static` runs a battery of structural consistency checks
against the source tree.  It is the bridge between "the code compiled"
and "the code is internally consistent."  The checks are cheap (target
is single-digit seconds) and require no runtime execution beyond what
`make` already does.

Trinity's fuzzer binary cannot safely run on developer hosts; it only
runs on an isolated fuzz machine.  Architectural invariants that would
normally surface as a runtime assertion failure therefore have to be
caught earlier.  `check-static` is where that catching happens.

## Running

    make check-static

Each check prints one of:

    PASS: <check-name>                       (exit 0, counted)
    WARN: <check-name>: <message>            (exit 0, counted; tripwire)
    FAIL: <check-name>: <details on stderr>  (exit 1, counted)

The orchestrator exits 0 if every check passed (warnings allowed) or 1
if any check failed.  Detailed failure output goes to stderr.

## Skipping a check

    CHECK_STATIC_SKIP=childop-arrays,post-state-magic make check-static

Comma-separated list of check basenames (without `.sh`).

## Adding a check

Drop an executable shell script into `scripts/check-static/`.  The file
name (minus `.sh`) is the check name and what `CHECK_STATIC_SKIP`
matches against.  The script may rely on `$REPO_ROOT` (exported by the
orchestrator) to locate sources.  Conventions:

- Print exactly one `PASS:` / `WARN:` / `FAIL:` line on stdout.
- Emit detail on stderr.
- Return 0 on pass/warn, non-zero on fail.
- Keep runtime under one second; the whole battery should stay fast
  enough that contributors run it after every edit.

## What today's checks enforce

(See each script for the precise rule.  This list is hand-maintained;
when scripts are added to or removed from `scripts/check-static/`,
update this section to match `ls scripts/check-static/*.sh`.)

- `activate-syscall-active-flag`: every direct `activate_syscall*()`
  callsite must first set the entry's ACTIVE flag, so the flag-driven
  init / dump / picker consumers see the activated entry.
- `check-alt-op-rotation`: every `CHILD_OP_*` referenced from
  `pick_op_type_table[]` must be reachable via `alt_op_rotation[]` or
  explicitly listed in `alt-op-rotation.denylist` with a reason.
- `child-exit-zero-error-path`: flag `_exit(0)` callsites in
  child-context source (`childops/*.c`, `syscalls/*.c`, `child.c`,
  `kcov.c`) whose preceding ~10 lines contain failure-branch tokens
  (`perror`, `output_err`, `warn`, `fatal`, `abort`, `goto err*`,
  `goto fail*`, or a `case` label naming `err`/`fail`/`abort`/
  `recovery_exhausted`).  Such an exit is invisible to
  `reap_entry_is_fast_die()` and silently neutralises the fork-storm
  fast-die breaker; the fix is `_exit(<sentinel>)` with a non-zero
  code.  Genuine happy-path callsites that over-fire the heuristic
  are pinned in `scripts/check-static/child-exit-zero-error-path.baseline`;
  that list should shrink over time, never grow.
- `child-context-output`: flag `output()` / `outputerr()` /
  `outputstd()` calls reachable from child-context code (`.post`
  handlers and `childops/*.c`), where they vanish into the child's
  /dev/null'd stdio.
- `childop-arrays`: arrays and dispatch tables indexed by
  `NR_CHILD_OP_TYPES` must have one entry per `enum child_op_type`
  value.
- `doc-pointer-exists`: every flat `Documentation/<name>.md` path named
  in a code comment must resolve to a real file, so the one-line
  pointers that replaced carved-out design essays never dangle.
  Kernel-tree references (`Documentation/<subdir>/...`) are out of
  scope -- they point outside this repo.
- `fd-event-close-direct`: every producer of `FD_EVENT_CLOSE` outside
  `fd-event.c` must go through the canonical
  `notify_child_fd_closed[_range]()` helper to preserve the close
  contract.
- `fd-from-object-coverage`: `fd_from_object()` in `objects/dispatch.c` must
  switch on every `OBJ_FD_*` enum value, and every case label must
  still refer to a live enum member.
- `nested-writable-len`: flag nested `get_writable_struct` /
  `get_writable_long_string` allocations stored straight into an outer
  struct field without a NULL check -- the NULL-pointer-with-nonzero-
  length ioctl bug class.
- `no-libc-rand`: reject libc PRNG callsites (`rand`, `random`,
  `srand`, `*rand48`) outside the `rand/` wrapper layer and
  `include/rnd.h`.
- `pdeathsig-getppid-recheck`: every `prctl(PR_SET_PDEATHSIG, ...)`
  arming callsite in child code (`childops/*.c`, `syscalls/*.c`
  excluding `syscalls/prctl.c`, `child.c`) must be followed within
  the same function body by a `getppid()` (or raw
  `syscall(__NR_getppid)`) re-check before the next blocking call.
  Without it, a parent that dies in the window between `clone3()`
  returning in the child and the prctl landing leaves the child
  reparented under PID 1, blocked forever in `pause()` /
  `raw_futex_wait()`.  Grandfathered callsites the heuristic
  over-fires on are pinned in
  `scripts/check-static/pdeathsig-getppid-recheck.baseline`; that
  list should shrink over time, never grow.
- `post-double-publish`: a `.post` handler must not call both a
  `register_*` and a `publish_*` helper on the same object -- the
  syscall return path already registers, so a post-side publish
  enrolls the object twice.
- `post-state-deref`: every `.post` handler that dereferences a
  pointer read from `rec->post_state` must first gate it with
  `looks_like_corrupted_ptr()` or a `*_POST_STATE_MAGIC` cookie
  compare.
- `post-state-magic`: every `struct *_post_state` in `syscalls/` must
  begin with `unsigned long magic` and ship a matching
  `*_POST_STATE_MAGIC` constant -- the convention that prevented the
  ppoll bad-free regression class.  Grandfathered structs that predate
  the convention are listed in
  `scripts/check-static/post-state-magic.baseline`; that list should
  shrink over time, never grow.
- `sanitiser-slow-path`: forbid hot-path slow-syscall callsites
  (`/proc/self/maps`, `fopen`/`getline`, `mincore`/`mprotect` probes)
  in the per-syscall sanitiser / argument-generation file set.
- `shared-region-budget`: tripwire that warns when the number of
  shared-region producer call sites approaches `MAX_SHARED_ALLOCS`.
  Silent under-protection is the bug class, not loud over-protection.
- `shm-latch-direct`: latch fields of `struct shm_s` (`exit_reason`,
  `current_strategy`, `current_selection_reason`,
  `plateau_current_hypothesis`) must only be read or written through
  `__atomic_*` intrinsics; a plain `shm->field` access is a torn write
  that breaks the publish ordering.
- `signal-handler-async-unsafe`: forbid async-signal-UNSAFE libc calls
  (`snprintf`, `malloc`, `fopen`, `syslog`, ...) inside known signal
  handlers discovered in `signals.c`.
- `syscall-metadata`: best-effort sanity on `struct syscallentry` --
  ARG_RANGE arguments must declare low/high bounds.
- `track-shared-region-pairing`: every `track_shared_region()` must
  have a matching `untrack_shared_region()` on every cleanup-goto exit
  path that can free or recycle the backing mapping.

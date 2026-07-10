# health/signals.c design notes

Long-form design rationale extracted from `health/signals.c`.  The `.c`
file keeps concise per-site summaries plus load-bearing invariants (async-
signal-safety notes, "don't revert this" guards, per-declaration one-
liners); this document holds the multi-paragraph narratives explaining
*why* each piece is shaped the way it is.

## Capturing glibc's `__abort_msg` per child

`capture_abort_msg_to_buglog()` writes glibc's `__abort_msg` directly into
the per-pid bug log via raw `syscall(SYS_write, ...)`, bypassing libc
stdio and `STDERR_FILENO` entirely.

Why not just write to `STDERR_FILENO` after `dup2`?  Because every child
inherits the SAME underlying `struct file` for the stderr memfd via
`fork`: one offset, one inode.  Concurrent `writev()`s from N children's
`glibc malloc_printerr -> __libc_message` paths race with each other AND
with sibling SIGABRT handlers' `lseek(0)+read` drain blocks.  Most
messages are overwritten before the originator drains, or attributed to
the wrong bug log when a sibling's `lseek` mutates the shared offset
mid-drain.  Empirical capture rate sat at ~13-15% regardless of pool
size.

`__abort_msg`, on the other hand, is per-process: glibc's
`__libc_message` `mmap()`s the backing buffer in the abort()ing child's
own address space and populates it before raising SIGABRT.  No sharing
across fork, no race, no offset state.  Writing it directly into the
per-pid `bug_fd` -- which the handler just `open()`ed for this specific
child with `O_APPEND` -- sidesteps the shared-memfd path entirely.

Async-signal-safe throughout:

- `syscall(SYS_write, ...)` is the raw syscall instruction; `write()`
  itself is on POSIX 2024 §2.4.3's safe list, and the wrapper does no
  extra libc work beyond setting up the registers.
- `strnlen()` walks memory looking for NUL; no allocation, no locale, no
  lock.  Bounded by `min(m->size, ABORT_MSG_MAX)` -- `m->size` is
  treated as advisory because `m` lives in the same glibc allocation
  we're salvaging post-corruption and may itself be scribbled.

The `m->msg[0] == '\0'` early-out catches the rare path where glibc
allocated the buffer but bailed before formatting (e.g. format failed
inside `vfprintf`-on-string).  Don't emit a bare `"abort_msg: \n"`.

The cached `glibc_abort_msg_p` pointer is resolved once at child init so
there is no link-time `GLIBC_PRIVATE` dependency: a glibc upgrade that
drops the symbol leaves the pointer NULL and the SIGABRT handler
silently skips the capture.  This mirrors gdb's pattern for reading the
same symbol.  Neither `dlvsym()` nor `dlsym()` is async-signal-safe;
both are called only from `init_abort_msg_capture()`.

`__abort_msg` points at a glibc-internal struct whose layout has been
stable since 2.34: a 4-byte size field followed by a NUL-terminated
message in a flexible array.  The struct is mirrored locally rather
than pulled from a private glibc header.

## Buffering child stderr in an anonymous memfd

`init_stderr_memfd()` buffers the child's stderr writes in an anonymous
in-memory file so glibc's `malloc_printerr` / `__libc_message` /
`__fortify_fail` / `__stack_chk_fail` family text -- which happens
BEFORE any trinity signal handler runs -- survives long enough for the
fault handler to flush it into the on-disk bug log.  Only on a real
crash: trinity's own `outputerr()` noise from healthy children is
silently discarded with the process at clean exit.

Paired with the drain block at the top of `child_fault_handler`: the
handler `open()`s the bug log, `lseek()`s the memfd to 0, and splices
the buffered text into the log before its own writes.

`snprintf()` is NOT async-signal-safe, so the bug-log path is formatted
here at init time (under the inherited non-fuzzed locale state) and
stashed in the file-static `buglog_path[]`.  `trinity_tmpdir_abs()` is
used so a fuzzed `chdir()` can't move us off the writable tmp dir
mid-run; `getpid()` is used instead of `mypid()` because the
`cached_pid` backing `mypid()` isn't populated until `set_child_cache`
runs later in `init_child_rendezvous_parent`.

On `memfd_create()` failure (`CONFIG_MEMFD_CREATE=n` or sandbox) stderr
stays at `/dev/null` per `init_child_isolate_io()`'s baseline: the
per-pid bug log still gets the in-handler backtrace + siginfo via the
handler's explicit open + dup2, only the pre-crash glibc text capture
is lost.

The fd is intentionally NOT closed after `dup2` onto `STDERR_FILENO` --
the handler reads it back from the same fd.

## Async-signal-safe siginfo dump (replacing `psiginfo`)

`write_siginfo_safely()` is the signal-safe siginfo dump shared by
`child_fault_handler` and `main_fault_handler`.

Don't use `psiginfo()` -- it calls `fmemopen()`, which calls `calloc()`,
which deadlocks if this signal was raised by glibc's own `abort()`
while malloc's arena lock is still held by us.  Same family as the
`libgcc_s`/backtrace deadlock fixed in 81143aaeaba6, just one frame up.

Hand-roll a signal-safe equivalent: a lookup table covering every
signal either fault handler is installed for, formatting via the
`sigsafe_*` helpers (byte stores into a stack buffer), and a single
`write()`.  No allocator involvement, no stdio, no syslog.

Used by both the child fault handler (SIGSEGV/SIGABRT/SIGBUS/SIGILL)
and the parent's `main_fault_handler` (which adds SIGFPE/SIGQUIT/
SIGTRAP/SIGSYS -- see `setup_main_signals`).  Without this in the
parent path, a SIGSEGV or SIGABRT raised by glibc with the arena
lock held (e.g. heap corruption from shm scribble, or an internal
assertion) would `fmemopen`->`calloc` and wedge the parent's death
path forever -- the pool would then sit on a non-responsive trinity
main until something external SIGKILLed it.

## Guarding beacon writes against wild `me` pointers

`stamp_fault_beacon()` gates its first `me`-deref on `me` belonging to a
tracked shared region.  `this_child()` returns a raw pointer into
per-child shm childdata; a child whose shm childdata mapping has been
torn down or corrupted yields a non-NULL but unmapped pointer, so the
NULL check alone is insufficient -- the first plain load
(`me->syscall.state`, `&me->fault_beacon`, ...) re-faults inside this
very handler and the kernel escalates to SIGKILL, erasing the original
crash class entirely.

`range_in_tracked_shared()` walks `shared_regions[]` (and the overflow
tail) linearly -- no allocator, no stdio, no lock, no `this_child()`,
no `stats_ring` enqueue, no global mutation -- which is the async-
signal-safe property this handler requires.  `range_overlaps_shared()`
is NOT used here: on its confirmed-overlap path it calls
`this_child()`, `stats_ring_enqueue()` twice, `output()` under
verbosity, and writes the `last_reject_*` globals -- exactly the
re-entrant / async-signal-unsafe class this gate exists to keep out of
the fault handler.

Containment polarity (fully inside one tracked region) also matches the
shape of the probe: each childdata is registered as a single
`shared_regions[]` entry covering its full `sizeof`, so a valid `me`
passes; a wild `me` that merely shares a 2 MiB bitmap chunk with some
tracked region is correctly rejected here where `range_overlaps_shared()`
would over-accept.

This proves `me` lies in a TRACKED region; it does NOT prove the
underlying page is currently mapped/readable (a child that `munmap`'d
its own childdata while the region stays registered would still pass
this gate and re-fault on the deref).  That residual is a separate
root-cause concern; this gate cleanly catches the wild/stale/corrupt-
`me` class.  On a miss the beacon stamp is skipped (dropped-beacon,
surfaced by the parent's existing `written == 0` path) so the kernel-
side crash artefacts still land instead of a silent handler double-fault.

## Local-then-publish for the fault beacon

`stamp_fault_beacon()` builds the stamp on the stack first, then
publishes the whole record via a single struct assignment.

`fault_sa` in `mask_signals_child()` installs this handler with
`sa_mask = empty` and no `SA_NODEFER` on SIGABRT/SIGBUS/SIGILL, so a
different fatal signal delivered mid-stamp can run an inner copy of
this handler to completion.  If we stamped field-by-field directly into
the shared slot, the inner handler would publish a full record (its
own release-store of `.written = 1`) and the outer handler's resumed
plain stores would then overwrite the shared fields piecemeal, leaving
a torn forensic line (signo from one fault, ip/sp from another) for
the parent's acquire-load to read.

With local-then-publish: an inner handler that runs to completion
publishes its own self-consistent record; when the outer handler
resumes, the single struct assignment from this stack snapshot
rewrites the shared slot with a self-consistent outer record before
the trailing release-store of `.written = 1` seals it.  Either way the
parent never observes a mixed record.

`.written` is left zero in the local so the struct assignment
transiently clears the published bit; the release-store below is the
real publish edge.

## SIGTRAP handler for the writer-pinning canary

`writer_trap_handler()` is the SIGTRAP handler for the Stage-2 writer-
pinning canary (perf HW breakpoint armed by `writer-watch.c` with
`perf_event_attr.sigtrap=1`).  The kernel delivers SIGTRAP
SYNCHRONOUSLY in the writing thread with `si_code=TRAP_PERF`;
`info->si_addr` is the faulting instruction and the ucontext RIP is
the writer's instruction pointer (just past the write on x86 hardware-
data-breakpoints).  This handler dumps the writer's identity and
`_exit()`s so the trap does not re-fire when the kernel resumes the
interrupted thread.

Synchronous delivery requires `perf_event_attr.sigtrap=1` (kernel >=
5.13).  The earlier `F_SETSIG`/SIGIO route is asynchronous and would
make `info->si_addr` meaningless -- explicitly NOT used.

STRICTLY ASYNC-SIGNAL-SAFE: only `write(2)`, the `sigsafe_*` helpers
(byte stores into caller-owned stack buffer), and pure inline reads
from caller-owned ucontext.  No libc malloc / stdio / locale / lock,
no symbolization (`dladdr` is unsafe -- the `WRITER-PINNED` line emits
the RAW PC; resolve it offline against the `[load-bases]` line
`log_load_bases()` prints at startup, same convention as the `FAULT!`
line).  The `this_child()` deref is gated by `range_in_tracked_shared`
exactly like `stamp_fault_beacon` does, so a wild/torn-down `me` does
not double-fault in this very handler.

Caveat (documented spec limit): for a kernel-side value-result write
(`copy_to_user` via a fuzzed pointer) the breakpoint may or may not
trap from user-mode debug registers on every arch --
`exclude_kernel=0` is the best the perf interface offers, but the
synchronous trap is not guaranteed for in-kernel writers on all
configurations.  Trinity-userspace writers ARE caught synchronously
with the exact RIP.

## Sanitiser copy-fault recovery (`asb_relocate`)

`child_fault_handler` runs the `asb_copy_active` recovery FIRST, before
the sibling-spoof gate and before the fault beacon stamp, because the
`longjmp` aborts the handler outright and must not leave any publish-
side side effects (a beacon record, a bug-log open) on a fault we're
about to retry-as-skip in the sanitiser.

Gated on:

- SIGSEGV or SIGBUS only (the `memcpy` faults the kernel raises for
  an unmapped/torn-down source; SIGILL/SIGABRT are not produced by
  the speculative read and are left to the normal crash path);
- `si_code > 0`, i.e. a real kernel-generated fault.  A sibling
  `kill`/`tkill` that happens to deliver SIGSEGV while the flag is
  set has `si_code <= 0` and would resume the `memcpy` on return
  anyway -- `siglongjmp`'ing on it would falsely mark the copy as
  faulted and lose accuracy in the counter;
- `asb_copy_active`, which `asb_relocate()` sets ONLY across the
  `memcpy` itself and clears immediately after.  Any other SIGSEGV/
  SIGBUS the child takes (real kernel bug found by fuzzing, crash
  in unrelated code) sees the flag clear and falls through to the
  existing diagnostic + `_exit` path.

`sigsetjmp` was installed with `savemask=1` so `siglongjmp` restores
the application's signal mask; the kernel's per-handler add-the-
current-signal mask is unwound as part of that restore so a subsequent
SIGSEGV in the same child still reaches this handler (no permanently-
blocked SEGV after recovery).

The identical shape repeats for the `cmp_hints_collect()` field-scoped
ARG_TIMESPEC deref (`cmp_field_read_active`), the `vma_split_storm`
`touch_random_page()` one-byte store (`vma_split_storm_touch_active`),
and (under `CONFIG_GUARD_SHARED`) the `kcov_enable_trace()`
`trace_buf[0] = 0` reset (`kcov_protect_active`): the same three-way
gate on signo / `si_code` / active-flag, each flag set only across the
specific probe, so any unrelated fatal signal still falls through to
the normal crash path.

## Draining pre-crash stderr into the per-pid bug log

The fault handler opens the per-pid bug log and (if `init_stderr_memfd()`
succeeded for this child) drains the buffered pre-crash stderr text
into it BEFORE redirecting `STDERR_FILENO` at the file -- otherwise the
in-handler `write_siginfo_safely()` / `backtrace_symbols_fd()` output
would land before the glibc `malloc_printerr` text that explains why
we're here.

The drain captures every stderr write the child made before faulting:
glibc's `__libc_message` / `__fortify_fail` / `__stack_chk_fail`
formatted complaints (the whole point of pre-redirecting stderr), plus
every trinity `outputerr()` line accumulated this run.  The
`outputerr` noise is harmless here because the on-disk bug log only
materialises on a real crash -- clean exits discard the memfd with the
process.

`buglog_path[]` was pre-formatted in `init_stderr_memfd()` so the
`snprintf()` doesn't happen in this handler (not async-signal-safe per
POSIX 2024 §2.4.3).  `open` / `lseek` / `read` / `write` / `dup2` /
`close` ARE all on the POSIX safe list.

If `init_stderr_memfd()` failed (`CONFIG_MEMFD_CREATE=n`) or this is a
child that started before that init step, `stderr_memfd` is `-1` and
we skip the drain -- the bug log still gets the in-handler backtrace +
siginfo, just without the pre-crash glibc text.  If the `open()`
itself fails (fuzzed unlink of the tmp dir, ENOSPC, ...) there is
nothing to be done; the child dies silently as it would have anyway.

The drain is capped at 1 MiB: a fuzzed child can extend the stderr
memfd to a huge sparse size, and an uncapped copy loop would
materialise the NUL holes as real bytes on tmpfs and produce multi-GB
bug logs (log-DoS).

`__abort_msg` capture (see the first section above) runs BEFORE this
drain: the memfd is fork-shared and its offset almost certainly raced
with a sibling's drain, but `__abort_msg` lives in this child's private
address space and has no such race.  Read it while we are guaranteed
exclusive access to our own per-pid `bug_fd`.

## Guard-page attribution (`CONFIG_GUARD_SHARED`)

`emit_guard_page_attribution()` decodes a `CONFIG_GUARD_SHARED` guard-
page trip.  When `--guard-shared` wrapped a tracked region in
`PROT_NONE` pages and a fuzzer write overflows past the buffer, the
kernel raises SIGSEGV at the writing instruction with `si_addr` inside
the guard page.  Walk the tracked-region table to find the abutting
region and emit a single line naming WHICH region was overflowed,
WHICH direction (leading = underflow vs trailing = forward overflow),
how far past the edge, and the writer PC -- the one-line root cause
the hunt instrument exists to produce.

Skipped for non-SIGSEGV faults (a SIGBUS or SIGABRT can still reach
the in-handler diagnostic path but is not a guard trip by
construction).

Async-signal-safe: `guard_pages_classify` is a plain read of
`shared_regions[]`, the format path uses only the `sigsafe_*` byte
builders that `write_siginfo_safely` already relies on, and the output
is a single `write()` to the inherited stderr (which `dup2` redirected
to the per-pid bug log a few statements above).  No allocator, no
stdio, no libc lookup, no lock.

The writer PC is emitted raw rather than resolved through `dladdr()`
because `dladdr` is not on the POSIX 2024 §2.4.3 safe list and the
existing handler bans it for the same reason; the `bugs.txt`
post-parser resolves PIE-relative offsets offline against the binary's
load base, same idiom as the fault beacon's stored `fault_ip`.

## Child-op identity stamp

`stamp_childop_identity()` writes the currently-running childop's
identity (`childop=<name> op_nr=<n> last_syscall_nr=<n>\n`) to the
inherited stderr (the per-pid bug log after the `dup2` above) so the
canary queue and post-mortem grep-mining can attribute a SIGSEGV /
SIGBUS / SIGILL / SIGABRT to a specific op rather than bottoming out
at `child_process+offset` like the bare `libgcc` backtrace does.

`this_child()` reads a plain pointer set once per child in
`init_child()` (see `pids.c::set_child_cache`); `alt_op_name()` is a
pure switch over an enum with no allocation or locking.  Both are safe
to call from this handler.

Hand-rolled formatter rather than `dprintf()` so the write is a single
syscall and uses no stdio buffering -- mirrors the
`write_siginfo_safely()` pattern.  `PATH_MAX` is comfortably oversized
for `"childop=<longest-name> op_nr=<ulong> last_syscall_nr=<int>\n"`.

`last_syscall_nr` is the in-flight syscall number sourced from
`me->syscall.nr` -- the per-child syscallrecord embedded in childdata,
populated by `set_syscall_nr()` before each dispatch.  Reading a plain
`unsigned int` from process-local shm-resident memory is async-signal-
safe (no allocation, no lock, no table lookup).  We emit the NUMBER
rather than the name because the number->name map
(`get_syscall_entry` / `syscalls[].name`) is a pointer-chasing table
walk that is not on the POSIX async-signal-safe list; the `bugs.txt`
post-parser can resolve names offline.

Gate on `me->syscall.state` to avoid emitting a stale number when the
signal hit between syscalls.  `rec->nr` is only meaningfully populated
once `set_syscall_nr()` has run for the current iteration; states
UNKNOWN (child just started, never picked) and AFTER (previous call
returned, next not yet picked) both mean "no syscall in flight".  In
those cases we emit `-1` rather than a misleading number that points
at the *previous* call.

#pragma once

#include <stdbool.h>

#include "kernel/hw_breakpoint.h"
/*
 * Stage-2 writer-pinning canary (--writer-watch=<hexaddr>).
 *
 * Hardware watchpoint, opened per-child after fork via
 * perf_event_open(PERF_TYPE_BREAKPOINT, HW_BREAKPOINT_W) on the address
 * passed via --writer-watch.  A write to the watched address traps
 * synchronously in the writing child at the exact instruction; the
 * SIGTRAP handler in health/signals-fault-handler.c (writer_trap_handler)
 * dumps the writer PC, syscall nr, childop, op_nr and pid, then
 * _exit()s so the trap does not re-fire on resume.
 *
 * This is the WRITER-NAMER half of the writer-pinning canary.  Stage 1
 * (--writer-pin-sweep) hands an address to this stage; Stage 2 names
 * the wild writer.
 *
 * Default-OFF: a zero writer_watch_addr leaves every call below a
 * no-op.  Heavyweight debug tool -- only enable for a targeted
 * corruption hunt: the perf fd has real cost and the SIGTRAP handler
 * _exit()s, so an accidental hit on a live host kills the child.
 */

/* Whether this kernel, with these privileges, opens the breakpoint the
 * children will: checked before the fork and reported here, since a
 * child's own failure reaches only its stderr memfd.  True when
 * writer_watch_addr is zero. */
bool writer_watch_probe(void);

/* Open the per-child hardware write breakpoint, disabled.  Called from
 * init_child before the sandbox drops the child's capabilities, as
 * watching kernel writes needs CAP_PERFMON unless perf_event_paranoid
 * <= 1.  No-op when writer_watch_addr is zero. */
void writer_watch_open_child(void);

/* Enable the breakpoint writer_watch_open_child() opened, closing it if
 * the enable fails.  Called last in init_child, after the per-child
 * SIGTRAP disposition is in place; no-op when none is open. */
void writer_watch_arm_child(void);

/* The breakpoint's fd, or -1 when none is open: a close or dup2 over it
 * ends the watch, so the protected-fd registry names it. */
int writer_watch_child_fd(void);

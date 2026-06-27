#pragma once

/*
 * Stage-2 writer-pinning canary (--writer-watch=<hexaddr>).
 *
 * Hardware watchpoint, opened per-child after fork via
 * perf_event_open(PERF_TYPE_BREAKPOINT, HW_BREAKPOINT_W) on the address
 * passed via --writer-watch.  A write to the watched address traps
 * synchronously in the writing child at the exact instruction; the
 * SIGTRAP handler in signals.c (writer_trap_handler) dumps the writer
 * PC, syscall nr, childop, op_nr and pid, then _exit()s so the trap
 * does not re-fire on resume.
 *
 * This is the WRITER-NAMER half of the writer-pinning canary.  Stage 1
 * (--writer-pin-sweep) hands an address to this stage; Stage 2 names
 * the wild writer.
 *
 * Default-OFF: a NULL writer_watch_addr leaves writer_watch_arm_child()
 * as a no-op.  Heavyweight debug tool -- only enable for a targeted
 * corruption hunt: the perf fd has real cost and the SIGTRAP handler
 * _exit()s, so an accidental hit on a live host kills the child.
 */

/* Open the per-child hardware write breakpoint.  Called once from
 * init_child after fork, after the per-child SIGTRAP disposition is in
 * place.  Reads writer_watch_addr; no-op when it is zero. */
void writer_watch_arm_child(void);

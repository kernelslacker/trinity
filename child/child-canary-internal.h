/*
 * child-canary-internal.h -- private interface between the four child-canary-*.c
 * translation units (policy, state, picker, report).
 *
 * The public API is in include/child-api.h; nothing outside child/child-canary-*.c
 * should include this header.
 *
 * Layout:
 *   - Cross-file constants shared by more than one canary TU.
 *   - Extern declarations for the parent-private state cells
 *     (canary_ops[], the two-stage active/pending op cells, the parked/live
 *     flags, the promotion ring, picker cursors, the plateau-edge latch).
 *   - Extern declarations for internal helpers whose callers now live in a
 *     different TU from the definition.
 */
#ifndef CHILD_CANARY_INTERNAL_H
#define CHILD_CANARY_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "child-api.h"
#include "params.h"

/* --------------------------------------------------------------------
 * Cross-file constants.  Kept here (not in the owning TU) because more
 * than one child-canary-*.c reads them.
 * -------------------------------------------------------------------- */

/* Seconds a DEMOTED op must wait before re-entering the picker.  Long
 * enough that a backed-off op does not churn-cycle, short enough that
 * a single multi-hour fuzz run gets to re-test misjudged ops. */
#define CANARY_BACKOFF_TIME		1800

/* Backoff for an op demoted with reason setup_broken.  Much longer
 * than CANARY_BACKOFF_TIME because a 100%-setup-failure shape will
 * not self-heal in 30 minutes -- it needs a code fix to the op's
 * setup path (missing kconfig probe, stale capability check, wrong
 * netns scope).  Re-canarying before then just burns another window
 * rediscovering the same broken setup.  4 h is still inside a single
 * long fuzz session, so a fix that lands mid-run does get re-evaluated. */
#define CANARY_SETUP_BROKEN_BACKOFF_TIME	(4 * 3600)

/* Width of the small ring of recently-promoted op names rendered by
 * canary_queue_summary().  Fixed at 5; spec verbatim. */
#define CANARY_PROMOTION_RING_SIZE	5

/* --------------------------------------------------------------------
 * Per-op queue state.  Parent-private; indexed by child_op_type enum.
 * Owned by child-canary-state.c; the picker, policy, and report TUs
 * read/mutate it via this extern.
 * -------------------------------------------------------------------- */
extern struct canary_op_state canary_ops[NR_CHILD_OP_TYPES];

/* Per-op latch set by leave_canarying_demote_setup_broken() to mark an op
 * whose last demotion was for 100%-setup-failure shape.  Read by the
 * picker's DEMOTED-state backoff check, which then uses
 * CANARY_SETUP_BROKEN_BACKOFF_TIME instead of CANARY_BACKOFF_TIME.
 * Cleared in enter_canarying() so a re-canary that survives (or hits a
 * different demote reason) drops back to the normal backoff schedule. */
extern bool canary_op_setup_broken[NR_CHILD_OP_TYPES];

/* Active op the canary slot(s) should be running right now.  Two-stage
 * commit: enter_canarying() writes canary_pending_op and stamps the
 * window-start counters, but canary_active_op_cell is only flipped
 * when canary_queue_on_child_respawn() fires -- the slot's previous
 * child has actually exited and a fresh one has been forked with the
 * new op.  Straggler iterations of the old op therefore do not
 * pollute the new op's window edges/crashes counters. */
extern enum child_op_type canary_active_op_cell;
extern enum child_op_type canary_pending_op;
extern bool canary_active_op_set;
extern bool canary_pending_op_set;

/* Parked state: when canary_queue_tick() finds the picker exhausted
 * (no eligible candidate after the active window closes), the queue
 * has no op to run on the canary slot(s) but the slot children are
 * still alive with the just-demoted/finished op stamped from a prior
 * spawn.  Dedicated alt-op children keep child->op_type for life, so
 * without intervention the demoted op keeps executing on the slot --
 * and crashes from it are dropped because canary_active_op_set is
 * false.  Parking the slot stamps it with CHILD_OP_SYSCALL on the
 * next respawn (the canary path still wins in assign_dedicated_alt_op
 * because canary_slot_active() returns true while parked), so the
 * slot drops back to the default syscall picker until the next canary
 * cycle stages a new pending op via enter_canarying(). */
extern bool canary_slots_parked;

/* True once the queue is fully initialised AND not gated off by
 * --no-canary-queue / canary_slots=0.  When false, every public entry
 * point returns immediately and the dormant gate is consulted as a
 * historical static vector. */
extern bool canary_queue_live;

/* --------------------------------------------------------------------
 * Picker cursors and priority-seed override storage.
 * Owned by child-canary-picker.c; canary_queue_init() (state TU) resets
 * them on epoch start.
 * -------------------------------------------------------------------- */

/* Picker cursors.  canary_priority_cursor is the next index into
 * canary_priority_list (the per-run random shuffle, or the operator-
 * supplied override).  fifo_cursor is the last enum value picked from
 * the general FIFO walk; the next pick resumes from cursor+1 and wraps. */
extern unsigned int canary_priority_cursor;
extern enum child_op_type canary_fifo_cursor;

/* Resolved priority list pointer.  Defaults to a per-epoch random shuffle
 * of every eligible op (built in canary_queue_init()); if --canary-seed
 * was passed, the parser put op enums into canary_seed_override[] /
 * canary_seed_override_count and the init path swaps that in. */
extern const enum child_op_type *canary_priority_list;
extern unsigned int canary_priority_list_count;

/* Storage backing canary_priority_list when --canary-seed is in use.  The
 * parser stuffs unsigned-char-narrowed op enums into
 * canary_seed_override[]; we widen them into a real enum array here so
 * the picker can iterate by value rather than by re-casting on every
 * pick. */
extern enum child_op_type canary_seed_override_widened[CANARY_SEED_OVERRIDE_MAX];

/* Last observed plateau_active value, used for edge-triggered logging in
 * canary_queue_tick().  File-static (not a function-local static) so
 * canary_queue_init() can reset it per-epoch -- otherwise stale state from
 * the previous epoch would suppress the first plateau-change log of the
 * new epoch (or emit a spurious one if the flag flipped while the queue
 * was reinitialising). */
extern bool canary_last_plateau;

/* --------------------------------------------------------------------
 * Recently-promoted ring + summary throttle.  Owned by
 * child-canary-report.c; state TU's leave_canarying_promote() drops
 * entries in via push_promotion(); state TU's canary_queue_init()
 * resets the throttle timestamp.
 * -------------------------------------------------------------------- */
extern enum child_op_type canary_promotion_ring[CANARY_PROMOTION_RING_SIZE];
extern unsigned int canary_promotion_ring_count;
extern unsigned int canary_promotion_ring_head;
extern time_t canary_last_summary;

/* --------------------------------------------------------------------
 * Policy tables (owned by child-canary-policy.c).  Sizes are exposed as
 * companion const-int counts because a bare `extern T tbl[]` declaration
 * has an incomplete type and cannot be fed to ARRAY_SIZE() -- the
 * counts let consumers walk the tables without re-declaring the sizes.
 * -------------------------------------------------------------------- */

extern const enum child_op_type canary_config_blocked[];
extern const unsigned int canary_config_blocked_count;

extern const enum child_op_type canary_risky_defer[];
extern const unsigned int canary_risky_defer_count;

/* --------------------------------------------------------------------
 * Internal helpers whose caller now lives in a different TU from the
 * definition.  Grouped by the TU that owns the definition.
 * -------------------------------------------------------------------- */

/* State TU (child-canary-state.c): shared helpers + cross-TU transitions. */
time_t monotonic_seconds(void);
unsigned int window_iters_resolved(void);
unsigned long edges_for_op(enum child_op_type op);
unsigned long invocations_for_op(enum child_op_type op);
void kill_canary_slot_children(void);
void enter_canarying(enum child_op_type op);
void leave_canarying_demote_setup_broken(enum child_op_type op,
					 unsigned long window_iters,
					 unsigned long setup_failures);
void leave_canarying_demote_wedged(enum child_op_type op, time_t window_age_sec);
void close_window_and_decide(enum child_op_type op);

/* Policy TU (child-canary-policy.c): eligibility + setup-reason helpers. */
bool fork_pressure_should_suppress(enum child_op_type op);
const char *canary_setup_fail_reason_name(enum canary_setup_fail_reason r);
enum canary_setup_fail_reason canary_setup_fail_reason_for_op(enum child_op_type op);
const char *canary_blocked_reason_name(enum canary_blocked_reason r);

/* Picker TU (child-canary-picker.c): candidate selection. */
bool pick_next_canary(enum child_op_type *out);

/* Report TU (child-canary-report.c): promotion-ring mutator. */
void push_promotion(enum child_op_type op);

/* Report TU (child-canary-report.c): render the per-window crash-signature
 * breakdown into a caller-supplied buffer.  Format is space-separated tokens
 * "SIG/code=N/pc=binary+0xOFF x COUNT" per distinct signature, followed by
 * "+N overflow" if window_crash_sigs_overflow > 0.  Writes an empty string
 * (buf[0] = 0) when window_crash_sigs_count == 0 so callers can concatenate
 * unconditionally.  Returns buf. */
const char *canary_crash_sig_render(enum child_op_type op, char *buf, size_t buflen);

#endif /* CHILD_CANARY_INTERNAL_H */

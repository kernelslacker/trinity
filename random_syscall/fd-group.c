/*
 * Per-child fd + group bookkeeping ran at the tail of dispatch_step:
 * fd leak counters, live-fd ring push for arg-generation reuse, the
 * group_bias-gated last_group stamp, and the F-RSEQ group-pin damper
 * state machine (group-change streak reset, streak bump, fd-warm
 * bump, coverage watermark advance).
 *
 * Carved out of strategy-accounting.c; the sibling seams (rotation,
 * remote-adaptive decide, per-syscall edge accounting, warm-cold
 * reserve) live in their own TUs under random_syscall/.
 *
 * account_fd_and_group is cross-cluster private and declared in
 * random_syscall/strategy-accounting-internal.h.
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "random-syscall-internal.h"
#include "reach-band.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy-accounting-internal.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* FD leak tracking (count successful fd-creating and fd-closing
 * syscalls per child for leak diagnosis), the live-fd ring push for
 * preferential reuse in arg generation, the group_bias-gated
 * last_group stamp, and the F-RSEQ group-pin damper per-child
 * bookkeeping (group-change streak reset, streak bump, fd-warm
 * bump, coverage watermark advance).  All pieces are per-call
 * child-state updates that key off the just-completed syscall's
 * entry / rec and touch no shared region, so they collapse into
 * one helper at the end of the dispatch_step bookkeeping tail.
 *
 * found_local_coverage is the dispatch-step coverage signal the
 * watermark advance keys on: true when this call landed at least
 * one new PC-edge or one new LOCAL transition-edge.  Remote-
 * collected coverage is intentionally excluded -- remote /
 * deferred edges can land on whichever syscall happened to harvest
 * them and would falsely productive-mark a pure observer, so the
 * watermark uses the same _real_local lane satcool already
 * isolates.  Computed at the dispatch_step seam where new_edges
 * and pcres.transition_edges_real_local are both in scope. */
void account_fd_and_group(struct childdata *child,
				 struct syscallentry *entry,
				 struct syscallrecord *rec,
				 bool found_local_coverage)
{
	enum frontier_group_antilock_mode antilock_mode;

	if (rec->retval != -1UL) {
		if (entry->rettype == RET_FD) {
			child->fd_created++;
			if (entry->group < NR_GROUPS)
				child->fd_created_by_group[entry->group]++;
			/* Track returned fd for preferential reuse in arg generation. */
			if ((int)rec->retval > 2)
				child_fd_ring_push(&child->live_fds, (int)rec->retval);
		}
		if (entry->is_close_syscall)
			child->fd_closed++;
	}

	/* F-RSEQ group-pin damper per-child bookkeeping.  Gated on
	 * frontier_group_antilock_mode != OFF so default mode=OFF is
	 * byte-identical to a build before this commit -- the mode load
	 * is the only added cost when off, and the field writes inside
	 * the branch are owner-only with no shm touched.  Inner gate on
	 * group_bias mirrors the last_group write below: the streak
	 * state is a per-pin counter on top of last_group, so it only
	 * makes sense to advance it under the same flag that keeps
	 * last_group meaningful (the F-RSEQ-5 fleet-invocation caveat
	 * in the design note).  See the group_streak_len / last_cov_at_
	 * streak / group_fd_created_in_streak field comments in
	 * include/child.h for the bookkeeping order rationale. */
	antilock_mode = __atomic_load_n(&frontier_group_antilock_mode,
					__ATOMIC_RELAXED);
	if (antilock_mode != FRONTIER_GROUP_ANTILOCK_MODE_OFF && group_bias) {
		/* Group-change reset: a new pin starts clean.  Compared
		 * BEFORE last_group is overwritten below so the
		 * comparison sees the previous pin's group. */
		if (entry->group != child->last_group) {
			child->group_streak_len = 0;
			child->last_cov_at_streak = 0;
			child->group_fd_created_in_streak = 0;
		}
		/* Saturate at UINT_MAX to keep the predicate arithmetic
		 * defined even after pathological pin lengths -- a real
		 * pin will never reach UINT_MAX, but a saturating bump
		 * costs the same as an unguarded one on the hot path
		 * and is correct against the unsigned-subtraction guard
		 * the pin_stale predicate uses (streak_len -
		 * last_cov_at_streak). */
		if (child->group_streak_len != UINT_MAX)
			child->group_streak_len++;
		/* fd-warm bump: a pin holding live state (warm setup
		 * chains -- socket -> bind -> sendmsg, openat -> read ->
		 * close) is spared from release even when coverage-
		 * barren, because the produced object is the locality
		 * the group bias is really protecting.  Gated by the
		 * same retval-not-(-1) AND RET_FD condition the
		 * fd_created bump above uses so the warm signal stays
		 * symmetric with the leak-instrumentation signal.  No
		 * group bound check needed -- the bump tracks any fd
		 * produced inside the current pin, regardless of which
		 * group that pin is. */
		if (rec->retval != -1UL && entry->rettype == RET_FD &&
		    child->group_fd_created_in_streak != UINT_MAX)
			child->group_fd_created_in_streak++;
		/* Coverage watermark advance: tracks the most recent
		 * streak position at which the pin landed an edge.
		 * Productive group clusters (NET socket -> bind ->
		 * sendto, VFS openat -> read -> close) advance this on
		 * every yielding member so pin_stale never holds, and
		 * the pin is preserved; pure-getter pins (no edges,
		 * no transitions) leave it pinned at 0 so after
		 * MIN_STREAK + COV_WINDOW picks the pin goes stale. */
		if (found_local_coverage)
			child->last_cov_at_streak = child->group_streak_len;
	}

	/* Track the group for biasing.  WRITE LAST so the F-RSEQ
	 * group-change detection above can compare against the
	 * previous pin's group; reordering this above the F-RSEQ
	 * block would null out every reset. */
	if (group_bias)
		child->last_group = entry->group;
}

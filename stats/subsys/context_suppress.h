#ifndef _TRINITY_STATS_SUBSYS_CONTEXT_SUPPRESS_H
#define _TRINITY_STATS_SUBSYS_CONTEXT_SUPPRESS_H

#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * SHADOW_ONLY-mode context-regular suppression classifier telemetry
 * (strategy/strategy-frontier.c :: context_regular_suppressed_shadow).
 *
 * Partitions the picker on empirical per-syscall EPERM behaviour --
 * the classifier is data-gated (per_syscall_calls / per_syscall_errno
 * [EPERM] / [SUCCESS] / per_syscall_edges), NOT a curated exception
 * list -- a newly-productive syscall stops being regular_suppressed
 * on its own without any manual map edit.  Shared spare-lane
 * predicate (frontier_spare_lane_decide) is consumed at the site:
 * a syscall whose K-window ring is nonzero (or which recently
 * transitioned to a first CMP-insert / first SUCCESS) is spared
 * from the would_skip attribution even when its lifetime EPERM
 * rate clears the threshold.
 *
 * candidates                : cumulative pick-finalise bumps -- the
 *   set the classifier gets to peel from.  Matched to the cost_pool_
 *   selector_live_note cadence so the ratio against would_skip reads
 *   directly off the same denominator the cost row uses.
 * would_skip                : subset where the data-gated classifier
 *   says a live Path-A suppression would remove the pick.
 * spared_windowed           : subset spared because the K-window
 *   frontier-edge ring is nonzero (recently productive).
 * spared_arggen             : subset spared because a distinct CMP-
 *   insert landed or a first-success TRANSITION fired.
 * spared_objproducer        : subset spared because entry's ret_
 *   objtype != OBJ_NONE (coverage paid to downstream consumer).
 * would_skip_per_syscall[]  : per-nr breakdown of would_skip -- the
 *   headline SHADOW_ONLY diagnostic; top entries SHOULD be the
 *   measured EPERM hogs (fchown/chown/lchown/fchownat + cred family).
 *
 * Observability-only in this commit: NO live suppression wired.
 * COMBINED is reserved in the enum for the follow-up that flips the
 * gate live.
 *
 * The surrounding struct stats_s composes an instance of struct
 * context_suppress_stats as its "context_suppress" member.
 */
struct context_suppress_stats {
	unsigned long candidates;
	unsigned long would_skip;
	unsigned long spared_windowed;
	unsigned long spared_arggen;
	unsigned long spared_objproducer;
	unsigned long would_skip_per_syscall[MAX_NR_SYSCALL];
};

#endif	/* _TRINITY_STATS_SUBSYS_CONTEXT_SUPPRESS_H */

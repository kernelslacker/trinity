/*
 * Post-parse default derivation for the params cluster: max_children
 * cap arithmetic (derive_max_children_cap + binding_name) and the
 * clamp_default_*() helpers main() calls after parse_args() finalises
 * the raw operator input.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arg-len-semantics.h"
#include "bdevs.h"
#include "child.h"
#include "blob_mutator.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cmsg-richness.h"
#include "fd.h"
#include "kcov.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "reach-band.h"
#include "self_cgroup.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"	// progname, max_files_rlimit
#include "utils.h"

#include "kernel/hw_breakpoint.h"
#include "kernel/socket.h"

#include "internal.h"

/* ------------------------------------------------------------------ *
 * max_children cap derivation
 *
 * Ceilings on max_children to keep a typo (-C 999999999) from turning
 * into a host-level fork/allocation storm.  Three independent budgets:
 *
 *   (a) shared_regions[] capacity:  each child consumes
 *       SHARED_REGIONS_PER_CHILD slots in alloc_shared()'s static
 *       tracker, with SHARED_REGIONS_GLOBAL_RESERVE held back for
 *       fixed allocations (shm, syscall table, kcov, image segments,
 *       etc).
 *   (b) RLIMIT_NPROC - HOST_NPROC_RESERVE: leave headroom for the
 *       parent and the operator's surrounding processes.
 *   (c) RLIMIT_NOFILE - PARENT_NOFILE_RESERVE: parent opens one
 *       /proc/<pid>/stat fd per child plus its own ancillary fds.
 *
 * The derived cap is the smallest of those plus PROJECT_MAX_CHILDREN.
 * derive_max_children_cap() also reports which budget is binding so
 * the operator-facing error/warning can name the source.
 * ------------------------------------------------------------------ */

#define HOST_NPROC_RESERVE	32
#define PARENT_NOFILE_RESERVE	64
#define PROJECT_MAX_CHILDREN	16384

const char *binding_name(enum max_children_binding b)
{
	switch (b) {
	case BINDING_PROJECT_MAX:    return "project sanity limit";
	case BINDING_SHARED_REGIONS: return "shared_regions[] capacity";
	case BINDING_NPROC:          return "RLIMIT_NPROC";
	case BINDING_NOFILE:         return "RLIMIT_NOFILE";
	}
	return "?";
}

unsigned long derive_max_children_cap(enum max_children_binding *out_binding)
{
	unsigned long cap = PROJECT_MAX_CHILDREN;
	enum max_children_binding b = BINDING_PROJECT_MAX;
	unsigned long shared_cap;
	struct rlimit nproc;

	shared_cap = (MAX_SHARED_ALLOCS - SHARED_REGIONS_GLOBAL_RESERVE) /
		     SHARED_REGIONS_PER_CHILD;
	if (shared_cap < cap) {
		cap = shared_cap;
		b = BINDING_SHARED_REGIONS;
	}

	if (getrlimit(RLIMIT_NPROC, &nproc) == 0 &&
	    nproc.rlim_cur != RLIM_INFINITY) {
		unsigned long nproc_cap;

		if (nproc.rlim_cur > HOST_NPROC_RESERVE)
			nproc_cap = nproc.rlim_cur - HOST_NPROC_RESERVE;
		else
			nproc_cap = 0;
		if (nproc_cap < cap) {
			cap = nproc_cap;
			b = BINDING_NPROC;
		}
	}

	if (max_files_rlimit.rlim_cur != RLIM_INFINITY) {
		unsigned long nofile_cap;

		if (max_files_rlimit.rlim_cur > PARENT_NOFILE_RESERVE)
			nofile_cap = max_files_rlimit.rlim_cur - PARENT_NOFILE_RESERVE;
		else
			nofile_cap = 0;
		if (nofile_cap < cap) {
			cap = nofile_cap;
			b = BINDING_NOFILE;
		}
	}

	if (out_binding != NULL)
		*out_binding = b;
	return cap;
}

/*
 * Compute the default explorer-pool size when --explorer-children was not
 * passed.  The default is mode-aware: max_children/4 (25%) under
 * PICKER_BANDIT_UCB1 (for -C64 → 16 explorers, -C16 → 4, -C8 → 2, -C4
 * → 1), zero under every other picker mode.
 *
 * The explorer pool exists to provide a strategy-independent baseline
 * alongside the bandit's learned policy, with its coverage discoveries
 * recorded separately and excluded from the bandit's reward signal.
 * That role only makes sense when the bandit is the active picker --
 * under round-robin or any other deterministic picker the explorer
 * slots would silently divert 25% of the fleet to STRATEGY_RANDOM and
 * the active strategy would only actually run on 75% of children, which
 * contradicts what --strategy advertises.  Default to zero outside
 * bandit mode so non-bandit pickers run pure.
 *
 * The operator can still force a non-zero pool in any mode by passing
 * --explorer-children=N; that path is unconditional and only the upper
 * ceiling (max_children/2) is enforced -- more than half being
 * explorers would leave the bandit pool too small for UCB1 to
 * differentiate arms, and even in non-bandit modes the same imbalance
 * argument applies to the active strategy.
 *
 * Called from main() after clamp_default_max_children() so max_children
 * is final.  Mirrors the alt_op_children clamp pattern in trinity.c.
 */
/* Default-fill canary_slots when the operator did not pass
 * --canary-slots.  Called from main() after parse_args has finalised
 * alt_op_children so the derived value tracks the final pool size.
 * The auto-couple is min(alt_op_children, 2): zero when there is no
 * alt-op pool to carve from (skipping the noisy --canary-slots-vs-
 * --alt-op-children=0 warning on default runs), and the historical
 * default of 2 once the operator opts into an alt-op pool with at
 * least 2 slots.  An explicit --canary-slots=N is recorded in
 * user_specified_canary_slots and left untouched here -- the
 * downstream clamps in trinity.c handle range enforcement against
 * alt_op_children for both auto-derived and explicit values. */
void clamp_default_canary_slots(void)
{
	if (user_specified_canary_slots)
		return;

	canary_slots = (alt_op_children < 2) ? alt_op_children : 2;
}

/* Default-fill alt_op_children when the operator did not pass
 * --alt-op-children.  Without a non-zero default, canary_slots
 * auto-couples to zero, the canary queue stays dark, and the static
 * dormant_op_disabled[] vector hides the majority of alt ops from
 * ever being promoted.  Default to max(2, max_children/8): the floor
 * of 2 keeps the downstream canary_slots = min(alt_op_children, 2)
 * derivation at its historical cap, and the /8 scaling keeps the
 * alt-op reservation modest as the fleet grows.  An explicit
 * --alt-op-children=N (including =0) is recorded in
 * user_specified_alt_op_children and bypasses the auto-derive --
 * range enforcement against max_children still applies in
 * trinity.c. */
void clamp_default_alt_op_children(void)
{
	if (user_specified_alt_op_children)
		return;

	alt_op_children = (max_children / 8 < 2) ? 2 : max_children / 8;
}

void clamp_default_explorer_children(void)
{
	/* Explorer slots are reserved AFTER the dedicated alt-op slots
	 * (see init_child() in child.c), so the ceiling is computed
	 * against the slots that remain once alt_op_children has been
	 * carved off the front -- not against raw max_children, which
	 * would let the explorer range overlap the alt-op range and
	 * silently consume the random-explorer baseline. */
	unsigned int remaining = (max_children > alt_op_children) ?
				 max_children - alt_op_children : 0;
	unsigned int ceiling = remaining / 2;

	if (!user_specified_explorer_children) {
		if (picker_mode_arg == PICKER_BANDIT_UCB1)
			explorer_children = remaining / 4;
		/* else: leave explorer_children at its 0 init so the
		 * active strategy runs on every non-alt-op child slot. */
		return;
	}

	if (explorer_children > ceiling) {
		outputerr("warning: --explorer-children=%u exceeds (max_children-alt_op_children)/2 (%u); clamping to %u\n",
			  explorer_children, ceiling, ceiling);
		explorer_children = ceiling;
	}
}

void clamp_default_max_children(void)
{
	enum max_children_binding b;
	unsigned long cap;

	/* -C path validates against the cap inside parse_args; nothing to do. */
	if (user_specified_children != 0)
		return;

	cap = derive_max_children_cap(&b);
	if (cap == 0) {
		outputerr("cannot run trinity: %s leaves no budget for children\n",
			  binding_name(b));
		exit(EXIT_FAILURE);
	}
	if ((unsigned long)max_children > cap) {
		outputerr("warning: default max_children=%u (num_online_cpus*4) "
			  "exceeds %s cap of %lu; clamping\n",
			  max_children, binding_name(b), cap);
		max_children = (unsigned int)cap;
	}
}

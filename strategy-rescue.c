/*
 * Random-rescue classifier.  A "rescue" is a SR_PLATEAU_FORCE
 * intervention call (always STRATEGY_RANDOM) that lands new edges on
 * a syscall the picker had been ignoring; this module attributes
 * each rescue to a class so the orchestrator can amplify the most
 * productive intervention shape.  Split from strategy.c so the
 * classifier compiles independently of the picker / plateau / dump
 * translation units.
 */

#include "child.h"		/* struct childdata */
#include "cmp_hints.h"		/* cmp_hints_shm, cmp_hints_pool_safe_count */
#include "shm.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */

/*
 * RRC_COLD_SKIP threshold.  STRATEGY_HEURISTIC's kcov_syscall_cold_skip_pct
 * returns the per-syscall probability the heuristic picker rejects the
 * candidate on the cold-skip retry; 50 is the baseline the heuristic uses
 * for a freshly-cold syscall (see kcov.c).  A SR_PLATEAU_FORCE rescue
 * whose rec->nr scores at or above the baseline would have been skipped
 * by the heuristic at least half the time -- enough that the RANDOM
 * intervention is plausibly the only path that exercised it.
 */
#define RRC_COLD_SKIP_PCT 50U

const char *random_rescue_class_name(enum random_rescue_class c)
{
	switch (c) {
	case RRC_COLD_SKIP:		return "COLD_SKIP";
	case RRC_UNUSUAL_FD_PRODUCER:	return "UNUSUAL_FD_PRODUCER";
	case RRC_WRONG_TYPE_FD:		return "WRONG_TYPE_FD";
	case RRC_CMP_DERIVED:		return "CMP_DERIVED";
	case RRC_PERSONA_GATED:		return "PERSONA_GATED";
	case RRC_UNKNOWN:		return "UNKNOWN";
	case RRC_NR_CLASSES:		break;	/* sentinel */
	}
	return "?";
}

enum random_rescue_class classify_random_rescue(struct syscallrecord *rec,
						struct childdata *child,
						unsigned int cold_skip_pct_before)
{
	unsigned int curr;

	if (rec == NULL || child == NULL)
		return RRC_UNKNOWN;
	if (rec->nr >= MAX_NR_SYSCALL)
		return RRC_UNKNOWN;

	curr = (unsigned int)rec->nr;

	/* RRC_COLD_SKIP.  Heuristic picker would have rejected this nr at
	 * least half the time on the cold-skip retry path, so a RANDOM
	 * rescue that lands new edges on it is most plausibly recovering
	 * coverage the heuristic was filtering out.  The check runs against
	 * the same kcov_syscall_cold_skip_pct() the heuristic consults --
	 * but uses the caller's pre-kcov_collect snapshot, not a fresh
	 * read.  kcov_collect bumps last_edge_at[nr] on a new edge, which
	 * is exactly the case the rescue classifier fires on; a live read
	 * here would always see gap=0 and never return RRC_COLD_SKIP for
	 * the cold-syscall rescues this class exists to surface. */
	if (cold_skip_pct_before >= RRC_COLD_SKIP_PCT)
		return RRC_COLD_SKIP;

	/* RRC_CMP_DERIVED.  generate-args.c's ARG_OP / ARG_LIST /
	 * gen_undefined_arg paths roll a 1-in-16 cmp_hints_try_get on every
	 * call; if rec->nr has any hints in its pool, a learned constant
	 * may have carried this RANDOM call past a kernel validation check
	 * the structured pickers were not aware of.  Hint-pool occupancy is
	 * a soft signal (the per-call substitution probability is fixed and
	 * we have no per-call attribution), but a non-empty pool is the
	 * narrowest evidence available without adding per-call tracking. */
	if (cmp_hints_shm != NULL && curr < MAX_NR_SYSCALL &&
	    cmp_hints_pool_safe_count(&cmp_hints_shm->pools[curr][rec->do32bit ? 1 : 0]) > 0)
		return RRC_CMP_DERIVED;

	/* RRC_UNUSUAL_FD_PRODUCER / RRC_WRONG_TYPE_FD / RRC_PERSONA_GATED
	 * detection requires per-call fd-source tracking and persona
	 * attribution infrastructure that does not yet exist.  Rescues that
	 * land here fall through to UNKNOWN; the orchestrator's bias
	 * dispatch handles those classes for the future infrastructure to
	 * wire in without an enum reorder. */

	return RRC_UNKNOWN;
}

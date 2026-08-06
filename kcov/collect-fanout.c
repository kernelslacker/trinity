/*
 * kcov/collect-fanout.c — KCOV collection entry points that sit beside
 * (but outside) the hot kcov_collect() PC-walk in collect.c:
 *
 *   kcov_trace_pos()       — read-only snapshot of the trace-buffer
 *                            write position; safe inside an outer
 *                            bracket without perturbing dedup state.
 *   kcov_sample_new_edges() — read-only novelty probe over a slice of
 *                             trace_buf; advances a caller-held cursor.
 *   kcov_collect_cmp()     — CMP-record harvest dispatch: validates
 *                            the cmp trace buffer, then forwards into
 *                            cmp_hints_collect() and bandit_cmp_observe().
 *
 * All three are pure code-motion from collect.c; no logic has changed.
 * Declarations live in include/kcov-api.h.
 */

#include <stdbool.h>

#include "collect-internal.h"	/* kcov_canon_pc, pc_canon_to_edge */
#include "cmp_hints.h"		/* cmp_hints_collect */
#include "kcov-internal.h"	/* kcov_shm, kcov types, CMP constants */
#include "params.h"		/* kcov_trace_size */
#include "strategy.h"		/* bandit_cmp_observe */
#include "syscall.h"		/* MAX_NR_SYSCALL */

/*
 * Read-only snapshot of the child's current PC-trace write position.
 * Mirrors the count-load-and-cap sequence at the head of kcov_collect()
 * so callers get the same "how many PCs have landed so far" value the
 * collect path would see, but does not touch bucket_seen, dedup, or any
 * shm counter -- it is safe to call from inside an outer bracket
 * without perturbing the authoritative kcov_bracket_end harvest that
 * childop_edges_clean (and thus the child canary) reads.
 */
unsigned long kcov_trace_pos(struct kcov_child *kc)
{
	unsigned long count;

	if (kc == NULL || kc->trace_buf == NULL || !kc->active)
		return 0;
	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count >= (unsigned long)kcov_trace_size - 1)
		count = (unsigned long)kcov_trace_size - 1;
	return count;
}

/*
 * Read-only novelty probe over trace_buf[*cursor+1 .. trace_buf[0]].
 * Counts PCs whose canonicalised edge is currently unseen in
 * kcov_shm->bucket_seen[], then advances *cursor to the new trace end.
 * Intended for per-walk reward gates that live inside an outer
 * childop-attribution bracket: the outer kcov_bracket_end stays the
 * SOLE authoritative writer of bucket_seen, kc->dedup,
 * kc->current_generation, and kcov_shm->coverage.edges_found, so this probe
 * does not affect childop_edges_clean (the child canary signal) or
 * any dedup / generation state.  A brand-new edge that appears N
 * times in the sampled window contributes N to the returned count;
 * that hit-count weighting is accepted heuristic noise for the
 * reward path.
 */
unsigned long kcov_sample_new_edges(struct kcov_child *kc, unsigned long *cursor)
{
	unsigned long end, idx, start, n = 0;

	if (kc == NULL || cursor == NULL || kc->trace_buf == NULL || !kc->active)
		return 0;
	end = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (end >= (unsigned long)kcov_trace_size - 1)
		end = (unsigned long)kcov_trace_size - 1;
	start = *cursor;
	if (start > end)
		start = end;
	for (idx = start; idx < end; idx++) {
		unsigned long pc = __atomic_load_n(&kc->trace_buf[idx + 1],
						   __ATOMIC_RELAXED);
		unsigned int edge = pc_canon_to_edge(kcov_canon_pc(pc));

		if (__atomic_load_n(&kcov_shm->bucket_seen[edge],
				    __ATOMIC_RELAXED) == 0)
			n++;
	}
	*cursor = end;
	return n;
}

unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick)
{
	unsigned long count;
	unsigned long novel;

	if (kc == NULL || !kc->cmp_capable || kc->cmp_trace_buf == NULL)
		return 0;

	count = __atomic_load_n(&kc->cmp_trace_buf[0], __ATOMIC_RELAXED);
	if (count >= KCOV_CMP_RECORDS_MAX) {
		/* Kernel wanted to record more comparisons than the cmp
		 * buffer holds; the tail was dropped.  Mirrors the PC-side
		 * trace_truncated counter. */
		__atomic_fetch_add(&kcov_shm->cmp_records.cmp_trace_truncated, 1,
			__ATOMIC_RELAXED);
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][do32].cmp_trace_truncated,
				1, __ATOMIC_RELAXED);
		count = KCOV_CMP_RECORDS_MAX;
	}

	/* Reset the recover-on-EBADF attempt counter only when this call
	 * actually harvested cmp records.  Mirrors the PC-side reset in
	 * kcov_collect() -- a successful KCOV_ENABLE on cmp_fd that lands
	 * on a syscall harvesting zero records is a no-op recovery, and
	 * forgiving the attempt would let a close-race chain re-burn the
	 * budget every iteration without ever making progress. */
	if (count > 0 && kc->cmp_recovery_attempts != 0)
		kc->cmp_recovery_attempts = 0;

	if (count == 0)
		return 0;

	cmp_hints_collect(kc->cmp_trace_buf, nr, do32);
	novel = bandit_cmp_observe(kc->cmp_trace_buf, nr, do32,
				   is_explorer, strategy_at_pick);

	__atomic_fetch_add(&kcov_shm->cmp_records.cmp_records_collected, count,
		__ATOMIC_RELAXED);

	return novel;
}

/*
 * kcov/cold-skip.c — per-syscall cold-skip policy.
 *
 * Computes the probability (0..90%) with which the dispatcher should
 * skip a given syscall nr on a given call attempt because the syscall
 * has stopped contributing new coverage.  Two tiers:
 *
 *   saturation cap  — zero total edges after KCOV_SAT_CAP_CALLS
 *                     attempts, or calls/edge ratio past KCOV_SAT_CAP_RATIO
 *                     → hard 90% skip regardless of gap;
 *   graduated ramp  — 50% base plus 10 pp per KCOV_COLD_THRESHOLD-
 *                     sized step since the last new-edge call, capped
 *                     at 90% so even the deadest syscall gets one
 *                     attempt in ~10 (kernel state can change).
 *
 * Factored out of collect.c so the cold-skip policy is auditable and
 * testable independently of the hot PC-walk machinery.
 */

#include <stdbool.h>

#include "kcov-internal.h"	/* kcov_shm, per_syscall_*_total, constants */
#include "syscall.h"		/* MAX_NR_SYSCALL */

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr)
{
	unsigned long edges, calls, edges_total, calls_total, gap;
	unsigned int pct;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	/* Fold warm-loaded priors into the per-syscall view so the
	 * saturation cap fires on cross-session evidence the cold-skip
	 * path otherwise has to re-accumulate from scratch every run.
	 * The _prior arrays are frozen at warm-start (see kcov.h) so a
	 * plain read is sufficient -- no atomic needed. */
	edges = per_syscall_edges_total(nr);
	calls = per_syscall_calls_total(nr);
	edges_total = edges + per_syscall_edges_prior_total(nr);
	calls_total = calls + per_syscall_calls_prior_total(nr);

	/* Saturation cap: confirmed dead-weight slot, short-circuit the
	 * graduated path below.  See KCOV_SAT_CAP_CALLS / RATIO comment
	 * in include/kcov.h for the two-branch productivity test. */
	if (edges_total == 0) {
		if (calls_total >= KCOV_SAT_CAP_CALLS)
			return KCOV_SAT_CAP_SKIP_PCT;
	} else if (calls_total / edges_total >= KCOV_SAT_CAP_RATIO) {
		return KCOV_SAT_CAP_SKIP_PCT;
	}

	if (edges == 0) {
		/* Never produced an edge in THIS run.  Until this syscall has
		 * had KCOV_COLD_THRESHOLD attempts of its own, leave it alone —
		 * total_calls grows from every other syscall too, so basing
		 * the cutoff on total_calls would prematurely retire any
		 * syscall that the dispatch loop happens to under-pick.
		 * Once it has clearly had a fair shot, skip aggressively. */
		gap = calls;
	} else {
		unsigned long total, last;

		total = __atomic_load_n(&kcov_shm->coverage.total_calls,
			__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->per_syscall.last_edge_at[nr],
			__ATOMIC_RELAXED);
		if (total <= last)
			return 0;
		gap = total - last;
	}

	if (gap <= KCOV_COLD_THRESHOLD)
		return 0;

	/* Graduated skip: the further past the threshold, the more we skip.
	 * Formula is a 50% base plus 10 percentage points per additional
	 * KCOV_COLD_THRESHOLD-sized step, capped at 90% so even the deadest
	 * syscall still gets called once every ~10 attempts in case kernel
	 * state changes underneath us. */
	pct = 50 + (unsigned int)((gap / KCOV_COLD_THRESHOLD) * 10);
	if (pct > 90)
		pct = 90;
	return pct;
}

bool kcov_syscall_is_cold(unsigned int nr)
{
	return kcov_syscall_cold_skip_pct(nr) > 0;
}

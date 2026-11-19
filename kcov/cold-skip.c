/*
 * kcov/cold-skip.c — per-syscall cold-skip policy.
 *
 * kcov_syscall_cold_skip_pct() returns the probability (0..95%) that the
 * dispatcher skips a syscall nr on this attempt because it has stopped
 * contributing new coverage: a hard saturation cap (KCOV_SAT_CAP_SKIP_PCT)
 * for confirmed dead weight, otherwise a 50..90% ramp graded by the gap
 * since its last new edge.  The counters are the picked ABI's: a biarch
 * build's two tables give one number to different syscalls.
 */

#include <stdbool.h>

#include "kcov-internal.h"	/* kcov_shm, per_syscall_*_abi, constants */
#include "syscall.h"		/* MAX_NR_SYSCALL */

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr, bool do32)
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
	edges = per_syscall_edges_abi(nr, do32);
	calls = per_syscall_calls_abi(nr, do32);
	edges_total = edges + kcov_shm->per_syscall.per_syscall_edges_prior[nr][do32];
	calls_total = calls + kcov_shm->per_syscall.per_syscall_calls_prior[nr][do32];

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
	 * KCOV_COLD_THRESHOLD-sized step, capped at 90% so a syscall on the
	 * ramp still gets called once every ~10 attempts in case kernel
	 * state changes underneath us. */
	pct = 50 + (unsigned int)((gap / KCOV_COLD_THRESHOLD) * 10);
	if (pct > 90)
		pct = 90;
	return pct;
}

bool kcov_syscall_is_cold(unsigned int nr, bool do32)
{
	return kcov_syscall_cold_skip_pct(nr, do32) > 0;
}

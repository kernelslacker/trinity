/*
 * kcov/collect-fanout.c — kcov_collect_cmp(), the CMP-record harvest
 * dispatch that sits beside (but outside) the hot kcov_collect()
 * PC-walk in collect.c: it validates the cmp trace buffer, then
 * forwards into cmp_hints_collect() and bandit_cmp_observe().
 * Declared in include/kcov-api.h.
 */

#include <stdbool.h>

#include "cmp_hints.h"		/* cmp_hints_collect */
#include "kcov-internal.h"	/* kcov_shm, kcov types, CMP constants */
#include "strategy.h"		/* bandit_cmp_observe */
#include "syscall.h"		/* MAX_NR_SYSCALL */

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


#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * Childop vs random-syscall effort split.
 *
 * Three independent splits between CHILD_OP_SYSCALL (the random-syscall
 * fast path) and all other child_op_types (childop recipes):
 *
 *   walltime   -- cumulative ns spent inside op_fn for each side.
 *                 Source-of-truth for "where is the child loop
 *                 actually spending time".
 *   syscalls   -- random_syscall-mediated syscalls dispatched while
 *                 the per-child in_childop flag was set vs clear.
 *                 Childops that call libc/raw syscall() directly do
 *                 not flow through the call-complete enqueue and are
 *                 not counted here; the walltime metric covers them.
 *   iterations -- per-op_fn dispatch counts: childop_invocations[]
 *                 summed over op != CHILD_OP_SYSCALL vs the parallel
 *                 random_syscall_dispatches counter for the
 *                 CHILD_OP_SYSCALL path.
 *
 * Emitted as one human stat_row line and a single childop_split JSON
 * object so a grep-and-jq reader can audit raw numerators + denominators
 * alongside the rendered percentages.  Cumulative since the run started
 * -- the surrounding periodic_counter_rates_dump already supplies a
 * windowed view via per-dump deltas if the operator wants rate-of-rate
 * trends later.
 *
 * A pct_thousandths helper avoids dragging floating point into the parent
 * stats-dump path while preserving one decimal place of resolution; both
 * sides round to the same scale so the two percentages always sum to
 * 100.0% (within rounding) when the denominator is non-zero.
 */
static unsigned long pct_thousandths(unsigned long num, unsigned long denom)
{
	if (denom == 0)
		return 0;
	/* num * 100000 overflows unsigned long once num approaches ~1.8e14,
	 * which the cumulative childop_walltime_ns numerator reaches on a
	 * sustained run.  Shed low bits from both operands until the multiply
	 * (plus the denom/2 rounding term) can no longer overflow; the ratio
	 * is preserved and the helper only needs 0.1% resolution, so the
	 * dropped bits are immaterial.  num <= denom here, so gating on
	 * ULONG_MAX / 100001 leaves headroom for the rounding add. */
	while (denom > ULONG_MAX / 100001UL) {
		num >>= 1;
		denom >>= 1;
	}
	return (num * 100000UL + denom / 2) / denom;
}

void childop_split_dump(void)
{
	unsigned long wt_childop = __atomic_load_n(
		&shm->stats.childop.walltime_ns, __ATOMIC_RELAXED);
	unsigned long wt_syscall = __atomic_load_n(
		&shm->stats.syscall_walltime_ns, __ATOMIC_RELAXED);
	unsigned long sc_childop = __atomic_load_n(
		&shm->stats.syscalls_in_childops, __ATOMIC_RELAXED);
	unsigned long sc_random = __atomic_load_n(
		&shm->stats.syscalls_random, __ATOMIC_RELAXED);
	unsigned long it_random = __atomic_load_n(
		&shm->stats.random_syscall_dispatches, __ATOMIC_RELAXED);
	unsigned long it_childop = 0;
	unsigned long wt_total, sc_total, it_total;
	unsigned long wt_pct, sc_pct, it_pct;
	unsigned int op;

	/* Iteration denominator for the childop side: sum the existing
	 * childop_invocations[] over op != CHILD_OP_SYSCALL.  CHILD_OP_SYSCALL
	 * is gated out of that array by child_process()'s is_alt_op check,
	 * so the random_syscall_dispatches counter above is its separate
	 * parallel denominator. */
	for (op = 1; op < NR_CHILD_OP_TYPES; op++) {
		it_childop += __atomic_load_n(
			&shm->stats.childop.invocations[op],
			__ATOMIC_RELAXED);
	}

	wt_total = wt_childop + wt_syscall;
	sc_total = sc_childop + sc_random;
	it_total = it_childop + it_random;

	/* Silently skip the block if no dispatch has happened yet so a
	 * fresh-start dump doesn't print three "0/0 = 0.0%" rows. */
	if (wt_total == 0 && sc_total == 0 && it_total == 0)
		return;

	wt_pct = pct_thousandths(wt_childop, wt_total);
	sc_pct = pct_thousandths(sc_childop, sc_total);
	it_pct = pct_thousandths(it_childop, it_total);

	stats_log_write(
		"childop_split: walltime childop=%lu.%01lu%% (%lu/%lu ns)  "
		"syscalls childop=%lu.%01lu%% (%lu/%lu)  "
		"iterations childop=%lu.%01lu%% (%lu/%lu)\n",
		wt_pct / 1000, (wt_pct / 100) % 10, wt_childop, wt_total,
		sc_pct / 1000, (sc_pct / 100) % 10, sc_childop, sc_total,
		it_pct / 1000, (it_pct / 100) % 10, it_childop, it_total);

	stats_log_write(
		"childop_split_json: {"
		"\"walltime_ns\":{\"childop\":%lu,\"syscall\":%lu,\"pct_childop_x10\":%lu},"
		"\"syscalls\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu},"
		"\"iterations\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu}"
		"}\n",
		wt_childop, wt_syscall, wt_pct / 100,
		sc_childop, sc_random, sc_pct / 100,
		it_childop, it_random, it_pct / 100);
}

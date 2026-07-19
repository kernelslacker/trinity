#ifndef _TRINITY_STATS_SUBSYS_QRTR_BIND_RACE_H
#define _TRINITY_STATS_SUBSYS_QRTR_BIND_RACE_H

struct qrtr_bind_race_stats {
	/* qrtr_bind_race childop counters */
	unsigned long runs;			/* total qrtr_bind_race invocations */
	unsigned long setup_failed;		/* AF_QRTR socket() probe latch fired */
	unsigned long iter;			/* outer-loop iterations entered */
	unsigned long fork_failed;		/* fork() of a bind worker failed */
	unsigned long spawn_pair_ok;		/* both bind workers spawned for this round */
	unsigned long sibling_reaped_ok;		/* worker exited normally and was reaped */
	unsigned long sibling_crashed;		/* worker killed by signal (SEGV/BUS/KILL) -- forensic hint */
	/* In-worker setup-fail: bumped from the forked bind-child when its
	 * own socket(AF_QRTR) or getsockname() returns -1 before the bind
	 * attempt.  Distinct from qrtr_bind_race_setup_failed, which only
	 * fires from the parent-side probe latch and is invisible to a worker
	 * that crashes during its own per-iter setup phase.  Without this
	 * counter an op whose workers all fail setup looks identical to one
	 * that succeeded silently. */
	unsigned long setup_fail;
};

#endif /* _TRINITY_STATS_SUBSYS_QRTR_BIND_RACE_H */

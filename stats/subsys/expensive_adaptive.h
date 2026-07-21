#ifndef _TRINITY_STATS_SUBSYS_EXPENSIVE_ADAPTIVE_H
#define _TRINITY_STATS_SUBSYS_EXPENSIVE_ADAPTIVE_H

/*
 * Observability for the adaptive expensive-syscall accept gate
 * (random-syscall.c :: expensive_accept()).  Bumped on the adaptive
 * compute path (mode != OFF, kcov_shm != NULL, nr in range).  The
 * OFF / NULL-kcov / out-of-range early-return path MUST NOT bump
 * these -- byte-identity contract documented on expensive_accept().
 *
 *  samples         : total computations -- one bump per adaptive-
 *                    compute entry under SHADOW_ONLY or COMBINED.
 *                    Denominator for the dispositions below.
 *  extra_accepts   : mass of accepts the sub-floor n_adaptive rate
 *                    contributes over the static 1/FLOOR baseline.
 *                    Under COMBINED bumps on per-call sub-floor
 *                    accepts; under SHADOW_ONLY counts opportunities
 *                    (the accept stream is bit-identical to OFF for
 *                    a given seed).
 *  demotes         : per-call bumps from the stale-decay branch --
 *                    total_calls -- last_edge_at[nr] pushed
 *                    n_adaptive back toward the floor.  Pair against
 *                    extra_accepts to read the net granted mass.
 *
 * The surrounding struct stats_s composes an instance of struct
 * expensive_adaptive_stats as its "expensive_adaptive" member.
 */
struct expensive_adaptive_stats {
	unsigned long samples;
	unsigned long extra_accepts;
	unsigned long demotes;
};

#endif	/* _TRINITY_STATS_SUBSYS_EXPENSIVE_ADAPTIVE_H */

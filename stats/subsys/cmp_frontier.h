#ifndef _TRINITY_STATS_SUBSYS_CMP_FRONTIER_H
#define _TRINITY_STATS_SUBSYS_CMP_FRONTIER_H

/*
 * Observability for the CMP-weighted frontier picker arm
 * (--cmp-frontier=off|shadow-only|combined).  Bumped from the
 * silent-regime accept gate in set_syscall_nr_coverage_frontier()
 * on the non-OFF compute path; the OFF early-return MUST NOT bump
 * any of these -- byte-identity contract documented in
 * include/cmp-frontier.h.
 *
 *  samples       : per-call samples denominator (one bump per
 *                  silent-regime entry past the mode OFF gate).
 *  would_route   : subset where the plateau classifier reads
 *                  CMP_RISING_PC_FLAT -- the would-be COMBINED
 *                  population.  Under SHADOW_ONLY this is the
 *                  projected route volume; under COMBINED it
 *                  equals live_routes (mode-gated, not condition-
 *                  gated, lock-step under COMBINED).
 *  live_routes   : subset where mode is COMBINED AND the plateau
 *                  gate fired -- w was actually replaced with
 *                  cmp_frontier_weight() for the live accept roll.
 *                  Stays zero under SHADOW_ONLY by construction.
 *
 * Each addend is 1UL; overflow needs ~2^64 samples.  The
 * surrounding struct stats_s composes an instance of struct
 * cmp_frontier_stats as its "cmp_frontier" member.
 */
struct cmp_frontier_stats {
	unsigned long samples;
	unsigned long would_route;
	unsigned long live_routes;
};

#endif	/* _TRINITY_STATS_SUBSYS_CMP_FRONTIER_H */

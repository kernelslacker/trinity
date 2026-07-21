#ifndef _TRINITY_STATS_SUBSYS_AF_ALG_PROBE_H
#define _TRINITY_STATS_SUBSYS_AF_ALG_PROBE_H

/*
 * af_alg_template_probe childop counters.  One-shot enumeration of
 * which AF_ALG crypto template names this kernel accepts via bind(2);
 * per-template accept/reject lives in the parallel accept[]/reject[]
 * arrays, indexed by the probe_table[] order in
 * childops/net/af-alg-template-probe.c.  "done" is the fleet-wide
 * CAS election latch (0 -> 1) that elects a single child to run the
 * probe -- not a counter, but lives here so it shares the shm
 * mapping and survives across childdata recycles.
 *
 * The template-count sizing (NR_AF_ALG_PROBE_TEMPLATES = 12) is
 * exported so the flat descriptor tables that fan out per-slot JSON
 * keys can keep referring to it by name.
 *
 * The surrounding struct stats_s composes an instance of struct
 * af_alg_probe_stats as its "af_alg_probe" member.
 */
#define NR_AF_ALG_PROBE_TEMPLATES	12

struct af_alg_probe_stats {
	unsigned int  done;		/* 0 -> 1 CAS election latch */
	unsigned long runs;		/* probe winners (should == 1 fleet-wide) */
	unsigned long unsupported;	/* socket(AF_ALG) returned EAFNOSUPPORT */
	unsigned long accept_total;	/* sum of per-template binds that returned 0 */
	unsigned long reject_total;	/* sum of per-template binds that returned -1 */
	unsigned long accept[NR_AF_ALG_PROBE_TEMPLATES];
	unsigned long reject[NR_AF_ALG_PROBE_TEMPLATES];
};

#endif	/* _TRINITY_STATS_SUBSYS_AF_ALG_PROBE_H */

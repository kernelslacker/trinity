#ifndef _TRINITY_STATS_SUBSYS_XFRM_AH_ESN_H
#define _TRINITY_STATS_SUBSYS_XFRM_AH_ESN_H

struct xfrm_ah_esn_stats {
	unsigned long setup_ok;		/* AH+ESN+async-algo NEWSA accepted */
	unsigned long setup_fail;	/* AH+ESN+async-algo NEWSA rejected */
	unsigned long async_runs;	/* AH+ESN+async-algo sub-mode invocations */
	unsigned long delsa_races;	/* AH+ESN+async-algo DELSA accepted (race window) */
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_AH_ESN_H */

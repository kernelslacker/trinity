#ifndef _TRINITY_STATS_SUBSYS_IPVS_SYSCTL_WRITER_H
#define _TRINITY_STATS_SUBSYS_IPVS_SYSCTL_WRITER_H

struct ipvs_sysctl_writer_stats {
	/* ipvs_sysctl_writer childop counters */
	unsigned long runs;			/* total ipvs_sysctl_writer invocations */
	unsigned long writes_ok;		/* sysctl write returned >0 */
	unsigned long writes_failed;		/* open or write failed (kernel rejected payload) */
	unsigned long unsupported_latched;	/* unshare/open ENOENT latched op off */
	unsigned long burn_iters;		/* short-lived TCP connect/close iters into the in-test virtual service */
};

#endif /* _TRINITY_STATS_SUBSYS_IPVS_SYSCTL_WRITER_H */

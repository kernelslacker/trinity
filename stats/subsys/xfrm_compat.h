#ifndef _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H
#define _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H

struct xfrm_compat_stats {
	unsigned long sweep_runs;	/* xfrm_compat_msg_sweep sub-mode invocations */
	unsigned long sends_ok;		/* sweep sendto returned >= 0 */
	unsigned long sends_failed;	/* sweep sendto returned < 0 */
	unsigned long replies_seen;	/* sweep recv returned > 0 */
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_COMPAT_H */

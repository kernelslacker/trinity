#ifndef _TRINITY_STATS_SUBSYS_IPMR_GETROUTE_PKTINFO_H
#define _TRINITY_STATS_SUBSYS_IPMR_GETROUTE_PKTINFO_H

/*
 * ipmr_getroute_pktinfo childop counters.  Bespoke (non-category) RAW
 * group.  All bumps RELAXED on shm->stats.  The surrounding struct
 * stats_s composes an instance of struct ipmr_getroute_pktinfo_stats as
 * its "ipmr_getroute_pktinfo" member.
 */
struct ipmr_getroute_pktinfo_stats {
	unsigned long iters;		/* per-iteration RTM_GETROUTE query issues */
	unsigned long eperm;		/* MRT_INIT returned -EPERM (CAP_NET_ADMIN gate) */
	unsigned long pktinfo_ok;	/* recvmsg harvest with IP_PKTINFO cmsg succeeded */
	unsigned long getroute_ok;	/* RTM_GETROUTE send returned no error */
};

#endif	/* _TRINITY_STATS_SUBSYS_IPMR_GETROUTE_PKTINFO_H */

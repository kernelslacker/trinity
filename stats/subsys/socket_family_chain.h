#ifndef _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_CHAIN_H
#define _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_CHAIN_H

struct socket_family_chain_stats {
	/* socket_family_chain childop counters */
	unsigned long runs;			/* total invocations */
	unsigned long completed;		/* >=1 inner cycle reached recv */
	unsigned long failed;		/* every inner cycle bailed early */
	unsigned long authencesn_attempts;	/* authencesn name forced */
	unsigned long splice_attempts;	/* splice path replaced sendmsg data leg */
};

#endif /* _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_CHAIN_H */

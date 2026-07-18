#ifndef _TRINITY_STATS_SUBSYS_IP6GRE_LAPB_H
#define _TRINITY_STATS_SUBSYS_IP6GRE_LAPB_H

struct ip6gre_lapb_stats {
	/* ip6gre_bond_lapb_stack childop counters */
	unsigned long runs;				/* total ip6gre_bond_lapb_stack invocations */
	unsigned long setup_failed;			/* unshare/NEWLINK/SETLINK/lapb-resolve rejected */
	unsigned long flag_toggles;			/* RTM_SETLINK IFF_UP/IFF_DOWN messages issued on the lapb dev */
};

#endif /* _TRINITY_STATS_SUBSYS_IP6GRE_LAPB_H */

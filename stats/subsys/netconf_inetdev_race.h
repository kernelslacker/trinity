#ifndef _TRINITY_STATS_SUBSYS_NETCONF_INETDEV_RACE_H
#define _TRINITY_STATS_SUBSYS_NETCONF_INETDEV_RACE_H

struct netconf_inetdev_race_stats {
	/* netconf_getdevconf_inetdev_teardown_race childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* userns / veth / addr setup failed */
	unsigned long getconf_v4_ok;	/* RTM_GETNETCONF AF_INET returned response */
	unsigned long getconf_v6_ok;	/* RTM_GETNETCONF AF_INET6 returned response */
	unsigned long dellink_ok;	/* RTM_DELLINK ack 0 from Worker A */
	unsigned long completed_ok;	/* iteration reached reap cleanly */
};

#endif /* _TRINITY_STATS_SUBSYS_NETCONF_INETDEV_RACE_H */

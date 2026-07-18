#ifndef _TRINITY_STATS_SUBSYS_NETLINK_MONITOR_RACE_H
#define _TRINITY_STATS_SUBSYS_NETLINK_MONITOR_RACE_H

struct netlink_monitor_race_stats {
	/* netlink_monitor_race childop counters */
	unsigned long runs;	/* total netlink_monitor_race invocations */
	unsigned long setup_failed; /* unshare(CLONE_NEWNET) or socket open/bind failed */
	unsigned long mon_open;	/* monitor NETLINK_ROUTE socket bound with groups */
	unsigned long mut_open;	/* mutator NETLINK_ROUTE socket opened */
	unsigned long mut_op_ok;	/* RTM_NEW/DEL LINK/ADDR ack==0 from mutator */
	unsigned long recv_drained; /* recvmsg(MSG_DONTWAIT) returned >0 on monitor */
	unsigned long group_drop;	/* NETLINK_DROP_MEMBERSHIP setsockopt accepted */
	unsigned long group_add;	/* NETLINK_ADD_MEMBERSHIP setsockopt accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_NETLINK_MONITOR_RACE_H */

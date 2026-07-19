#ifndef _TRINITY_STATS_SUBSYS_TC_LIVE_TRAFFIC_H
#define _TRINITY_STATS_SUBSYS_TC_LIVE_TRAFFIC_H

struct tc_live_traffic_stats {
	/* tc_live_traffic childop counters */
	unsigned long runs;		/* total tc_live_traffic invocations */
	unsigned long setup_failed;	/* userns / rtnl open / grandchild fork latched */
	unsigned long qdisc_ok;		/* clsact install on the A veth end accepted */
	unsigned long qdisc_fail;	/* clsact install on the A veth end rejected */
	unsigned long filter_ok;	/* initial matchall+gact/mirred filter install accepted */
	unsigned long filter_fail;	/* initial matchall+gact/mirred filter install rejected */
	unsigned long filter_del_ok;	/* mid-burst RTM_DELTFILTER on the running slot accepted */
	unsigned long filter_replace_ok;	/* mid-burst RTM_NEWTFILTER at a new prio slot accepted (races tcf_classify) */
	unsigned long packet_sent_ok;	/* live UDP sendto through the classified ingress path returned >0 */
	unsigned long link_del_ok;	/* RTM_DELLINK on the A veth end at teardown accepted */
	unsigned long bpf_load_ok;	/* cls_bpf BPF_PROG_LOAD (SCHED_CLS) accepted */
	unsigned long xdp_load_ok;	/* BPF_PROG_LOAD (BPF_PROG_TYPE_XDP) for the XDP-pass sub-chain accepted */
	unsigned long xdp_attach_ok;	/* RTM_NEWLINK IFLA_XDP attach on the A veth end accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_TC_LIVE_TRAFFIC_H */

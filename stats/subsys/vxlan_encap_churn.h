#ifndef _TRINITY_STATS_SUBSYS_VXLAN_ENCAP_CHURN_H
#define _TRINITY_STATS_SUBSYS_VXLAN_ENCAP_CHURN_H

struct vxlan_encap_churn_stats {
	/* vxlan_encap_churn childop counters */
	unsigned long runs;		/* total vxlan_encap_churn invocations */
	unsigned long setup_failed;	/* unshare(CLONE_NEWNET) / rtnl_open / all-kinds latched */
	unsigned long link_create_ok;	/* RTM_NEWLINK type=vxlan/gre/geneve accepted */
	unsigned long fdb_add_ok;	/* RTM_NEWNEIGH NTF_SELF accepted (vxlan only) */
	unsigned long link_up_ok;	/* RTM_NEWLINK setlink IFF_UP accepted */
	unsigned long packet_sent_ok;	/* sendto on AF_PACKET raw bound to tunnel returned >0 */
	unsigned long link_del_ok;	/* RTM_DELLINK accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_VXLAN_ENCAP_CHURN_H */

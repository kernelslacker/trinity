#ifndef _TRINITY_STATS_SUBSYS_VETH_ASYMMETRIC_XDP_H
#define _TRINITY_STATS_SUBSYS_VETH_ASYMMETRIC_XDP_H

struct veth_asymmetric_xdp_stats {
	/* veth_asymmetric_xdp childop counters */
	unsigned long iters;				/* total veth_asymmetric_xdp invocations */
	unsigned long eperm;				/* unshare/NEWLINK rejected with EPERM */
	unsigned long unsupported;			/* veth or XDP latched off (separate latches inside the op) */
	unsigned long pair_ok;			/* RTM_NEWLINK created an asymmetric-queue veth pair */
	unsigned long xdp_attach_ok;			/* RTM_NEWLINK + IFLA_XDP attached the prog (SKB mode) */
	unsigned long send_ok;
};

#endif /* _TRINITY_STATS_SUBSYS_VETH_ASYMMETRIC_XDP_H */

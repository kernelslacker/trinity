#ifndef _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H
#define _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H

struct afxdp_churn_stats {
	/* afxdp_churn childop counters */
	unsigned long runs;				/* total afxdp_churn invocations */
	unsigned long setup_failed;			/* socket / mmap / setsockopt / cap-gate latched */
	unsigned long umem_reg_ok;			/* setsockopt(XDP_UMEM_REG) accepted */
	unsigned long rings_setup_ok;		/* all four XDP_*_RING setsockopts accepted */
	unsigned long prog_load_ok;			/* bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_XDP) accepted */
	unsigned long map_create_ok;		/* bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_XSKMAP) accepted */
	unsigned long map_update_ok;		/* bpf(BPF_MAP_UPDATE_ELEM) installed xsk_fd at xskmap key */
	unsigned long bind_ok;			/* bind(XDP_USE_NEED_WAKEUP, lo, qid=0) accepted */
	unsigned long link_attach_ok;		/* bpf(BPF_LINK_CREATE, BPF_XDP) attached prog to lo */
	unsigned long netlink_attach_ok;		/* RTM_NEWLINK + IFLA_XDP_FD fallback attached prog to lo */
	unsigned long attach_failed;		/* both attach paths failed -- RACE A window stays cold */
	unsigned long send_ok;			/* sendto() kick on bound xsk returned >=0 (or EAGAIN/ENOBUFS/EBUSY) */
	unsigned long recv_ok;			/* getsockopt(XDP_STATISTICS) on bound xsk succeeded */
	unsigned long map_delete_ok;		/* bpf(BPF_MAP_DELETE_ELEM) on bound xskmap key (race target) */
	unsigned long munmap_race_ok;		/* munmap of FILL ring while bound (race target) */
	unsigned long xsg_iters;			/* per-iter knob enable_sg=1: USE_SG umem + XDP_USE_SG bind + chained TX desc */
	unsigned long tx_metadata_iters;		/* per-iter knob enable_tx_md=1: tx_metadata_len umem + XDP_TX_METADATA stamp */
	unsigned long tun_bind_iters;			/* per-iter knob: bound to tun (IFF_NAPI|IFF_NAPI_FRAGS) instead of lo */
	unsigned long tunnel_bind_iters;		/* per-iter knob: bound to NNM-created gre/ipip/sit device (xsk_generic_xmit → tunnel ndo_start_xmit) */
	unsigned long bind_failed;				/* any bind() error (EOPNOTSUPP, EINVAL, ...); broad telemetry sentinel */
	unsigned long xsg_bind_failed;			/* UMEM_REG with XDP_UMEM_FLAGS_USE_SG rejected; latched off, retried without */
	unsigned long tx_md_bind_failed;		/* UMEM_REG with tx_metadata_len rejected; latched off, retried without */
	unsigned long tailroom_iters;			/* tailroom-probe TX desc sent (near-full-chunk len + AF_PACKET tap) */

	/* Per-arm entry tally for dead-arm detection.  Bumped at the top
	 * of the XDP_COPY bind arm (the memset+sxdp+bind block in
	 * afxdp_iter_bind()) before the bind() retry loop, independent
	 * of bind() success or failure.  When arm_entered_bind == 0 and
	 * runs > 0 the entire bind+attach+io phase was never reached
	 * (e.g. setup always bailed before bind was attempted); when
	 * arm_entered_bind > 0 and bind_ok == 0 the arm was reached but
	 * always failed (the class of bug fixed by adding XDP_COPY to the
	 * bind flags). */
	unsigned long arm_entered_bind; /* XDP_COPY bind arm entered */
};

#endif /* _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H */

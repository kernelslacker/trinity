#ifndef _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H
#define _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H

struct afxdp_churn_stats {
	/* afxdp_churn childop counters */
	unsigned long runs;				/* total afxdp_churn invocations */
	unsigned long runs_stubbed;			/* invocations from #else stub (XDP headers absent; not a real childop run) */
	unsigned long setup_failed;			/* socket / mmap / setsockopt / cap-gate latched */
	unsigned long setup_failed_unsupported;		/* ns_unsupported_afxdp latch fired — feature absent in this netns */
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

	/* Runtime cap-denied probe counter (access-after-cap-drop class).
	 *
	 * setup_failed_cap_denied is incremented in two places:
	 *   (a) in afxdp_iter_setup_umem() when socket(AF_XDP) returns
	 *       EPERM or EACCES -- these indicate the fuzz user lacks
	 *       CAP_NET_RAW or is blocked by seccomp/LSM, as distinct from
	 *       EAFNOSUPPORT/EPROTONOSUPPORT which means AF_XDP is absent
	 *       from the kernel build;
	 *   (b) in the early-bail path of afxdp_churn() when
	 *       ns_cap_denied_afxdp is already latched.
	 *
	 * When setup_failed_cap_denied == runs the arm is cap-dead:
	 * CONFIG_XDP_SOCKETS is compiled in (socket() finds the protocol)
	 * but the fuzz user's capability set prevents socket creation.
	 * dump_stats_dead_arm_check() emits RUNTIME_DEAD_ARM for this case,
	 * distinct from UNSUPPORTED_ARM (AF_XDP not in kernel). */
	unsigned long setup_failed_cap_denied;

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

	/* arm_effective_bind: incremented when the bind arm produces
	 * detectable output (bind_ok and at least one I/O or stats
	 * operation completed).  A run where arm_entered_bind > 0 but
	 * arm_effective_bind == 0 means the arm entered but produced no
	 * observable output -- typically a uapi-value-wrong or a silent
	 * kernel-side rejection past the bind() call itself. */
	unsigned long arm_effective_bind; /* XDP_COPY bind arm produced output */
};

#endif /* _TRINITY_STATS_SUBSYS_AFXDP_CHURN_H */

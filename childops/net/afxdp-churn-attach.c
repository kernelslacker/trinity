/*
 * afxdp-churn-attach: bind + XDP-program-attach helpers for afxdp_churn.
 *
 * Owns the phases that select the netdev, bind the xsk to it, and
 * attach the loaded XDP redirect program.  Split from the setup-side
 * (UMEM/ring/BPF) so the multiple attach paths (BPF_LINK_CREATE +
 * netlink IFLA_XDP fallback) and the tun-open + queue selection sit
 * together in one translation unit.
 *
 *   afxdp_iter_bind         — pick tunN-with-NAPI_FRAGS or lo, bind()
 *                             the xsk with XDP_USE_NEED_WAKEUP (+ SG
 *                             where the per-iter knob fires);
 *   afxdp_iter_attach_prog  — BPF_LINK_CREATE first (auto-detach on
 *                             link fd close), then RTM_NEWLINK +
 *                             IFLA_XDP_FD in SKB mode as fallback.
 *
 * xdp_netlink_set_fd is non-static because xsk_teardown() in
 * afxdp-churn-teardown.c also invokes it (with prog_fd == -1) to
 * reverse a netlink-fallback attach.
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include "afxdp-churn-internal.h"

/*
 * Open /dev/net/tun and create a tunN device with IFF_NAPI_FRAGS so the
 * rx path uses the napi-frag (non-linear skb) shape — exactly the
 * IFF_TX_SKB_NO_LINEAR netdev class that d73a9a63f9f7 missed when
 * binding sw-csum TX metadata.  Returns fd on success and writes the
 * kernel-assigned name into @name_out (IFNAMSIZ buffer); -1 on failure.
 * Caller must keep the fd open while the xsk is bound to the device.
 * The kernel-assigned name is also recorded into the NAME_KIND_NETDEV
 * pool so later cross-syscall name draws can reference this live tunN
 * instead of always synthesising a fresh-random name that the kernel
 * has no entry for and that misses the name-keyed lookup branches.
 */
static int tun_open_napi_frags(char *name_out)
{
	struct ifreq ifr;
	size_t nlen;
	int fd;

	fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS;
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return -1;
	}
	memcpy(name_out, ifr.ifr_name, IFNAMSIZ);
	nlen = strnlen(name_out, IFNAMSIZ);
	if (nlen > 0)
		name_pool_record(NAME_KIND_NETDEV, name_out, nlen);
	return fd;
}

/*
 * BPF_LINK_CREATE attach for XDP.  Returns the link fd on success.
 * Auto-detaches on close(link_fd), so teardown is just close().
 */
static int xdp_link_attach(int prog_fd, unsigned int ifindex)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd        = (uint32_t)prog_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type    = BPF_XDP;

	return sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
}

/*
 * Open a NETLINK_ROUTE socket for the XDP attach fallback.  Bound,
 * RCVTIMEO 1s so a wedged rtnl can't outlive the SIGALRM(1s) cap.
 * Returns 0 on success and stamps @ctx; -1 on failure.
 */
static int xdp_netlink_open(struct nl_ctx *ctx)
{
	struct nl_open_opts opts;

	memset(&opts, 0, sizeof(opts));
	opts.proto         = NETLINK_ROUTE;
	opts.recv_timeo_s  = 1;
	/* Set caller_op explicitly so the netlink transport credits the
	 * AF_XDP churn op directly rather than relying on the implicit
	 * this_child()->op_type fallback in nl_open / nl_close. */
	opts.caller_op     = CHILD_OP_AFXDP_CHURN;
	return nl_open(ctx, &opts);
}

/*
 * Send an RTM_NEWLINK with a nested IFLA_XDP { IFLA_XDP_FD,
 * IFLA_XDP_FLAGS=SKB_MODE } attribute to attach (prog_fd >= 0) or
 * detach (prog_fd == -1) the XDP program on @ifindex.  Returns 0 on
 * success, kernel errno (negated) on failure, -EIO on transport error.
 */
int xdp_netlink_set_fd(struct nl_ctx *rtnl, unsigned int ifindex,
		       int prog_fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, nest_off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = (int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	nest_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_XDP | NLA_F_NESTED);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FD,
		      &fdval, sizeof(fdval));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	nla_nest_end(buf, nest_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Phase 4: pick the bind target ifindex (tun-with-NAPI_FRAGS when the
 * per-iter knob fires and the tunN is reachable, otherwise lo) and run
 * bind() with bounded EAGAIN/EBUSY retry.  Clears *want_tun if the tun
 * path fell through to lo so downstream stats reflect what actually
 * bound.  Returns -1 only when no ifindex is reachable; bind() failure
 * leaves st->bound == false and the iteration continues into races.
 */
int afxdp_iter_bind(struct xsk_state *st, bool want_sg,
		    bool *want_tun, char *tun_name,
		    unsigned int *target_ifindex_out)
{
	struct sockaddr_xdp sxdp;
	unsigned int target_ifindex = 0;
	unsigned int retry;
	int rc;
	/* Accumulate non-netlink raw syscall count for the direct-syscall
	 * reporter.  The netlink open / close path (xdp_netlink_open +
	 * nl_close via xsk_teardown) credits its own calls under
	 * CHILD_OP_AFXDP_CHURN via opts.caller_op; only count the
	 * non-netlink sites here: tun open/ioctl/close and bind(). */
	unsigned long dc = 0;

	/* Pick bind target: tun-with-NAPI_FRAGS when the per-iter knob fired
	 * (and tun is reachable), else lo.  d73a9a63f9f7's bug surface is
	 * the IFF_TX_SKB_NO_LINEAR class of netdev — tun in NAPI mode
	 * exposes that path; lo does not. */
	if (*want_tun) {
		st->tun_fd = tun_open_napi_frags(tun_name);
		/* tun_open_napi_frags issues open() and on success ioctl();
		 * credit two syscalls on success, one on failed open. */
		dc += (st->tun_fd >= 0) ? 2 : 1;
		if (st->tun_fd >= 0)
			target_ifindex = if_nametoindex(tun_name);
		if (target_ifindex == 0) {
			if (st->tun_fd >= 0) {
				close(st->tun_fd);
				st->tun_fd = -1;
				dc++;			/* close() */
			}
			*want_tun = false;
		}
	}
	if (target_ifindex == 0)
		target_ifindex = if_nametoindex("lo");
	if (target_ifindex == 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		/* Publish any tun-phase syscalls credited before the bail. */
		if (dc) {
			struct childdata *tc = this_child();
			const enum child_op_type op = tc ? tc->op_type :
				NR_CHILD_OP_TYPES;
			if ((int)op >= 0 && op < NR_CHILD_OP_TYPES)
				childop_direct_syscalls_add(op, dc);
		}
		return -1;
	}

	memset(&sxdp, 0, sizeof(sxdp));
	sxdp.sxdp_family       = AF_XDP;
	sxdp.sxdp_flags        = XDP_USE_NEED_WAKEUP |
				 (want_sg ? XDP_USE_SG : 0);
	sxdp.sxdp_ifindex      = target_ifindex;
	sxdp.sxdp_queue_id     = 0;
	sxdp.sxdp_shared_umem_fd = 0;

	rc = -1;
	for (retry = 0; retry < AFXDP_RETRY_CAP; retry++) {
		rc = bind(st->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
		dc++;				/* bind() */
		if (rc == 0 || !afxdp_retryable(errno))
			break;
	}
	if (rc == 0) {
		st->bound = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn.bind_ok,
				   1, __ATOMIC_RELAXED);
		if (*want_tun)
			__atomic_add_fetch(&shm->stats.afxdp_churn.tun_bind_iters,
					   1, __ATOMIC_RELAXED);
	} else if (want_sg && errno == EINVAL) {
		/* Bind-time rejection of XDP_USE_SG (e.g. driver path).
		 * Latch so subsequent iters don't ask for it again. */
		ns_unsupported_xdp_sg = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn.xsg_bind_failed,
				   1, __ATOMIC_RELAXED);
	}

	*target_ifindex_out = target_ifindex;
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type :
			NR_CHILD_OP_TYPES;
		if ((int)op >= 0 && op < NR_CHILD_OP_TYPES && dc)
			childop_direct_syscalls_add(op, dc);
	}
	return 0;
}

/*
 * Phase 5: attach the loaded XDP redirect program to the bound ifindex
 * so xdp_do_redirect() walks the XSKMAP -- without an attached prog,
 * the RACE A map-delete below has no concurrent reader and never opens
 * the CVE-2024-50115 window.  BPF_LINK_CREATE first (auto-detach on
 * link fd close), then RTM_NEWLINK + IFLA_XDP_FD in SKB mode on older
 * kernels or when another iter_one already won the slot.
 */
void afxdp_iter_attach_prog(struct xsk_state *st,
			    unsigned int target_ifindex)
{
	if (!st->bound || st->prog_fd < 0)
		return;

	st->xdp_link_fd = xdp_link_attach(st->prog_fd, target_ifindex);
	/* xdp_link_attach wraps sys_bpf(BPF_LINK_CREATE); credit one
	 * non-netlink syscall unconditionally (always attempted when
	 * st->bound && st->prog_fd >= 0).  The netlink fallback path
	 * (xdp_netlink_open + xdp_netlink_set_fd) credits its own calls
	 * to CHILD_OP_AFXDP_CHURN via opts.caller_op in xdp_netlink_open. */
	unsigned long dc = 1;
	if (st->xdp_link_fd >= 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.link_attach_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		int rc_open = xdp_netlink_open(&st->rtnl);

		if (rc_open == 0 &&
		    xdp_netlink_set_fd(&st->rtnl, target_ifindex,
				       st->prog_fd) == 0) {
			st->nl_attached_ifindex = target_ifindex;
			__atomic_add_fetch(&shm->stats.afxdp_churn.netlink_attach_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.afxdp_churn.attach_failed,
					   1, __ATOMIC_RELAXED);
		}
	}
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type :
			NR_CHILD_OP_TYPES;
		if ((int)op >= 0 && op < NR_CHILD_OP_TYPES)
			childop_direct_syscalls_add(op, dc);
	}
}

#endif /* __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>) */

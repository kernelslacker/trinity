/*
 * nat_t_churn - coherent IPsec NAT-Traversal pipeline walk (RFC 3948).
 *
 * Other XFRM ops touch the NAT-T pieces only incidentally; none
 * assemble the coherent triple this op does: a UDP socket primed with
 * UDP_ENCAP_ESPINUDP, a matching XFRM SA whose XFRMA_ENCAP agrees with
 * the socket, and actual ESP-in-UDP bytes arriving on that port.  That
 * triple drives esp4_input / xfrm_input: demux UDP-encapsulated ESP,
 * validate sport/dport against the SA's xfrm_encap_tmpl, step the
 * replay window.  The ESP frame is intentionally undecryptable -- the
 * point is the demux + validate + replay-step path on a coherent SA,
 * not a successful decrypt.
 *
 * Per invocation (inside a private user+net namespace via
 * userns_run_in_ns; _exit reaps the SA/socket/netns): bring lo up, open
 * NETLINK_XFRM, XFRM_MSG_NEWSA, prime a UDP socket with UDP_ENCAP,
 * sendto a garbage ESP-in-UDP frame to :4500, then XFRM_MSG_DELSA (the
 * explicit delete keeps the SAD from growing unbounded).
 *
 * Rotates per invocation across mode (transport/tunnel), ESN on/off
 * with seq_hi wrap edges (0, 1, 0xfffffffe, 0xffffffff), encap type,
 * auth/crypt algs (incl. a deliberately mistyped name to walk the
 * crypto lookup error path), replay window, and random SPI.
 *
 * Latch: userns -EPERM (or NETLINK_XFRM EPROTONOSUPPORT) gates the op
 * off -- the wrapper bit persists for the child's life; the
 * in-grandchild bit dies on _exit() so a CONFIG-absent kernel re-probes
 * once per invocation.  Self-bounding: one SA cycle/invocation, all I/O
 * MSG_DONTWAIT or SO_RCVTIMEO, loopback-only in the private netns,
 * SIGALRM(1s) cap + stall-threshold 40.  Header-gated on <linux/xfrm.h>.
 */

#include "nat-t-churn-internal.h"

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct nat_t_churn_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any links,
 * addrs, xfrm SAs, UDP encap bindings and sockets left behind are
 * reaped by the kernel along with the namespace.  Return value is
 * ignored by the helper.
 */
static int nat_t_churn_in_ns(void *arg)
{
	struct nat_t_churn_ctx *cctx = (struct nat_t_churn_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_XFRM,
		.recv_timeo_s = NAT_T_RECV_TIMEO_S,
	};
	int udp = -1;
	__be32 spi;
	__u8 mode;
	bool esn;
	enum nat_t_encap_choice encap_choice;
	__u8 replay_window;
	const struct nat_t_alg *auth, *crypt;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (!lo_brought_up) {
		bring_lo_up();
		lo_brought_up = true;
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Sibling branch: half of invocations drive the AF_INET6 /
	 * UDPv6-encap-ESP error path (xfrm6 dst-leak fix in upstream
	 * bc0fcb9823cd).  Latched off if the kernel lacks ipv6 / xfrm6
	 * so we don't burn syscalls on an unsupported config. */
	if (!ns_unsupported_xfrm6 && ONE_IN(2)) {
		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		nat_t_churn_v6();
		return 0;
	}

	if (nl_open(&ctx, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT ||
		    errno == EPERM) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			warn_once_unsupported("NETLINK_XFRM open", errno);
		}
		__atomic_add_fetch(&shm->stats.nat_t_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/* nat_keepalive error-path sub-branch: ~1 in 4 iterations swap
	 * the baseline single-SA data-plane cycle for a tight NEWSA -->
	 * DELSA on an SA whose XFRMA_SA_DIR / XFRMA_ENCAP /
	 * XFRMA_NAT_KEEPALIVE_INTERVAL combination flips between the
	 * accepted OUT-arms-worker path and the two rejected shapes
	 * (IN + interval; encap-less + interval).  Rejected shapes drive
	 * the construct-error teardown; accepted shapes race the delete
	 * against the per-net worker arming.  Same netns / netlink fd as
	 * the baseline branch -- no extra socket cost. */
	if (ONE_IN(4)) {
		nat_keepalive_err_cycle(&ctx);
		goto out;
	}

	mode  = (rand32() & 1U) ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
	esn   = (rand32() & 1U) != 0;
	replay_window = nat_t_replay_windows[rnd_modulo_u32(nat_t_replay_windows_n)];
	auth  = &nat_t_auth_algs[rnd_modulo_u32(nat_t_auth_algs_n)];
	crypt = &nat_t_crypt_algs[rnd_modulo_u32(nat_t_crypt_algs_n)];
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);

	/* encap omission is only meaningful in tunnel mode -- in
	 * transport mode the SA without an encap attribute is a plain
	 * ESP transport-mode SA already covered by xfrm_churn.  Coin
	 * flip on tunnel-mode iterations decides whether to omit. */
	if (mode == XFRM_MODE_TUNNEL && (rand32() & 3U) == 0)
		encap_choice = NAT_T_ENCAP_OMIT;
	else if ((rand32() & 1U) == 0)
		encap_choice = NAT_T_ENCAP_NON_IKE;
	else
		encap_choice = NAT_T_ENCAP_ESPINUDP;

	rc = nat_t_build_newsa(&ctx, spi, mode, esn, encap_choice,
			 replay_window, auth, crypt);
	if (rc != 0)
		goto out;
	__atomic_add_fetch(&shm->stats.nat_t_churn.sa_added,
			   1, __ATOMIC_RELAXED);

	udp = nat_t_open_encap_udp();
	if (udp >= 0) {
		__u32 seq = ++g_iter;

		if (nat_t_send_esp_in_udp(udp, spi, seq))
			__atomic_add_fetch(&shm->stats.nat_t_churn.frames_sent,
					   1, __ATOMIC_RELAXED);
		nat_t_maybe_drain_recv(udp);
	}

	if (nat_t_build_delsa(&ctx, spi) == 0)
		__atomic_add_fetch(&shm->stats.nat_t_churn.sa_deleted,
				   1, __ATOMIC_RELAXED);

out:
	if (udp >= 0)
		close(udp);
	nl_close(&ctx);

	return 0;
}

bool nat_t_churn(struct childdata *child)
{
	struct nat_t_churn_ctx cctx = { .child = child };
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nat_t_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_nat_t)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, nat_t_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported("userns_run_in_ns(CLONE_NEWNET)", EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.nat_t_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

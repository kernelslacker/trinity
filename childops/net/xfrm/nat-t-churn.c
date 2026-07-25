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
 * Build XFRM_MSG_NEWSA carrying the full attribute set for one
 * NAT-T-shaped SA.  spi / mode / encap_choice are captured by the
 * caller for the matching DELSA and for the encap port the UDP socket
 * targets.
 */
static int build_newsa(struct nl_ctx *ctx, __be32 spi, __u8 mode, bool esn,
		       enum nat_t_encap_choice encap_choice,
		       __u8 replay_window,
		       const struct nat_t_alg *auth,
		       const struct nat_t_alg *crypt)
{
	unsigned char buf[NAT_T_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	nat_t_fill_selector(&sa->sel);
	sa->id.daddr.a4   = NAT_T_DADDR_BE;
	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_ESP;
	sa->saddr.a4      = NAT_T_SADDR_BE;
	nat_t_fill_lifetime(&sa->lft);
	sa->reqid         = 1;
	sa->family        = AF_INET;
	sa->mode          = mode;
	sa->replay_window = replay_window;
	sa->flags         = esn ? XFRM_STATE_ESN : 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = nat_t_append_auth_trunc(buf, off, sizeof(buf), auth);
	if (!off)
		return -EIO;

	off = nat_t_append_crypt(buf, off, sizeof(buf), crypt);
	if (!off)
		return -EIO;

	if (encap_choice != NAT_T_ENCAP_OMIT) {
		__u16 et = (encap_choice == NAT_T_ENCAP_NON_IKE)
				? UDP_ENCAP_ESPINUDP_NON_IKE
				: UDP_ENCAP_ESPINUDP;
		off = nat_t_append_encap(buf, off, sizeof(buf), et);
		if (!off)
			return -EIO;
	}

	if (esn) {
		off = nat_t_append_replay_esn(buf, off, sizeof(buf),
					replay_window ? replay_window : 32U,
					nat_t_pick_seq_hi());
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_delsa(struct nl_ctx *ctx, __be32 spi)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	uid->daddr.a4 = NAT_T_DADDR_BE;
	uid->spi      = spi;
	uid->family   = AF_INET;
	uid->proto    = IPPROTO_ESP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/* Keepalive interval rotation (seconds).  0 disables the keepalive
 * worker entirely; non-zero + XFRMA_SA_DIR=OUT + XFRMA_ENCAP arms the
 * per-net keepalive worker on the SA at construct time.  Small values
 * exercise the worker's arming/rearming path; a large value exercises
 * the same setup arithmetic without ever actually firing during the
 * op's 1s lifetime. */
static const __u32 nat_keepalive_intervals[] = {
	1U, 2U, 5U, 60U, 0xffffU,
};

/*
 * Build XFRM_MSG_NEWSA carrying the standard NAT-T attribute set plus
 * XFRMA_SA_DIR and XFRMA_NAT_KEEPALIVE_INTERVAL.  The kernel accepts
 * the SA only when the (direction, encap-present, interval) triple is
 * mutually consistent -- OUT + encap + non-zero interval arms the
 * per-net keepalive worker; IN with a non-zero interval or an
 * encap-less SA with a non-zero interval is rejected by
 * xfrm_nat_keepalive_init after the SA shell has already been
 * partly-constructed, driving the construct-error teardown path.
 *
 * Every combination is emitted intentionally so the rejection paths
 * get roughly equal cycles alongside the accepted (OUT + encap +
 * interval) baseline.
 */
static int build_newsa_keepalive(struct nl_ctx *ctx, __be32 spi, __u8 mode,
				 enum nat_t_encap_choice encap_choice,
				 __u8 sa_dir, __u32 interval,
				 const struct nat_t_alg *auth,
				 const struct nat_t_alg *crypt)
{
	unsigned char buf[NAT_T_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	nat_t_fill_selector(&sa->sel);
	sa->id.daddr.a4   = NAT_T_DADDR_BE;
	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_ESP;
	sa->saddr.a4      = NAT_T_SADDR_BE;
	nat_t_fill_lifetime(&sa->lft);
	sa->reqid         = 1;
	sa->family        = AF_INET;
	sa->mode          = mode;
	/* Kernel rejects OUT SAs whose replay_window is non-zero once
	 * XFRMA_SA_DIR is present; pair the two so the accepted path
	 * doesn't fall over on that unrelated check. */
	sa->replay_window = (sa_dir == XFRM_SA_DIR_OUT) ? 0 : 32;
	sa->flags         = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = nat_t_append_auth_trunc(buf, off, sizeof(buf), auth);
	if (!off)
		return -EIO;

	off = nat_t_append_crypt(buf, off, sizeof(buf), crypt);
	if (!off)
		return -EIO;

	if (encap_choice != NAT_T_ENCAP_OMIT) {
		__u16 et = (encap_choice == NAT_T_ENCAP_NON_IKE)
				? UDP_ENCAP_ESPINUDP_NON_IKE
				: UDP_ENCAP_ESPINUDP;
		off = nat_t_append_encap(buf, off, sizeof(buf), et);
		if (!off)
			return -EIO;
	}

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, sa_dir);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  XFRMA_NAT_KEEPALIVE_INTERVAL, interval);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Drive one full nat_keepalive setup->teardown cycle over one SA:
 * pick a (direction, encap-present, interval) triple, dispatch NEWSA
 * (accepted or rejected depending on the triple's coherence), then
 * DELSA on the same SPI so a successful install runs the teardown side
 * of xfrm_nat_keepalive_fini and a failing install has already walked
 * the construct-error cleanup path.  Consistent-triple iterations
 * (OUT + encap + interval>0) additionally short-race the worker
 * arming with the DELSA so the delete lands while the worker's per-net
 * accounting is still transient.
 */
static void nat_keepalive_err_cycle(struct nl_ctx *ctx)
{
	__be32 spi;
	__u8 mode, sa_dir;
	__u32 interval;
	enum nat_t_encap_choice encap_choice;
	const struct nat_t_alg *auth, *crypt;
	int rc;

	mode  = (rand32() & 1U) ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
	auth  = &nat_t_auth_algs[rnd_modulo_u32(nat_t_auth_algs_n)];
	crypt = &nat_t_crypt_algs[rnd_modulo_u32(nat_t_crypt_algs_n)];
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);

	/* Rotate every triple corner deliberately -- the point of this
	 * cycle is to exercise both the arming path and the two error
	 * shapes (IN + interval; no-encap + interval), not to bias
	 * toward one. */
	sa_dir       = (rand32() & 1U) ? XFRM_SA_DIR_OUT : XFRM_SA_DIR_IN;
	interval     = ONE_IN(3) ? 0U : RAND_ARRAY(nat_keepalive_intervals);
	encap_choice = ONE_IN(3) ? NAT_T_ENCAP_OMIT
				 : ((rand32() & 1U) ? NAT_T_ENCAP_NON_IKE
						    : NAT_T_ENCAP_ESPINUDP);

	rc = build_newsa_keepalive(ctx, spi, mode, encap_choice, sa_dir,
				   interval, auth, crypt);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nat_t_churn.sa_added,
				   1, __ATOMIC_RELAXED);

	if (build_delsa(ctx, spi) == 0)
		__atomic_add_fetch(&shm->stats.nat_t_churn.sa_deleted,
				   1, __ATOMIC_RELAXED);
}

/*
 * Open a UDP socket bound to (127.0.0.1, NAT_T_ENCAP_PORT) and prime
 * it with UDP_ENCAP_ESPINUDP so the kernel installs the encap demux
 * callback.  Returns the fd on success, -1 on failure.  Bind on the
 * fixed port can fail with EADDRINUSE if a sibling iteration in this
 * netns hasn't fully torn down yet -- caller treats that as a soft
 * failure for the iteration.
 */
static int open_encap_udp(void)
{
	struct sockaddr_in src;
	int udp;
	int encap_type = UDP_ENCAP_ESPINUDP;

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (udp < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			warn_once_unsupported("AF_INET socket", errno);
		return -1;
	}

	memset(&src, 0, sizeof(src));
	src.sin_family      = AF_INET;
	src.sin_addr.s_addr = NAT_T_SADDR_BE;
	src.sin_port        = htons(NAT_T_ENCAP_PORT);
	if (bind(udp, (struct sockaddr *)&src, sizeof(src)) < 0) {
		close(udp);
		return -1;
	}

	if (setsockopt(udp, SOL_UDP, UDP_ENCAP, &encap_type,
		       sizeof(encap_type)) < 0) {
		close(udp);
		return -1;
	}

	return udp;
}

/*
 * Send one ESP-in-UDP frame to (127.0.0.1, NAT_T_ENCAP_PORT).  Frame
 * layout: SPI (matches the SA), sequence number (iteration counter),
 * then NAT_T_INNER_PAYLOAD_LEN bytes of garbage standing in for
 * ciphertext + ICV.  The frame is intentionally undecryptable; the
 * point is to drive the kernel's udp_encap_rcv -> xfrm_input demux +
 * authenticate path, not to land a successful decrypt.
 */
static bool send_esp_in_udp(int udp, __be32 spi, __u32 seq)
{
	struct sockaddr_in dst;
	unsigned char frame[8 + NAT_T_INNER_PAYLOAD_LEN];
	__be32 *hdr = (__be32 *)frame;

	hdr[0] = spi;
	hdr[1] = htonl(seq);
	generate_rand_bytes(frame + 8, NAT_T_INNER_PAYLOAD_LEN);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = NAT_T_DADDR_BE;
	dst.sin_port        = htons(NAT_T_ENCAP_PORT);

	return sendto(udp, frame, sizeof(frame), MSG_DONTWAIT,
		      (struct sockaddr *)&dst, sizeof(dst)) > 0;
}

static void maybe_drain_recv(int udp)
{
	unsigned char rbuf[256];

	if ((rand32() & 3U) != 0)
		return;
	(void)recv(udp, rbuf, sizeof(rbuf), MSG_DONTWAIT);
}

/*
 * v6 sibling of build_newsa: same attribute set, but the selector /
 * template / id daddrs are 2001:db8::dead and the family is AF_INET6,
 * so the kernel installs an xfrm6 SA whose ESP-encap output path runs
 * through esp6_output rather than esp4_output.  Pure-add helper -- the
 * IPv4 build_newsa is left untouched.
 */
static int build_newsa6(struct nl_ctx *ctx, __be32 spi, __u8 mode, bool esn,
			enum nat_t_encap_choice encap_choice,
			__u8 replay_window,
			const struct nat_t_alg *auth,
			const struct nat_t_alg *crypt)
{
	unsigned char buf[NAT_T_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	memset(&sa->sel, 0, sizeof(sa->sel));
	memcpy(sa->sel.saddr.a6, nat_t_v6_addr, sizeof(sa->sel.saddr.a6));
	memcpy(sa->sel.daddr.a6, nat_t_v6_addr, sizeof(sa->sel.daddr.a6));
	sa->sel.family      = AF_INET6;
	sa->sel.prefixlen_s = 128;
	sa->sel.prefixlen_d = 128;
	sa->sel.proto       = IPPROTO_UDP;

	memcpy(sa->id.daddr.a6, nat_t_v6_addr, sizeof(sa->id.daddr.a6));
	sa->id.spi   = spi;
	sa->id.proto = IPPROTO_ESP;
	memcpy(sa->saddr.a6, nat_t_v6_addr, sizeof(sa->saddr.a6));
	nat_t_fill_lifetime(&sa->lft);
	sa->reqid         = NAT_T_V6_REQID;
	sa->family        = AF_INET6;
	sa->mode          = mode;
	sa->replay_window = replay_window;
	sa->flags         = esn ? XFRM_STATE_ESN : 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = nat_t_append_auth_trunc(buf, off, sizeof(buf), auth);
	if (!off)
		return -EIO;

	off = nat_t_append_crypt(buf, off, sizeof(buf), crypt);
	if (!off)
		return -EIO;

	if (encap_choice != NAT_T_ENCAP_OMIT) {
		__u16 et = (encap_choice == NAT_T_ENCAP_NON_IKE)
				? UDP_ENCAP_ESPINUDP_NON_IKE
				: UDP_ENCAP_ESPINUDP;
		off = nat_t_append_encap(buf, off, sizeof(buf), et);
		if (!off)
			return -EIO;
	}

	if (esn) {
		off = nat_t_append_replay_esn(buf, off, sizeof(buf),
					replay_window ? replay_window : 32U,
					nat_t_pick_seq_hi());
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_delsa6(struct nl_ctx *ctx, __be32 spi)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	memcpy(uid->daddr.a6, nat_t_v6_addr, sizeof(uid->daddr.a6));
	uid->spi    = spi;
	uid->family = AF_INET6;
	uid->proto  = IPPROTO_ESP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Open an AF_INET6 / SOCK_DGRAM / IPPROTO_UDP socket, bind to
 * (in6addr_any, port 0) so the kernel picks an ephemeral port, and
 * prime it with UDP_ENCAP_ESPINUDP[_NON_IKE].  This is the IPv6 sibling
 * of open_encap_udp().  The setsockopt is what installs the encap
 * callback on the udp6 sock and is the trigger that makes a subsequent
 * sendto() walk through the UDPv6-encap-ESP output path -- which on an
 * unreachable v6 destination hits the xfrm6 dst error-return path the
 * upstream commit fixed.
 */
static int open_encap_udp6(void)
{
	struct sockaddr_in6 src;
	int udp;
	int encap_type = ONE_IN(2)
			? UDP_ENCAP_ESPINUDP_NON_IKE
			: UDP_ENCAP_ESPINUDP;

	udp = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (udp < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			if (!ns_unsupported_xfrm6) {
				ns_unsupported_xfrm6 = true;
				outputerr("nat_t_churn: AF_INET6 socket failed (errno=%d), latching unsupported_xfrm6\n",
					  errno);
			}
		}
		return -1;
	}

	memset(&src, 0, sizeof(src));
	src.sin6_family = AF_INET6;
	src.sin6_addr   = in6addr_any;
	src.sin6_port   = 0;
	if (bind(udp, (struct sockaddr *)&src, sizeof(src)) < 0) {
		close(udp);
		return -1;
	}

	if (setsockopt(udp, SOL_UDP, UDP_ENCAP, &encap_type,
		       sizeof(encap_type)) < 0) {
		if (errno == EOPNOTSUPP) {
			if (!ns_unsupported_xfrm6) {
				ns_unsupported_xfrm6 = true;
				outputerr("nat_t_churn: UDP_ENCAP setsockopt v6 failed (errno=%d), latching unsupported_xfrm6\n",
					  errno);
			}
		}
		close(udp);
		return -1;
	}

	return udp;
}

static long nat_t_ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

/*
 * Drive one full IPv6 / UDPv6-encap-ESP error-path cycle:
 *
 *   1. Install an xfrm v6 SA via XFRM_MSG_NEWSA (AF_INET6 family,
 *      IPPROTO_ESP, fake reqid, sel/template addr in 2001:db8::/32).
 *      Bounded retry on transient EAGAIN/EBUSY/ENOMEM.
 *   2. Open AF_INET6 / SOCK_DGRAM / IPPROTO_UDP socket bound to
 *      (in6addr_any, port 0) and prime it with UDP_ENCAP_ESPINUDP or
 *      UDP_ENCAP_ESPINUDP_NON_IKE (rolled per invocation).
 *   3. BUDGETED+JITTER sendto() burst targeting 2001:db8::dead port
 *      4500 -- the unreachable v6 dest that drives the kernel's
 *      xfrm_lookup -> esp6_output -> error-return path.  Bounded by
 *      both an iteration cap and a 200 ms wall-clock cap.
 *   4. Mid-flight XFRM_MSG_DELSA on the same (daddr, spi) tuple --
 *      fired roughly halfway through the sendto burst so the DELSA
 *      races the in-flight ESP6 output / error-return.
 *   5. Final cleanup DELSA if the mid-flight one didn't fire.
 *   6. Close UDP socket; close netlink socket.
 */
static void nat_t_churn_v6(void)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_XFRM,
		.recv_timeo_s = NAT_T_RECV_TIMEO_S,
	};
	int udp = -1;
	__be32 spi = 0;
	__u8 mode;
	bool esn;
	enum nat_t_encap_choice encap_choice;
	__u8 replay_window;
	const struct nat_t_alg *auth, *crypt;
	int rc = -EIO;
	unsigned int retries;
	unsigned int sends, s;
	bool delsa_fired = false;
	bool sa_installed = false;
	struct timespec t0;

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_setup_fail,
				   1, __ATOMIC_RELAXED);
		return;
	}

	mode  = (rand32() & 1U) ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
	esn   = (rand32() & 1U) != 0;
	replay_window = nat_t_replay_windows[rnd_modulo_u32(nat_t_replay_windows_n)];
	auth  = &nat_t_auth_algs[rnd_modulo_u32(nat_t_auth_algs_n)];
	crypt = &nat_t_crypt_algs[rnd_modulo_u32(nat_t_crypt_algs_n)];

	if (mode == XFRM_MODE_TUNNEL && (rand32() & 3U) == 0)
		encap_choice = NAT_T_ENCAP_OMIT;
	else if ((rand32() & 1U) == 0)
		encap_choice = NAT_T_ENCAP_NON_IKE;
	else
		encap_choice = NAT_T_ENCAP_ESPINUDP;

	for (retries = 0; retries < NAT_T_XFRM6_RETRY_CAP; retries++) {
		spi = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
		rc = build_newsa6(&ctx, spi, mode, esn, encap_choice,
				  replay_window, auth, crypt);
		if (rc == 0) {
			sa_installed = true;
			break;
		}
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -EPROTONOSUPPORT) {
			if (!ns_unsupported_xfrm6) {
				ns_unsupported_xfrm6 = true;
				outputerr("nat_t_churn: xfrm6 NEWSA rejected (rc=%d), latching unsupported_xfrm6\n",
					  rc);
			}
			__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_setup_fail,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		if (rc != -EAGAIN && rc != -EBUSY && rc != -ENOMEM)
			break;
	}

	if (!sa_installed) {
		__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_setup_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	udp = open_encap_udp6();
	if (udp < 0) {
		__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_setup_fail,
				   1, __ATOMIC_RELAXED);
		goto delsa;
	}

	__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_setup_ok,
			   1, __ATOMIC_RELAXED);

	{
		struct sockaddr_in6 dst;
		unsigned char frame[8 + NAT_T_INNER_PAYLOAD_LEN];
		__be32 *hdr = (__be32 *)frame;

		memset(&dst, 0, sizeof(dst));
		dst.sin6_family = AF_INET6;
		memcpy(&dst.sin6_addr, nat_t_v6_addr, sizeof(dst.sin6_addr));
		dst.sin6_port   = htons(NAT_T_ENCAP_PORT);

		hdr[0] = spi;
		/* Fill the inner payload once.  xfrm6's esp6_input drops
		 * these frames at the auth/decrypt step well before any byte
		 * past the SPI+seq header is consulted, so per-iteration
		 * re-randomisation of the payload is pure overhead --
		 * generate_rand_bytes is a hot call on the chacha20 RNG and
		 * burning it NAT_T_XFRM6_SEND_CAP times per op shows up at
		 * the top of perf top for this childop. */
		generate_rand_bytes(frame + 8, NAT_T_INNER_PAYLOAD_LEN);

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		sends = BUDGETED(CHILD_OP_NAT_T_CHURN,
				 JITTER_RANGE(NAT_T_XFRM6_SEND_BASE));
		if (sends < NAT_T_XFRM6_SEND_FLOOR)
			sends = NAT_T_XFRM6_SEND_FLOOR;
		if (sends > NAT_T_XFRM6_SEND_CAP)
			sends = NAT_T_XFRM6_SEND_CAP;

		for (s = 0; s < sends; s++) {
			if (nat_t_ns_since(&t0) >= NAT_T_XFRM6_SEND_NS_CAP)
				break;
			hdr[1] = htonl(++g_iter);
			(void)sendto(udp, frame, sizeof(frame), MSG_DONTWAIT,
				     (struct sockaddr *)&dst, sizeof(dst));
			__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_sendto_runs,
					   1, __ATOMIC_RELAXED);

			/* Mid-flight DELSA: fire roughly halfway so the
			 * teardown races the in-flight esp6_output /
			 * error-return path. */
			if (!delsa_fired && s == sends / 2U) {
				if (build_delsa6(&ctx, spi) == 0)
					__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_delsa_races,
							   1, __ATOMIC_RELAXED);
				delsa_fired = true;
			}
		}
	}

delsa:
	if (!delsa_fired)
		(void)build_delsa6(&ctx, spi);

out:
	if (udp >= 0)
		close(udp);
	nl_close(&ctx);
}

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

	rc = build_newsa(&ctx, spi, mode, esn, encap_choice,
			 replay_window, auth, crypt);
	if (rc != 0)
		goto out;
	__atomic_add_fetch(&shm->stats.nat_t_churn.sa_added,
			   1, __ATOMIC_RELAXED);

	udp = open_encap_udp();
	if (udp >= 0) {
		__u32 seq = ++g_iter;

		if (send_esp_in_udp(udp, spi, seq))
			__atomic_add_fetch(&shm->stats.nat_t_churn.frames_sent,
					   1, __ATOMIC_RELAXED);
		maybe_drain_recv(udp);
	}

	if (build_delsa(&ctx, spi) == 0)
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

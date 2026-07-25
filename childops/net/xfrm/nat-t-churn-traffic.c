/*
 * nat-t-churn-traffic - UDP-encaps-ESP data-plane drivers for the
 * nat_t_churn childop.  Carved out of childops/net/xfrm/nat-t-churn.c
 * so the v4 socket priming / sendto / recv-drain helpers and the
 * larger v6 UDPv6-encap-ESP error-path driver (nat_t_churn_v6, plus
 * its socket sibling and its monotonic-elapsed helper) compile as
 * their own TU alongside the shared SA assemblers and the setup /
 * cleanup TUs.
 *
 * Pure relocation: every function body and rationale is byte-for-byte
 * the same as the original.  The only linkage change is widening the
 * v4 socket / send / drain helpers plus the v6 driver from
 * file-static to external so the top-level dispatch in nat-t-churn.c
 * can reach them across the TU boundary; the v6 socket sibling and
 * the monotonic-elapsed helper keep file-static linkage because they
 * have no cross-TU callers.  Renamed with a nat_t_ prefix in line with
 * the sa.c naming convention.
 */

#include "nat-t-churn-internal.h"

/*
 * Open a UDP socket bound to (127.0.0.1, NAT_T_ENCAP_PORT) and prime
 * it with UDP_ENCAP_ESPINUDP so the kernel installs the encap demux
 * callback.  Returns the fd on success, -1 on failure.  Bind on the
 * fixed port can fail with EADDRINUSE if a sibling iteration in this
 * netns hasn't fully torn down yet -- caller treats that as a soft
 * failure for the iteration.
 */
int nat_t_open_encap_udp(void)
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
bool nat_t_send_esp_in_udp(int udp, __be32 spi, __u32 seq)
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

void nat_t_maybe_drain_recv(int udp)
{
	unsigned char rbuf[256];

	if ((rand32() & 3U) != 0)
		return;
	(void)recv(udp, rbuf, sizeof(rbuf), MSG_DONTWAIT);
}

/*
 * Open an AF_INET6 / SOCK_DGRAM / IPPROTO_UDP socket, bind to
 * (in6addr_any, port 0) so the kernel picks an ephemeral port, and
 * prime it with UDP_ENCAP_ESPINUDP[_NON_IKE].  This is the IPv6 sibling
 * of nat_t_open_encap_udp().  The setsockopt is what installs the encap
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
void nat_t_churn_v6(void)
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
		rc = nat_t_build_newsa6(&ctx, spi, mode, esn, encap_choice,
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
				if (nat_t_build_delsa6(&ctx, spi) == 0)
					__atomic_add_fetch(&shm->stats.nat_t_churn.xfrm6_delsa_races,
							   1, __ATOMIC_RELAXED);
				delsa_fired = true;
			}
		}
	}

delsa:
	if (!delsa_fired)
		(void)nat_t_build_delsa6(&ctx, spi);

out:
	if (udp >= 0)
		close(udp);
	nl_close(&ctx);
}

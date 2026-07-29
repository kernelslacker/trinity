/*
 * xfrm-churn-sk-policy - socket-attached xfrm policy sub-mode for the
 * xfrm_churn childop.  Carved out of childops/net/xfrm/xfrm-churn.c
 * so the setsockopt(IP_XFRM_POLICY / IPV6_XFRM_POLICY) driver and its
 * sadb_x_policy shim layout compile as their own TU alongside the
 * netlink builders and inner-traffic drivers.
 *
 * Pure relocation: every function body is byte-for-byte the same as
 * the original.  xfrm_sk_policy_churn widens from file-static to
 * external linkage so the xfrm-churn.c teardown phase can reach it
 * across the TU boundary; build_sk_policy_blob, the per-child
 * ns_unsupported_sk_xfrm_policy latch and the sadb_x_policy shim
 * layout stay file-static because they have no cross-TU callers.
 */

#include "xfrm-churn-internal.h"

/*
 * Per-child latch for the setsockopt(IP_XFRM_POLICY / IPV6_XFRM_POLICY)
 * path.  Both sockopts route through xfrm_user_policy(), which is
 * plumbed through PF_KEYv2's compile_policy for the actual parse; a
 * kernel built without CONFIG_NET_KEY has no compile_policy registered
 * and every attempt returns EINVAL early.  Latched on the first
 * EOPNOTSUPP / EPROTONOSUPPORT / ENOPROTOOPT so subsequent iterations
 * don't burn a socket + connect + setsockopt round for nothing.
 */
static bool ns_unsupported_sk_xfrm_policy;

/* IP_XFRM_POLICY / IPV6_XFRM_POLICY sockopts and the sadb_x_policy
 * IPSEC_* / DIR_* / TYPE_* vocabulary.  UAPI-stable IDs; shims here
 * keep the build working on stripped sysroots without <linux/in.h> or
 * <linux/ipsec.h>. */
#ifndef IP_XFRM_POLICY
#define IP_XFRM_POLICY			17
#endif
#ifndef IPV6_XFRM_POLICY
#define IPV6_XFRM_POLICY		35
#endif
#ifndef SADB_X_EXT_POLICY
#define SADB_X_EXT_POLICY		18
#endif
#define SK_XFRM_IPSEC_DIR_IN		1
#define SK_XFRM_IPSEC_DIR_OUT		2
#define SK_XFRM_IPSEC_DIR_FWD		3
#define SK_XFRM_IPSEC_TYPE_DISCARD	0
#define SK_XFRM_IPSEC_TYPE_NONE		1
#define SK_XFRM_IPSEC_TYPE_BYPASS	4

/* Kernel enforces optlen <= PAGE_SIZE in xfrm_user_policy(); larger
 * blobs short-circuit at the length check before any parse or
 * sk_dst_cache touch.  Cap the buffer at page-plus so an oversized
 * rotation lands the EMSGSIZE reject arm intentionally. */
#define SK_POLICY_BUF_BYTES		(4096U + 64U)

/* sadb_x_policy layout is fixed at 16 bytes since RFC 2367; matches the
 * kernel's struct sadb_x_policy byte-for-byte.  Duplicated as a shim
 * because pfkeyv2.h on stripped sysroots may not carry the packed
 * layout, and pfkey_flush_burst() above only touches struct sadb_msg. */
struct sk_xfrm_sadb_x_policy {
	__u16	len;
	__u16	exttype;
	__u16	type;
	__u8	dir;
	__u8	reserved;
	__u32	id;
	__u32	priority;
};

/*
 * Encode one sadb_x_policy at buf[0].  Returns the number of bytes
 * written -- always 16 for the fixed layout when buf is large enough,
 * 0 otherwise.  Direction / type are rotated by the caller so the
 * kernel-side parse reaches both the accepted (dir in {IN,OUT}, type
 * BYPASS/DISCARD/NONE) and the rejected (dir == 0/5, type garbage)
 * arms of pfkey_compile_policy.
 */
static size_t build_sk_policy_blob(unsigned char *buf, size_t cap,
				   __u8 dir, __u16 type)
{
	struct sk_xfrm_sadb_x_policy *p;

	if (cap < sizeof(*p))
		return 0;

	memset(buf, 0, sizeof(*p));
	p = (struct sk_xfrm_sadb_x_policy *)buf;
	p->len      = sizeof(*p) / 8;	/* pfkey length in 8-octet units */
	p->exttype  = SADB_X_EXT_POLICY;
	p->type     = type;
	p->dir      = dir;
	p->id       = 0;
	p->priority = 0;
	return sizeof(*p);
}

/*
 * Drive the socket-attached xfrm policy path (net/xfrm/xfrm_state.c:
 * xfrm_user_policy) through both the accepted-and-inserted branch and
 * the rejection branches on a UDP socket whose sk_dst_cache has been
 * primed by connect().  Sequence per invocation:
 *
 *   1. Open AF_INET or AF_INET6 UDP socket (rotated).
 *   2. connect() to 127.0.0.1 / ::1 -- kernel resolves and stashes the
 *      dst on sk_dst_cache, so any subsequent policy insert has to
 *      reset it.
 *   3. Rotate several setsockopt(IP_XFRM_POLICY / IPV6_XFRM_POLICY)
 *      calls covering (dir, type, length) triples: well-formed
 *      IN/OUT+BYPASS/DISCARD/NONE (compile succeeds -> insert ->
 *      sk_dst_reset); dir=0/5 or type=99 (compile rejects with EINVAL
 *      after the memdup); optlen=0 and optlen>PAGE_SIZE (rejected at
 *      the sock-layer length check before any parse).  Two cycles per
 *      invocation so the accepted insert -> reject -> replace path
 *      runs at least once per iteration.
 *   4. close() -- runs __sk_destruct -> xfrm_sk_free_policy over any
 *      still-attached policy while the cached dst is stale.
 *
 * All setsockopt calls are best-effort: parse/length rejections are
 * silently absorbed -- the coverage value is in the kernel-side walk
 * they trigger, not the userland verdict.  Only permanent-unsupported
 * errnos flip the latch and skip subsequent iterations.  The (fresh
 * netns, transient socket) frame contains everything this helper
 * touches.
 */
void xfrm_sk_policy_churn(struct childdata *child)
{
	unsigned char buf[SK_POLICY_BUF_BYTES];
	struct sockaddr_in dst4;
	struct sockaddr_in6 dst6;
	const struct sockaddr *dst;
	socklen_t dstlen;
	int fd, family, level, opt, i;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_sk_xfrm_policy || ns_unsupported_inet)
		return;

	family = ONE_IN(2) ? AF_INET6 : AF_INET;
	fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;

	if (family == AF_INET6) {
		memset(&dst6, 0, sizeof(dst6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_addr   = in6addr_loopback;
		dst6.sin6_port   = htons(XFRM_INNER_PORT);
		dst    = (struct sockaddr *)&dst6;
		dstlen = sizeof(dst6);
		level  = IPPROTO_IPV6;
		opt    = IPV6_XFRM_POLICY;
	} else {
		memset(&dst4, 0, sizeof(dst4));
		dst4.sin_family      = AF_INET;
		dst4.sin_addr.s_addr = XFRM_DADDR_BE;
		dst4.sin_port        = htons(XFRM_INNER_PORT);
		dst    = (struct sockaddr *)&dst4;
		dstlen = sizeof(dst4);
		level  = IPPROTO_IP;
		opt    = IP_XFRM_POLICY;
	}

	/* connect(): populate sk_dst_cache so the subsequent policy
	 * insert has a cached dst to reset.  Ignore return value --
	 * even an ECONNREFUSED-shaped path leaves sk_dst set on the
	 * kernel side. */
	(void)connect(fd, dst, dstlen);

	/* Two setsockopt rotations per invocation.  Independent
	 * (dir, type, length) draws so an accepted insert (which sets
	 * up sk_policy[dir]) can be immediately re-hit with an accepted
	 * replace or a rejected retry against the still-attached
	 * policy. */
	for (i = 0; i < 2; i++) {
		static const __u8  dirs[]  = {
			SK_XFRM_IPSEC_DIR_IN, SK_XFRM_IPSEC_DIR_OUT,
			SK_XFRM_IPSEC_DIR_FWD, 0, 5,
		};
		static const __u16 types[] = {
			SK_XFRM_IPSEC_TYPE_BYPASS,
			SK_XFRM_IPSEC_TYPE_DISCARD,
			SK_XFRM_IPSEC_TYPE_NONE,
			99,
		};
		size_t len;
		int rc;

		switch (rand32() & 7U) {
		case 0:  len = 0; break;
		case 1:
			/* > PAGE_SIZE arm: kernel rejects with EMSGSIZE
			 * before touching the buffer, but zero-fill so
			 * --dry-run stays byte-identical and MSan / valgrind
			 * don't flag the setsockopt() read. */
			memset(buf, 0, sizeof(buf));
			len = sizeof(buf);
			break;
		default:
			len = build_sk_policy_blob(buf, sizeof(buf),
						   RAND_ARRAY(dirs),
						   RAND_ARRAY(types));
			break;
		}

		if (len == 0) {
			rc = setsockopt(fd, level, opt, NULL, 0);
		} else {
			if (len > sizeof(buf))
				len = sizeof(buf);
			rc = setsockopt(fd, level, opt, buf, len);
		}

		if (rc == 0) {
			/* Accepted inserts share the xfrm_churn_pol_added
			 * counter with the netlink NEWPOLICY path: both are
			 * an SPD-visible policy install by the time the
			 * kernel returns success. */
			__atomic_add_fetch(&shm->stats.xfrm_churn.pol_added,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
			   errno == ENOPROTOOPT) {
			ns_unsupported_sk_xfrm_policy = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			break;
		}
	}

	close(fd);
}

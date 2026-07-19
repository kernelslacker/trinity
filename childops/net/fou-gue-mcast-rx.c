/*
 * fou_gue_mcast_rx - install a FOU (direct UDP encap) or GUE (UDP +
 * GUE variant header) receive port inside a private netns, then blast
 * hand-rolled outer IPv4/IPv6 UDP-encap frames with a MULTICAST outer
 * destination.  Targets the udp_v4_mcast_deliver / __udp6_lib_mcast_deliver
 * path where a mcast-arriving UDP frame with encap set gets resubmitted
 * to the FOU/GUE encap_rcv, and the encap-resubmit peels the outer
 * headers and hands the inner header to ip_local_deliver / ip6_input.
 * Random arg fuzzing cannot chance-assemble a valid UDP-encap frame at
 * an installed FOU port; steady coverage of that seam needs the port
 * install + hand-rolled matching frame together.
 *
 * Bug class of interest: encap-resubmit inside multicast deliver.  The
 * kernel walks every matching mcast socket, and for each one with
 * encap set calls encap_rcv (fou_udp_recv / gue_udp_recv), which
 * __skb_pull()s past the outer UDP + any GUE extension bytes and
 * re-enters the L3 input path.  Truncation past a length parsed inside
 * the encap header (GUE Hlen, GUE flags-controlled extensions, or an
 * inner IP header shorter than its own ihl claims) is the recurring
 * shape here.  KASAN-visible when the parser reads past the linear
 * alloc.  Not a repro: the point is generic coverage of the encap-
 * resubmit seam plus the multicast walker interaction, which nothing
 * else in the tree exercises.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child
 * runs a one-shot best-effort modprobe of fou / fou6 before the
 * userns hop (finit_module needs CAP_SYS_MODULE in init_user_ns).  In
 * the grandchild:
 *   1. Bring lo up so 127.0.0.0/8 and ::/0 loopback delivery works.
 *   2. Open NETLINK_GENERIC and resolve the "fou" family.  Missing
 *      family (ENOENT) latches the kind off via shm.
 *   3. Roll { encap = FOU | GUE, AF = v4 | v6, port } and issue
 *      FOU_CMD_ADD.  Rejection with CONFIG_NET_FOU / CONFIG_IPV6_FOU
 *      absent errno set (EOPNOTSUPP / EPROTONOSUPPORT / EAFNOSUPPORT /
 *      ENOPROTOOPT / EPERM / ENOENT) latches the kind off.
 *   4. Open SOCK_RAW / IPPROTO_RAW (v4) or SOCK_RAW / IPPROTO_RAW +
 *      IPV6_HDRINCL (v6) so we can hand-roll the outer IP + UDP +
 *      optional GUE + inner header ourselves.
 *   5. BUDGETED+JITTER burst (base 5) of hand-rolled frames.  Each
 *      frame picks:
 *        - outer dst: multicast most of the time (v4: rotating group
 *          in 224.0.0.0/24; v6: rotating ff02::/16 group) with an
 *          occasional unicast loopback dst so the non-mcast path
 *          gets coverage too,
 *        - GUE variant: version {0, 1, 2, 3}, control bit, Hlen in
 *          4-byte units {0, 1, 2, 4, 8, 31}, proto (inner ip proto
 *          for ver 0), and a random flags word.  Version 0 is the
 *          spec'd form; ver 2/3 walk the reject path; ver 1's first
 *          32-bit word is treated as an inner IP header (RFC-legacy
 *          direct-IP variant).  FOU has no GUE header.
 *        - inner IP shape: v4 or v6 header (matched to the outer AF
 *          for FOU; free choice for GUE ver 0),
 *        - inner proto: TCP / UDP / ICMP / random -- picks the
 *          post-decap parser entry,
 *        - inner truncation: {0, 1, 4, 8, 16} bytes shaved off the
 *          declared inner header, so most frames declare a header
 *          longer than the payload the kernel actually holds.
 *   6. sendto MSG_DONTWAIT so a queue-backed loopback cannot pin the
 *      grandchild past the inherited SIGALRM(1s) safety net.
 *
 * Brick-safety: loopback / link-local mcast only inside the private
 * netns.  One FOU_CMD_ADD / FOU_CMD_DEL per invocation, all sends
 * MSG_DONTWAIT.  Netns destruction on grandchild _exit reaps any port
 * install or raw socket left behind by a mid-iteration bail.
 *
 * Latches: ns_unsupported_fou_gue_mcast_rx master gate on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled).
 * shm->fou_gue_mcast_rx_kind_unsupported on genl_open("fou") -ENOENT
 * or FOU_CMD_ADD failing with the CONFIG_NET_FOU absent errno set.
 * Per-kind latch lives in shm because the rejection is observed
 * inside the grandchild -- a process-local static would die on _exit
 * and re-attempt the missing kind forever.
 */

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "child.h"
#include "childops-genl.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

/*
 * FOU UAPI fallbacks.  linux/fou.h may be absent on a stripped
 * sysroot; the values are stable in the kernel UAPI (net/ipv4/fou.c
 * has not renumbered them since introduction).  Guarded so a real
 * header inclusion would still win, but we intentionally do not
 * include linux/fou.h here -- it drags linux/udp.h which conflicts
 * with netinet/udp.h on this codebase's include set.
 */
#ifndef FOU_GENL_NAME
#define FOU_GENL_NAME		"fou"
#endif

#ifndef FOU_CMD_ADD
#define FOU_CMD_ADD		1
#define FOU_CMD_DEL		2
#endif

#ifndef FOU_ATTR_PORT
#define FOU_ATTR_PORT		1	/* __be16 */
#define FOU_ATTR_AF		2	/* u8  */
#define FOU_ATTR_IPPROTO	3	/* u8  */
#define FOU_ATTR_TYPE		4	/* u8  */
#endif

#ifndef FOU_ENCAP_DIRECT
#define FOU_ENCAP_DIRECT	1	/* raw IP inside UDP */
#define FOU_ENCAP_GUE		2	/* GUE header + inner */
#endif

/* Loopback endpoints for the private netns.  Outer saddr is
 * 127.0.0.1 / ::1; outer daddr is a multicast group most of the
 * time and a unicast loopback otherwise. */
#define FGMR_V4_SADDR_BE	(__be32)__builtin_bswap32(0x7f000001U)
#define FGMR_V4_UCAST_BE	(__be32)__builtin_bswap32(0x7f000001U)

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one
 * shrinks to floor.  Sends are MSG_DONTWAIT so the inherited
 * SIGALRM(1s) cap is not gated on socket-buffer backpressure. */
#define FGMR_PACKET_BASE	5U

/* Outer packet buffer size.  Outer IPv6 (40) + UDP (8) + GUE with
 * max Hlen*4 (124) + inner IPv6 (40) + slack fits well under 320;
 * leaves headroom for length randomisation. */
#define FGMR_PKT_MAX		320

/* Maximum inner header we may emit before applying truncation.
 * Nominal inner IPv6 = 40, IPv4 = 20; nominal L4 min = 20 (TCP).
 * A single 96-byte scratch is more than enough. */
#define FGMR_INNER_NOMINAL	96

/* GUE Hlen is a 5-bit field expressed in 4-byte units, so the
 * maximum extension byte count is 31 * 4 = 124.  The picker rotates a
 * small set of Hlen values that includes this 31 (124-byte) maximum. */
#define FGMR_GUE_HLEN_MAX	31U

/* FOU udp port range.  Stays above the assigned-port well-known band
 * so we never collide with anything the host runtime might poke.  */
#define FGMR_PORT_MIN		0x4000U
#define FGMR_PORT_RANGE		0x8000U

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT install a FOU port on the host, so the op stays disabled
 * for the remainder of this child's lifetime.
 */
static bool ns_unsupported_fou_gue_mcast_rx;

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

/* Set once per persistent child after the modprobe attempts run.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->fou_gue_mcast_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->fou_gue_mcast_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * IPv4 header + UDP one's-complement 16-bit fold.  Kept local so this
 * file has no dependency on utils/csum plumbing.  Mirrors the same
 * helper in ip_gre-churn.c / esp-crafted-rx.c / sctp-chunk-rx.c.
 */
static __u16 csum16_fold(const void *data, size_t len)
{
	const __u16 *p = data;
	__u32 s = 0;

	while (len > 1) {
		s += *p++;
		len -= 2;
	}
	if (len)
		s += *(const __u8 *)p;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/*
 * Draw the inner protocol byte for a crafted frame.  Weighting keeps
 * TCP/UDP/ICMP in the mix (each maps to its own kernel parser entry
 * on the post-decap path) plus an escape hatch of random bytes for
 * the unknown-protocol reject branch.
 */
static uint8_t pick_inner_proto(void)
{
	switch (rnd_modulo_u32(8)) {
	case 0: case 1: case 2: return IPPROTO_TCP;
	case 3: case 4:         return IPPROTO_UDP;
	case 5:                 return IPPROTO_ICMP;
	default:                return (uint8_t)rnd_modulo_u32(256);
	}
}

/*
 * Draw an inner-payload truncation length.  {0, 1, 4, 8, 16} shave
 * bytes off the declared inner header so the post-decap header walk
 * over-reads.  0 leaves nothing after the outer UDP + optional GUE
 * for the L3 parser to consume; 16 is a common short-header size
 * that slices a real fixed header off mid-field.
 */
static uint8_t pick_inner_trunc_len(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 4U;
	case 3:  return 8U;
	default: return 16U;
	}
}

/*
 * Draw a GUE Hlen in 4-byte units.  0 is the standard GUE-0 form
 * (fixed 4-byte header, no extensions); 1/2/4/8 are common extension
 * lengths; 31 is the maximum a 5-bit field can express and forces
 * the parser to consume 124 bytes of extension before touching the
 * inner header.  The extension bytes themselves are random.
 */
static uint8_t pick_gue_hlen(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 2U;
	case 3:  return 4U;
	case 4:  return 8U;
	default: return FGMR_GUE_HLEN_MAX;
	}
}

/*
 * Fill the outer v4 mcast destination.  Rotates 224.0.0.0/24 (the
 * link-local mcast band) so udp_v4_mcast_deliver's per-socket walker
 * runs across a range of hashes.  ONE_IN(8) escapes to 127.0.0.1 so
 * the unicast (non-mcast-deliver) path is exercised too.
 */
static __be32 pick_v4_dst(void)
{
	if (ONE_IN(8))
		return FGMR_V4_UCAST_BE;
	return htonl(0xe0000000U | (rand32() & 0xffU));
}

/*
 * Fill the outer v6 mcast destination.  ff02::/16 is link-local
 * mcast; the low bits rotate so __udp6_lib_mcast_deliver's hash
 * walker sees a range.  ONE_IN(8) escapes to ::1 for the unicast
 * path.
 */
static void pick_v6_dst(uint8_t out[16])
{
	memset(out, 0, 16);
	if (ONE_IN(8)) {
		out[15] = 1;			/* ::1 */
		return;
	}
	out[0]  = 0xff;
	out[1]  = 0x02;				/* ff02:: link-local scope */
	out[13] = (uint8_t)(rand32() & 0xffU);
	out[14] = (uint8_t)(rand32() & 0xffU);
	out[15] = (uint8_t)((rand32() & 0xffU) | 1U);
}

/*
 * Install a FOU or GUE receive port via genl "fou" FOU_CMD_ADD.  af,
 * proto and encap_type are captured by the caller so the packet-emit
 * loop can stamp matching outer AF + UDP dport, and the DELSA-style
 * FOU_CMD_DEL on teardown can name the same port back.  Returns 0 on
 * netlink-ack success, negated errno on kernel rejection, -EIO on
 * local encode failure.
 */
static int fou_cmd_port(struct genl_ctx *ctx, __u8 cmd, __be16 port,
			__u8 af, __u8 ipproto, __u8 encap_type)
{
	unsigned char buf[256];
	size_t off;
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl), cmd, 0);
	if (!off)
		return -EIO;

	off = nla_put(buf, off, sizeof(buf), FOU_ATTR_PORT, &port, sizeof(port));
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), FOU_ATTR_AF, af);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), FOU_ATTR_IPPROTO, ipproto);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), FOU_ATTR_TYPE, encap_type);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Stamp an inner IP header (v4 or v6) into buf, up to nominal size,
 * then apply truncation by returning a length strictly less than the
 * nominal.  The kernel's post-decap L3 parser reads the fixed portion
 * of the inner header (20 bytes for v4, 40 for v6) trusting the frame
 * still has that many linear bytes; emitting fewer than nominal is
 * what drives the parse-past-end seam.
 */
static size_t build_inner(uint8_t *buf, bool inner_v6, uint8_t inner_proto,
			  uint8_t trunc_len)
{
	size_t nominal = inner_v6 ? 40U : 20U;
	size_t emit;

	memset(buf, 0, FGMR_INNER_NOMINAL);
	if (inner_v6) {
		buf[0] = 0x60;			/* v6, tc=0, flow=0 */
		buf[6] = inner_proto;		/* next header */
		buf[7] = 64;			/* hop_limit */
		buf[8 + 15]  = 1;		/* saddr ::1 */
		buf[24 + 15] = 1;		/* daddr ::1 */
	} else {
		buf[0] = 0x45;			/* v4, ihl=5 */
		buf[8] = 64;			/* ttl */
		buf[9] = inner_proto;
		*(__be32 *)(buf + 12) = FGMR_V4_SADDR_BE;
		*(__be32 *)(buf + 16) = FGMR_V4_UCAST_BE;
	}

	emit = (trunc_len >= nominal) ? 0U : (nominal - trunc_len);
	return emit;
}

/*
 * Build a GUE header at buf.  Version, control bit, Hlen (in 4-byte
 * units), proto and flags are drawn by the caller so the packet-emit
 * loop can churn each dimension independently.  Extension bytes
 * (Hlen*4) are random.  Returns the header length in bytes (4 + Hlen*4).
 */
static size_t build_gue_hdr(uint8_t *buf, uint8_t ver, bool control,
			    uint8_t hlen, uint8_t proto, __be16 flags)
{
	size_t ext_bytes = (size_t)hlen * 4U;

	buf[0] = (uint8_t)(((ver & 0x3U) << 6) |
			   ((control ? 1U : 0U) << 5) |
			   (hlen & 0x1fU));
	buf[1] = proto;
	*(__be16 *)(buf + 2) = flags;
	if (ext_bytes)
		generate_rand_bytes(buf + 4, (unsigned int)ext_bytes);
	return 4U + ext_bytes;
}

/*
 * Compose one outer IPv4 UDP-encap frame at buf.  Layout:
 *   [outer IPv4 (20)]
 *   [UDP (8)]
 *   [optional GUE header (4 + Hlen*4)]
 *   [inner IPv4/IPv6 header, truncated per trunc_len]
 * Returns total wire length.  Outer daddr is drawn by the caller so
 * mcast-vs-unicast rotates per-frame; sport = 0 (kernel accepts).
 */
static size_t build_v4_frame(uint8_t *buf, __be16 dport, __be32 daddr,
			     bool is_gue, uint8_t gue_ver, bool gue_ctrl,
			     uint8_t gue_hlen, uint8_t inner_proto,
			     bool inner_v6, uint8_t trunc_len)
{
	struct iphdr *iph;
	struct udphdr *uh;
	size_t off;
	size_t udp_start;
	size_t inner_bytes;
	uint8_t inner[FGMR_INNER_NOMINAL];

	memset(buf, 0, FGMR_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr    = FGMR_V4_SADDR_BE;
	iph->daddr    = daddr;
	off = sizeof(*iph);

	udp_start = off;
	uh = (struct udphdr *)(buf + off);
	uh->source = 0;
	uh->dest   = dport;
	off += sizeof(*uh);

	if (is_gue) {
		__be16 flags = (__be16)(rand32() & 0xffffU);

		off += build_gue_hdr(buf + off, gue_ver, gue_ctrl,
				     gue_hlen, inner_proto, flags);
	}

	inner_bytes = build_inner(inner, inner_v6, inner_proto, trunc_len);
	if (inner_bytes) {
		memcpy(buf + off, inner, inner_bytes);
		off += inner_bytes;
	}

	uh->len      = htons((uint16_t)(off - udp_start));
	uh->check    = 0;			/* UDPv4 zero checksum permitted */
	iph->tot_len = htons((uint16_t)off);
	iph->check   = 0;
	iph->check   = csum16_fold(iph, sizeof(*iph));

	return off;
}

/*
 * Compose one outer IPv6 UDP-encap frame at buf.  Same shape as the
 * v4 builder but with an outer IPv6 header (40 bytes, next_header=UDP,
 * payload_length covers UDP + optional GUE + inner).  IPv6 UDP
 * checksum is mandatory but the kernel does not verify it on the
 * receive-side lo path; we leave it zeroed to keep the builder simple
 * (the checksum-mismatch drop is itself a covered path).
 */
static size_t build_v6_frame(uint8_t *buf, __be16 dport, const uint8_t daddr[16],
			     bool is_gue, uint8_t gue_ver, bool gue_ctrl,
			     uint8_t gue_hlen, uint8_t inner_proto,
			     bool inner_v6, uint8_t trunc_len)
{
	struct udphdr *uh;
	size_t off;
	size_t udp_start;
	size_t inner_bytes;
	uint16_t payload_len;
	uint8_t inner[FGMR_INNER_NOMINAL];

	memset(buf, 0, FGMR_PKT_MAX);

	buf[0]  = 0x60;
	buf[6]  = IPPROTO_UDP;
	buf[7]  = 64;
	buf[8 + 15] = 1;			/* saddr = ::1 */
	memcpy(buf + 24, daddr, 16);		/* daddr = mcast or ::1 */
	off = 40;

	udp_start = off;
	uh = (struct udphdr *)(buf + off);
	uh->source = 0;
	uh->dest   = dport;
	off += sizeof(*uh);

	if (is_gue) {
		__be16 flags = (__be16)(rand32() & 0xffffU);

		off += build_gue_hdr(buf + off, gue_ver, gue_ctrl,
				     gue_hlen, inner_proto, flags);
	}

	inner_bytes = build_inner(inner, inner_v6, inner_proto, trunc_len);
	if (inner_bytes) {
		memcpy(buf + off, inner, inner_bytes);
		off += inner_bytes;
	}

	uh->len   = htons((uint16_t)(off - udp_start));
	uh->check = 0;
	payload_len = (uint16_t)(off - 40);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)payload_len;

	return off;
}

/*
 * Per-invocation state shared across the fou_gue_mcast_rx_iter_*
 * helpers.  Lives on the orchestrator's stack.  Fields default so
 * teardown can close-or-skip unconditionally regardless of which
 * earlier phase bailed.
 */
struct fou_gue_iter_ctx {
	struct genl_ctx genl;
	int raw_fd;
	__be16 port;
	__u8 encap_type;
	bool port_added;
	bool v6;
	bool ctx_open;
	struct childdata *child;
};

/*
 * Bring lo up (per-grandchild one-time) and open the genl "fou"
 * family.  Returns 0 on success, -1 on failure.  ENOENT from
 * genl_open (fou module absent, CONFIG_NET_FOU=n) latches the kind
 * off so subsequent invocations short-circuit.
 */
static int fou_gue_iter_open_ctx(struct fou_gue_iter_ctx *ctx)
{
	struct genl_open_opts opts = {
		.family_name  = FOU_GENL_NAME,
		.version      = 1,
		.recv_timeo_s = 1,
	};
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if (!lo_brought_up) {
		struct nl_ctx rtnl = { .fd = -1 };
		struct nl_open_opts rtnl_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = 1,
		};

		if (nl_open(&rtnl, &rtnl_opts) == 0) {
			rtnl_bring_lo_up(&rtnl);
			nl_close(&rtnl);
		}
		lo_brought_up = true;
	}

	rc = genl_open(&ctx->genl, &opts);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT) {
			mark_kind_unsupported();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->ctx_open = true;
	return 0;
}

/*
 * Install the FOU/GUE receive port for this invocation.  Rolls port +
 * v6 + encap_type fresh each call so the FOU table's hash-insert path
 * is exercised across a range of keys.  Latches the kind off on
 * CONFIG_NET_FOU absent (EOPNOTSUPP / EPROTONOSUPPORT / EAFNOSUPPORT /
 * ENOPROTOOPT / EPERM / ENOENT).
 */
static int fou_gue_iter_install_port(struct fou_gue_iter_ctx *ctx)
{
	int rc;
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->port       = htons((__u16)((rand32() % FGMR_PORT_RANGE) +
					FGMR_PORT_MIN));
	ctx->v6         = ONE_IN(2);
	ctx->encap_type = ONE_IN(2) ? FOU_ENCAP_GUE : FOU_ENCAP_DIRECT;

	rc = fou_cmd_port(&ctx->genl, FOU_CMD_ADD, ctx->port,
			  ctx->v6 ? AF_INET6 : AF_INET,
			  IPPROTO_IPIP, ctx->encap_type);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.port_install_failed,
				   1, __ATOMIC_RELAXED);
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT || rc == -ENOPROTOOPT ||
		    rc == -EPERM || rc == -ENOENT) {
			mark_kind_unsupported();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->port_added = true;
	__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.port_install_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Open the raw socket for the outer AF.  IPPROTO_RAW implies
 * IP_HDRINCL for v4; for v6 we set IPV6_HDRINCL explicitly.  Failure
 * to open leaves ctx->raw_fd at -1 and the burst phase becomes a
 * no-op; the port install already ran so the FOU hash-insert path was
 * still exercised for the invocation.
 */
static void fou_gue_iter_open_raw(struct fou_gue_iter_ctx *ctx)
{
	int one = 1;

	if (ctx->v6) {
		ctx->raw_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
				     IPPROTO_RAW);
		if (ctx->raw_fd >= 0)
			(void)setsockopt(ctx->raw_fd, IPPROTO_IPV6,
					 IPV6_HDRINCL, &one, sizeof(one));
	} else {
		ctx->raw_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC,
				     IPPROTO_RAW);
	}
}

/*
 * BUDGETED+JITTER burst of hand-rolled UDP-encap frames at the
 * installed FOU port.  Each iteration rerolls outer dst (mcast most
 * of the time, unicast otherwise), inner proto, inner truncation and
 * -- when the installed encap is GUE -- GUE version / ctrl / Hlen.
 * MSG_DONTWAIT so a backed-up loopback queue cannot stall the
 * iteration past the SIGALRM(1s) cap.
 */
static void fou_gue_iter_send_burst(struct fou_gue_iter_ctx *ctx)
{
	unsigned int iters;
	unsigned int i;
	bool is_gue = (ctx->encap_type == FOU_ENCAP_GUE);

	if (ctx->raw_fd < 0)
		return;

	iters = BUDGETED(CHILD_OP_FOU_GUE_MCAST_RX,
			 JITTER_RANGE(FGMR_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[FGMR_PKT_MAX];
		size_t len;
		ssize_t n;
		uint8_t inner_proto = pick_inner_proto();
		uint8_t trunc_len   = pick_inner_trunc_len();
		bool inner_v6       = ONE_IN(2);
		uint8_t gue_ver     = (uint8_t)(rand32() & 0x3U);
		bool gue_ctrl       = ONE_IN(4);
		uint8_t gue_hlen    = pick_gue_hlen();

		if (ctx->v6) {
			struct sockaddr_in6 dst;
			uint8_t d6[16];

			pick_v6_dst(d6);
			memset(&dst, 0, sizeof(dst));
			dst.sin6_family = AF_INET6;
			memcpy(&dst.sin6_addr, d6, 16);
			len = build_v6_frame(pkt, ctx->port, d6, is_gue,
					     gue_ver, gue_ctrl, gue_hlen,
					     inner_proto, inner_v6, trunc_len);
			n = sendto(ctx->raw_fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
		} else {
			struct sockaddr_in dst;
			__be32 d4 = pick_v4_dst();

			memset(&dst, 0, sizeof(dst));
			dst.sin_family      = AF_INET;
			dst.sin_addr.s_addr = d4;
			len = build_v4_frame(pkt, ctx->port, d4, is_gue,
					     gue_ver, gue_ctrl, gue_hlen,
					     inner_proto, inner_v6, trunc_len);
			n = sendto(ctx->raw_fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
		}
		if (n > 0)
			__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown: FOU_CMD_DEL the installed port (best-effort; netns
 * teardown covers a mid-flow bail) and close the raw fd and genl
 * socket.  Guards ensure the helper is safe to call from any bail
 * point, including one where the port was never installed.
 */
static void fou_gue_iter_teardown(struct fou_gue_iter_ctx *ctx)
{
	if (ctx->raw_fd >= 0)
		close(ctx->raw_fd);
	if (ctx->port_added) {
		if (fou_cmd_port(&ctx->genl, FOU_CMD_DEL, ctx->port,
				 ctx->v6 ? AF_INET6 : AF_INET,
				 IPPROTO_IPIP, ctx->encap_type) == 0)
			__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.port_delete_ok,
					   1, __ATOMIC_RELAXED);
	}
	if (ctx->ctx_open)
		genl_close(&ctx->genl);
}

struct fou_gue_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any port
 * install, raw socket and packet buffers left behind are reaped along
 * with the namespace.  Return value is ignored by the helper.
 */
static int fou_gue_mcast_rx_in_ns(void *arg)
{
	struct fou_gue_ctx *cctx = (struct fou_gue_ctx *)arg;
	struct childdata *child = cctx->child;
	struct fou_gue_iter_ctx ctx = {
		.genl = GENL_CTX_INIT,
		.raw_fd = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (fou_gue_iter_open_ctx(&ctx) != 0)
		return 0;

	if (fou_gue_iter_install_port(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	fou_gue_iter_open_raw(&ctx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	fou_gue_iter_send_burst(&ctx);

out:
	fou_gue_iter_teardown(&ctx);
	return 0;
}

bool fou_gue_mcast_rx(struct childdata *child)
{
	struct fou_gue_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_fou_gue_mcast_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("fou");
		try_modprobe("fou6");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, fou_gue_mcast_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_fou_gue_mcast_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.fou_gue_mcast_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

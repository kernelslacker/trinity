/*
 * bareudp_rx - v4 bareudp RX-decap fuzz.  Fills the coverage gap left
 * by the netlink kinds table (net/netlink/msg-tables.c lists "bareudp"
 * so RTM_NEWLINK link-management path gets some coverage) but nothing
 * exercises drivers/net/bareudp.c's bareudp_udp_encap_recv path with a
 * crafted outer IPv4/UDP frame.  bareudp is a generic L3-over-UDP
 * tunnel with a configurable UDP dport and a per-tunnel ethertype
 * (ETH_P_IP / ETH_P_IPV6 / ETH_P_MPLS_UC + optional multi_proto_mode
 * that widens the accept set); the RX-decap path branches on the
 * per-tunnel ethertype, peeks the first byte of the payload after the
 * 8-byte UDP header for an IP version nibble on the IP-family path,
 * and hands the inner L3 frame to iptunnel_pull_header +
 * gro_cells_receive.  Random arg fuzzing cannot chance-assemble that
 * IP/UDP/inner-L3 stack aimed at a live bareudp socket.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs
 * a one-shot best-effort modprobe of bareudp before the userns hop
 * (finit_module needs CAP_SYS_MODULE in init_user_ns).  RTM_NEWLINK
 * creates a bareudp dev with a random ephemeral UDP port and a picked
 * ethertype (rotating IP / IPV6 / MPLS_UC / random-unknown) and
 * ONE_IN(3) sets the multi_proto_mode flag regardless of ethertype so
 * both the accept and the "cannot set multiproto for this ethertype"
 * reject paths run.  The grandchild brings the dev up, then blasts a
 * BUDGETED+JITTER (base 5) burst of hand-rolled IPv4/UDP/inner-L3
 * frames via SOCK_RAW / IPPROTO_RAW to 127.0.0.1 with UDP dport equal
 * to the tunnel's port -- the outer daddr matches lo, bareudp's UDP
 * encap socket catches the frame, and the ethertype-branching RX path
 * either walks the ipversion peek, the MPLS outer-daddr multicast
 * branch, or the direct proto-fallthrough case.
 *
 * Bug class of interest: the ethertype-branching RX-decap path.  On
 * ETH_P_IP the first payload byte's top nibble drives accept-4 /
 * accept-6-if-multiproto / drop.  On ETH_P_MPLS_UC the outer network
 * header's dst-address multicast bit drives proto=MPLS_UC /
 * proto=MPLS_MC-if-multiproto / drop.  Truncation past the parsed
 * BAREUDP_BASE_HLEN and truncation past the declared inner L3 header
 * length are the recurring tunnel-RX bug shape (iptunnel_pull_header
 * and the post-decap pskb_inet_may_pull walk over-read).  A random
 * ethertype (outside {IP, IPV6, MPLS_UC}) walks the direct
 * proto = ethertype fallthrough where iptunnel_pull_header hands the
 * frame back to the input path with an ethertype the L3 rx table does
 * not recognise -- exercises the netif_rx unknown-proto drop.
 *
 * Brick-safety: loopback only inside the private netns (outer sends
 * target 127.0.0.1 inside the grandchild's own netns), one link
 * create/destroy per invocation, all sends MSG_DONTWAIT, netlink ack
 * SO_RCVTIMEO=1s so an unresponsive rtnl can't wedge past child.c's
 * SIGALRM.
 *
 * Latches: ns_unsupported_bareudp_rx master gate on userns_run_in_ns()
 * -EPERM (unprivileged userns disabled).
 * shm->bareudp_rx_kind_unsupported on RTM_NEWLINK kind="bareudp"
 * rejection with the module/CONFIG_BAREUDP-absent errno set
 * (EAFNOSUPPORT / EOPNOTSUPP / ENOTSUP / ENOENT / EPROTONOSUPPORT).
 * Per-kind latch lives in shm because the rejection is observed inside
 * a transient grandchild -- a process-local static would die on _exit
 * and re-attempt the missing kind forever.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

/*
 * IFLA_BAREUDP_* fallbacks.  linux/if_link.h on a stripped sysroot may
 * predate the bareudp link-info attributes.  UAPI values are stable
 * per drivers/net/bareudp.c and include/uapi/linux/if_link.h.
 */
#ifndef IFLA_BAREUDP_PORT
#define IFLA_BAREUDP_PORT		1
#endif
#ifndef IFLA_BAREUDP_ETHERTYPE
#define IFLA_BAREUDP_ETHERTYPE		2
#endif
#ifndef IFLA_BAREUDP_SRCPORT_MIN
#define IFLA_BAREUDP_SRCPORT_MIN	3
#endif
#ifndef IFLA_BAREUDP_MULTIPROTO_MODE
#define IFLA_BAREUDP_MULTIPROTO_MODE	4
#endif

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC			0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC			0x8848
#endif

/* Reasonable ceiling for a single rtnl link-create message + payload;
 * bareudp RTM_NEWLINK with all attributes set is well under 1 KiB. */
#define BRX_RTNL_BUF			2048

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define BRX_PACKET_BASE			5U

/* Outer packet buffer size.  Outer IPv4 (20) + UDP (8) + inner IPv6
 * (40) + slack fits well under 256; leaves headroom for length
 * randomisation and the occasional random-bytes stamp. */
#define BRX_PKT_MAX			256

/* Loopback endpoint for the private netns. */
#define BRX_V4_LOCAL_BE			(__be32)__builtin_bswap32(0x7f000001U)

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's routing tables, so the op stays disabled
 * for the remainder of this child's lifetime.
 */
static bool ns_unsupported_bareudp_rx;

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

/* Set once per persistent child after the modprobe attempt runs.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->bareudp_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->bareudp_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * IPv4 header + UDP one's-complement 16-bit fold.  Kept local so this
 * file has no dependency on utils/csum plumbing.  Mirrors the same
 * helper in ip_gre-churn.c / esp-crafted-rx.c / fou-gue-mcast-rx.c /
 * geneve-rx.c.
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
 * Draw the per-tunnel ethertype.  IP / IPV6 / MPLS_UC are the three
 * kernel-accepted values that drive the three RX-decap branches; a
 * random unknown ethertype walks the direct proto = ethertype
 * fallthrough where the L3 input path drops the frame as an unknown
 * ethertype (bareudp_configure does not restrict ethertype so the
 * link create succeeds and the reject fires on the RX-path handoff).
 */
static uint16_t pick_ethertype(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0: case 1:	return (uint16_t)ETH_P_IP;
	case 2:		return (uint16_t)ETH_P_IPV6;
	case 3: case 4:	return (uint16_t)ETH_P_MPLS_UC;
	default:	return (uint16_t)(rand32() & 0xffffU);
	}
}

/*
 * Draw the payload-shape "kind" independently of the tunnel ethertype
 * so the RX path sees payload-vs-tunnel-ethertype mismatches too.  IPv4
 * -shaped payload triggers the version=4 accept on ETH_P_IP tunnels
 * and the outer-daddr multicast peek on ETH_P_MPLS_UC tunnels; IPv6-
 * shaped triggers version=6-if-multiproto on IP tunnels; MPLS-shaped
 * (4-byte label header) is what MPLS_UC tunnels normally carry; the
 * "random" and "empty" arms drive the drop / over-read branches.
 */
enum brx_inner_kind {
	BRX_INNER_IPV4 = 0,
	BRX_INNER_IPV6,
	BRX_INNER_MPLS,
	BRX_INNER_RANDOM,
	BRX_INNER_EMPTY,
};

static enum brx_inner_kind pick_inner_kind(void)
{
	switch (rnd_modulo_u32(8)) {
	case 0: case 1: case 2:	return BRX_INNER_IPV4;
	case 3: case 4:		return BRX_INNER_IPV6;
	case 5:			return BRX_INNER_MPLS;
	case 6:			return BRX_INNER_RANDOM;
	default:		return BRX_INNER_EMPTY;
	}
}

/*
 * Draw an inner-payload truncation length.  {0, 1, 4, 8, 20} shave
 * bytes off the declared inner frame so the post-decap header walk
 * over-reads.  0 leaves the frame at full nominal length; 1 slices a
 * single byte so the IP version nibble is still visible but the rest
 * of the header is truncated; 20 slices an inner IPv4 header off
 * entirely.  40 would slice an IPv6 header off entirely -- covered
 * by the "empty inner" kind above.
 */
static uint8_t pick_inner_trunc(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 4U;
	case 3:  return 8U;
	default: return 20U;
	}
}

/*
 * Draw an IP version nibble to stamp into the first payload byte on
 * IPv4-shaped payloads.  {4, 6} are the two accept branches on IP
 * tunnels (6 needs multiproto to accept); other values walk the drop
 * branch on IP tunnels and are consumed as leading-byte noise on the
 * MPLS_UC / IPV6 / random tunnels.
 */
static uint8_t pick_ip_version_nibble(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0: case 1: case 2:	return 4U;
	case 3: case 4:		return 6U;
	default:		return (uint8_t)(rand32() & 0xfU);
	}
}

/*
 * Build & send RTM_NEWLINK creating a bareudp dev with a picked UDP
 * port + ethertype and optionally the multi_proto_mode flag.  Returns
 * 0 on accept, negated errno on rejection, -EIO on local failure.
 */
static int build_bareudp_link(struct nl_ctx *ctx, const char *name,
			      uint16_t port, uint16_t ethertype,
			      bool multiproto)
{
	unsigned char buf[BRX_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	size_t li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bareudp");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	/* IFLA_BAREUDP_PORT is NLA_U16 network-order (kernel does the
	 * htons at store time via nla_get_u16 -- see bareudp2info). */
	off = nla_put_u16(buf, off, sizeof(buf), IFLA_BAREUDP_PORT,
			  htons(port));
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf), IFLA_BAREUDP_ETHERTYPE,
			  htons(ethertype));
	if (!off)
		return -EIO;

	if (multiproto) {
		/* NLA_FLAG: 0-length payload signals presence.  No helper
		 * so open-code it via nla_put with a NULL body. */
		off = nla_put(buf, off, sizeof(buf),
			      IFLA_BAREUDP_MULTIPROTO_MODE, NULL, 0);
		if (!off)
			return -EIO;
	}

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Compose one outer IPv4/UDP/inner-L3 frame at buf.  Layout:
 *   [outer IPv4 (20)]
 *   [outer UDP (8, dport=tunnel port)]
 *   [inner L3 payload: inner_kind-shaped, truncated per trunc]
 * Returns total wire length.  udp_len_override != 0 stamps a lied
 * UDP length so the outer parser sees a declared length exceeding the
 * actually-written bytes; udp_len_override == 0 stamps the true length.
 */
static size_t build_bareudp_frame(uint8_t *buf, uint16_t udp_dport,
				  enum brx_inner_kind inner_kind,
				  uint8_t ip_version_nibble,
				  uint8_t inner_trunc,
				  uint16_t udp_len_override)
{
	struct iphdr *iph;
	struct udphdr *uh;
	size_t off;
	size_t udp_start;
	unsigned int inner_nominal;
	unsigned int inner_emit;

	memset(buf, 0, BRX_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr    = BRX_V4_LOCAL_BE;
	iph->daddr    = BRX_V4_LOCAL_BE;
	off = sizeof(*iph);

	udp_start = off;
	uh = (struct udphdr *)(buf + off);
	uh->source = 0;
	uh->dest   = htons(udp_dport);
	off += sizeof(*uh);

	switch (inner_kind) {
	case BRX_INNER_IPV4:	inner_nominal = 20U; break;
	case BRX_INNER_IPV6:	inner_nominal = 40U; break;
	case BRX_INNER_MPLS:	inner_nominal = 4U;  break;
	case BRX_INNER_RANDOM:	inner_nominal = 16U; break;
	case BRX_INNER_EMPTY:
	default:		inner_nominal = 0U;  break;
	}
	inner_emit = (inner_trunc >= inner_nominal)
		     ? 0U : (inner_nominal - inner_trunc);
	if (inner_emit > 0U) {
		if (off + inner_emit > BRX_PKT_MAX)
			inner_emit = (unsigned int)(BRX_PKT_MAX - off);
		if (inner_kind == BRX_INNER_IPV4 && inner_emit >= 20U) {
			struct iphdr *inner = (struct iphdr *)(buf + off);
			inner->version  = (ip_version_nibble & 0xfU);
			inner->ihl      = 5;
			inner->ttl      = 64;
			inner->protocol = IPPROTO_UDP;
			inner->saddr    = BRX_V4_LOCAL_BE;
			inner->daddr    = BRX_V4_LOCAL_BE;
			inner->tot_len  = htons((uint16_t)inner_emit);
		} else if (inner_kind == BRX_INNER_IPV4) {
			/* Truncated IPv4 header: stamp only the version
			 * nibble so the peek at BAREUDP_BASE_HLEN sees it,
			 * then leave the rest of the shortened header
			 * zeroed. */
			buf[off] = (uint8_t)(((ip_version_nibble & 0xfU) << 4) |
					     0x5U);
		} else if (inner_kind == BRX_INNER_IPV6 && inner_emit >= 40U) {
			/* Version=6 top nibble so the IP-tunnel-multiproto
			 * path accepts the peek; hop-by-hop next-header
			 * NONE and lo saddr/daddr for the post-decap walk. */
			buf[off + 0]  = 0x60;
			buf[off + 6]  = IPPROTO_NONE;
			buf[off + 7]  = 64;
			buf[off + 8 + 15]  = 1;		/* saddr ::1 */
			buf[off + 24 + 15] = 1;		/* daddr ::1 */
		} else if (inner_kind == BRX_INNER_IPV6) {
			/* Truncated IPv6: only the version nibble matters
			 * for the ETH_P_IP tunnel peek path. */
			buf[off] = 0x60;
		} else if (inner_kind == BRX_INNER_MPLS && inner_emit >= 4U) {
			/* Minimal MPLS label stack entry: label=0 tc=0 s=1
			 * ttl=64.  Bottom-of-stack bit forces the walker to
			 * stop after one label. */
			buf[off + 0] = 0x00;
			buf[off + 1] = 0x00;
			buf[off + 2] = 0x01;		/* s=1 */
			buf[off + 3] = 64;		/* ttl */
		} else {
			generate_rand_bytes(buf + off, inner_emit);
		}
		off += inner_emit;
	}

	if (udp_len_override != 0U)
		uh->len  = htons(udp_len_override);
	else
		uh->len  = htons((uint16_t)(off - udp_start));
	uh->check    = 0;			/* UDPv4 zero checksum permitted */
	iph->tot_len = htons((uint16_t)off);
	iph->check   = 0;
	iph->check   = csum16_fold(iph, sizeof(*iph));

	return off;
}

/*
 * Per-invocation state shared across the bareudp_rx_iter_* helpers.
 * Lives on the orchestrator's stack.  Only fields read/written across
 * helper boundaries are lifted here; packet-burst scratch stays on
 * that helper's stack.  Gates encode the partial-state teardown
 * contract.
 */
struct bareudp_rx_iter_ctx {
	struct nl_ctx	nl;
	char		ifname[IFNAMSIZ];
	uint16_t	port;
	uint16_t	ethertype;
	int		ifindex;
	int		raw;		/* IPPROTO_RAW fd, -1 until opened */
	bool		nl_opened;
	bool		link_added;
	struct childdata *child;
};

/*
 * Open the rtnl socket and bring lo up inside the private netns.
 * Returns 0 on success, -1 on failure.  Teardown is safe on failure
 * because it gates on ctx->nl_opened.
 */
static int bareudp_rx_iter_open_ctx(struct bareudp_rx_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.bareudp_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->nl_opened = true;

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ctx->nl);
		lo_brought_up = true;
	}
	return 0;
}

/*
 * Build phase: pick ifname + port + ethertype + multiproto, RTM_NEWLINK
 * the bareudp dev, resolve its ifindex, bring it up.  Returns 0 if the
 * burst phase should run, -1 otherwise.  On the link-create rejection
 * path, rtnl_link_ops-not-registered errnos latch the kind off (missing
 * CONFIG_BAREUDP); other rejections (multiproto/ethertype invalid combo,
 * EBUSY, EINVAL) leave the latch alone.
 */
static int bareudp_rx_iter_build_link(struct bareudp_rx_iter_ctx *ctx)
{
	bool name_from_pool = false;
	bool multiproto = ONE_IN(3);
	int rc;
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ONE_IN(8)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_NETDEV,
						    ctx->ifname,
						    sizeof(ctx->ifname));
		if (got > 0) {
			if (got >= sizeof(ctx->ifname))
				got = sizeof(ctx->ifname) - 1;
			ctx->ifname[got] = '\0';
			name_from_pool = true;
		}
	}
	if (!name_from_pool) {
		snprintf(ctx->ifname, sizeof(ctx->ifname), "trbu%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	/* Ephemeral-range UDP port so we don't collide with common
	 * services inside the private netns; a fresh netns has no
	 * bound ports at start, but pinning to the ephemeral range
	 * keeps the intent obvious. */
	ctx->port = (uint16_t)(0xc000U | (rand32() & 0x3fffU));
	ctx->ethertype = pick_ethertype();

	rc = build_bareudp_link(&ctx->nl, ctx->ifname, ctx->port,
				ctx->ethertype, multiproto);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.bareudp_rx_link_create_failed,
				   1, __ATOMIC_RELAXED);
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT ||
		    rc == -EPROTONOSUPPORT) {
			mark_kind_unsupported();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->link_added = true;
	__atomic_add_fetch(&shm->stats.bareudp_rx_link_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex == 0)
		return -1;

	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));

	if (rtnl_setlink_up(&ctx->nl, ctx->ifindex) == 0)
		__atomic_add_fetch(&shm->stats.bareudp_rx_link_up_ok,
				   1, __ATOMIC_RELAXED);

	return 0;
}

/*
 * Burst phase: open SOCK_RAW / IPPROTO_RAW, then push BUDGETED+JITTER
 * hand-rolled outer IPv4/UDP/inner-L3 frames at 127.0.0.1 with UDP
 * dport equal to the tunnel's port.  The outer daddr matches lo, so
 * the grandchild's own netns loopback delivers the frame back onto
 * bareudp_udp_encap_recv.  Each iteration rerolls inner kind, IP
 * version nibble, inner truncation, and (occasionally) a lied UDP
 * length so the ethertype-branching decap path sees the full set of
 * payload-shape / tunnel-ethertype combinations.  MSG_DONTWAIT so a
 * backed-up loopback queue can't stall the iteration past the
 * inherited SIGALRM(1s) cap.
 */
static void bareudp_rx_iter_send_burst(struct bareudp_rx_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (ctx->raw < 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = BRX_V4_LOCAL_BE;

	iters = BUDGETED(CHILD_OP_BAREUDP_RX, JITTER_RANGE(BRX_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[BRX_PKT_MAX];
		size_t len;
		ssize_t n;
		enum brx_inner_kind inner_kind = pick_inner_kind();
		uint8_t ip_ver = pick_ip_version_nibble();
		uint8_t inner_trunc = pick_inner_trunc();
		uint16_t udp_len_override = 0U;

		/* ONE_IN(4): declare a UDP length past the buffer end so
		 * the outer UDP parser sees an over-declared payload.  The
		 * outer UDP layer typically drops before bareudp is invoked,
		 * but rotating this in keeps the shape covered against
		 * future changes to the encap-socket dispatch. */
		if (ONE_IN(4))
			udp_len_override = (uint16_t)(0x0400U +
						      (rand32() & 0x0fffU));

		len = build_bareudp_frame(pkt, ctx->port, inner_kind,
					  ip_ver, inner_trunc,
					  udp_len_override);

		n = sendto(ctx->raw, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.bareudp_rx_packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown phase: close the raw fd and tear down the bareudp dev + rtnl
 * socket.  Each cleanup is gated independently so it is safe to call
 * from any bail-out point in the orchestrator -- including the early
 * returns where ctx is fully zero-initialised -- without leaking the
 * raw fd or sending a dellink for an ifindex that was never resolved.
 * Netns destruction on grandchild exit catches anything left behind.
 */
static void bareudp_rx_iter_teardown(struct bareudp_rx_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (!ctx->nl_opened)
		return;

	if (ctx->link_added && ctx->ifindex > 0) {
		if (rtnl_dellink(&ctx->nl, ctx->ifindex) == 0)
			__atomic_add_fetch(&shm->stats.bareudp_rx_link_del_ok,
					   1, __ATOMIC_RELAXED);
	}
	nl_close(&ctx->nl);
}

struct bareudp_rx_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any tunnel
 * devs, raw sockets and packet buffers left behind are reaped along
 * with the namespace.  Return value is ignored by the helper.
 */
static int bareudp_rx_in_ns(void *arg)
{
	struct bareudp_rx_ctx *cctx = (struct bareudp_rx_ctx *)arg;
	struct childdata *child = cctx->child;
	struct bareudp_rx_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (bareudp_rx_iter_open_ctx(&ctx) == 0 &&
	    bareudp_rx_iter_build_link(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		bareudp_rx_iter_send_burst(&ctx);
	}

	bareudp_rx_iter_teardown(&ctx);
	return 0;
}

bool bareudp_rx(struct childdata *child)
{
	struct bareudp_rx_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.bareudp_rx_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_bareudp_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.bareudp_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("bareudp");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, bareudp_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_bareudp_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.bareudp_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.bareudp_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

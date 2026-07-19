/*
 * geneve_rx - v4 geneve RX-decap fuzz.  Fills the coverage gap left
 * by ip6erspan-netns-migrate / ovs-tunnel-vport / vxlan-encap: those
 * reach the geneve LINK-management path (RTM_NEWLINK kind="geneve")
 * but nothing exercises net/ipv4/geneve_core.c / drivers/net/geneve.c's
 * RX-decap path with a crafted outer UDP/GENEVE frame.  The tunnel-RX
 * bugs that live in geneve_udp_encap_recv / geneve_rx / the variable-
 * option parser need an outer IPv4(UDP-dport-6081)(GENEVE) frame with
 * a specific Opt-Len + option-class + critical-bit + inner-payload
 * shape (including truncation past a parsed option length) delivered
 * onto a live geneve dev's UDP tunnel socket.  Random arg fuzzing
 * cannot chance-assemble that nested header stack.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs
 * a one-shot best-effort modprobe of geneve before the userns hop
 * (finit_module needs CAP_SYS_MODULE in init_user_ns).  RTM_NEWLINK
 * creates a geneve dev pinned to 127.0.0.2 remote + a random 24-bit VNI,
 * brings it up, then blasts a BUDGETED+JITTER (base 5) burst of
 * hand-rolled IPv4/UDP(6081)/GENEVE/options/inner frames via SOCK_RAW /
 * IPPROTO_RAW to 127.0.0.1 -- the outer daddr matches the tunnel's
 * local, so geneve_udp_encap_recv catches it, the option walker parses
 * opt_len*4 bytes of TLVs, and the inner protocol is handed to the
 * matching L2/L3 input path.  Truncation-past-a-parsed-length variants
 * (Opt-Len declares more than the packet holds; per-TLV Length declares
 * more than the option-blob holds) are the specific recurring bug shape
 * for tunnel variable-option parsing.
 *
 * Bug class of interest: the GENEVE option walker.  Opt-Len is 6 bits
 * (max 63) expressed in 4-byte units, so an outer frame can legitimately
 * claim up to 252 bytes of options.  The per-TLV Length field is 5 bits,
 * also in 4-byte units, so a single option can claim up to 124 bytes.
 * A frame whose declared Opt-Len exceeds the remaining UDP payload, or
 * whose per-TLV Length exceeds the remaining option blob, drives the
 * kernel walker past skb_tail.  The critical-bit branch (C=1 with an
 * unrecognised option-class) also gets exercised so the reject path
 * runs alongside the accept path.
 *
 * Brick-safety: loopback only inside the private netns (outer sends
 * target 127.0.0.1 inside the grandchild's own netns), one link
 * create/destroy per invocation, all sends MSG_DONTWAIT, netlink ack
 * SO_RCVTIMEO=1s so an unresponsive rtnl can't wedge past child.c's
 * SIGALRM.
 *
 * Latches: ns_unsupported_geneve_rx master gate on userns_run_in_ns()
 * -EPERM (unprivileged userns disabled).
 * shm->geneve_rx_kind_unsupported on RTM_NEWLINK kind="geneve" rejection
 * with the module/CONFIG_GENEVE-absent errno set (EAFNOSUPPORT /
 * EOPNOTSUPP / ENOTSUP / ENOENT / EPROTONOSUPPORT).  Per-kind latch
 * lives in shm because the rejection is observed inside a transient
 * grandchild -- a process-local static would die on _exit and re-attempt
 * the missing kind forever.
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
 * IFLA_GENEVE_* fallbacks.  linux/if_link.h on a stripped sysroot may
 * predate the geneve link-info attributes.  UAPI values are stable
 * per drivers/net/geneve.c and Documentation/networking/geneve.rst.
 */
#ifndef IFLA_GENEVE_ID
#define IFLA_GENEVE_ID			1
#endif
#ifndef IFLA_GENEVE_REMOTE
#define IFLA_GENEVE_REMOTE		2
#endif
#ifndef IFLA_GENEVE_PORT
#define IFLA_GENEVE_PORT		5
#endif

#ifndef ETH_P_TEB
#define ETH_P_TEB			0x6558
#endif

/* Reasonable ceiling for a single rtnl link-create message + payload;
 * geneve RTM_NEWLINK with all attributes set is well under 1 KiB. */
#define GRX_RTNL_BUF			2048

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define GRX_PACKET_BASE			5U

/* Outer packet buffer size.  Outer IPv4 (20) + UDP (8) + GENEVE base
 * (8) + options (up to 252) + inner ethernet (14) + inner IPv4 (20) +
 * slack fits well under 512; leaves headroom for length randomisation. */
#define GRX_PKT_MAX			512

/* GENEVE Opt-Len ceiling in 4-byte units.  Field is 6 bits so the
 * spec ceiling is 63; we rotate a small set of representative values
 * so the option walker sees both short and long declared blobs. */
#define GRX_OPT_LEN_MAX			63U

/* Per-TLV option Length ceiling in 4-byte units (5-bit field).  Same
 * rotation strategy as the outer Opt-Len -- exercise both short and
 * long-per-TLV declared lengths so the inner walker over-reads too. */
#define GRX_TLV_LEN_MAX			31U

/* GENEVE UDP destination port (IANA-assigned, RFC 8926 section 3.3). */
#define GRX_UDP_PORT_GENEVE		6081

/* Loopback endpoints for the private netns. */
#define GRX_V4_LOCAL_BE			(__be32)__builtin_bswap32(0x7f000001U)
#define GRX_V4_REMOTE_BE		(__be32)__builtin_bswap32(0x7f000002U)

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's routing tables, so the op stays disabled
 * for the remainder of this child's lifetime.
 */
static bool ns_unsupported_geneve_rx;

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
	return __atomic_load_n(&shm->geneve_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->geneve_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * IPv4 header + UDP one's-complement 16-bit fold.  Kept local so this
 * file has no dependency on utils/csum plumbing.  Mirrors the same
 * helper in ip_gre-churn.c / esp-crafted-rx.c / fou-gue-mcast-rx.c.
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
 * Build & send RTM_NEWLINK creating a geneve dev with remote pinned to
 * 127.0.0.2 (loopback peer inside the private netns) and a random
 * 24-bit VNI.  Returns 0 on accept, negated errno on rejection, -EIO
 * on local failure.
 */
static int build_geneve_link(struct nl_ctx *ctx, const char *name, __u32 vni)
{
	unsigned char buf[GRX_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	__u32 remote_addr;
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "geneve");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_GENEVE_ID,
			  vni & 0x00ffffffU);
	if (!off)
		return -EIO;

	remote_addr = GRX_V4_REMOTE_BE;
	off = nla_put(buf, off, sizeof(buf), IFLA_GENEVE_REMOTE,
		      &remote_addr, sizeof(remote_addr));
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Draw a GENEVE outer Opt-Len in 4-byte units.  0 is the standard
 * no-options form; 1/2/4/8 are common short blobs; 63 is the spec
 * maximum a 6-bit field can express and forces the walker to consume
 * 252 bytes of TLVs before touching the inner frame.
 */
static uint8_t pick_opt_len(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 2U;
	case 3:  return 4U;
	case 4:  return 8U;
	default: return GRX_OPT_LEN_MAX;
	}
}

/*
 * Draw a per-TLV option Length in 4-byte units.  Same rotation as the
 * outer Opt-Len: the walker sees both short and maximum-length options
 * so both the accept path and the length-overrun reject path get
 * coverage.  Field is 5 bits, spec max is 31.
 */
static uint8_t pick_tlv_len(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 2U;
	case 3:  return 4U;
	default: return GRX_TLV_LEN_MAX;
	}
}

/*
 * Draw a GENEVE Option Class.  0x0000..0x00ff is the IETF-standard
 * range (recognised classes); 0xffff and other high values fall in the
 * experimental / vendor / unknown range, which drives the critical-bit
 * reject path when combined with C=1.
 */
static uint16_t pick_opt_class(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0x0000U;
	case 1:  return 0x0001U;		/* IETF-assigned */
	case 2:  return 0xffffU;		/* experimental / unknown */
	default: return (uint16_t)(rand32() & 0xffffU);
	}
}

/*
 * Draw the inner protocol type stamped into the GENEVE base header
 * "Protocol Type" field.  ETH_P_TEB is the standard L2-payload marker
 * (inner Ethernet frame); ETH_P_IP / ETH_P_IPV6 mark a direct inner
 * L3 payload; other random values walk the unknown-inner-proto reject
 * branch.
 */
static uint16_t pick_inner_ethertype(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0: case 1: case 2: return (uint16_t)ETH_P_TEB;
	case 3:                 return (uint16_t)ETH_P_IP;
	case 4:                 return (uint16_t)ETH_P_IPV6;
	default:                return (uint16_t)(rand32() & 0xffffU);
	}
}

/*
 * Draw an inner-payload truncation length.  {0, 4, 8, 14, 20} shave
 * bytes off the declared inner frame so the post-decap header walk
 * over-reads.  0 leaves nothing after the outer UDP/GENEVE/options
 * blob for the inner parser to consume; 14 slices the inner ethernet
 * header off mid-VLAN; 20 slices an inner IPv4 header off mid-field.
 */
static uint8_t pick_inner_trunc(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0:  return 0U;
	case 1:  return 4U;
	case 2:  return 8U;
	case 3:  return 14U;
	default: return 20U;
	}
}

/*
 * Stamp opt_len*4 bytes of GENEVE options into buf.  Each TLV is a
 * 4-byte header (Option Class 2 + Type 1 + R/R/R+Length 1) followed by
 * TLV-Length*4 payload bytes.  We over-stamp as many TLVs as fit until
 * the declared opt-blob is filled; critical bit rides on the type byte
 * roughly ONE_IN(4) of the time so the C=1-with-unknown-class reject
 * branch is exercised alongside the accept path.  The declared total
 * (opt_len*4) may exceed the actually-written bytes when a per-TLV
 * length walks past the blob -- that is the parse-past-end shape.
 */
static void stamp_geneve_options(uint8_t *buf, uint8_t opt_len)
{
	unsigned int total_bytes = (unsigned int)opt_len * 4U;
	unsigned int off = 0;

	if (total_bytes == 0U)
		return;

	generate_rand_bytes(buf, total_bytes);
	while (off + 4U <= total_bytes) {
		uint16_t opt_class = pick_opt_class();
		uint8_t  tlv_len   = pick_tlv_len();
		uint8_t  crit_bit  = ONE_IN(4) ? 0x80U : 0x00U;
		uint8_t  type      = (uint8_t)((rand32() & 0x7fU) | crit_bit);

		buf[off + 0] = (uint8_t)(opt_class >> 8);
		buf[off + 1] = (uint8_t)(opt_class & 0xffU);
		buf[off + 2] = type;
		buf[off + 3] = tlv_len & 0x1fU;
		off += 4U + (unsigned int)tlv_len * 4U;
	}
}

/*
 * Compose one outer IPv4/UDP/GENEVE frame at buf.  Layout:
 *   [outer IPv4 (20)]
 *   [outer UDP (8, dport=6081)]
 *   [GENEVE base (8): Ver=0 Opt-Len O/C proto VNI]
 *   [GENEVE options (opt_len*4 bytes; may over-declare vs actual)]
 *   [inner frame: inner_ethertype-shaped header, truncated per trunc]
 * Returns total wire length.
 */
static size_t build_geneve_frame(uint8_t *buf, uint8_t opt_len,
				 uint16_t opt_written_cap, bool oam_flag,
				 bool crit_present, uint16_t inner_ethertype,
				 __u32 vni, uint8_t inner_trunc)
{
	struct iphdr *iph;
	struct udphdr *uh;
	size_t off;
	size_t udp_start;
	size_t geneve_start;
	unsigned int opt_declared_bytes = (unsigned int)opt_len * 4U;
	unsigned int opt_written_bytes;
	unsigned int inner_nominal;
	unsigned int inner_emit;

	memset(buf, 0, GRX_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr    = GRX_V4_REMOTE_BE;	/* outer src = tunnel remote */
	iph->daddr    = GRX_V4_LOCAL_BE;	/* outer dst = tunnel local */
	off = sizeof(*iph);

	udp_start = off;
	uh = (struct udphdr *)(buf + off);
	uh->source = 0;
	uh->dest   = htons((uint16_t)GRX_UDP_PORT_GENEVE);
	off += sizeof(*uh);

	geneve_start = off;
	/* Ver (2 top bits) = 0, Opt-Len (6 low bits) in 4-byte units. */
	buf[off + 0] = (uint8_t)(opt_len & 0x3fU);
	/* O (bit 7) = OAM, C (bit 6) = critical options present. */
	buf[off + 1] = (uint8_t)((oam_flag ? 0x80U : 0U) |
				 (crit_present ? 0x40U : 0U));
	/* Protocol Type (2 bytes) */
	buf[off + 2] = (uint8_t)(inner_ethertype >> 8);
	buf[off + 3] = (uint8_t)(inner_ethertype & 0xffU);
	/* VNI (3 bytes) + Rsvd (1 byte).  VNI is shifted left by 8. */
	buf[off + 4] = (uint8_t)((vni >> 16) & 0xffU);
	buf[off + 5] = (uint8_t)((vni >> 8) & 0xffU);
	buf[off + 6] = (uint8_t)(vni & 0xffU);
	buf[off + 7] = 0;
	off += 8;

	/* Actually-written options may be capped BELOW the declared count
	 * so the walker's per-TLV Length or the outer Opt-Len walks past
	 * skb_tail.  opt_written_cap == 0xffff means "write the full
	 * declared blob"; anything less is a deliberate truncation. */
	opt_written_bytes = opt_declared_bytes;
	if (opt_written_cap != 0xffffU &&
	    (unsigned int)opt_written_cap < opt_declared_bytes)
		opt_written_bytes = (unsigned int)opt_written_cap;
	if (opt_written_bytes > 0U) {
		if (off + opt_written_bytes > GRX_PKT_MAX)
			opt_written_bytes = (unsigned int)(GRX_PKT_MAX - off);
		stamp_geneve_options(buf + off, (uint8_t)(opt_written_bytes / 4U));
		off += opt_written_bytes;
	}

	/* Inner header nominal length by ethertype.  ETH_P_TEB (inner
	 * Ethernet) = 14; ETH_P_IP = 20; ETH_P_IPV6 = 40; unknown protos
	 * get a small nominal 14 so the parser sees a partial header. */
	switch (inner_ethertype) {
	case ETH_P_TEB:		inner_nominal = 14U; break;
	case ETH_P_IP:		inner_nominal = 20U; break;
	case ETH_P_IPV6:	inner_nominal = 40U; break;
	default:		inner_nominal = 14U; break;
	}
	inner_emit = (inner_trunc >= inner_nominal)
		     ? 0U : (inner_nominal - inner_trunc);
	if (inner_emit > 0U) {
		if (off + inner_emit > GRX_PKT_MAX)
			inner_emit = (unsigned int)(GRX_PKT_MAX - off);
		if (inner_ethertype == ETH_P_IP && inner_emit >= 20U) {
			struct iphdr *inner = (struct iphdr *)(buf + off);
			inner->version  = 4;
			inner->ihl      = 5;
			inner->ttl      = 64;
			inner->protocol = IPPROTO_UDP;
			inner->saddr    = GRX_V4_LOCAL_BE;
			inner->daddr    = GRX_V4_LOCAL_BE;
			inner->tot_len  = htons((uint16_t)inner_emit);
		} else if (inner_ethertype == ETH_P_IPV6 && inner_emit >= 40U) {
			buf[off + 0]  = 0x60;
			buf[off + 6]  = IPPROTO_UDP;
			buf[off + 7]  = 64;
			buf[off + 8 + 15]  = 1;		/* saddr ::1 */
			buf[off + 24 + 15] = 1;		/* daddr ::1 */
		} else {
			/* ETH_P_TEB and unknown: leave the 14-byte eth
			 * header zeroed; h_proto follows at offset 12 and
			 * stays 0x0000 which walks the drop-unknown branch. */
		}
		off += inner_emit;
	}

	uh->len      = htons((uint16_t)(off - udp_start));
	uh->check    = 0;			/* UDPv4 zero checksum permitted */
	iph->tot_len = htons((uint16_t)off);
	iph->check   = 0;
	iph->check   = csum16_fold(iph, sizeof(*iph));

	(void)geneve_start;
	return off;
}

/*
 * Per-invocation state shared across the geneve_rx_iter_* helpers.
 * Lives on the orchestrator's stack.  Only fields read/written across
 * helper boundaries are lifted here; packet-burst scratch stays on
 * that helper's stack.  Gates encode the partial-state teardown
 * contract.
 */
struct geneve_rx_iter_ctx {
	struct nl_ctx	nl;
	char		ifname[IFNAMSIZ];
	__u32		vni;
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
static int geneve_rx_iter_open_ctx(struct geneve_rx_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.geneve_rx.setup_failed,
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
 * Build phase: pick ifname + VNI, RTM_NEWLINK the geneve dev, resolve
 * its ifindex, bring it up.  Returns 0 if the burst phase should run,
 * -1 otherwise.  On the link-create rejection path, rtnl_link_ops-not-
 * registered errnos latch the kind off (missing CONFIG_GENEVE); other
 * rejections leave the latch alone.
 */
static int geneve_rx_iter_build_link(struct geneve_rx_iter_ctx *ctx)
{
	bool name_from_pool = false;
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
		snprintf(ctx->ifname, sizeof(ctx->ifname), "trgv%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	ctx->vni = rand32() & 0x00ffffffU;

	rc = build_geneve_link(&ctx->nl, ctx->ifname, ctx->vni);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.geneve_rx.link_create_failed,
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
	__atomic_add_fetch(&shm->stats.geneve_rx.link_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex == 0)
		return -1;

	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));

	if (rtnl_setlink_up(&ctx->nl, ctx->ifindex) == 0)
		__atomic_add_fetch(&shm->stats.geneve_rx.link_up_ok,
				   1, __ATOMIC_RELAXED);

	return 0;
}

/*
 * Burst phase: open SOCK_RAW / IPPROTO_RAW, then push BUDGETED+JITTER
 * hand-rolled outer IPv4/UDP(6081)/GENEVE/options/inner frames at
 * 127.0.0.1.  The outer daddr matches the tunnel's local, so the
 * grandchild's own netns loopback delivers the frame back onto
 * geneve_udp_encap_recv.  Each iteration rerolls Opt-Len, per-TLV
 * length, option-class, critical bit, inner ethertype, VNI-mismatch
 * ratio and inner truncation so the decap path sees the full set of
 * variable-option variants.  MSG_DONTWAIT so a backed-up loopback
 * queue can't stall the iteration past the inherited SIGALRM(1s) cap.
 */
static void geneve_rx_iter_send_burst(struct geneve_rx_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (ctx->raw < 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = GRX_V4_LOCAL_BE;

	iters = BUDGETED(CHILD_OP_GENEVE_RX, JITTER_RANGE(GRX_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[GRX_PKT_MAX];
		size_t len;
		ssize_t n;
		uint8_t opt_len         = pick_opt_len();
		uint16_t inner_type     = pick_inner_ethertype();
		uint8_t inner_trunc     = pick_inner_trunc();
		bool oam_flag           = ONE_IN(8);
		bool crit_present       = ONE_IN(3);
		uint16_t opt_written_cap;
		__u32 frame_vni;

		/* ONE_IN(3): declare more options than we actually stamp
		 * (opt_written_cap in bytes below the declared blob), so
		 * the walker over-reads.  Otherwise emit the full blob. */
		if (ONE_IN(3)) {
			unsigned int declared = (unsigned int)opt_len * 4U;

			if (declared > 4U)
				opt_written_cap = (uint16_t)(declared - 4U);
			else
				opt_written_cap = 0U;
		} else {
			opt_written_cap = 0xffffU;
		}

		/* Most frames carry the installed VNI; ONE_IN(4) uses a
		 * mismatched VNI so the geneve_lookup miss path runs. */
		frame_vni = ONE_IN(4) ? (rand32() & 0x00ffffffU) : ctx->vni;

		len = build_geneve_frame(pkt, opt_len, opt_written_cap,
					 oam_flag, crit_present, inner_type,
					 frame_vni, inner_trunc);

		n = sendto(ctx->raw, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.geneve_rx.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown phase: close the raw fd and tear down the geneve dev + rtnl
 * socket.  Each cleanup is gated independently so it is safe to call
 * from any bail-out point in the orchestrator -- including the early
 * returns where ctx is fully zero-initialised -- without leaking the
 * raw fd or sending a dellink for an ifindex that was never resolved.
 * Netns destruction on grandchild exit catches anything left behind.
 */
static void geneve_rx_iter_teardown(struct geneve_rx_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (!ctx->nl_opened)
		return;

	if (ctx->link_added && ctx->ifindex > 0) {
		if (rtnl_dellink(&ctx->nl, ctx->ifindex) == 0)
			__atomic_add_fetch(&shm->stats.geneve_rx.link_del_ok,
					   1, __ATOMIC_RELAXED);
	}
	nl_close(&ctx->nl);
}

struct geneve_rx_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any tunnel
 * devs, raw sockets and packet buffers left behind are reaped along
 * with the namespace.  Return value is ignored by the helper.
 */
static int geneve_rx_in_ns(void *arg)
{
	struct geneve_rx_ctx *cctx = (struct geneve_rx_ctx *)arg;
	struct childdata *child = cctx->child;
	struct geneve_rx_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (geneve_rx_iter_open_ctx(&ctx) == 0 &&
	    geneve_rx_iter_build_link(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		geneve_rx_iter_send_burst(&ctx);
	}

	geneve_rx_iter_teardown(&ctx);
	return 0;
}

bool geneve_rx(struct childdata *child)
{
	struct geneve_rx_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.geneve_rx.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_geneve_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.geneve_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("geneve");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, geneve_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_geneve_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.geneve_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.geneve_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

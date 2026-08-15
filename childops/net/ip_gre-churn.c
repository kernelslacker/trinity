/*
 * ip_gre_churn - v4 gretap / ip_gre RX-path fuzz.  Fills the coverage gap
 * left by ip6gre / ip6erspan / vxlan-encap / ovs-tunnel-vport: those reach
 * the v6 tunnel families and the vxlan/geneve overlays but nothing exercises
 * net/ipv4/ip_gre.c's decap path directly.  The tunnel-RX bugs that live in
 * ip_tunnel_rcv / __iptunnel_pull_header / IP_ECN_decapsulate need an outer
 * IPv4(GRE) + GRE(TEB) frame with a specific inner-Ethernet shape (bare IP,
 * plain Ethernet, VLAN-tagged, truncated-past-a-parsed-length) delivered
 * onto a live gretap dev's RX queue.  Random arg fuzzing cannot assemble
 * that nested header stack by chance.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs a
 * one-shot best-effort modprobe of ip_gre before the userns hop
 * (finit_module needs CAP_SYS_MODULE in init_user_ns).  RTM_NEWLINK creates
 * a gretap dev pinned to 127.0.0.1/127.0.0.2 with a random 32-bit key and a
 * random subset of {csum, seq, key} flags, brings it up, then blasts a
 * BUDGETED+JITTER (base 4) burst of hand-rolled IPv4(GRE)/GRE(TEB)/inner
 * frames via SOCK_RAW / IPPROTO_RAW to 127.0.0.1 — the outer daddr matches
 * the tunnel's local, so gre_rcv catches it, __iptunnel_pull_header strips
 * the outer + GRE + inner-eth, and IP_ECN_decapsulate walks the inner
 * protocol.  Truncation-past-the-parsed-length variants are the specific
 * KMSAN-visible ECN/VLAN uninit bug shape (the KASAN-invisible read past
 * skb_tail into linear-alloc slack); other inner-shape variants surface
 * whatever KASAN-visible ip_gre decap bugs exist.
 *
 * Brick-safety: loopback only inside the private netns (outer sends target
 * 127.0.0.1 inside the grandchild's own netns), one create/destroy per
 * invocation, all sends MSG_DONTWAIT, netlink ack SO_RCVTIMEO=1s so an
 * unresponsive rtnl can't wedge past child.c's SIGALRM.
 *
 * Latches: ns_unsupported_ip_gre master gate on userns_run_in_ns() -EPERM.
 * shm->ip_gre_kind_unsupported on RTM_NEWLINK EAFNOSUPPORT / EOPNOTSUPP /
 * ENOTSUP / ENOENT / EPROTONOSUPPORT (missing CONFIG_NET_IPGRE / absent
 * module).  Per-kind latch lives in shm because the rejection is observed
 * inside the grandchild -- a process-local static would die on _exit and
 * re-attempt the missing kind forever.
 *
 * Detection note: the specific IP_ECN_decapsulate/__vlan_get_protocol
 * uninit read is KMSAN-only-visible (past skb_tail but inside the linear
 * alloc); the default-off sanitiser build won't flag it.  This op still
 * pays: KASAN-visible ip_gre decap bugs land here, and the same frames
 * become substrate for a targeted debugging run on a KMSAN-configured
 * kernel where the uninit-value class is in-scope.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
/* IFLA_GRE_* and GRE flag word bits.  Defined inline because
 * linux/if_tunnel.h conflicts with netinet/ip.h (both define struct iphdr)
 * on this codebase's include set.  UAPI values are stable per
 * Documentation/networking/generic-netlink.rst and net/ipv4/ip_gre.c. */
#define IFLA_GRE_LINK		1
#define IFLA_GRE_IFLAGS		2
#define IFLA_GRE_OFLAGS		3
#define IFLA_GRE_IKEY		4
#define IFLA_GRE_OKEY		5
#define IFLA_GRE_LOCAL		6
#define IFLA_GRE_REMOTE		7

/* GRE flag word bits, network-byte-order 16-bit constants that ride in
 * the first two octets of the GRE header. */
#define GRE_CSUM_FLAG		htons(0x8000)
#define GRE_KEY_FLAG		htons(0x2000)
#define GRE_SEQ_FLAG		htons(0x1000)

#ifndef ETH_P_TEB
#define ETH_P_TEB		0x6558
#endif

/* ERSPAN-specific IFLA_GRE_* attribute ids (UAPI stable, net/ipv4/ip_gre.c). */
#ifndef IFLA_GRE_ERSPAN_INDEX
#define IFLA_GRE_ERSPAN_INDEX		21
#define IFLA_GRE_ERSPAN_VER		22
#endif

/* Reasonable ceiling for a single rtnl message + payload; gretap link
 * create with all attributes set is well under 1 KiB. */
#define RTNL_BUF_BYTES		2048

/* Per-iteration outer-frame burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks to
 * floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap is not
 * gated on socket-buffer backpressure. */
#define IP_GRE_PACKET_BASE	4U

/* Outer packet buffer size.  Outer IPv4 (20) + GRE with optional key/csum/
 * seq (up to 16) + inner Ethernet (14) + optional double VLAN (8) + inner
 * IPv4 (20) fits well under 128; leaves headroom for length randomisation. */
#define OUTER_PKT_MAX		192

enum inner_shape {
	INNER_BARE_IP = 0,	/* eth h_proto=IP + inner IPv4 header */
	INNER_ETH_MIN,		/* eth header only, h_proto=IP, no payload */
	INNER_VLAN_TAGGED,	/* eth h_proto=0x8100 + VLAN tag + inner IP */
	INNER_VLAN_TRUNC,	/* eth h_proto=0x8100 truncated -- ECN/VLAN oob */
	INNER_QINQ_TRUNC,	/* eth h_proto=0x88a8 truncated -- double-tag oob */
	INNER_SHAPE_NR,
};

/* Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we MUST
 * NOT touch the host's routing tables, so the op stays disabled for the
 * remainder of this child's lifetime. */
static bool ns_unsupported_ip_gre;

/* Set once per persistent child after the modprobe attempt runs.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->ip_gre_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->ip_gre_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * IPv4 header checksum, standard one's-complement over the 20-byte
 * header.  Kept local so this file has no dependency on utils/csum
 * plumbing that the other childops don't pull in.
 */
static __u16 ip_csum16(const void *data, size_t len)
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
 * Build & send RTM_NEWLINK creating a gretap dev with local/remote pinned
 * to 127.0.0.1/127.0.0.2 (loopback inside the private netns).  A random
 * subset of {csum, seq, key} rides on IFLA_GRE_IFLAGS/OFLAGS; the key is
 * a 32-bit random value.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
static int build_gretap_link(struct nl_ctx *ctx, const char *name,
			     __u32 key, __be16 flags)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	__u32 local_addr;
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "gretap");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	local_addr  = htonl(0x7f000001U);
	remote_addr = htonl(0x7f000002U);

	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_LOCAL,
		      &local_addr, sizeof(local_addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_REMOTE,
		      &remote_addr, sizeof(remote_addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_IFLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_OFLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	if (flags & GRE_KEY_FLAG) {
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_IKEY,
				  htonl(key));
		if (!off)
			return -EIO;
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_OKEY,
				  htonl(key));
		if (!off)
			return -EIO;
	}

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Stamp the GRE header (flags/version + protocol + optional key/csum/seq
 * fields in the order the RFC prescribes) into buf, returning the new
 * offset.  Caller has already reserved OUTER_PKT_MAX bytes so the writes
 * stay in-bounds for any combination of the three optional fields.
 */
static size_t stamp_gre_header(unsigned char *buf, size_t off,
			       __be16 flags, __u32 key, __u32 seq)
{
	*(__be16 *)(buf + off) = flags;
	off += 2;
	*(__be16 *)(buf + off) = htons(ETH_P_TEB);
	off += 2;
	if (flags & GRE_CSUM_FLAG) {
		*(__be32 *)(buf + off) = 0;	/* checksum + reserved */
		off += 4;
	}
	if (flags & GRE_KEY_FLAG) {
		*(__be32 *)(buf + off) = htonl(key);
		off += 4;
	}
	if (flags & GRE_SEQ_FLAG) {
		*(__be32 *)(buf + off) = htonl(seq);
		off += 4;
	}
	return off;
}

/*
 * Stamp the inner frame (Ethernet header + optional VLAN/QinQ tags +
 * optional inner IPv4) per shape variant into buf, returning the new
 * offset.  The truncation variants deliberately stop mid-header so
 * the decap path parses a header length that is not actually there.
 */
static size_t stamp_inner_frame(unsigned char *buf, size_t off,
				enum inner_shape shape)
{
	unsigned char *p = buf + off;

	memset(p, 0, 12);				/* dst[6] src[6] */
	switch (shape) {
	case INNER_BARE_IP:
	case INNER_ETH_MIN:
		*(__be16 *)(p + 12) = htons(ETH_P_IP);
		off += 14;
		if (shape == INNER_BARE_IP) {
			struct iphdr *inner = (struct iphdr *)(buf + off);
			memset(inner, 0, sizeof(*inner));
			inner->version  = 4;
			inner->ihl      = 5;
			inner->ttl      = 64;
			inner->protocol = IPPROTO_UDP;
			inner->saddr    = htonl(0x7f000001U);
			inner->daddr    = htonl(0x7f000001U);
			inner->tot_len  = htons(sizeof(*inner));
			off += sizeof(*inner);
		}
		break;
	case INNER_VLAN_TAGGED:
		*(__be16 *)(p + 12) = htons(ETH_P_8021Q);
		off += 14;
		*(__be16 *)(buf + off)     = htons(0x0064);	/* pcp/vid */
		*(__be16 *)(buf + off + 2) = htons(ETH_P_IP);
		off += 4;
		break;
	case INNER_VLAN_TRUNC:
		/* h_proto claims VLAN, buffer ends -- ECN/VLAN oob repro. */
		*(__be16 *)(p + 12) = htons(ETH_P_8021Q);
		off += 14;
		break;
	case INNER_QINQ_TRUNC:
		/* h_proto claims 802.1ad, buffer ends -- double-tag oob. */
		*(__be16 *)(p + 12) = htons(0x88a8);
		off += 14;
		break;
	case INNER_SHAPE_NR:
		break;
	}
	return off;
}

/*
 * Per-invocation state shared across the ip_gre_iter_* helpers.  Lives on
 * the orchestrator's stack.  Only fields read/written across helper
 * boundaries are lifted here; packet-burst scratch stays on that helper's
 * stack.  Gates encode the partial-state teardown contract.
 */
struct ip_gre_iter_ctx {
	struct nl_ctx	nl;
	char		ifname[IFNAMSIZ];
	__u32		key;
	__be16		gre_flags;
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
static int ip_gre_iter_open_ctx(struct ip_gre_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_IP_GRE_CHURN,
	};

	if (nl_open(&ctx->nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ip_gre_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->nl_opened = true;

	rtnl_bring_lo_up(&ctx->nl);
	return 0;
}

/*
 * Roll a random subset of {csum, key, seq} bits for the GRE flags word.
 * All-zero is a valid choice (bare gretap TEB frame) and is left in the
 * mix so the "no-options" decap path is exercised too.
 */
static __be16 pick_gre_flags(void)
{
	__be16 f = 0;

	if (ONE_IN(2))
		f |= GRE_KEY_FLAG;
	if (ONE_IN(3))
		f |= GRE_CSUM_FLAG;
	if (ONE_IN(3))
		f |= GRE_SEQ_FLAG;
	return f;
}

/*
 * Build phase: pick ifname + key + flags, RTM_NEWLINK the gretap dev,
 * resolve its ifindex, bring it up.  Returns 0 if the burst phase should
 * run, -1 otherwise.  On the link-create rejection path, rtnl_link_ops-
 * not-registered errnos latch the kind off (missing CONFIG_NET_IPGRE);
 * other rejections leave the latch alone.
 */
static int ip_gre_iter_build_link(struct ip_gre_iter_ctx *ctx)
{
	bool name_from_pool = false;
	int rc;

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
		snprintf(ctx->ifname, sizeof(ctx->ifname), "trgt%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	ctx->key       = rand32();
	ctx->gre_flags = pick_gre_flags();

	rc = build_gretap_link(&ctx->nl, ctx->ifname, ctx->key, ctx->gre_flags);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT) {
			mark_kind_unsupported();
			const enum child_op_type op = ctx->child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->link_added = true;
	__atomic_add_fetch(&shm->stats.ip_gre_churn.link_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex == 0)
		return -1;

	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));

	if (rtnl_setlink_up(&ctx->nl, ctx->ifindex) == 0)
		__atomic_add_fetch(&shm->stats.ip_gre_churn.link_up_ok,
				   1, __ATOMIC_RELAXED);

	return 0;
}

/*
 * Burst phase: open SOCK_RAW / IPPROTO_RAW, then push BUDGETED+JITTER
 * hand-rolled IPv4(GRE) / GRE(TEB) / inner-eth frames at 127.0.0.1.  The
 * outer daddr matches the tunnel's local, so the grandchild's own netns
 * loopback delivers the frame back onto gre_rcv.  Each iteration rerolls
 * the inner shape + total length so the decap path sees the full set of
 * {bare IP, plain eth, VLAN-tagged, truncated-VLAN, truncated-QinQ}
 * variants.  MSG_DONTWAIT so a backed-up loopback queue can't stall the
 * iteration past the inherited SIGALRM(1s) cap.
 */
static void ip_gre_iter_send_burst(struct ip_gre_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (ctx->raw < 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);

	iters = BUDGETED(CHILD_OP_IP_GRE_CHURN, JITTER_RANGE(IP_GRE_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		unsigned char pkt[OUTER_PKT_MAX];
		struct iphdr *iph;
		size_t off;
		enum inner_shape shape;
		ssize_t n;

		memset(pkt, 0, sizeof(pkt));
		iph = (struct iphdr *)pkt;
		iph->version  = 4;
		iph->ihl      = 5;
		iph->ttl      = 64;
		iph->protocol = IPPROTO_GRE;
		iph->saddr    = htonl(0x7f000002U);	/* peer remote */
		iph->daddr    = htonl(0x7f000001U);	/* local */
		off = sizeof(*iph);

		off = stamp_gre_header(pkt, off, ctx->gre_flags,
				       ctx->key, (__u32)i);

		shape = (enum inner_shape)rnd_modulo_u32(INNER_SHAPE_NR);
		off = stamp_inner_frame(pkt, off, shape);

		iph->tot_len = htons((__u16)off);
		iph->check   = 0;
		iph->check   = ip_csum16(iph, sizeof(*iph));

		n = sendto(ctx->raw, pkt, off, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.ip_gre_churn.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown phase: close the raw fd and tear down the gretap dev + rtnl
 * socket.  Each cleanup is gated independently so it is safe to call
 * from any bail-out point in the orchestrator -- including the early
 * returns where ctx is fully zero-initialised -- without leaking the
 * raw fd or sending a dellink for an ifindex that was never resolved.
 * Netns destruction on grandchild exit catches anything left behind.
 */
static void ip_gre_iter_teardown(struct ip_gre_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (!ctx->nl_opened)
		return;

	if (ctx->link_added && ctx->ifindex > 0) {
		if (rtnl_dellink(&ctx->nl, ctx->ifindex) == 0)
			__atomic_add_fetch(&shm->stats.ip_gre_churn.link_del_ok,
					   1, __ATOMIC_RELAXED);
	}
	nl_close(&ctx->nl);
}

/*
 * build_erspan_link - RTM_NEWLINK creating an "erspan" v1 tunnel.
 *
 * Sets both iflags and oflags to GRE_KEY_FLAG | GRE_SEQ_FLAG — the exact
 * pair that net/ipv4/ip_gre.c:erspan_xmit() clears locklessly on every TX,
 * permanently mutating tunnel->parms.o_flags and corrupting subsequent
 * RTM_GETLINK reports.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
static int build_erspan_link(struct nl_ctx *ctx, const char *name, __u32 key)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	__u32 local_addr;
	__u32 remote_addr;
	__be16 flags;
	__be32 erspan_key;
	__u8 erspan_ver;
	__be32 erspan_idx;
	size_t off;
	size_t li_off, id_off;

	flags = GRE_KEY_FLAG | GRE_SEQ_FLAG;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "erspan");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	local_addr  = htonl(0x7f000001U);
	remote_addr = htonl(0x7f000002U);

	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_LOCAL,
		      &local_addr, sizeof(local_addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_REMOTE,
		      &remote_addr, sizeof(remote_addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_IFLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_OFLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;

	erspan_key = htonl(key);
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_IKEY,
		      &erspan_key, sizeof(erspan_key));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_OKEY,
		      &erspan_key, sizeof(erspan_key));
	if (!off)
		return -EIO;

	/* ERSPAN version 1 with index 1. */
	erspan_ver = 1;
	off = nla_put_u8(buf, off, sizeof(buf), IFLA_GRE_ERSPAN_VER, erspan_ver);
	if (!off)
		return -EIO;
	erspan_idx = htonl(1);
	off = nla_put(buf, off, sizeof(buf), IFLA_GRE_ERSPAN_INDEX,
		      &erspan_idx, sizeof(erspan_idx));
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * erspan_getlink_oflags - RTM_GETLINK for @ifindex and extract IFLA_GRE_OFLAGS
 * from the IFLA_LINKINFO/IFLA_INFO_DATA nested payload.
 *
 * Sends a unicast (non-dump) RTM_GETLINK and receives exactly one RTM_NEWLINK
 * reply.  Walks the top-level attribute list looking for IFLA_LINKINFO, then
 * IFLA_INFO_DATA within it, then IFLA_GRE_OFLAGS within that.  Returns 0
 * and stores the flag word via @oflags_out on success; returns -EIO or a
 * negated errno on failure.
 *
 * Attribute walking uses the same open-coded style as the rest of this tree
 * (no NLA_OK/NLA_NEXT macros — those are kernel-internal).
 */
static int erspan_getlink_oflags(struct nl_ctx *ctx, int ifindex,
				 __be16 *oflags_out)
{
	unsigned char req[RTNL_BUF_BYTES];
	unsigned char resp[8192];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	const unsigned char *attrs;
	size_t attrs_len;
	size_t off;
	ssize_t n;

	memset(req, 0, sizeof(req));
	nlh = (struct nlmsghdr *)req;
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;	/* no NLM_F_ACK: one RTM_NEWLINK back */
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;

	if (send(ctx->fd, req, off, 0) != (ssize_t)off)
		return -EIO;

	n = recv(ctx->fd, resp, sizeof(resp), 0);
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)resp;
	if ((size_t)n < nlh->nlmsg_len || nlh->nlmsg_len < NLMSG_HDRLEN)
		return -EIO;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		const struct nlmsgerr *e =
			(const struct nlmsgerr *)NLMSG_DATA(nlh);
		return e->error;
	}
	if (nlh->nlmsg_type != RTM_NEWLINK)
		return -EIO;
	if (nlh->nlmsg_len < NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)))
		return -EIO;

	/* Top-level attrs start after the fixed ifinfomsg. */
	attrs     = (const unsigned char *)resp +
		    NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg));
	attrs_len = nlh->nlmsg_len -
		    NLMSG_HDRLEN - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	/* Walk top-level attrs to find IFLA_LINKINFO. */
	for (off = 0; off + NLA_HDRLEN <= attrs_len; ) {
		const struct nlattr *nla =
			(const struct nlattr *)(attrs + off);
		size_t nla_full;

		if (nla->nla_len < NLA_HDRLEN)
			break;
		nla_full = nla->nla_len;
		if (nla_full > attrs_len - off)
			break;

		if ((nla->nla_type & NLA_TYPE_MASK) == IFLA_LINKINFO) {
			/* Walk IFLA_LINKINFO payload for IFLA_INFO_DATA. */
			const unsigned char *li_pay =
				(const unsigned char *)nla + NLA_HDRLEN;
			size_t li_len = nla_full - NLA_HDRLEN;
			size_t li_off;

			for (li_off = 0; li_off + NLA_HDRLEN <= li_len; ) {
				const struct nlattr *li_nla =
					(const struct nlattr *)(li_pay + li_off);
				size_t li_nla_full;

				if (li_nla->nla_len < NLA_HDRLEN)
					break;
				li_nla_full = li_nla->nla_len;
				if (li_nla_full > li_len - li_off)
					break;

				if ((li_nla->nla_type & NLA_TYPE_MASK) ==
				    IFLA_INFO_DATA) {
					/* Walk IFLA_INFO_DATA for IFLA_GRE_OFLAGS. */
					const unsigned char *id_pay =
						(const unsigned char *)li_nla +
						NLA_HDRLEN;
					size_t id_len =
						li_nla_full - NLA_HDRLEN;
					size_t id_off;

					for (id_off = 0;
					     id_off + NLA_HDRLEN <= id_len; ) {
						const struct nlattr *id_nla =
							(const struct nlattr *)
							(id_pay + id_off);
						size_t id_nla_full;

						if (id_nla->nla_len < NLA_HDRLEN)
							break;
						id_nla_full = id_nla->nla_len;
						if (id_nla_full > id_len - id_off)
							break;

						if ((id_nla->nla_type &
						     NLA_TYPE_MASK) ==
						    IFLA_GRE_OFLAGS &&
						    id_nla_full >=
						    NLA_HDRLEN +
						    sizeof(__be16)) {
							memcpy(oflags_out,
							       (const unsigned char *)id_nla +
							       NLA_HDRLEN,
							       sizeof(__be16));
							return 0;
						}
						id_off += NLA_ALIGN(id_nla_full);
					}
				}
				li_off += NLA_ALIGN(li_nla_full);
			}
		}
		off += NLA_ALIGN(nla_full);
	}
	return -ENODATA;
}

/*
 * ip_gre_erspan_oflags_oracle - ERSPAN tx-invariance oracle.
 *
 * Creates an "erspan" v1 tunnel with GRE_KEY_FLAG | GRE_SEQ_FLAG in
 * IFLA_GRE_OFLAGS, snapshots the reported oflags before and after a TX
 * burst, and fires the oflags_corrupted counter on any mismatch.
 *
 * Background: net/ipv4/ip_gre.c:erspan_xmit() clears IP_TUNNEL_SEQ and
 * IP_TUNNEL_KEY from tunnel->parms.o_flags locklessly in the xmit path,
 * permanently altering the tunnel's reported configuration.  A correct
 * kernel leaves oflags unchanged across transmits that carry no
 * configuration change.
 *
 * The oracle is self-contained: it opens its own rtnl socket, creates a
 * uniquely-named erspan link, tests it, and tears it down.  EOPNOTSUPP /
 * ENOENT from RTM_NEWLINK mean the "erspan" kind is not registered (module
 * absent or kernel config missing); that case is skipped silently.
 */
static void ip_gre_erspan_oflags_oracle(struct childdata *child)
{
	/* Oracle state: independent nl_ctx, erspan link, AF_PACKET fd. */
	struct nl_ctx nl = NL_CTX_INIT;
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_IP_GRE_CHURN,
	};
	char ifname[IFNAMSIZ];
	__u32 key;
	int ifindex;
	int pkt_fd = -1;
	__be16 oflags_before;
	__be16 oflags_after;
	unsigned int burst_i;
	unsigned int burst_n;
	int rc;

	__atomic_add_fetch(&shm->stats.ip_gre_churn.oracle_runs,
			   1, __ATOMIC_RELAXED);

	if (nl_open(&nl, &opts) < 0)
		return;

	rtnl_bring_lo_up(&nl);

	key = rand32();
	snprintf(ifname, sizeof(ifname), "orsp%u",
		 (unsigned int)(rand32() & 0xffffu));

	rc = build_erspan_link(&nl, ifname, key);
	if (rc != 0) {
		/*
		 * EOPNOTSUPP / ENOENT: "erspan" kind not registered.
		 * EAFNOSUPPORT / EPROTONOSUPPORT: tunnel family absent.
		 * All four mean no erspan support; skip silently.
		 */
		nl_close(&nl);
		return;
	}

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex == 0)
		goto out_del;

	/* Snapshot IFLA_GRE_OFLAGS before TX. */
	oflags_before = 0;
	if (erspan_getlink_oflags(&nl, ifindex, &oflags_before) != 0)
		goto out_del;

	/* Bring the tunnel up so ndo_start_xmit is reachable. */
	rtnl_setlink_up(&nl, ifindex);

	/*
	 * TX burst via AF_PACKET/SOCK_RAW injected directly into the
	 * erspan interface.  ERSPAN is a L2 (ARPHRD_ETHER) tunnel, so
	 * AF_PACKET frames go straight into erspan_xmit() — the path
	 * that unconditionally clears IP_TUNNEL_KEY and IP_TUNNEL_SEQ
	 * from tunnel->parms.o_flags on every transmit on affected kernels.
	 */
	pkt_fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (pkt_fd >= 0) {
		unsigned char frame[64];
		struct sockaddr_ll sll;

		memset(frame, 0, sizeof(frame));
		/* Minimal Ethernet frame: dst/src all-zeros, EtherType=IP. */
		frame[12] = 0x08;	/* ETH_P_IP big-endian */
		frame[13] = 0x00;

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex  = ifindex;

		burst_n = 8;
		for (burst_i = 0; burst_i < burst_n; burst_i++)
			sendto(pkt_fd, frame, sizeof(frame), MSG_DONTWAIT,
			       (struct sockaddr *)&sll, sizeof(sll));

		close(pkt_fd);
		pkt_fd = -1;
	}

	/* Snapshot IFLA_GRE_OFLAGS after TX. */
	oflags_after = 0;
	if (erspan_getlink_oflags(&nl, ifindex, &oflags_after) != 0)
		goto out_del;

	/*
	 * Invariance check: oflags must survive a TX burst unchanged.
	 * A mismatch means the kernel mutated the tunnel's reported
	 * configuration — the lockless o_flags corruption in erspan_xmit().
	 */
	if (oflags_before != oflags_after)
		__atomic_add_fetch(&shm->stats.ip_gre_churn.oflags_corrupted,
				   1, __ATOMIC_RELAXED);

out_del:
	if (ifindex > 0)
		rtnl_dellink(&nl, ifindex);
	nl_close(&nl);
	(void)child;
}

struct ip_gre_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any tunnel
 * devs, raw sockets and packet buffers left behind are reaped along
 * with the namespace.  Return value is ignored by the helper.
 */
static int ip_gre_in_ns(void *arg)
{
	struct ip_gre_ctx *cctx = (struct ip_gre_ctx *)arg;
	struct childdata *child = cctx->child;
	struct ip_gre_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (ip_gre_iter_open_ctx(&ctx) == 0 &&
	    ip_gre_iter_build_link(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		ip_gre_iter_send_burst(&ctx);
	}

	ip_gre_iter_teardown(&ctx);

	/*
	 * ERSPAN oflags invariance oracle: create a separate "erspan" v1
	 * tunnel, snapshot oflags before and after a TX burst, fire the
	 * corruption counter on any mismatch.  Runs unconditionally inside
	 * this private netns — the oracle uses its own link name so it
	 * does not interfere with the gretap link above even if both are
	 * alive simultaneously (they are not: teardown runs first).
	 */
	if (!kind_unsupported())
		ip_gre_erspan_oflags_oracle(child);

	return 0;
}

bool ip_gre_churn(struct childdata *child)
{
	struct ip_gre_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.ip_gre_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ip_gre)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.ip_gre_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("ip_gre");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, ip_gre_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_ip_gre = true;
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.ip_gre_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.ip_gre_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

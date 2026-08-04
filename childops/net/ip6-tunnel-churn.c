/*
 * ip6_tunnel_churn - drive the ip6ip6 tunnel error and transmit
 * decode paths that unmodified syscall fuzzing never reaches.
 *
 * Two lanes, both against a small ip6ip6 tunnel created via rtnetlink
 * inside a private user + net namespace so the persistent fuzz child
 * never mutates its own credentials or the host namespace stack.
 *
 * Lane 1 (ip6ip6_err(): stale skb->cb[] on ICMP quote re-inject).
 *   Raw AF_INET6 IPPROTO_ICMPV6 socket in the private netns sends
 *   crafted ICMPv6 Destination-Unreachable / Packet-Too-Big /
 *   Parameter-Problem messages whose quoted-packet body carries an
 *   ip6ip6 (nexthdr 41) header addressed to the tunnel's remote
 *   endpoint.  ip6ip6_err() resolves the originating tunnel and
 *   forwards the ICMP quote to the inner-protocol err handler.
 *   Historical shape: ip6ip6_err() did not memset(IPCB(skb2)) before
 *   the re-inject while the sibling ip4ip6_err() at
 *   net/ipv6/ip6_tunnel.c:612 already does.  A stale skb->cb[] then
 *   reaches the inner handler carrying whatever the outer decode
 *   scribbled.  Quoted-packet length, quoted extension-header shape,
 *   and ICMPv6 type/code are churned so the inner handler runs
 *   against several distinct cb[] silhouettes.  Random syscall
 *   fuzzing essentially never assembles (a) a raw ICMPv6 socket in a
 *   netns that owns a live ip6ip6 tunnel, (b) a well-formed ICMPv6
 *   error frame quoting an inner packet whose nexthdr matches the
 *   tunnel's outer proto, and (c) endpoint addresses that steer the
 *   quote through the tunnel err handler in a single child's life.
 *   Lane 1 stands alone -- it does not depend on lane 2's underlay
 *   listener; a lane-2 setup failure does not gate lane 1.
 *
 * Lane 2 (ip6_tnl_xmit(): missing skb_cow_head() on cloned head).
 *   An AF_PACKET SOCK_RAW listener with protocol=ETH_P_ALL is bound
 *   to loopback before TX drives the tunnel.  ETH_P_ALL attachment
 *   forces dev_queue_xmit_nit() to clone every egress skb, so by the
 *   time ip6_tnl_xmit() runs on the tunnel's underlay the skb head
 *   is shared with the tap-side clone.  A missing skb_cow_head() on
 *   the transmit path then mutates the header of a shared clone.
 *   TX is a bounded UDPv6 sendmsg burst against an IPv6 address
 *   assigned to the tunnel device so the datagrams flow through
 *   ip6_tnl_xmit() rather than lo's local-out shortcut.  Oracle
 *   note: KASAN does not fire on a shared-clone write (no OOB,
 *   nothing freed); the sibling refrag childops don't yet supply a
 *   generic shared-write oracle either.  This lane exists to plant
 *   the shape reliably so a future shared-write detector has
 *   something to observe; today it is coverage-only.
 *
 * Config-gated / degrade-to-noop latches (all in shm, all
 * false -> true only, RELAXED atomic load/store idempotent):
 *   ip6_tunnel_churn_ns_unsupported          userns_run_in_ns()
 *                                            -EPERM (hardened userns
 *                                            policy).
 *   ip6_tunnel_churn_ns_unsupported_ip6tnl   RTM_NEWLINK "ip6tnl"
 *                                            rejected with
 *                                            EAFNOSUPPORT /
 *                                            EPROTONOSUPPORT /
 *                                            ENOTSUP / EOPNOTSUPP /
 *                                            ENOENT (kernel built
 *                                            without CONFIG_IPV6_TUNNEL).
 *   ip6_tunnel_churn_ns_unsupported_af_packet  AF_PACKET socket()
 *                                            refused (no CONFIG_PACKET).
 *
 * Self-bounding: one create + two-lane drive + teardown per outer
 * invocation.  ONE_IN(8) gate keeps per-child cost low.  All I/O is
 * MSG_DONTWAIT; the rtnl socket carries SO_RCVTIMEO=1s so an
 * unresponsive kernel cannot wedge us past child.c's SIGALRM(1s).
 * Loopback only (private netns).
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_tunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/*
 * UAPI fallbacks.  linux/if_tunnel.h ships IFLA_IPTUN_* on every
 * sysroot trinity targets, but a stripped build host may not; the
 * numeric values match the upstream UAPI.  Inline shims rather than a
 * topic-specific compat-iftunnel.h: three defines total, well under
 * the ~30 LOC / 3-consumer threshold for a dedicated header.
 */
#ifndef IFLA_IPTUN_LINK
#define IFLA_IPTUN_LINK			1
#define IFLA_IPTUN_LOCAL		2
#define IFLA_IPTUN_REMOTE		3
#define IFLA_IPTUN_PROTO		9
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6			41
#endif

/* Internal lane picker.  One iteration drives both lanes back to back
 * so a single ip6tnl create + teardown covers both bug shapes; the
 * error-lane sender and the xmit-lane listener share the tunnel and
 * the netns via the outer setup helpers. */
enum ip6_tunnel_lane {
	CHILDOP_IP6_TUNNEL_LANE_ERR,
	CHILDOP_IP6_TUNNEL_LANE_XMIT,
	CHILDOP_IP6_TUNNEL_LANE_NR,
};

#define IP6T_BUF			1024
#define IP6T_ERR_BURST_BASE		4U
#define IP6T_ERR_BURST_CAP		12U
#define IP6T_XMIT_BURST_BASE		4U
#define IP6T_XMIT_BURST_CAP		12U
#define IP6T_XMIT_PAYLOAD_MAX		512U
#define IP6T_IP6HDR_LEN			40U
#define IP6T_ICMP6_HDR_LEN		8U

/* fdaa:6:1::1 local / fdaa:6:1::2 remote for the tunnel underlay so
 * the packets stay off any accidentally-configured link-local scope. */
static const uint8_t ip6t_local[16] = {
	0xfd, 0xaa, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};
static const uint8_t ip6t_remote[16] = {
	0xfd, 0xaa, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};
/* Inner-overlay /64 sitting on the tunnel netdev so UDPv6 sendto the
 * peer address routes through ip6_tnl_xmit() rather than the lo
 * local-out shortcut. */
static const uint8_t ip6t_inner_local[16] = {
	0xfd, 0xaa, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};
static const uint8_t ip6t_inner_remote[16] = {
	0xfd, 0xaa, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

/* Per-subsystem config-absent gates live in shm.  The write sites sit
 * inside the userns_run_in_ns() grandchild body -- a process-local
 * static would die with the grandchild on _exit() and every subsequent
 * invocation would re-attempt the same unsupported RTM_NEWLINK /
 * AF_PACKET socket() forever (latch-in-grandchild bug).  RELAXED
 * atomic load/store is safe: only false -> true, idempotent write. */
static bool ns_unsupported(void)
{
	return __atomic_load_n(&shm->ip6_tunnel_churn_ns_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported(void)
{
	__atomic_store_n(&shm->ip6_tunnel_churn_ns_unsupported, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_ip6tnl(void)
{
	return __atomic_load_n(&shm->ip6_tunnel_churn_ns_unsupported_ip6tnl,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_ip6tnl(void)
{
	__atomic_store_n(&shm->ip6_tunnel_churn_ns_unsupported_ip6tnl, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_af_packet(void)
{
	return __atomic_load_n(&shm->ip6_tunnel_churn_ns_unsupported_af_packet,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_af_packet(void)
{
	__atomic_store_n(&shm->ip6_tunnel_churn_ns_unsupported_af_packet, true,
			 __ATOMIC_RELAXED);
}

/*
 * RTM_NEWLINK "ip6tnl" carrying IFLA_IPTUN_PROTO=IPPROTO_IPV6
 * (ip6ip6 mode), IFLA_IPTUN_LOCAL/REMOTE = fdaa:6:1::1/::2, and
 * IFLA_IPTUN_LINK = ifindex(lo) so the underlay is loopback.
 */
static int ip6t_rtnl_create_ip6tnl(struct nl_ctx *rtnl, const char *ifname,
				   int underlay_idx)
{
	unsigned char buf[IP6T_BUF];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;
	__u8 proto = IPPROTO_IPV6;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "ip6tnl");
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_IPTUN_LINK,
			  (__u32)underlay_idx);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_IPTUN_LOCAL,
		      ip6t_local, sizeof(ip6t_local));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_IPTUN_REMOTE,
		      ip6t_remote, sizeof(ip6t_remote));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_IPTUN_PROTO,
		      &proto, sizeof(proto));
	if (!off) return -EIO;
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * RTM_NEWADDR ipv6 /prefix on ifindex.  Same shape as
 * bridge_ip6_refrag_fraggap's helper; independent copy so the two
 * sibling ops do not share translation-unit state.
 */
static int ip6t_rtnl_addr_add_v6(struct nl_ctx *rtnl, int idx,
				 const uint8_t *addr, __u8 prefix)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = prefix;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, addr, 16);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, addr, 16);
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Build one ICMPv6 error frame whose quoted-packet body wraps an
 * ip6ip6 (nexthdr 41) inner header addressed to the tunnel's remote
 * endpoint.  The frame is written directly into `buf`; caller ships
 * it via sendto() on a raw ICMPv6 socket.
 *
 * Layout:
 *   [icmp6 hdr (8B, type/code/csum/mtu-or-ptr)]
 *   [quoted outer IPv6 hdr (40B, nexthdr=41)]
 *   [optional quoted extension header stub (8B)]
 *   [quoted inner IPv6 hdr (variable, may be truncated)]
 *
 * Returns bytes written; the kernel fills the ICMPv6 checksum on the
 * raw send.
 */
static size_t ip6t_build_icmp6_error(unsigned char *buf, size_t cap,
				     unsigned int variant)
{
	size_t off = 0;
	uint8_t type;
	uint8_t code;
	unsigned int quote_ext_kind = variant & 0x3U;
	unsigned int quote_inner_len_pick = (variant >> 2) & 0x7U;
	size_t quote_inner_len;
	size_t ext_len = 0;
	uint8_t outer_nexthdr;

	if (cap < IP6T_ICMP6_HDR_LEN + IP6T_IP6HDR_LEN + 8U)
		return 0;

	/* Rotate over the three quote-carrying ICMPv6 error types so the
	 * error handler runs against different quote-consumers per burst. */
	switch ((variant >> 5) & 0x3U) {
	case 0: type = 1; code = 0; break;	/* Destination Unreachable */
	case 1: type = 2; code = 0; break;	/* Packet Too Big */
	default: type = 4; code = 0; break;	/* Parameter Problem */
	}

	buf[off + 0] = type;
	buf[off + 1] = code;
	buf[off + 2] = 0; buf[off + 3] = 0;	/* checksum (kernel stamps) */
	/* union body: MTU for type=2 / pointer for type=4 / unused for type=1 */
	buf[off + 4] = 0; buf[off + 5] = 0;
	buf[off + 6] = 0x05; buf[off + 7] = 0xa0;	/* mtu=1440 or ptr */
	off += IP6T_ICMP6_HDR_LEN;

	/* Quoted outer IPv6 header addressed local -> remote so
	 * ip6ip6_err() resolves the tunnel via the __ipv6_addr_equal on
	 * remote and hands the quote to ip6ip6_rcv's err handler. */
	outer_nexthdr = IPPROTO_IPV6;			/* 41 */
	if (quote_ext_kind == 1)
		outer_nexthdr = 0;			/* Hop-by-Hop */
	else if (quote_ext_kind == 2)
		outer_nexthdr = 60;			/* Destination */

	memset(buf + off, 0, IP6T_IP6HDR_LEN);
	buf[off + 0] = 0x60;
	buf[off + 6] = outer_nexthdr;
	buf[off + 7] = 64;				/* hop limit */
	memcpy(buf + off + 8, ip6t_local, 16);
	memcpy(buf + off + 24, ip6t_remote, 16);
	off += IP6T_IP6HDR_LEN;

	if (quote_ext_kind == 1 || quote_ext_kind == 2) {
		if (off + 8U > cap)
			return 0;
		buf[off + 0] = IPPROTO_IPV6;		/* next-hdr = 41 */
		buf[off + 1] = 0;			/* hdr_ext_len */
		buf[off + 2] = 0x01;			/* PadN */
		buf[off + 3] = 0x04;
		memset(buf + off + 4, 0, 4);
		ext_len = 8U;
		off += ext_len;
	}

	/* Sweep the quoted inner-header length across {0, 4, 8, 20, 40}
	 * so ip6ip6_err()'s inner re-inject runs against several
	 * pskb_may_pull() gates.  cb[] contamination is what the bug is
	 * about; the inner-length sweep is defensive so a future kernel
	 * that adds a pskb_may_pull() to ip6ip6_err() still walks a
	 * distribution of quote-lengths. */
	switch (quote_inner_len_pick) {
	case 0: quote_inner_len = 0; break;
	case 1: quote_inner_len = 4; break;
	case 2: quote_inner_len = 8; break;
	case 3: quote_inner_len = 20; break;
	default: quote_inner_len = 40; break;
	}
	if (off + quote_inner_len > cap)
		quote_inner_len = cap - off;

	if (quote_inner_len > 0) {
		memset(buf + off, 0, quote_inner_len);
		if (quote_inner_len >= 1)
			buf[off + 0] = 0x60;		/* version=6 */
		off += quote_inner_len;
	}
	(void)ext_len;					/* ext_len used only for readability */

	return off;
}

/* Per-invocation state shared across the extracted phase helpers.
 * fd fields default to -1 via the orchestrator's designated
 * initialiser so the teardown helper can close them unconditionally
 * regardless of which earlier phase bailed. */
struct ip6t_iter_ctx {
	char			ifname[IFNAMSIZ];
	struct nl_ctx		rtnl;
	int			tnl_idx;
	int			tap_fd;
	int			icmp_fd;
	int			udp_fd;
	bool			tnl_added;
	struct childdata	*child;
	/* Accumulates own-body raw-syscall count; published once via
	 * childop_direct_syscalls_add() at ip6_tunnel_churn_in_ns() exit. */
	unsigned long		direct_calls;
};

/*
 * Phase 1: pick a per-invocation interface name + open the rtnl
 * socket.  Interface name derives from a single 16-bit random suffix
 * for stable in-netns correlation.
 */
static int ip6t_iter_setup(struct ip6t_iter_ctx *ctx)
{
	struct nl_open_opts rtnl_opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	unsigned int rng;

	if (nl_open(&ctx->rtnl, &rtnl_opts) < 0)
		return -1;
	rng = rand32() & 0xffffU;
	snprintf(ctx->ifname, sizeof(ctx->ifname), "it6t%u", rng);
	rtnl_bring_lo_up(&ctx->rtnl);
	return 0;
}

/*
 * Phase 2: RTM_NEWLINK the ip6tnl (mode ip6ip6) over lo, bring it up,
 * assign the inner-overlay /64 so UDPv6 sendto the peer routes
 * through ip6_tnl_xmit().  On the ip6tnl create rejection latch
 * ns_unsupported_ip6tnl (kernel built without CONFIG_IPV6_TUNNEL) so
 * siblings stop probing.
 */
static int ip6t_iter_create_tnl(struct ip6t_iter_ctx *ctx)
{
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;
	unsigned int lo_idx;

	lo_idx = if_nametoindex("lo");
	if (lo_idx == 0)
		return -1;
	rc = ip6t_rtnl_create_ip6tnl(&ctx->rtnl, ctx->ifname, (int)lo_idx);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -EPROTONOSUPPORT ||
		    rc == -ENOENT) {
			mark_ns_unsupported_ip6tnl();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->tnl_added = true;
	ctx->tnl_idx = (int)if_nametoindex(ctx->ifname);
	if (ctx->tnl_idx <= 0)
		return -1;
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->tnl_idx);
	(void)ip6t_rtnl_addr_add_v6(&ctx->rtnl, ctx->tnl_idx,
				    ip6t_inner_local, 64);
	(void)ip6t_rtnl_addr_add_v6(&ctx->rtnl, (int)lo_idx,
				    ip6t_local, 128);
	return 0;
}

/*
 * Phase 3 (lane 1): raw AF_INET6 IPPROTO_ICMPV6 socket bound to the
 * netns; send a bounded burst of ICMPv6 error frames whose quote
 * carries an ip6ip6 inner packet.  Destination is the loopback local
 * address so the frame is delivered locally and ip6ip6_err() runs on
 * the inner ip6ip6 quote.  Each iteration draws a fresh (type, code,
 * quote_ext, quote_inner_len) tuple so the burst sweeps distinct
 * cb[] silhouettes at the inner-handler re-inject.
 */
static void ip6t_iter_lane_err(struct ip6t_iter_ctx *ctx)
{
	unsigned char buf[IP6T_BUF];
	struct sockaddr_in6 dst;
	unsigned int iters, i;

	ctx->icmp_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
			      IPPROTO_ICMPV6);
	ctx->direct_calls++;
	if (ctx->icmp_fd < 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	memcpy(&dst.sin6_addr, ip6t_local, 16);

	iters = IP6T_ERR_BURST_BASE +
		rnd_modulo_u32(IP6T_ERR_BURST_CAP - IP6T_ERR_BURST_BASE + 1U);
	for (i = 0; i < iters; i++) {
		size_t len;

		len = ip6t_build_icmp6_error(buf, sizeof(buf), rand32());
		if (!len)
			continue;
		(void)sendto(ctx->icmp_fd, buf, len, MSG_DONTWAIT,
			     (struct sockaddr *)&dst, sizeof(dst));
		ctx->direct_calls++;
	}
}

/*
 * Phase 4 (lane 2): AF_PACKET SOCK_RAW listener with ETH_P_ALL bound
 * to loopback forces dev_queue_xmit_nit() to clone every egress skb;
 * a UDPv6 sendmsg burst against the tunnel's inner peer then drives
 * ip6_tnl_xmit() with a shared/cloned skb head.  ETH_P_ALL binding
 * on the underlay (lo) is what forces the clone; the UDP peer sits
 * on the tunnel netdev so the datagram flows through ip6_tnl_xmit()
 * rather than lo's local-out shortcut.
 */
static void ip6t_iter_lane_xmit(struct ip6t_iter_ctx *ctx)
{
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	struct sockaddr_ll bind_sll;
	struct sockaddr_in6 peer;
	unsigned char payload[IP6T_XMIT_PAYLOAD_MAX];
	unsigned int iters, i;
	unsigned int lo_idx;

	if (ns_unsupported_af_packet())
		return;

	ctx->tap_fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			     htons(ETH_P_ALL));
	ctx->direct_calls++;
	if (ctx->tap_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			mark_ns_unsupported_af_packet();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}
	lo_idx = if_nametoindex("lo");
	if (lo_idx == 0)
		return;
	memset(&bind_sll, 0, sizeof(bind_sll));
	bind_sll.sll_family   = AF_PACKET;
	bind_sll.sll_protocol = htons(ETH_P_ALL);
	bind_sll.sll_ifindex  = (int)lo_idx;
	ctx->direct_calls++;
	(void)bind(ctx->tap_fd, (struct sockaddr *)&bind_sll,
		   sizeof(bind_sll));

	ctx->udp_fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC,
			     IPPROTO_UDP);
	ctx->direct_calls++;
	if (ctx->udp_fd < 0)
		return;

	memset(&peer, 0, sizeof(peer));
	peer.sin6_family = AF_INET6;
	peer.sin6_port   = htons(9);			/* discard */
	memcpy(&peer.sin6_addr, ip6t_inner_remote, 16);

	iters = IP6T_XMIT_BURST_BASE +
		rnd_modulo_u32(IP6T_XMIT_BURST_CAP -
			       IP6T_XMIT_BURST_BASE + 1U);
	for (i = 0; i < iters; i++) {
		size_t payload_len;

		payload_len = 64U + rnd_modulo_u32(IP6T_XMIT_PAYLOAD_MAX - 64U);
		generate_rand_bytes(payload, payload_len);
		(void)sendto(ctx->udp_fd, payload, payload_len, MSG_DONTWAIT,
			     (struct sockaddr *)&peer, sizeof(peer));
		ctx->direct_calls++;
	}
}

/*
 * Phase 5: unified teardown.  Runs on every exit path; all fds
 * default to -1 via the designated initialiser.  RTM_DELLINK the
 * tunnel while the rtnl socket is still open so cleanup_net's
 * teardown does not carry the tunnel through the namespace drop.
 */
static void ip6t_iter_teardown(struct ip6t_iter_ctx *ctx)
{
	if (ctx->udp_fd >= 0) {
		ctx->direct_calls++;
		close(ctx->udp_fd);
	}
	if (ctx->tap_fd >= 0) {
		unsigned char drain[256];

		while (recv(ctx->tap_fd, drain, sizeof(drain),
			    MSG_DONTWAIT) > 0)
			;
		ctx->direct_calls++;
		close(ctx->tap_fd);
	}
	if (ctx->icmp_fd >= 0) {
		ctx->direct_calls++;
		close(ctx->icmp_fd);
	}
	if (ctx->rtnl.fd >= 0) {
		if (ctx->tnl_added && ctx->tnl_idx > 0)
			(void)rtnl_dellink(&ctx->rtnl, ctx->tnl_idx);
		nl_close(&ctx->rtnl);
	}
}

/*
 * Per-invocation body that runs inside the grandchild's private net
 * namespace.  Executed by userns_run_in_ns(CLONE_NEWNET); the
 * grandchild's userns + netns are torn down on _exit() so any link,
 * rtnetlink socket and tunnel state left behind is reaped along with
 * the namespace.  Explicit teardown still runs so the tunnel is
 * dropped before the grandchild exits and the setup_accepted /
 * data_path counters advance only when a lane actually drove work.
 */
static int ip6_tunnel_churn_in_ns(void *arg)
{
	struct childdata *child = (struct childdata *)arg;
	struct ip6t_iter_ctx ctx = {
		.rtnl    = { .fd = -1 },
		.tap_fd  = -1,
		.icmp_fd = -1,
		.udp_fd  = -1,
		.child   = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ip6t_iter_setup(&ctx) != 0)
		goto out;
	if (ip6t_iter_create_tnl(&ctx) != 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* Lane 1 stands alone -- a lane-2 setup failure does not gate
	 * lane 1, and vice versa.  Both lanes share ctx->rtnl / the
	 * netns / the tunnel; each lane's fds live in ctx and are
	 * dropped in the unified teardown regardless of ordering. */
	ip6t_iter_lane_err(&ctx);
	ip6t_iter_lane_xmit(&ctx);

out:
	ip6t_iter_teardown(&ctx);
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_calls);
	return 0;
}

bool ip6_tunnel_churn(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if (ns_unsupported() || ns_unsupported_ip6tnl())
		return true;
	if (!ONE_IN(8))
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ip6_tunnel_churn_in_ns, child);
	if (rc == -EPERM) {
		mark_ns_unsupported();
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	/* Transient grandchild setup failure (fork, id-map write,
	 * secondary unshare).  Skip without latching -- not policy. */
	(void)rc;
	return true;
}

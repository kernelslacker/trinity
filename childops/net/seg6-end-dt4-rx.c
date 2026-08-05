/*
 * seg6_end_dt4_rx - SRv6 End.DT4 crafted-RX fuzz.
 *
 * Targets the seg6_local input path input_action_end_dt4() in
 * net/ipv6/seg6_local.c.  The decap hands the freshly-uncovered inner
 * IPv4 packet to ip_route_input_noref() and then dst_input() without
 * running ip_rcv_core() first, so the skb still carries the outer
 * frame's IP6CB overlay in skb->cb[].  Any downstream code that reads
 * the IPv4-side IPCB (options offset in particular) is looking at
 * stale bytes -- __ip_options_echo() reads a bogus option offset from
 * that overlay and copies past its saved-options allocation.  On a
 * KASAN build this manifests as a slab-out-of-bounds write; no extra
 * oracle infra required.
 *
 * Reach shape per invocation (inside a userns_run_in_ns grandchild --
 * identity userns + CLONE_NEWNET, _exit reaps):
 *   1. Bring lo up in the private netns; write net.ipv6.conf.all.
 *      seg6_enabled and net.ipv6.conf.lo.seg6_enabled to 1.
 *   2. RTM_NEWLINK kind="vrf" with IFLA_VRF_TABLE=100, then
 *      RTM_SETLINK IFF_UP so a VRF backed by table 100 exists for the
 *      End.DT4 vrftable lookup.
 *   3. RTM_NEWROUTE family=AF_INET6 dst=<sid>/128 dev=lo
 *      RTA_ENCAP_TYPE=LWTUNNEL_ENCAP_SEG6_LOCAL, nested RTA_ENCAP:
 *        SEG6_LOCAL_ACTION=SEG6_LOCAL_ACTION_END_DT4
 *        SEG6_LOCAL_VRFTABLE=100
 *      When the kernel refuses the encap type as unsupported
 *      (CONFIG_IPV6_SEG6_LWTUNNEL=n on this build), we accept the
 *      wasted round-trip and skip the burst.  The target fleet is
 *      built with the feature so this path is expected to install.
 *   4. Open AF_PACKET SOCK_RAW bound to lo with sll_protocol=ETH_P_IPV6
 *      and blast a BUDGETED+JITTER burst of hand-rolled
 *      Ether/IPv6(nh=43,dst=<sid>)/SRH/inner-IPv4-with-IP-options
 *      frames.  Each iteration rerolls:
 *        - SRH segment count (1..4) and segments_left (drives
 *          "still routing" vs "at final SID" paths -- End.DT4 fires on
 *          the final SID)
 *        - inner IPv4 IHL (5..8), forcing 0/8/16/20 bytes of options
 *        - inner IPv4 option payloads: timestamp (type 68) and
 *          record-route (type 7) with pointer values swept around the
 *          option-length boundary so __ip_options_echo() sees a
 *          plausible-looking IPCB overlay when it reads the bogus
 *          stale bytes
 *        - inner IPv4 TTL = 1 or a bad dst so the post-decap forward
 *          path elicits an ICMP error -- __ip_options_echo() runs on
 *          the ICMP reply path
 *
 * Brick-safety: loopback only inside the private netns (frames target
 * lo inside the grandchild's own netns), sysctl writes are per-net
 * (net.ipv6.conf.* is registered per-net so the host tree is
 * untouched), all sends MSG_DONTWAIT, netlink ack SO_RCVTIMEO=1s so an
 * unresponsive rtnl can't wedge past child.c's SIGALRM.
 *
 * Latches: ns_unsupported_seg6_end_dt4_rx master gate on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled).  No shm
 * latch for the seg6_local kind: the gate is CONFIG_IPV6_SEG6_LWTUNNEL
 * =y (verified on the target config); a rare RTM_NEWROUTE rejection just wastes a
 * netlink round-trip per invocation.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"

/*
 * UAPI fallbacks.  Stable per include/uapi/linux/lwtunnel.h and
 * include/uapi/linux/seg6_local.h; supply defaults so an old sysroot
 * doesn't fail the -Werror build.
 */
#ifndef LWTUNNEL_ENCAP_SEG6_LOCAL
#define LWTUNNEL_ENCAP_SEG6_LOCAL	7
#endif
#ifndef SEG6_LOCAL_ACTION
#define SEG6_LOCAL_ACTION		1
#endif
#ifndef SEG6_LOCAL_VRFTABLE
#define SEG6_LOCAL_VRFTABLE		9
#endif
#ifndef SEG6_LOCAL_ACTION_END_DT4
#define SEG6_LOCAL_ACTION_END_DT4	8
#endif
#ifndef IFLA_VRF_TABLE
#define IFLA_VRF_TABLE			1
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING			43
#endif

#define SED_VRF_TABLE			100U

/* Outer packet buffer: Eth(14) + IPv6(40) + SRH(8 + 16*4) + inner
 * IPv4 header + max options (60 total) + slack.  256 is comfortable. */
#define SED_PKT_MAX			256U

/* SRH per-hop capacity: fits inside SED_PKT_MAX after outer IPv6 +
 * inner IPv4 with max options.  4 is enough to walk the segment-count
 * decision branches. */
#define SED_SRH_MAX_SEGS		4U

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define SED_PACKET_BASE			5U

#define SED_ETH_HLEN			14U

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's routing tables, so the op stays disabled
 * for the remainder of this child's lifetime.
 */
static bool ns_unsupported_seg6_end_dt4_rx;

/*
 * SID prefix for the End.DT4 route.  fd00::/8 is ULA -- private,
 * non-routable, will never leak past the grandchild's netns.  The
 * low 64 bits are randomised per invocation so successive iterations
 * don't reinstall the same route.
 */
static void draw_sid(struct in6_addr *sid)
{
	uint8_t *b = sid->s6_addr;
	unsigned int i;

	memset(sid, 0, sizeof(*sid));
	b[0] = 0xfd;
	b[1] = 0x00;
	for (i = 8; i < 16; i++)
		b[i] = (uint8_t)(rand32() & 0xffU);
}

/*
 * Write "1" to /proc/sys/net/ipv6/conf/all/seg6_enabled and
 * /proc/sys/net/ipv6/conf/lo/seg6_enabled inside the current (private)
 * netns.  Per-net sysctls; the host tree is untouched.  Best-effort:
 * on kernels without CONFIG_IPV6_SEG6_LWTUNNEL the files are absent
 * (ENOENT) and the caller falls through to the netlink install which
 * will also fail, so the burst is skipped.
 */
static void sed_enable_seg6(unsigned long *direct_calls_p)
{
	static const char * const paths[] = {
		"/proc/sys/net/ipv6/conf/all/seg6_enabled",
		"/proc/sys/net/ipv6/conf/lo/seg6_enabled",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		int fd = open(paths[i], O_WRONLY | O_CLOEXEC);
		ssize_t n;

		(*direct_calls_p)++;
		if (fd < 0)
			continue;
		n = write(fd, "1", 1);
		(*direct_calls_p)++;
		(void)n;
		close(fd);
	}
}

/*
 * Build & send RTM_NEWLINK creating a VRF dev named `name` bound to
 * routing table `table`.  Returns 0 on accept, negated errno on
 * rejection, or -EIO on local failure.
 */
static int build_vrf_link(struct nl_ctx *ctx, const char *name, __u32 table)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "vrf");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_VRF_TABLE, table);
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build & send RTM_NEWROUTE installing an IPv6 /128 route for `sid`
 * pointing at lo, with lwtunnel encap SEG6_LOCAL, action End.DT4,
 * vrftable=100.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
static int build_seg6local_route(struct nl_ctx *ctx,
				 const struct in6_addr *sid, int lo_ifindex)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t off, encap_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET6;
	rtm->rtm_dst_len  = 128;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	off = nla_put(buf, off, sizeof(buf), RTA_DST, sid, sizeof(*sid));
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF,
			  (__u32)lo_ifindex);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf), RTA_ENCAP_TYPE,
			  LWTUNNEL_ENCAP_SEG6_LOCAL);
	if (!off)
		return -EIO;

	encap_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), RTA_ENCAP);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), SEG6_LOCAL_ACTION,
			  SEG6_LOCAL_ACTION_END_DT4);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), SEG6_LOCAL_VRFTABLE,
			  SED_VRF_TABLE);
	if (!off)
		return -EIO;

	nla_nest_end(buf, encap_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Draw an IHL (in 4-byte words) for the inner IPv4 header.  5 is a
 * base header with no options; 6..8 adds 4/12/20 option bytes.  The
 * mixed distribution keeps the burst dominated by option-bearing
 * frames so __ip_options_echo() runs, while still exercising the
 * no-options branch as a control.
 */
static uint8_t sed_pick_ihl(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0:			return 5U;
	case 1:			return 6U;
	case 2:			return 7U;
	default:		return 8U;
	}
}

/*
 * Draw the number of segments in the outer SRH.  1..SED_SRH_MAX_SEGS.
 * DT4 fires when segments_left == 0 (already at the final SID), so
 * the burst below stamps segments_left independently.
 */
static uint8_t sed_pick_nseg(void)
{
	return (uint8_t)(1U + rnd_modulo_u32(SED_SRH_MAX_SEGS));
}

/*
 * Stamp IPv4 options into the inner header at `optbase` for `optbytes`
 * bytes.  Rotates timestamp (type 68) and record-route (type 7) with
 * pointer values swept around the option-length boundary; these are
 * the option types __ip_options_echo() actually walks.  Options are
 * padded to `optbytes` with NOP (type 1) if the payload is shorter,
 * then closed with EOOL (type 0).
 */
static void sed_stamp_ipv4_options(uint8_t *optbase, unsigned int optbytes)
{
	unsigned int off = 0;
	uint8_t type;
	uint8_t optlen;

	if (optbytes == 0U)
		return;

	memset(optbase, 1U, optbytes);	/* NOPs by default */

	type = (rand32() & 1U) ? 68U /* timestamp */ : 7U /* record-route */;
	optlen = (uint8_t)(optbytes > 12U ? 12U : optbytes);
	if (optlen < 4U)
		optlen = (uint8_t)optbytes;

	optbase[off + 0] = type;
	if (optlen >= 2U)
		optbase[off + 1] = optlen;
	if (optlen >= 3U) {
		/* Pointer is 1-based into the option; sweep it around the
		 * option-length boundary so the parser exercises both the
		 * in-range and past-end branches. */
		uint8_t ptr_bias = (uint8_t)(rand32() % 5U);
		optbase[off + 2] = (uint8_t)(optlen - 3U + ptr_bias);
	}
	if (optlen >= 4U)
		optbase[off + 3] = 0U;	/* overflow/flag byte for timestamp */

	off += optlen;
	if (off < optbytes)
		optbase[optbytes - 1U] = 0U;	/* EOOL */
}

/*
 * Compose one Ether / IPv6(nh=routing) / SRH / inner-IPv4(with options)
 * frame at buf.  Returns total wire length or 0 on layout overflow.
 *
 * Layout:
 *   [ether (14): dst=zero (PACKET_HOST on lo), src=locally-administered, type=0x86dd]
 *   [outer IPv6 (40): nh=43, hop_limit=64, saddr=::1, daddr=sid]
 *   [SRH (8 + 16*nseg): routing_type=4, segments_left, first_segment,
 *                       segments[0..nseg-1], segments[0]=sid]
 *   [inner IPv4 (ihl*4): options as above, TTL=1 to elicit ICMP TIME
 *                        EXCEEDED so the icmp reply path runs
 *                        __ip_options_echo() over the crafted options]
 */
static size_t build_seg6_frame(uint8_t *buf, const struct in6_addr *sid,
			       uint8_t nseg, uint8_t segs_left, uint8_t ihl)
{
	unsigned int off = 0;
	unsigned int i;
	unsigned int srh_bytes;
	unsigned int inner_bytes;
	unsigned int inner_off;
	unsigned int payload_len;
	unsigned int optbytes;

	if (nseg == 0U || nseg > SED_SRH_MAX_SEGS)
		return 0U;
	if (ihl < 5U || ihl > 8U)
		return 0U;

	srh_bytes   = 8U + 16U * nseg;
	inner_bytes = (unsigned int)ihl * 4U;

	if (SED_ETH_HLEN + 40U + srh_bytes + inner_bytes > SED_PKT_MAX)
		return 0U;

	memset(buf, 0, SED_PKT_MAX);

	/* Ethernet header. */
	off += 6;				/* dst stays zero: PACKET_HOST on lo */
	buf[off + 0] = 0x02;			/* locally-administered src */
	off += 6;
	buf[off + 0] = 0x86;			/* ethertype IPv6 = 0x86dd */
	buf[off + 1] = 0xdd;
	off += 2;

	/* Outer IPv6 header. */
	payload_len = srh_bytes + inner_bytes;
	buf[off + 0] = 0x60;			/* version=6 */
	buf[off + 4] = (uint8_t)((payload_len >> 8) & 0xffU);
	buf[off + 5] = (uint8_t)(payload_len & 0xffU);
	buf[off + 6] = IPPROTO_ROUTING;		/* nh = 43 */
	buf[off + 7] = 64U;			/* hop_limit */
	/* saddr = ::1 */
	buf[off + 8 + 15] = 1U;
	/* daddr = sid */
	memcpy(buf + off + 24, sid, 16);
	off += 40;

	/* SRH.  routing_type = 4 (Segment Routing).  first_segment /
	 * last_entry is nseg - 1 (the array index of the last entry). */
	buf[off + 0] = IPPROTO_IPIP;		/* inner is IPv4 */
	buf[off + 1] = (uint8_t)((srh_bytes / 8U) - 1U);	/* hdrlen */
	buf[off + 2] = 4U;			/* SR routing_type */
	buf[off + 3] = segs_left;		/* segments_left */
	buf[off + 4] = (uint8_t)(nseg - 1U);	/* first_segment */
	buf[off + 5] = 0U;			/* flags */
	buf[off + 6] = 0U;			/* tag hi */
	buf[off + 7] = 0U;			/* tag lo */
	off += 8;
	/* segments[0] must be the SID (final SID reached when
	 * segments_left == 0 -- End.DT4 fires on that). */
	memcpy(buf + off, sid, 16);
	off += 16;
	for (i = 1; i < nseg; i++) {
		memset(buf + off, 0, 16);
		off += 16;
	}

	/* Inner IPv4 header, ihl in 4-byte words. */
	inner_off = off;
	buf[off + 0] = (uint8_t)(0x40U | (ihl & 0x0fU));	/* version=4 | ihl */
	buf[off + 1] = 0U;					/* TOS */
	buf[off + 2] = (uint8_t)((inner_bytes >> 8) & 0xffU);	/* tot_len hi */
	buf[off + 3] = (uint8_t)(inner_bytes & 0xffU);		/* tot_len lo */
	buf[off + 4] = 0U; buf[off + 5] = 0U;			/* id */
	buf[off + 6] = 0U; buf[off + 7] = 0U;			/* frag_off */
	buf[off + 8] = 1U;					/* TTL=1 */
	buf[off + 9] = IPPROTO_UDP;				/* proto */
	buf[off + 10] = 0U; buf[off + 11] = 0U;			/* csum */
	/* saddr = 127.0.0.2, daddr = 127.0.0.1 -- both loopback so the
	 * post-decap forward path runs but nothing escapes the netns. */
	buf[off + 12] = 127U; buf[off + 13] = 0U;
	buf[off + 14] = 0U;   buf[off + 15] = 2U;
	buf[off + 16] = 127U; buf[off + 17] = 0U;
	buf[off + 18] = 0U;   buf[off + 19] = 1U;

	optbytes = inner_bytes - 20U;
	if (optbytes > 0U)
		sed_stamp_ipv4_options(buf + inner_off + 20U, optbytes);

	off += inner_bytes;
	return off;
}

struct sed_iter_ctx {
	struct nl_ctx		nl;
	int			lo_ifindex;
	int			raw;
	bool			nl_opened;
	struct in6_addr		sid;
	bool			route_added;
	int			vrf_ifindex;
	bool			vrf_added;
	struct childdata	*child;
	/* Accumulates own-body raw-syscall count; published once via
	 * childop_direct_syscalls_add() at seg6_end_dt4_rx_in_ns() exit. */
	unsigned long		direct_calls;
};

/*
 * Open the rtnl socket and bring lo up inside the private netns.
 * Returns 0 on success, -1 on failure.  Teardown is safe on failure
 * because it gates on ctx->nl_opened.
 */
static int sed_open_ctx(struct sed_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0)
		return -1;
	ctx->nl_opened = true;
	rtnl_bring_lo_up(&ctx->nl);
	return 0;
}

/*
 * Build phase: enable per-netns seg6 sysctls, create a VRF for table
 * SED_VRF_TABLE, install a seg6local End.DT4 route pointing at lo for
 * a freshly-drawn SID.  Returns 0 if the burst phase should run, -1
 * otherwise.
 */
static int sed_build(struct sed_iter_ctx *ctx)
{
	char vrf_name[IFNAMSIZ];

	sed_enable_seg6(&ctx->direct_calls);

	ctx->lo_ifindex = (int)if_nametoindex("lo");
	if (ctx->lo_ifindex <= 0)
		return -1;

	snprintf(vrf_name, sizeof(vrf_name), "trsedvrf%u",
		 (unsigned int)(rand32() & 0xffffU));
	if (build_vrf_link(&ctx->nl, vrf_name, SED_VRF_TABLE) == 0) {
		ctx->vrf_ifindex = (int)if_nametoindex(vrf_name);
		if (ctx->vrf_ifindex > 0) {
			ctx->vrf_added = true;
			(void)rtnl_setlink_up(&ctx->nl, ctx->vrf_ifindex);
		}
	}

	draw_sid(&ctx->sid);
	if (build_seg6local_route(&ctx->nl, &ctx->sid, ctx->lo_ifindex) != 0)
		return -1;
	ctx->route_added = true;
	return 0;
}

/*
 * Burst phase: open AF_PACKET / SOCK_RAW bound to lo with
 * sll_protocol=ETH_P_IPV6, then push BUDGETED+JITTER hand-rolled
 * Ether/IPv6/SRH/inner-IPv4-with-options frames at lo.  The outer
 * daddr matches the seg6local route we just installed so
 * input_action_end_dt4() runs on delivery.  Each iteration rerolls
 * segment count, segments_left, and inner IHL (option length) so the
 * post-decap options walk sees the full option-length distribution.
 * MSG_DONTWAIT so a backed-up loopback queue can't stall the iteration
 * past the inherited SIGALRM(1s) cap.
 */
static void sed_burst(struct sed_iter_ctx *ctx)
{
	struct sockaddr_ll sll;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_IPV6));
	ctx->direct_calls++;
	if (ctx->raw < 0)
		return;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ctx->lo_ifindex;
	ctx->direct_calls++;
	if (bind(ctx->raw, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return;

	iters = BUDGETED(CHILD_OP_SEG6_END_DT4_RX,
			 JITTER_RANGE(SED_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[SED_PKT_MAX];
		size_t len;
		uint8_t nseg = sed_pick_nseg();
		uint8_t ihl  = sed_pick_ihl();
		/* segments_left is drawn independently: 0 fires End.DT4;
		 * nseg-1 walks the "still routing, decrement seg_left"
		 * branch; a wild value past first_segment covers the
		 * validity-check reject path. */
		uint8_t seg_left;
		struct sockaddr_ll dst;

		switch (rnd_modulo_u32(4)) {
		case 0: case 1:	seg_left = 0U; break;
		case 2:		seg_left = (uint8_t)(nseg - 1U); break;
		default:	seg_left = (uint8_t)(nseg + 4U); break;
		}

		len = build_seg6_frame(pkt, &ctx->sid, nseg, seg_left, ihl);
		if (len == 0U)
			continue;

		memset(&dst, 0, sizeof(dst));
		dst.sll_family   = AF_PACKET;
		dst.sll_protocol = htons(ETH_P_IPV6);
		dst.sll_ifindex  = ctx->lo_ifindex;
		dst.sll_halen    = 6;
		memset(dst.sll_addr, 0xff, 6);

		(void)sendto(ctx->raw, pkt, len, MSG_DONTWAIT,
			     (struct sockaddr *)&dst, sizeof(dst));
		ctx->direct_calls++;
	}
}

/*
 * Teardown phase.  Each cleanup is gated independently so it is safe
 * to call from any bail-out point in the orchestrator -- including
 * the early returns where ctx is fully zero-initialised -- without
 * leaking the raw fd, the seg6local route, or the VRF link.  Netns
 * destruction on grandchild exit catches anything left behind.
 */
static void sed_teardown(struct sed_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (!ctx->nl_opened)
		return;

	if (ctx->vrf_added && ctx->vrf_ifindex > 0)
		(void)rtnl_dellink(&ctx->nl, ctx->vrf_ifindex);

	nl_close(&ctx->nl);
}

struct sed_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the raw
 * socket, per-net seg6 sysctls, seg6local route and VRF link left
 * behind are reaped along with the namespace.  Return value is
 * ignored by the helper.
 */
static int seg6_end_dt4_rx_in_ns(void *arg)
{
	struct sed_ctx *cctx = (struct sed_ctx *)arg;
	struct sed_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = cctx->child,
	};
	const enum child_op_type op = cctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (sed_open_ctx(&ctx) == 0 && sed_build(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		sed_burst(&ctx);
	}

	sed_teardown(&ctx);
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_calls);
	return 0;
}

bool seg6_end_dt4_rx(struct childdata *child)
{
	struct sed_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_seg6_end_dt4_rx)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, seg6_end_dt4_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_seg6_end_dt4_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
	return true;
}

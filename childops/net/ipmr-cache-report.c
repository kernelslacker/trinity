/*
 * ipmr_cache_report - exercise the IPv4 multicast routing NOCACHE
 * upcall path that delivers a struct igmpmsg cache report to the
 * mrouted control socket / NETLINK_ROUTE RTNLGRP_IPV4_MROUTE_R group.
 *
 * The historical bug class here is a stack/heap infoleak in the kernel
 * mroute upcall builder: the cache-report descriptor was emitted to
 * userspace without first scrubbing the trailing pad bytes between the
 * struct fields, leaking ~6 uninitialised bytes of kernel memory per
 * NOCACHE upcall.  Upstream fixed this in 4f34002e2e37
 * ("ipv4: ipmr: fix tiny info leak in __ipmr_fill_mroute()") by
 * memset()ing the whole report buffer before populating it.  Reaching
 * the upcall requires (a) MRT_INIT on a raw IGMP socket, (b) at least
 * one VIF installed via MRT_ADD_VIF, and (c) a multicast packet
 * destined for a group with no MFC entry — i.e. the assemble-a-coherent
 * mroute-control-plane sequence the random fuzzer effectively never
 * produces.
 *
 * Sequence (per invocation):
 *   1. Enter a private net namespace via userns_run_in_ns(): a
 *      transient grandchild fork installs an identity user namespace
 *      plus a fresh CLONE_NEWNET, runs the body below, and _exit()s
 *      so the kernel reaps the VIF, MFC entries, raw IGMP socket,
 *      netlink listener and lo address with the grandchild's netns.
 *      MRT_INIT (exclusive per netns) therefore can't conflict with
 *      anything on the host, and nothing strands across invocations.
 *      The persistent fuzz child never changes its own credentials
 *      or namespace stack, so the cap-drop oracle keeps observing
 *      the host credential profile.  Helper -EPERM (hardened userns
 *      policy refused CLONE_NEWUSER) latches the childop off for the
 *      remainder of this child's lifetime; -EAGAIN (transient setup
 *      failure: fork, id-map write, secondary unshare) skips the
 *      iteration without latching.
 *   2. Open a NETLINK_ROUTE socket with nl_groups including
 *      RTNLGRP_IPV4_MROUTE_R, the multicast group the kernel uses to
 *      broadcast cache reports.  Best-effort — we don't require the
 *      ack to land for the upcall path itself to fire.
 *   3. Bring lo up via RTM_NEWLINK so the kernel will accept
 *      127.0.0.1 as a vifc_lcl_addr and so the multicast send actually
 *      egresses an interface.
 *   4. Open AF_INET / SOCK_RAW / IPPROTO_IGMP and setsockopt
 *      IPPROTO_IP/MRT_INIT.  -EPERM here means the host has dropped
 *      CAP_NET_ADMIN before we got into the netns (trinity auto-drops
 *      to nobody when started as root); bump the eperm counter and
 *      latch — this op is dead for the rest of the child's life.
 *   5. MRT_ADD_VIF with vifc_vifi=0, vifc_lcl_addr=127.0.0.1,
 *      vifc_rmt_addr=0.  No flags so the kernel takes the local
 *      interface lookup branch.
 *   6. socket(AF_INET, SOCK_DGRAM); set IP_MULTICAST_IF to 127.0.0.1;
 *      sendto a tiny payload to a random group address with no MFC
 *      entry installed (uniformly drawn from 224/4 minus the
 *      well-known 224.0.0.0/24 link-local block, so the kernel doesn't
 *      short-circuit on the local-control set).  This is the trigger
 *      that walks ipmr_cache_unresolved -> ipmr_cache_report ->
 *      __ipmr_fill_mroute -- the NOCACHE upcall path that historically
 *      leaked the pad bytes.
 *   7. Best-effort drain on the netlink socket so a message that did
 *      land doesn't pile up indefinitely.  Discard payload (trinity is
 *      fuzz, not analyser).
 *   8. MRT_DONE, then close the raw + netlink fds.  netns destroy on
 *      child exit catches anything left behind.
 *
 * Self-bounding: one full create / emit / teardown cycle per
 * invocation.  Inner emit loop BUDGETED+JITTER around base 5 with
 * STORM_BUDGET_NS 200 ms wall-clock cap and a 32-iteration ceiling so
 * even an unbounded burst can't stall past the SIGALRM(1s) cap
 * inherited from child.c.  All sockets non-blocking on the send side;
 * netlink recv uses MSG_DONTWAIT.  Single VIF per netns, no other
 * netdev kinds touched.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
/* RTNLGRP_IPV4_MROUTE_R is the cache-report multicast group, added to
 * UAPI relatively recently.  Stripped sysroots may predate it; the ID
 * is stable. */
#ifndef RTNLGRP_IPV4_MROUTE_R
#define RTNLGRP_IPV4_MROUTE_R	30
#endif

#define RTNL_BUF_BYTES		512
#define IPMR_RECV_BURST		4

/* Inner-loop budget tuning — same shape as the other loop-style
 * childops in this directory. */
#define IPMR_LOOP_BASE		5U
#define IPMR_LOOP_FLOOR		8U
#define IPMR_LOOP_CAP		32U
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared. */

/* Latched per-child: userns_run_in_ns() returned -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we MUST NOT touch the host's IPv4 mroute
 * tables or install a VIF against the host's lo, so the op stays
 * disabled for the remainder of this child's lifetime.  Transient
 * setup failures (helper return -EAGAIN) do not set this -- they may
 * not recur on the next iteration. */
static bool ns_userns_unsupported_ipmr_cache_report;
/* CONFIG-absent + EPERM latches live in shm
 * (shm->ipmr_cache_report_ns_unsupported / shm->ipmr_cache_report_ns_eperm).
 * Set inside the grandchild's address space when the raw IGMP socket
 * or MRT_INIT setsockopt returns a structural-unsupport errno
 * (EAFNOSUPPORT / EPROTONOSUPPORT / EOPNOTSUPP / ENOPROTOOPT /
 * EADDRINUSE), or an EPERM (MRT_INIT / raw-socket -- trinity has
 * dropped CAP_NET_ADMIN before entering the grandchild).  The write
 * site sits inside the userns_run_in_ns() grandchild -- a
 * process-local static would die with the grandchild on _exit() and
 * every subsequent invocation would re-attempt the same unsupported
 * probe forever (latch-in-grandchild bug).  Living in shm lets the
 * probe be paid once per fleet rather than once per grandchild.
 * RELAXED atomic load/store from multiple grandchildren is safe --
 * only false -> true, and the write is idempotent. */

static bool ns_unsupported_ipmr_cache_report(void)
{
	return __atomic_load_n(&shm->ipmr_cache_report_ns_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_ipmr_cache_report(void)
{
	__atomic_store_n(&shm->ipmr_cache_report_ns_unsupported, true,
			 __ATOMIC_RELAXED);
}

static bool ns_eperm_ipmr_cache_report(void)
{
	return __atomic_load_n(&shm->ipmr_cache_report_ns_eperm,
			       __ATOMIC_RELAXED);
}

static void mark_ns_eperm_ipmr_cache_report(void)
{
	__atomic_store_n(&shm->ipmr_cache_report_ns_eperm, true,
			 __ATOMIC_RELAXED);
}

/* Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot. */
struct ipmr_cache_report_ctx {
	struct childdata *child;
};

/*
 * Open NETLINK_ROUTE bound to the IPv4 mroute cache-report multicast
 * group.  Returns 0 on success; the upcall path itself still fires
 * even if no listener is around, so this is best-effort.  On older
 * kernels without RTNLGRP_IPV4_MROUTE_R the bind() will EINVAL, so
 * retry once with no group subscription.
 */
static int open_mroute_listener(struct nl_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto     = NETLINK_ROUTE,
		.groups    = 1U << (RTNLGRP_IPV4_MROUTE_R - 1),
		.caller_op = CHILD_OP_IPMR_CACHE_REPORT,
	};

	if (nl_open(ctx, &opts) == 0)
		return 0;

	opts.groups = 0;
	return nl_open(ctx, &opts);
}

/*
 * Pick a multicast group address that the kernel won't have any MFC
 * entry for.  239/8 is the administratively-scoped block — safe to
 * fuzz, won't trip any well-known control protocol.  224/8 random
 * draws skip the link-local 224.0.0.0/24 control block (224.0.0.x is
 * special-cased and short-circuits before the upcall path).
 */
static __be32 pick_nocache_group(void)
{
	unsigned int r = rand32();
	unsigned int b1, b2, b3;

	if (r & 1U) {
		/* 239.b1.b2.b3 */
		b1 = (r >> 1)  & 0xff;
		b2 = (r >> 9)  & 0xff;
		b3 = (r >> 17) & 0xff;
		return htonl((239U << 24) | (b1 << 16) | (b2 << 8) | b3);
	}
	/* 224.b1.b2.b3, b1 != 0 to dodge link-local control */
	b1 = ((r >> 1) & 0xff) | 1U;
	b2 = (r >> 9)  & 0xff;
	b3 = (r >> 17) & 0xff;
	return htonl((224U << 24) | (b1 << 16) | (b2 << 8) | b3);
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the VIF,
 * MFC entries, raw IGMP socket, netlink listener and lo address are
 * reaped by the kernel along with the namespace.  Return value is
 * ignored by the helper.
 */
static int ipmr_cache_report_in_ns(void *arg)
{
	struct ipmr_cache_report_ctx *cctx =
		(struct ipmr_cache_report_ctx *)arg;
	struct childdata *child = cctx->child;
	struct vifctl vc;
	struct sockaddr_in dst;
	struct in_addr lcl;
	struct nl_ctx nl = NL_CTX_INIT;
	int raw = -1;
	int udp = -1;
	int one = 1;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	/* Count raw kernel entries not covered by the netlink transport:
	 * socket(), setsockopt() on the raw IGMP socket, sendto() on the
	 * multicast UDP socket, and if_nametoindex("lo") inside
	 * rtnl_bring_lo_up().  The RTM_NEWLINK/mroute netlink transport
	 * (open_mroute_listener via nl_open/nl_send_recv/nl_close and
	 * rtnl_bring_lo_up via nl_send_recv) is published by nl_close()
	 * via opts.caller_op; those counts are not duplicated here.
	 * Published once at exit via childop_direct_syscalls_add(). */
	unsigned long direct_calls = 0;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	(void)open_mroute_listener(&nl);		/* best-effort */
	rtnl_bring_lo_up(&nl);
	/* if_nametoindex("lo"): socket + ioctl + close. */
	direct_calls += 3;

	raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	direct_calls++;
	if (raw < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			mark_ns_unsupported_ipmr_cache_report();
		else if (errno == EPERM)
			mark_ns_eperm_ipmr_cache_report();
		goto out;
	}

	direct_calls++;
	if (setsockopt(raw, IPPROTO_IP, MRT_INIT, &one, sizeof(one)) < 0) {
		if (errno == EPERM) {
			__atomic_add_fetch(&shm->stats.ipmr_cache_report.eperm,
					   1, __ATOMIC_RELAXED);
			mark_ns_eperm_ipmr_cache_report();
		} else if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
			   errno == EADDRINUSE) {
			mark_ns_unsupported_ipmr_cache_report();
		}
		goto out;
	}

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi      = 0;
	vc.vifc_flags     = 0;
	vc.vifc_threshold = 1;
	vc.vifc_lcl_addr.s_addr = htonl(INADDR_LOOPBACK);
	vc.vifc_rmt_addr.s_addr = 0;
	direct_calls++;
	if (setsockopt(raw, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc)) < 0)
		goto done;

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	direct_calls++;
	if (udp < 0)
		goto done;

	lcl.s_addr = htonl(INADDR_LOOPBACK);
	(void)setsockopt(udp, IPPROTO_IP, IP_MULTICAST_IF, &lcl, sizeof(lcl));
	direct_calls++;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_IPMR_CACHE_REPORT,
			 JITTER_RANGE(IPMR_LOOP_BASE));
	if (iters < IPMR_LOOP_FLOOR)
		iters = IPMR_LOOP_FLOOR;
	if (iters > IPMR_LOOP_CAP)
		iters = IPMR_LOOP_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < iters; i++) {
		const char payload[8] = { 'i','p','m','r','c','r','p','t' };
		ssize_t r;

		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		__atomic_add_fetch(&shm->stats.ipmr_cache_report.iters, 1,
				   __ATOMIC_RELAXED);

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(1024 + (rand32() & 0x3fff));
		dst.sin_addr.s_addr = pick_nocache_group();

		r = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		direct_calls++;
		if (r >= 0)
			__atomic_add_fetch(&shm->stats.ipmr_cache_report.emit_ok,
					   1, __ATOMIC_RELAXED);

		if (nl.fd >= 0) {
			unsigned char rbuf[RTNL_BUF_BYTES];
			unsigned int j;

			for (j = 0; j < IPMR_RECV_BURST; j++) {
				if (recv(nl.fd, rbuf, sizeof(rbuf),
					 MSG_DONTWAIT) < 0)
					break;
			}
		}
	}

done:
	(void)setsockopt(raw, IPPROTO_IP, MRT_DONE, NULL, 0);
	direct_calls++;

out:
	if (udp >= 0)
		close(udp);
	if (raw >= 0)
		close(raw);
	if (nl.fd >= 0)
		nl_close(&nl);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return 0;
}

/* ------------------------------------------------------------------ *
 * RTM_GETROUTE / IP_PKTINFO arm                                       *
 *                                                                      *
 * Exercises the ipmr_cache_report() → IP_PKTINFO delivery path        *
 * exposed by commit bb7403655b3c ("ipmr: support IP_PKTINFO on cache   *
 * report IGMP msg").  The relevant overlap: ipmr_cache_report() clones *
 * the arriving skb's cb[] into the new report skb; the mrouted raw     *
 * socket's receive path reads that cb[] as IPCB(), so the ipi_ifindex  *
 * field sits over the same bytes as NETLINK_CB(skb).portid when the    *
 * trigger skb was synthesised by the RTM_GETROUTE handler.  KASAN /    *
 * a garbage ipi_ifindex in the recvmsg PKTINFO cmsg are the oracle.    *
 *                                                                       *
 * Sequence (per invocation, inside private netns):                     *
 *   1. MRT_INIT + IP_PKTINFO on the raw IGMP socket — IP_PKTINFO on   *
 *      the mrouted socket is what makes the overlap consumable.        *
 *   2. MRT_ADD_VIF as in the NOCACHE arm.                              *
 *   3. Loop:                                                            *
 *      a. Send RTM_GETROUTE (AF_INET, RTA_DST=mcast group) via         *
 *         NETLINK_ROUTE — exercises ipmr_rtm_getroute and potentially  *
 *         builds a report skb whose cb[] carries NETLINK_CB portid.    *
 *      b. sendto() a UDP datagram to the same group (no MFC entry) to  *
 *         fire the NOCACHE upcall and deliver the report to raw.       *
 *      c. recvmsg() on raw with a cmsg buffer; harvest IP_PKTINFO and  *
 *         bump pktinfo_ok so the stat surface shows coverage.          *
 * ------------------------------------------------------------------ */

#define IPMR_PKTINFO_LOOP_BASE	5U
#define IPMR_PKTINFO_LOOP_FLOOR	8U
#define IPMR_PKTINFO_LOOP_CAP	32U
#define IPMR_PKTINFO_BUDGET_NS	200000000L	/* 200 ms */

static bool ns_userns_unsupported_ipmr_getroute_pktinfo;

static bool ns_unsupported_ipmr_getroute_pktinfo(void)
{
	return __atomic_load_n(&shm->ipmr_getroute_pktinfo_ns_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_ipmr_getroute_pktinfo(void)
{
	__atomic_store_n(&shm->ipmr_getroute_pktinfo_ns_unsupported, true,
			 __ATOMIC_RELAXED);
}

static bool ns_eperm_ipmr_getroute_pktinfo(void)
{
	return __atomic_load_n(&shm->ipmr_getroute_pktinfo_ns_eperm,
			       __ATOMIC_RELAXED);
}

static void mark_ns_eperm_ipmr_getroute_pktinfo(void)
{
	__atomic_store_n(&shm->ipmr_getroute_pktinfo_ns_eperm, true,
			 __ATOMIC_RELAXED);
}

struct ipmr_getroute_pktinfo_ctx {
	struct childdata *child;
};

/*
 * Build and send an RTM_GETROUTE query for the given multicast
 * destination address on the nl_ctx socket.  Best-effort: the response
 * (RTM_NEWROUTE or NLMSG_ERROR) is not consumed here — the caller
 * drains or ignores it.  Returns 0 on success, -1 on send failure.
 */
static int send_getroute_query(struct nl_ctx *ctx, __be32 dst_addr)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	rtm;
		unsigned char	attrs[RTA_LENGTH(4)];
	} req;
	struct rtattr *rta;
	ssize_t sent;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_type  = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq   = nl_seq_next(ctx);
	req.rtm.rtm_family  = AF_INET;
	req.rtm.rtm_dst_len = 32;

	rta = (struct rtattr *)req.attrs;
	rta->rta_type = RTA_DST;
	rta->rta_len  = (__u16)RTA_LENGTH(4);
	memcpy(RTA_DATA(rta), &dst_addr, 4);

	req.nlh.nlmsg_len = (__u32)(NLMSG_ALIGN(NLMSG_HDRLEN +
					    sizeof(req.rtm)) +
					    (unsigned int)rta->rta_len);

	sent = send(ctx->fd, &req, req.nlh.nlmsg_len, MSG_DONTWAIT);
	return (sent >= 0) ? 0 : -1;
}

static int ipmr_getroute_pktinfo_in_ns(void *arg)
{
	struct ipmr_getroute_pktinfo_ctx *cctx =
		(struct ipmr_getroute_pktinfo_ctx *)arg;
	struct childdata *child = cctx->child;
	struct vifctl vc;
	struct sockaddr_in dst;
	struct in_addr lcl;
	struct nl_ctx nl = NL_CTX_INIT;
	struct nl_open_opts nl_opts = {
		.proto     = NETLINK_ROUTE,
		.recv_timeo_s = 0,	/* non-blocking drain only */
		.caller_op = CHILD_OP_IPMR_GETROUTE_PKTINFO,
	};
	int raw = -1;
	int udp = -1;
	int one = 1;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned long direct_calls = 0;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (nl_open(&nl, &nl_opts) < 0) {
		/* NETLINK_ROUTE unavailable — still attempt the rest so we
		 * cover the IP_PKTINFO path even without RTM_GETROUTE. */
		nl.fd = -1;
	}
	rtnl_bring_lo_up(&nl);
	/* if_nametoindex("lo"): socket + ioctl + close. */
	direct_calls += 3;

	raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	direct_calls++;
	if (raw < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			mark_ns_unsupported_ipmr_getroute_pktinfo();
		else if (errno == EPERM)
			mark_ns_eperm_ipmr_getroute_pktinfo();
		goto out;
	}

	direct_calls++;
	if (setsockopt(raw, IPPROTO_IP, MRT_INIT, &one, sizeof(one)) < 0) {
		if (errno == EPERM) {
			__atomic_add_fetch(
				&shm->stats.ipmr_getroute_pktinfo.eperm,
				1, __ATOMIC_RELAXED);
			mark_ns_eperm_ipmr_getroute_pktinfo();
		} else if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
			   errno == EADDRINUSE) {
			mark_ns_unsupported_ipmr_getroute_pktinfo();
		}
		goto out;
	}

	/* Enable IP_PKTINFO on the mrouted socket so the kernel populates
	 * the PKTINFO cmsg when delivering the cache report.  This is the
	 * knob that makes the IPCB/NETLINK_CB cb[] overlap observable:
	 * without it the kernel skips the pktinfo fill entirely. */
	direct_calls++;
	(void)setsockopt(raw, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi	  = 0;
	vc.vifc_flags	  = 0;
	vc.vifc_threshold = 1;
	vc.vifc_lcl_addr.s_addr = htonl(INADDR_LOOPBACK);
	vc.vifc_rmt_addr.s_addr = 0;
	direct_calls++;
	if (setsockopt(raw, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc)) < 0)
		goto done;

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	direct_calls++;
	if (udp < 0)
		goto done;

	lcl.s_addr = htonl(INADDR_LOOPBACK);
	(void)setsockopt(udp, IPPROTO_IP, IP_MULTICAST_IF, &lcl, sizeof(lcl));
	direct_calls++;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_IPMR_GETROUTE_PKTINFO,
			 JITTER_RANGE(IPMR_PKTINFO_LOOP_BASE));
	if (iters < IPMR_PKTINFO_LOOP_FLOOR)
		iters = IPMR_PKTINFO_LOOP_FLOOR;
	if (iters > IPMR_PKTINFO_LOOP_CAP)
		iters = IPMR_PKTINFO_LOOP_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < iters; i++) {
		const char payload[8] = {
			'i','p','m','r','g','r','t','p'
		};
		unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		unsigned char rcvbuf[256];
		struct iovec iov;
		struct msghdr mh;
		struct cmsghdr *cmsg;
		ssize_t r;
		__be32 group;

		if (ns_since(&t0) >= IPMR_PKTINFO_BUDGET_NS)
			break;

		__atomic_add_fetch(&shm->stats.ipmr_getroute_pktinfo.iters,
				   1, __ATOMIC_RELAXED);

		group = pick_nocache_group();

		/* RTM_GETROUTE for this group — exercises ipmr_rtm_getroute
		 * and may build a report skb whose cb[] holds NETLINK_CB
		 * portid where IPCB ipi_ifindex would be read on delivery. */
		if (nl.fd >= 0) {
			if (send_getroute_query(&nl, group) == 0)
				__atomic_add_fetch(
					&shm->stats.ipmr_getroute_pktinfo.getroute_ok,
					1, __ATOMIC_RELAXED);
			/* Drain the NLMSG_ERROR / RTM_NEWROUTE reply so
			 * the socket does not pile up. */
			{
				unsigned char rbuf[RTNL_BUF_BYTES];
				(void)recv(nl.fd, rbuf, sizeof(rbuf),
					   MSG_DONTWAIT);
			}
		}

		/* UDP sendto triggers the NOCACHE upcall which calls
		 * ipmr_cache_report() and delivers the IGMP NOCACHE msg
		 * to raw (our mrouted socket) with IP_PKTINFO populated.
		 * The overlap oracle: ipi_ifindex in the PKTINFO cmsg may
		 * carry NETLINK_CB(skb).portid from a preceding skb reuse. */
		memset(&dst, 0, sizeof(dst));
		dst.sin_family	    = AF_INET;
		dst.sin_port	    = htons(1024 + (rand32() & 0x3fff));
		dst.sin_addr.s_addr = group;
		(void)sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			     (struct sockaddr *)&dst, sizeof(dst));
		direct_calls++;

		/* recvmsg on the mrouted socket with cmsg space for
		 * IP_PKTINFO — this is the IPCB/NETLINK_CB overlap site. */
		memset(&cmsgbuf, 0, sizeof(cmsgbuf));
		iov.iov_base = rcvbuf;
		iov.iov_len  = sizeof(rcvbuf);
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov	   = &iov;
		mh.msg_iovlen	   = 1;
		mh.msg_control	   = cmsgbuf;
		mh.msg_controllen  = sizeof(cmsgbuf);
		r = recvmsg(raw, &mh, MSG_DONTWAIT);
		direct_calls++;
		if (r >= 0) {
			for (cmsg = CMSG_FIRSTHDR(&mh); cmsg;
			     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
				if (cmsg->cmsg_level == IPPROTO_IP &&
				    cmsg->cmsg_type  == IP_PKTINFO) {
					__atomic_add_fetch(
						&shm->stats.ipmr_getroute_pktinfo.pktinfo_ok,
						1, __ATOMIC_RELAXED);
					break;
				}
			}
		}
	}

done:
	(void)setsockopt(raw, IPPROTO_IP, MRT_DONE, NULL, 0);
	direct_calls++;

out:
	if (udp >= 0)
		close(udp);
	if (raw >= 0)
		close(raw);
	if (nl.fd >= 0)
		nl_close(&nl);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return 0;
}

bool ipmr_getroute_pktinfo(struct childdata *child)
{
	struct ipmr_getroute_pktinfo_ctx cctx = { .child = child };
	int rc;

	if (ns_userns_unsupported_ipmr_getroute_pktinfo ||
	    ns_unsupported_ipmr_getroute_pktinfo() ||
	    ns_eperm_ipmr_getroute_pktinfo())
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ipmr_getroute_pktinfo_in_ns,
			      &cctx);
	if (rc == -EPERM) {
		ns_userns_unsupported_ipmr_getroute_pktinfo = true;
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_NS_UNSUPPORTED,
					__ATOMIC_RELAXED);
		}
		return true;
	}
	if (rc < 0)
		return true;

	return true;
}

bool ipmr_cache_report(struct childdata *child)
{
	struct ipmr_cache_report_ctx cctx = { .child = child };
	int rc;

	if (ns_userns_unsupported_ipmr_cache_report ||
	    ns_unsupported_ipmr_cache_report() ||
	    ns_eperm_ipmr_cache_report())
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ipmr_cache_report_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_userns_unsupported_ipmr_cache_report = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern ipmr_cache_report_in_ns above uses for
		 * its per-op writes. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		return true;
	}

	return true;
}

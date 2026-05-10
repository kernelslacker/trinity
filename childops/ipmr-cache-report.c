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
 *   1. unshare(CLONE_NEWNET) once per child so MRT_INIT (which is
 *      exclusive per netns) can't conflict with anything on the host
 *      and so any VIF / MFC state we install is torn down by netns
 *      destroy on child exit.  Failure latches the whole op off.
 *   2. Open a NETLINK_ROUTE socket with nl_groups including
 *      RTNLGRP_IPV4_MROUTE_R, the multicast group the kernel uses to
 *      broadcast cache reports.  Best-effort — we don't require the
 *      ack to land for the upcall path itself to fire.
 *   3. Bring lo up via RTM_NEWLINK so the kernel will accept
 *      127.0.0.1 as a vifc_lcl_addr and so the multicast send actually
 *      egresses an interface.
 *   4. Open AF_INET / SOCK_RAW / IPPROTO_IGMP and setsockopt
 *      IPPROTO_IP/MRT_INIT.  -EPERM here means the host has dropped
 *      CAP_NET_ADMIN before we got into the netns (trinity --dropprivs);
 *      bump the eperm counter and latch — this op is dead for the rest
 *      of the child's life.
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
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

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
static bool ns_unshared_ipmr_cache_report;
static bool ns_setup_failed_ipmr_cache_report;
static bool ns_unsupported_ipmr_cache_report;
static bool ns_eperm_ipmr_cache_report;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

/*
 * Open NETLINK_ROUTE bound to the IPv4 mroute cache-report multicast
 * group.  Returns -1 on failure; the upcall path itself still fires
 * even if no listener is around, so this is best-effort.
 */
static int rtnl_open_mroute_listener(void)
{
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = 1U << (RTNLGRP_IPV4_MROUTE_R - 1);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		/* Older kernel without RTNLGRP_IPV4_MROUTE_R will EINVAL on
		 * bind; fall back to an unsubscribed socket so the rest of
		 * the sequence still runs. */
		memset(&sa, 0, sizeof(sa));
		sa.nl_family = AF_NETLINK;
		if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

/*
 * Bring lo up so 127.0.0.1 is a valid vifc_lcl_addr and so the
 * multicast send egresses an interface.  Best-effort: failures are
 * ignored, the rest of the sequence will fail visibly if rtnl is
 * genuinely broken.
 */
static void bring_lo_up(void)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	int rtnl;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	rtnl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rtnl < 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len  = nlh->nlmsg_len;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
	(void)sendmsg(rtnl, &mh, 0);

	{
		unsigned char ack[256];
		(void)recv(rtnl, ack, sizeof(ack), MSG_DONTWAIT);
	}
	close(rtnl);
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

bool ipmr_cache_report(struct childdata *child)
{
	struct vifctl vc;
	struct sockaddr_in dst;
	struct in_addr lcl;
	int raw = -1;
	int udp = -1;
	int nl  = -1;
	int one = 1;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;

	(void)child;

	if (ns_setup_failed_ipmr_cache_report ||
	    ns_unsupported_ipmr_cache_report ||
	    ns_eperm_ipmr_cache_report)
		return true;

	if (!ns_unshared_ipmr_cache_report) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed_ipmr_cache_report = true;
			return true;
		}
		ns_unshared_ipmr_cache_report = true;
	}

	bring_lo_up();

	nl = rtnl_open_mroute_listener();		/* best-effort */

	raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	if (raw < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			ns_unsupported_ipmr_cache_report = true;
		else if (errno == EPERM)
			ns_eperm_ipmr_cache_report = true;
		goto out;
	}

	if (setsockopt(raw, IPPROTO_IP, MRT_INIT, &one, sizeof(one)) < 0) {
		if (errno == EPERM) {
			__atomic_add_fetch(&shm->stats.ipmr_cache_report_eperm,
					   1, __ATOMIC_RELAXED);
			ns_eperm_ipmr_cache_report = true;
		} else if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
			   errno == EADDRINUSE) {
			ns_unsupported_ipmr_cache_report = true;
		}
		goto out;
	}

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi      = 0;
	vc.vifc_flags     = 0;
	vc.vifc_threshold = 1;
	vc.vifc_lcl_addr.s_addr = htonl(INADDR_LOOPBACK);
	vc.vifc_rmt_addr.s_addr = 0;
	if (setsockopt(raw, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc)) < 0)
		goto done;

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (udp < 0)
		goto done;

	lcl.s_addr = htonl(INADDR_LOOPBACK);
	(void)setsockopt(udp, IPPROTO_IP, IP_MULTICAST_IF, &lcl, sizeof(lcl));

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_IPMR_CACHE_REPORT,
			 JITTER_RANGE(IPMR_LOOP_BASE));
	if (iters < IPMR_LOOP_FLOOR)
		iters = IPMR_LOOP_FLOOR;
	if (iters > IPMR_LOOP_CAP)
		iters = IPMR_LOOP_CAP;

	for (i = 0; i < iters; i++) {
		const char payload[8] = { 'i','p','m','r','c','r','p','t' };
		ssize_t r;

		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		__atomic_add_fetch(&shm->stats.ipmr_cache_report_iters, 1,
				   __ATOMIC_RELAXED);

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(1024 + (rand32() & 0x3fff));
		dst.sin_addr.s_addr = pick_nocache_group();

		r = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (r >= 0)
			__atomic_add_fetch(&shm->stats.ipmr_cache_report_emit_ok,
					   1, __ATOMIC_RELAXED);

		if (nl >= 0) {
			unsigned char rbuf[RTNL_BUF_BYTES];
			unsigned int j;

			for (j = 0; j < IPMR_RECV_BURST; j++) {
				if (recv(nl, rbuf, sizeof(rbuf),
					 MSG_DONTWAIT) < 0)
					break;
			}
		}
	}

done:
	(void)setsockopt(raw, IPPROTO_IP, MRT_DONE, NULL, 0);

out:
	if (udp >= 0)
		close(udp);
	if (raw >= 0)
		close(raw);
	if (nl >= 0)
		close(nl);

	return true;
}

/*
 * ip6mr_churn — IPv6 multicast routing early-demux socket UAF churn.
 *
 * Bug class: ip6_rcv_core() latches skb->sk (with sock_pfree as
 * destructor) via early demux during the outer RCU read section.
 * ip6_mc_input() takes the deliver==false branch and hands the
 * *original* skb to ip6_mr_input(), which may enqueue or forward it
 * well after the RCU lock is dropped — the prefetched socket pointer
 * embedded in skb->sk is now live past the socket's reference lifetime.
 * A concurrent close() on the early-demuxed socket produces a KASAN
 * use-after-free on skb->sk in the multicast routing fast path.
 *
 * Reaching the seam requires:
 *   (a) CONFIG_IPV6_MROUTE — without it ip6_mr_input() is a no-op stub,
 *   (b) MRT6_INIT + at least one MIF installed (so ip6_mroute_sk is set
 *       and ip6_mc_input() checks for routing),
 *   (c) a UDPv6 socket bound to the multicast group:port so early demux
 *       installs skb->sk before the packet reaches ip6_mc_input(),
 *   (d) the packet NOT locally delivered (forward-only path or NOCACHE
 *       upcall) so the original skb is touched by ip6_mr_input() while
 *       carrying the stale sk pointer,
 *   (e) concurrent socket close to put the last reference.
 * The random syscall fuzzer cannot assemble this sequencing from scratch.
 *
 * Sequence (per invocation):
 *   1. Enter a private net namespace via userns_run_in_ns() + CLONE_NEWNET.
 *      MRT6_INIT is exclusive per netns; grandchild _exit() reaps the
 *      MIF, raw socket, UDPv6 churn sockets and lo address atomically.
 *   2. Open RTNL socket; bring lo up via rtnl_bring_lo_up().
 *   3. Open AF_INET6 / SOCK_RAW / IPPROTO_ICMPV6; setsockopt
 *      IPPROTO_IPV6 / MRT6_INIT.  Structural failures (ENOPROTOOPT /
 *      EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT) latch
 *      ns_unsupported; -EPERM latches ns_eperm.
 *   4. MRT6_ADD_MIF with mif6c_mifi=0, mif6c_pifi=if_nametoindex("lo"),
 *      vifc_threshold=1, no flags.  Failure skips to teardown.
 *   5. Open a UDPv6 receiver (SOCK_DGRAM) bound to the group port with
 *      IPV6_ADD_MEMBERSHIP on lo so early demux registers the socket
 *      against the group.  IPV6_MULTICAST_LOOP=1 for loopback delivery.
 *   6. Loop (BUDGETED+JITTER, 200 ms wall cap):
 *        a. Send a tiny UDP payload from a separate AF_INET6 SOCK_DGRAM
 *           sender toward the group:port (MSG_DONTWAIT).  The packet
 *           enters ip6_rcv_core → early demux → ip6_mc_input →
 *           ip6_mr_input (NOCACHE path, no MFC installed).
 *        b. Close and re-open the receiver socket to race the skb->sk
 *           pointer with ip6_mr_input's packet lifetime.
 *   7. MRT6_DONE; close all fds.  Namespace destroyed on grandchild exit.
 *
 * Self-bounding: 200 ms wall cap + IPMR6_LOOP_CAP ceiling keep the op
 * inside child.c's SIGALRM(1s).  All sockets non-blocking on send.
 * Gate: CONFIG_IPV6_MROUTE.
 */

#if __has_include(<linux/mroute6.h>)

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/in6.h>
#include <linux/mroute6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

/*
 * RTNLGRP_IPV6_MROUTE_R is the IPv6 cache-report multicast group.
 * Stripped sysroots may predate it; the value is stable.
 */
#ifndef RTNLGRP_IPV6_MROUTE_R
#define RTNLGRP_IPV6_MROUTE_R	31
#endif

/*
 * IPV6_ADD_MEMBERSHIP / IPV6_MULTICAST_LOOP / IPV6_MULTICAST_IF
 * fallbacks for stripped sysroots.  The kernel returns ENOPROTOOPT
 * for unknown options — the ns_unsupported latch fires.
 */
#ifndef IPV6_MULTICAST_IF
#define IPV6_MULTICAST_IF	17
#endif
#ifndef IPV6_MULTICAST_LOOP
#define IPV6_MULTICAST_LOOP	19
#endif
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP	20
#endif

#define IP6MR_RECV_DRAIN	4

/* Inner-loop budget tuning — same shape as ipmr_cache_report. */
#define IPMR6_LOOP_BASE		5U
#define IPMR6_LOOP_FLOOR	8U
#define IPMR6_LOOP_CAP		32U
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* Fixed destination port for the UDPv6 multicast sender/receiver pair.
 * Stays out of the ephemeral range so we don't collide with an existing
 * early-demux binding on the host netns (we are in a private netns but
 * belt-and-suspenders). */
#define IP6MR_MC_PORT		4789

/*
 * Per-child latch: userns_run_in_ns() returned -EPERM (hardened userns
 * policy).  Without a private netns we must not touch any global IPv6
 * mroute table, so the op stays disabled for the rest of this child's
 * lifetime.  Transient -EAGAIN failures do not set this.
 */
static bool ns_userns_unsupported_ip6mr_churn;

static bool ns_unsupported_ip6mr_churn(void)
{
	return __atomic_load_n(&shm->ip6mr_churn_ns_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_ip6mr_churn(void)
{
	__atomic_store_n(&shm->ip6mr_churn_ns_unsupported, true,
			 __ATOMIC_RELAXED);
}

static bool ns_eperm_ip6mr_churn(void)
{
	return __atomic_load_n(&shm->ip6mr_churn_ns_eperm, __ATOMIC_RELAXED);
}

static void mark_ns_eperm_ip6mr_churn(void)
{
	__atomic_store_n(&shm->ip6mr_churn_ns_eperm, true, __ATOMIC_RELAXED);
}

/* Per-invocation context passed through userns_run_in_ns(). */
struct ip6mr_churn_ctx {
	struct childdata *child;
};

/*
 * Pick a random administratively-scoped IPv6 multicast group in
 * ff3e::/32 (global scope, admin-scoped block) that the kernel won't
 * have an MFC6 entry for.  The high 32 bits are fixed (ff3e::);
 * the low 96 bits are randomised, with the constraint that the result
 * is non-zero to avoid the all-zeros group which some stacks treat as
 * invalid.
 */
static void pick_nocache_group6(struct in6_addr *out)
{
	uint32_t r0 = rand32();
	uint32_t r1 = rand32();
	uint32_t r2 = rand32();

	memset(out, 0, sizeof(*out));
	/* ff3e:0000:... — global-scope administratively-scoped block */
	out->s6_addr[0]  = 0xff;
	out->s6_addr[1]  = 0x3e;
	/* bits [32..127]: fill from random, ensure at least one bit set */
	out->s6_addr[4]  = (r0 >> 24) & 0xff;
	out->s6_addr[5]  = (r0 >> 16) & 0xff;
	out->s6_addr[6]  = (r0 >>  8) & 0xff;
	out->s6_addr[7]  = (r0 | 1U)  & 0xff;	/* low byte non-zero */
	out->s6_addr[8]  = (r1 >> 24) & 0xff;
	out->s6_addr[9]  = (r1 >> 16) & 0xff;
	out->s6_addr[10] = (r1 >>  8) & 0xff;
	out->s6_addr[11] = (r1)       & 0xff;
	out->s6_addr[12] = (r2 >> 24) & 0xff;
	out->s6_addr[13] = (r2 >> 16) & 0xff;
	out->s6_addr[14] = (r2 >>  8) & 0xff;
	out->s6_addr[15] = (r2)       & 0xff;
}

/*
 * Open a UDPv6 receiver socket, join the given multicast group on lo,
 * and bind to the group port.  Returns the fd on success, -1 on failure.
 * IPV6_MULTICAST_LOOP=1 so the loopback send reaches us and early demux
 * installs skb->sk.
 */
static int open_mc6_receiver(const struct in6_addr *grp, unsigned int lo_idx)
{
	struct sockaddr_in6 sa;
	struct ipv6_mreq mr;
	int one = 1;
	int fd;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	(void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			 &one, sizeof(one));

	memset(&mr, 0, sizeof(mr));
	mr.ipv6mr_multiaddr = *grp;
	mr.ipv6mr_interface = lo_idx;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
		       &mr, sizeof(mr)) < 0) {
		close(fd);
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port   = htons(IP6MR_MC_PORT);
	sa.sin6_addr   = in6addr_any;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Per-invocation body that runs inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so all state is
 * cleaned up automatically.
 */
static int ip6mr_churn_in_ns(void *arg)
{
	struct ip6mr_churn_ctx *cctx = (struct ip6mr_churn_ctx *)arg;
	struct childdata *child = cctx->child;
	struct mif6ctl mc;
	struct in6_addr grp;
	struct sockaddr_in6 dst;
	struct nl_ctx nl = { .fd = -1 };
	int raw  = -1;
	int udp  = -1;	/* sender */
	int rxfd = -1;	/* early-demux receiver (churned) */
	int one  = 1;
	unsigned int lo_idx;
	struct timespec t0;
	unsigned int iters, i;
	unsigned long direct_calls = 0;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	lo_idx = if_nametoindex("lo");
	if (lo_idx == 0)
		goto out;

	/* Open RTNL socket subscribed to RTNLGRP_IPV6_MROUTE_R so NOCACHE
	 * upcall notifications can be drained.  Also passed to
	 * rtnl_bring_lo_up() to bring lo up inside the private netns.
	 * Fall back to an unsubscribed socket on older kernels. */
	{
		struct nl_open_opts opts = {
			.proto      = NETLINK_ROUTE,
			.groups     = 1U << (RTNLGRP_IPV6_MROUTE_R - 1),
			.caller_op  = child->op_type,
		};
		if (nl_open(&nl, &opts) < 0) {
			opts.groups = 0;
			(void)nl_open(&nl, &opts);
		}
	}
	if (nl.fd >= 0)
		rtnl_bring_lo_up(&nl);

	raw = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	direct_calls++;
	if (raw < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			mark_ns_unsupported_ip6mr_churn();
		else if (errno == EPERM)
			mark_ns_eperm_ip6mr_churn();
		goto out;
	}

	direct_calls++;
	if (setsockopt(raw, IPPROTO_IPV6, MRT6_INIT, &one, sizeof(one)) < 0) {
		if (errno == EPERM) {
			__atomic_add_fetch(&shm->stats.ip6mr_churn.eperm,
					   1, __ATOMIC_RELAXED);
			mark_ns_eperm_ip6mr_churn();
		} else if (errno == EOPNOTSUPP  || errno == ENOPROTOOPT ||
			   errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
			   errno == EADDRINUSE) {
			mark_ns_unsupported_ip6mr_churn();
		}
		goto out;
	}

	/* Install MIF 0 on lo. */
	memset(&mc, 0, sizeof(mc));
	mc.mif6c_mifi      = 0;
	mc.mif6c_flags     = 0;
	mc.vifc_threshold  = 1;
	mc.mif6c_pifi      = (__u16)lo_idx;
	direct_calls++;
	if (setsockopt(raw, IPPROTO_IPV6, MRT6_ADD_MIF, &mc, sizeof(mc)) < 0)
		goto done;

	/* Pick a random ff3e::/32 group with no MFC entry. */
	pick_nocache_group6(&grp);

	/* Receiver socket: join the group so early demux anchors skb->sk. */
	rxfd = open_mc6_receiver(&grp, lo_idx);
	direct_calls += 3;	/* socket + setsockopt(LOOP) + setsockopt(JOIN) + bind */

	/* Sender socket. */
	udp = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	direct_calls++;
	if (udp < 0)
		goto done;

	{
		unsigned int ifidx = lo_idx;
		(void)setsockopt(udp, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				 &ifidx, sizeof(ifidx));
		(void)setsockopt(udp, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				 &one, sizeof(one));
		direct_calls += 2;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_port   = htons(IP6MR_MC_PORT);
	dst.sin6_addr   = grp;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_IP6MR_CHURN,
			 JITTER_RANGE(IPMR6_LOOP_BASE));
	if (iters < IPMR6_LOOP_FLOOR)
		iters = IPMR6_LOOP_FLOOR;
	if (iters > IPMR6_LOOP_CAP)
		iters = IPMR6_LOOP_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < iters; i++) {
		const char payload[8] = { 'i','p','6','m','r','c','h','n' };
		ssize_t r;

		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		__atomic_add_fetch(&shm->stats.ip6mr_churn.iters,
				   1, __ATOMIC_RELAXED);

		/*
		 * Send the multicast packet.  It enters ip6_rcv_core →
		 * early demux (skb->sk latched to 'recv') → ip6_mc_input →
		 * ip6_mr_input (NOCACHE: no MFC entry installed).
		 */
		r = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		direct_calls++;
		if (r >= 0)
			__atomic_add_fetch(&shm->stats.ip6mr_churn.emit_ok,
					   1, __ATOMIC_RELAXED);

		/*
		 * Churn the receiver socket: close and immediately
		 * re-open so the sk pointer early demux embedded in any
		 * in-flight skb->sk races against the socket free.
		 */
		if (rxfd >= 0) {
			close(rxfd);
			direct_calls++;
			rxfd = open_mc6_receiver(&grp, lo_idx);
			direct_calls += 3;
		}

		/* Drain any netlink notifications (best-effort). */
		if (nl.fd >= 0) {
			unsigned char rbuf[256];
			unsigned int j;

			for (j = 0; j < IP6MR_RECV_DRAIN; j++) {
				if (recvfrom(nl.fd, rbuf, sizeof(rbuf),
					     MSG_DONTWAIT, NULL, NULL) < 0)
					break;
			}
		}
	}

done:
	(void)setsockopt(raw, IPPROTO_IPV6, MRT6_DONE, NULL, 0);
	direct_calls++;

out:
	if (rxfd >= 0)
		close(rxfd);
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

bool ip6mr_churn(struct childdata *child)
{
	struct ip6mr_churn_ctx cctx = { .child = child };
	int rc;

	if (ns_userns_unsupported_ip6mr_churn ||
	    ns_unsupported_ip6mr_churn()       ||
	    ns_eperm_ip6mr_churn())
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ip6mr_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_userns_unsupported_ip6mr_churn = true;
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

#else	/* !__has_include(<linux/mroute6.h>) */

#include "child.h"

bool ip6mr_churn(struct childdata *child __attribute__((unused)))
{
	return true;
}

#endif	/* __has_include(<linux/mroute6.h>) */

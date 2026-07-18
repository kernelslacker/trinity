/*
 * ipv6_pmtu_teardown_race - race ICMPv6 PKT_TOOBIG processing against
 * concurrent netdev teardown of the route's egress device.
 *
 * Bug class: net/ipv6/route.c:fib6_mtu walks rt->rt6i_idev->cnf.
 * The netdev unregister path (in6_dev_finish_destroy via NETDEV_DOWN /
 * RTM_DELLINK) can clear rt6i_idev under a concurrent rt6_update_pmtu
 * that a PTB has kicked off.  Target is the pre-fix race window (read
 * rt6i_idev once, null-check before deref).
 *
 * Per outer iteration (BUDGETED, base 2, cap 6), inside a private
 * user+net namespace via userns_run_in_ns (grandchild _exit() reaps
 * every veth/route/socket/netns): create N=4 veth pairs on lo, install
 * an fc01::/64 addr and route per pair, then fork two workers -- A
 * tight-loops ICMPV6_PKT_TOOBIG sendto() with the advertised MTU
 * rotated 576..9000 to keep the rt6_update_pmtu lookup hot; B tight-
 * loops RTM_DELLINK/RTM_NEWLINK cycling r0..r3 so every route's egress
 * device is torn down under the PMTU walker.  Both workers self-bound
 * to 200 ms wall; the parent SIGKILLs laggards.
 *
 * Brick-safety: all netlink and raw-socket work runs inside the
 * grandchild's private netns; addresses are ULA (fc01::/64,
 * unroutable).  Per-iter dispatch preserves per-iter netns isolation
 * so partial teardown from one iter can't leak into the next.
 *
 * Latch: userns_run_in_ns -EPERM (hardened userns policy refused
 * CLONE_NEWUSER) permanently gates the op off for this child.
 * Transient helper failures (return < 0 but not -EPERM) skip without
 * latching.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>) && \
    __has_include(<linux/rtnetlink.h>) && __has_include(<linux/veth.h>)

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sched.h>

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "childops-netlink.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#ifndef ICMPV6_PKT_TOOBIG
#define ICMPV6_PKT_TOOBIG		2
#endif

/*
 * Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private user+net namespace we MUST NOT touch the host
 * netdev / route / addr tables, so the op stays disabled for the
 * remainder of this child's lifetime.  Transient helper failures
 * (return < 0 but not -EPERM) do not set this -- they may not recur
 * on the next iteration.
 */
static bool ns_unsupported_ipv6_pmtu_race;

#define V6PMTU_OUTER_BASE		1U
#define V6PMTU_OUTER_CAP		3U
#define V6PMTU_NUM_PAIRS		4U
#define V6PMTU_WORKER_WALL_NS		(200ULL * 1000ULL * 1000ULL)
#define V6PMTU_PARENT_WALL_NS		(250ULL * 1000ULL * 1000ULL)
#define V6PMTU_RTNL_BUF			512U

/*
 * RTM_NEWLINK type=veth name=<name> peer=<peer>.  Mirrors the shape
 * used by bridge-fdb-stp.c / bridge-vlan-churn.c: nested IFLA_LINKINFO
 * with IFLA_INFO_KIND=veth + IFLA_INFO_DATA holding VETH_INFO_PEER
 * whose payload starts with an ifinfomsg followed by IFLA_IFNAME for
 * the peer.
 */
static int build_veth_create(struct nl_ctx *ctx, const char *name, const char *peer)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

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
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off) return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off) return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_addaddr_v6(struct nl_ctx *ctx, int ifindex,
			    const struct in6_addr *addr, __u8 prefixlen)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = 0;	/* RT_SCOPE_UNIVERSE */
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, addr, sizeof(*addr));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, addr, sizeof(*addr));
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWROUTE ipv6 dst/<plen> gw=<gw> oif=<ifindex>.  RTPROT_BOOT and
 * RT_SCOPE_UNIVERSE keep the route eligible for the regular fib6
 * lookup; type RTN_UNICAST is required so rt6_update_pmtu treats it as
 * a normal forwarding entry.
 */
static int build_newroute_v6(struct nl_ctx *ctx, const struct in6_addr *dst,
			     __u8 plen, const struct in6_addr *gw, int ifindex)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET6;
	rtm->rtm_dst_len  = plen;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope    = 0;	/* RT_SCOPE_UNIVERSE */
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));
	off = nla_put(buf, off, sizeof(buf), RTA_DST, dst, sizeof(*dst));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), RTA_GATEWAY, gw, sizeof(*gw));
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF, (__u32)ifindex);
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_dellink_byname(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build the four (rN, pN) veth pairs, assign fc01::N/64 to rN, bring
 * rN up, install the fc01:N::/48 route via fc01::N+1 dev rN.  Best
 * effort: any single rtnl rejection just skips that pair's downstream
 * setup; the worker forks still run against whatever subset succeeded.
 */
static void setup_pairs(struct nl_ctx *ctx, char names[V6PMTU_NUM_PAIRS][8])
{
	unsigned int n;

	for (n = 0; n < V6PMTU_NUM_PAIRS; n++) {
		struct in6_addr addr, gw, dst;
		char peer[8];
		unsigned int rifx;

		(void)snprintf(names[n], sizeof(names[n]), "tr6r%u", n);
		(void)snprintf(peer, sizeof(peer), "tr6p%u", n);
		if (build_veth_create(ctx, names[n], peer) != 0)
			continue;

		rifx = if_nametoindex(names[n]);
		if (rifx == 0)
			continue;

		/* Kernel confirmed names[n] is a real device; publish the
		 * pair primary (n==0, tr6r0) via the NETDEV name pool so
		 * sibling childops and per-syscall fuzzers drawing this
		 * kind can land a HIT on dev_get_by_name /
		 * SO_BINDTODEVICE instead of always-fresh-random ENODEV.
		 * Primary only -- the per-kind ring is 16 slots and
		 * recording all four r-end leaves per setup would thrash
		 * it. */
		if (n == 0)
			name_pool_record(NAME_KIND_NETDEV, names[n],
					 strlen(names[n]));

		memset(&addr, 0, sizeof(addr));
		addr.s6_addr[0] = 0xfc;
		addr.s6_addr[1] = 0x01;
		addr.s6_addr[15] = (uint8_t)n;
		(void)build_addaddr_v6(ctx, (int)rifx, &addr, 64);
		(void)build_setlink_up(ctx, (int)rifx);

		memset(&dst, 0, sizeof(dst));
		dst.s6_addr[0] = 0xfc;
		dst.s6_addr[1] = 0x01;
		dst.s6_addr[5] = (uint8_t)n;	/* fc01:0:N::/48 */

		memset(&gw, 0, sizeof(gw));
		gw.s6_addr[0] = 0xfc;
		gw.s6_addr[1] = 0x01;
		gw.s6_addr[15] = (uint8_t)(n + 1);
		(void)build_newroute_v6(ctx, &dst, 48, &gw, (int)rifx);
	}
}

/*
 * Worker A.  Tight ICMPV6_PKT_TOOBIG sendto loop, rotating destination
 * across the four routes and rotating the advertised MTU through a
 * 576..9000 ladder so each PTB carries a different value (forces the
 * rt6_update_pmtu update path rather than caching).  Self-bounded by
 * V6PMTU_WORKER_WALL_NS.  Counter bumps land in shared shm directly
 * because the worker shares the trinity mapping.
 */
static void worker_ptb(void)
{
	int sfd;
	struct timespec start, now;
	struct sockaddr_in6 dst;
	struct icmp6_hdr hdr;
	unsigned int i = 0;
	static const __u32 mtu_ladder[] = { 576, 1280, 1500, 4096, 9000 };

	sfd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sfd < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;

	for (;; i++) {
		unsigned int n = i % V6PMTU_NUM_PAIRS;
		__u32 mtu = mtu_ladder[i % (sizeof(mtu_ladder) /
					    sizeof(mtu_ladder[0]))];
		ssize_t r;

		memset(&dst.sin6_addr, 0, sizeof(dst.sin6_addr));
		dst.sin6_addr.s6_addr[0]  = 0xfc;
		dst.sin6_addr.s6_addr[1]  = 0x01;
		dst.sin6_addr.s6_addr[5]  = (uint8_t)n;
		dst.sin6_addr.s6_addr[15] = 0x01;

		memset(&hdr, 0, sizeof(hdr));
		hdr.icmp6_type = ICMPV6_PKT_TOOBIG;
		hdr.icmp6_code = 0;
		hdr.icmp6_mtu  = htonl(mtu);

		r = sendto(sfd, &hdr, sizeof(hdr), MSG_DONTWAIT | MSG_NOSIGNAL,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (r >= 0)
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.ptb_sent_ok,
					   1, __ATOMIC_RELAXED);

		if ((i & 0x1fU) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= V6PMTU_WORKER_WALL_NS)
				break;
		}
	}

	(void)close(sfd);
	_exit(0);
}

/*
 * Worker B.  Round-robin RTM_DELLINK + RTM_NEWLINK recreate of rN.
 * The DELLINK on rN tears down rN and its peer pN; the recreate gives
 * the next iteration something to delete.  Self-bounded by
 * V6PMTU_WORKER_WALL_NS.
 */
static void worker_dellink(char names[V6PMTU_NUM_PAIRS][8])
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	struct timespec start, now;
	unsigned int i = 0;

	if (nl_open(&ctx, &opts) < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		unsigned int n = i % V6PMTU_NUM_PAIRS;
		char peer[8];

		(void)snprintf(peer, sizeof(peer), "tr6p%u", n);
		if (build_dellink_byname(&ctx, names[n]) == 0)
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.dellink_ok,
					   1, __ATOMIC_RELAXED);

		(void)build_veth_create(&ctx, names[n], peer);

		if ((i & 0x07U) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= V6PMTU_WORKER_WALL_NS)
				break;
		}
	}

	nl_close(&ctx);
	_exit(0);
}

/*
 * Reap one worker, retrying through EINTR.  After V6PMTU_PARENT_WALL_NS
 * a SIGKILL is sent so a wedged worker can't outrun the trinity SIGALRM.
 */
static void reap_with_deadline(pid_t pid, struct timespec *deadline)
{
	for (;;) {
		struct timespec now;
		int status;
		pid_t r;

		r = waitpid_eintr(pid, &status, WNOHANG);
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			return;
		}
		(void)usleep(2000);
	}
}

/*
 * Open a private rtnetlink socket, bring lo up, and install the four
 * veth pairs + addresses + routes via setup_pairs().  Returns 0 on
 * success, -1 (with setup_failed bumped) if the rtnl socket open
 * fails; partial setup_pairs() failures are intentionally tolerated.
 */
static int v6pmtu_iter_setup_network(char names[V6PMTU_NUM_PAIRS][8])
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	rtnl_bring_lo_up(&ctx);
	setup_pairs(&ctx, names);
	nl_close(&ctx);
	return 0;
}

/*
 * Fork both race workers.  Child A runs worker_ptb (never returns);
 * child B runs worker_dellink (never returns).  On a successful B
 * fork the parent returns 0 with the two pids written through.  If
 * fork B fails after A was spawned, A is SIGKILLed and reaped here
 * so the caller's failure bail doesn't leak a stray child.
 */
static int v6pmtu_iter_spawn_workers(char names[V6PMTU_NUM_PAIRS][8],
				     pid_t *a, pid_t *b)
{
	*a = fork();
	if (*a < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	if (*a == 0)
		worker_ptb();

	*b = fork();
	if (*b < 0) {
		(void)kill(*a, SIGKILL);
		(void)waitpid_eintr(*a, NULL, 0);
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	if (*b == 0)
		worker_dellink(names);

	return 0;
}

/*
 * Compute the parent's V6PMTU_PARENT_WALL_NS wall-clock deadline and
 * reap both workers under it.  reap_with_deadline SIGKILLs a laggard
 * past the deadline so a wedged worker can't outrun trinity's SIGALRM.
 */
static void v6pmtu_iter_reap_workers(pid_t a, pid_t b)
{
	struct timespec deadline;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)V6PMTU_PARENT_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	reap_with_deadline(a, &deadline);
	reap_with_deadline(b, &deadline);
}

/*
 * Per-invocation state handed to the in-ns callback so iter-time stats
 * writes keep landing against the right childop slot.
 */
struct ipv6_pmtu_race_ctx {
	int op_type;
};

/*
 * One outer iteration's body, executed inside the grandchild's
 * userns + CLONE_NEWNET stack by userns_run_in_ns().  Setup the four
 * veth pairs + addresses + routes, fork the PTB sender and DELLINK
 * round-robin workers, reap them under the parent wall-clock
 * deadline.  Return value is ignored by the helper; the grandchild
 * _exit()s after this returns and the kernel reaps every veth,
 * route, raw socket and netlink socket along with the netns.
 */
static int iter_one_in_ns(void *arg)
{
	struct ipv6_pmtu_race_ctx *ctx = arg;
	const int op_type = ctx->op_type;
	char names[V6PMTU_NUM_PAIRS][8];
	pid_t a, b;
	/* op_type is a snapshot of child->op_type passed in by value; the
	 * field lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling.  Bounds-check the snapshot
	 * once and gate each per-op stats write, same pattern the child.c
	 * dispatch loop uses for its dispatch and alt-op accounting. */
	const bool valid_op = (op_type >= 0 && op_type < NR_CHILD_OP_TYPES);

	if (v6pmtu_iter_setup_network(names) != 0)
		return 0;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);

	if (v6pmtu_iter_spawn_workers(names, &a, &b) != 0)
		return 0;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op_type],
				   1, __ATOMIC_RELAXED);

	v6pmtu_iter_reap_workers(a, b);

	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.completed_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

bool ipv6_pmtu_teardown_race(struct childdata *child)
{
	struct ipv6_pmtu_race_ctx ctx = { .op_type = child->op_type };
	unsigned int outer, i;

	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_ipv6_pmtu_race) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	outer = BUDGETED(CHILD_OP_IPV6_PMTU_TEARDOWN_RACE,
			 JITTER_RANGE(V6PMTU_OUTER_BASE));
	if (outer > V6PMTU_OUTER_CAP)
		outer = V6PMTU_OUTER_CAP;
	if (outer == 0U)
		outer = 1U;

	for (i = 0; i < outer; i++) {
		int rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_ns, &ctx);

		if (rc == -EPERM) {
			/* Hardened userns policy refused CLONE_NEWUSER in
			 * the grandchild.  Latch the op off for the
			 * remainder of this child's lifetime. */
			ns_unsupported_ipv6_pmtu_race = true;
			{
				const int op = child->op_type;
				if (op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		if (rc < 0) {
			/* Transient grandchild setup failure (fork, id-map
			 * write, secondary CLONE_NEWNET unshare).  Skip this
			 * iteration without latching -- the failure is not
			 * policy and may not recur on the next iteration. */
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
	}

	return true;
}

#else  /* missing sched.h / netlink.h / rtnetlink.h / veth.h */

bool ipv6_pmtu_teardown_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif

/*
 * multipath_linkdown_rebalance - race the ignore_routes_with_linkdown
 * sysctl against the two-pass multipath rebalance, driving the FIB
 * upper-bound divisor to zero.  A real IPv4/IPv6 twin: the same bug
 * shape lives once per family and neither half exists in the tree.
 *
 * Kernel bug (unfixed at linux-linus 0f23d56f17fd):
 *
 *   v4  fib_rebalance()             net/ipv4/fib_semantics.c:853
 *   v6  rt6_multipath_rebalance()   net/ipv6/route.c:4862
 *         -> rt6_multipath_total_weight() + rt6_upper_bound_set()
 *
 * Both compute a multipath route's total nexthop weight in a first
 * pass and then, in a second pass, assign each nexthop an upper bound
 *   DIV_ROUND_CLOSEST_ULL((u64)weight << 31, total) - 1
 * with NO `total != 0` guard.  Both passes read the per-device
 * ignore_routes_with_linkdown sysctl UNLOCKED (v4 ip_ignore_linkdown()
 * / v6 ip6_ignore_linkdown() via rt6_is_dead()).  If every nexthop is
 * UP-but-no-carrier (RTNH_F_LINKDOWN) and the sysctl reads 1 during
 * pass one, `total` is computed as 0.  If a concurrent writer flips
 * the sysctl 1 -> 0 before pass two, a linkdown nexthop is no longer
 * excluded, re-enters the divisor path, and the kernel divides by
 * zero: `Oops: divide error` (or UBSAN division-overflow under a
 * UBSAN build) -- both oracles are already classified.
 *
 * Why flat fuzzing never assembles this:
 *   - `ignore_routes_with_linkdown` has zero references tree-wide, so
 *     nothing mutates the sysctl at all, let alone concurrently.
 *   - RTNH_F_LINKDOWN has zero references: no childop builds an
 *     UP-but-no-carrier device, so a multipath route's `total` can
 *     never be driven to zero even by luck.
 *   - the rtnetlink route fuzzers are single-threaded against no
 *     sysctl writer, so the two-pass window never opens.
 *
 * How this childop assembles it (per invocation, one family chosen at
 * random, inside a userns_run_in_ns grandchild):
 *   1. Bring lo up in the fresh netns.
 *   2. Create MLR_LEGS (2) veth pairs.  Bring only the LOCAL end of
 *      each pair up; the PEER stays administratively down, so the
 *      local end is IFF_UP but has no carrier -- exactly the state
 *      that stamps RTNH_F_LINKDOWN on a nexthop that egresses it.
 *   3. Give each local end an address so the in-subnet gateway
 *      resolves; nexthop resolution uses FIB_LOOKUP_IGNORE_LINKSTATE
 *      so the carrier-down connected route still resolves.
 *   4. Set ignore_routes_with_linkdown = 1 on both local ends so the
 *      first-pass weight sum can reach zero.
 *   5. Install a multipath route whose two nexthops egress the two
 *      linkdown veths -- num_path == 2 arms fib_rebalance() /
 *      rt6_multipath_rebalance().
 *   6. fork() a flip worker that hammers the two devices'
 *      ignore_routes_with_linkdown sysctls 1 <-> 0 as fast as it can.
 *   7. The parent hammers RTM_NEWROUTE with NLM_F_REPLACE on the same
 *      multipath route; every replace re-runs fib_create_info() ->
 *      fib_rebalance() (v4) / fib6_add_rt2node() ->
 *      rt6_multipath_rebalance() (v6), so each iteration is a fresh
 *      two-pass window racing the flip worker.
 *   8. Parent SIGKILLs the worker at a wall deadline; the grandchild
 *      _exit()s and the kernel reaps every route/addr/link/socket
 *      with the namespace.
 *
 * All addresses live in private / documentation ranges (v4 10.55.x /
 * 198.18.x, v6 fc55::/ fd00::) inside the private netns; the outer
 * trinity child never changes its own credentials or namespace stack,
 * so the cap-drop oracle keeps observing the host credential profile
 * and a stray route cannot leak to the host table.
 *
 * Self-bounding: one family per invocation, bounded replace loop plus
 * a wall-clock cap, all fds O_CLOEXEC, SO_RCVTIMEO on the rtnl socket,
 * worker SIGKILLed at a deadline well inside the outer SIGALRM(1).
 * Helper -EPERM (hardened userns policy) latches the op off for this
 * child's lifetime; transient setup failures skip without latching.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "kernel/fcntl.h"

/*
 * VETH_INFO_PEER lives in linux/veth.h (present since 3.x, but older
 * sysroots may lack it).  Stub the whole childop when the header is
 * missing so the build stays clean -- without a veth pair we cannot
 * manufacture the UP-but-no-carrier nexthop the bug requires.
 */
#if __has_include(<linux/veth.h>)

#include <linux/veth.h>

#define MLR_RTNL_BUF		2048
#define MLR_LEGS		2U	/* nexthops in the multipath route */
#define MLR_REPLACE_ITERS	256U
#define MLR_FLIP_ITERS		200000U
#define MLR_WALL_NS		(150ULL * 1000ULL * 1000ULL)
#define MLR_REAP_WALL_NS	(250ULL * 1000ULL * 1000ULL)

/* userns_run_in_ns() returned -EPERM: hardened policy refused
 * CLONE_NEWUSER.  Latch off for the remainder of this child's life --
 * without a private netns we MUST NOT touch the host routing tables. */
static bool ns_unsupported;

struct mlr_ctx {
	struct childdata *child;
};

/* Per-leg naming + addressing, filled during setup.  gw4/gw6 are the
 * in-subnet gateway addresses used as the multipath nexthop targets. */
struct mlr_leg {
	char		local[IFNAMSIZ];	/* the UP, no-carrier end */
	char		peer[IFNAMSIZ];		/* stays down -> no carrier */
	int		ifindex;
	__u32		addr4_he;		/* host order local /24 addr */
	__u32		gw4_he;			/* host order nexthop gw */
	struct in6_addr	addr6;			/* local /64 addr */
	struct in6_addr	gw6;			/* nexthop gw */
};

/* ------------------------------------------------------------------ */
/* netlink builders                                                    */
/* ------------------------------------------------------------------ */

/*
 * Create a veth pair (local <-> peer).  Neither end is brought up
 * here; the caller ups the local end only, leaving the peer down so
 * the local end reports no carrier.
 */
static int mlr_create_veth(struct nl_ctx *nl, const char *local,
			   const char *peer)
{
	unsigned char buf[MLR_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, local);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	/* VETH_INFO_PEER: ifinfomsg + IFLA_IFNAME for the peer end. */
	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off)
		return -EIO;
	nla_nest_end(buf, peer_off, off);

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

static int mlr_add_addr4(struct nl_ctx *nl, int ifindex, __u32 addr_he)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr_be = htonl(addr_he);
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL,   &addr_be, 4);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr_be, 4);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

static int mlr_add_addr6(struct nl_ctx *nl, int ifindex,
			 const struct in6_addr *addr)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = 64;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, addr, sizeof(*addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, addr, sizeof(*addr));
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

/*
 * Build & send an RTM_NEWROUTE with an RTA_MULTIPATH payload of
 * MLR_LEGS gateway nexthops, one per leg.  `replace` selects
 * NLM_F_REPLACE|NLM_F_CREATE (re-run the rebalance) vs the initial
 * NLM_F_CREATE|NLM_F_EXCL install.  Handles both families off `v6`.
 */
static int mlr_build_route(struct nl_ctx *nl, bool v6,
			   const struct mlr_leg *legs, bool replace)
{
	unsigned char buf[MLR_RTNL_BUF];
	unsigned char mp[MLR_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t off, mp_off;
	unsigned int i;
	const size_t gw_sz = v6 ? sizeof(struct in6_addr) : sizeof(__u32);
	const size_t nh_sz = sizeof(struct rtnexthop) +
			     NLA_ALIGN(NLA_HDRLEN + gw_sz);

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	nlh->nlmsg_flags |= replace ? NLM_F_REPLACE : NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = v6 ? AF_INET6 : AF_INET;
	rtm->rtm_dst_len  = v6 ? 128 : 32;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	if (v6) {
		struct in6_addr dst;

		memset(&dst, 0, sizeof(dst));
		dst.s6_addr[0] = 0xfd;
		dst.s6_addr[1] = 0x00;
		dst.s6_addr[2] = 0xd1;
		dst.s6_addr[3] = 0xd2;
		dst.s6_addr[15] = 0x01;
		off = nla_put(buf, off, sizeof(buf), RTA_DST, &dst,
			      sizeof(dst));
	} else {
		__u32 dst = htonl(0xc6120701U);	/* 198.18.7.1 */

		off = nla_put(buf, off, sizeof(buf), RTA_DST, &dst,
			      sizeof(dst));
	}
	if (!off)
		return -EIO;

	/* Assemble the RTA_MULTIPATH payload: one rtnexthop + RTA_GATEWAY
	 * per leg.  Weights default to 1 (rtnh_hops == 0). */
	memset(mp, 0, sizeof(mp));
	mp_off = 0;
	for (i = 0; i < MLR_LEGS; i++) {
		struct rtnexthop *rtnh;
		struct nlattr *gw;

		if (mp_off + nh_sz > sizeof(mp))
			return -EIO;

		rtnh = (struct rtnexthop *)(mp + mp_off);
		rtnh->rtnh_flags   = 0;
		rtnh->rtnh_hops    = 0;
		rtnh->rtnh_ifindex = legs[i].ifindex;
		rtnh->rtnh_len     = (__u16)nh_sz;
		mp_off += sizeof(*rtnh);

		gw = (struct nlattr *)(mp + mp_off);
		gw->nla_type = RTA_GATEWAY;
		gw->nla_len  = (__u16)(NLA_HDRLEN + gw_sz);
		mp_off += NLA_HDRLEN;
		if (v6) {
			memcpy(mp + mp_off, &legs[i].gw6, sizeof(legs[i].gw6));
		} else {
			__u32 gw_be = htonl(legs[i].gw4_he);

			memcpy(mp + mp_off, &gw_be, sizeof(gw_be));
		}
		mp_off += NLA_ALIGN(gw_sz);
	}

	off = nla_put(buf, off, sizeof(buf), RTA_MULTIPATH, mp, mp_off);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

/* ------------------------------------------------------------------ */
/* sysctl flip worker                                                  */
/* ------------------------------------------------------------------ */

/*
 * Open the per-device ignore_routes_with_linkdown sysctl for writing.
 * Path is per-netns (net.* sysctls are namespaced), so this only ever
 * touches the grandchild's private netns.  Returns fd or -1.
 */
static int mlr_open_sysctl(bool v6, const char *dev)
{
	char path[128];

	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv%s/conf/%s/ignore_routes_with_linkdown",
		 v6 ? "6" : "4", dev);
	return open(path, O_WRONLY | O_CLOEXEC);
}

static void mlr_write_sysctl(int fd, char val)
{
	ssize_t w;

	if (fd < 0)
		return;
	w = pwrite(fd, &val, 1, 0);
	(void)w;
}

/*
 * Flip worker (fork()d): hammer the two legs' sysctls 1 <-> 0 as fast
 * as possible for MLR_WALL_NS.  Every 1 -> 0 transition that lands
 * between the rebalance's two passes turns `total == 0` into a live
 * divisor.  _exit()s -- noreturn.
 */
static void mlr_flip_worker(int fd_a, int fd_b)
{
	struct timespec t0;
	unsigned int i;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < MLR_FLIP_ITERS; i++) {
		char v = (char)('1' - (char)(i & 1U));	/* '1' then '0' */

		mlr_write_sysctl(fd_a, v);
		mlr_write_sysctl(fd_b, v);
		__atomic_add_fetch(
			&shm->stats.multipath_linkdown_rebalance.flip_writes,
			2, __ATOMIC_RELAXED);

		if ((i & 0x3ffU) == 0 &&
		    (unsigned long long)ns_since(&t0) >= MLR_WALL_NS)
			break;
	}

	_exit(0);
}

/*
 * Reap the flip worker; SIGKILL after MLR_REAP_WALL_NS so a wedged
 * worker cannot outrun the outer SIGALRM(1).
 */
static void mlr_reap_worker(pid_t pid)
{
	struct timespec deadline;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid_eintr(pid, NULL, 0);
		return;
	}
	deadline.tv_nsec += (long)MLR_REAP_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	for (;;) {
		struct timespec now;
		pid_t r;

		r = waitpid_eintr(pid, NULL, WNOHANG);
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline.tv_sec ||
		     (now.tv_sec == deadline.tv_sec &&
		      now.tv_nsec >= deadline.tv_nsec))) {
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, NULL, 0);
			return;
		}
		(void)usleep(2000);
	}
}

/* ------------------------------------------------------------------ */
/* per-invocation body                                                 */
/* ------------------------------------------------------------------ */

static int multipath_linkdown_rebalance_in_ns(void *arg)
{
	struct mlr_ctx *cctx = (struct mlr_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_MULTIPATH_LINKDOWN_REBALANCE,
	};
	struct mlr_leg legs[MLR_LEGS];
	const bool v6 = (rand32() & 1U) != 0;
	int fd_a = -1, fd_b = -1;
	pid_t worker = -1;
	unsigned int i;
	bool route_installed = false;
	unsigned long direct_calls = 0;
	struct timespec t0;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	memset(legs, 0, sizeof(legs));

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(
			&shm->stats.multipath_linkdown_rebalance.setup_failed,
			1, __ATOMIC_RELAXED);
		return 0;
	}

	rtnl_bring_lo_up(&ctx);

	__atomic_add_fetch(v6 ?
		&shm->stats.multipath_linkdown_rebalance.v6_runs :
		&shm->stats.multipath_linkdown_rebalance.v4_runs,
		1, __ATOMIC_RELAXED);

	/* Build MLR_LEGS veth pairs, each with the local end UP and the
	 * peer left DOWN so the local end has no carrier. */
	for (i = 0; i < MLR_LEGS; i++) {
		struct mlr_leg *l = &legs[i];
		unsigned int tag = rand32() & 0xffffU;

		snprintf(l->local, sizeof(l->local), "mlr%u_%x", i, tag);
		snprintf(l->peer,  sizeof(l->peer),  "mlrp%u_%x", i, tag);

		if (mlr_create_veth(&ctx, l->local, l->peer) != 0)
			goto out;

		l->ifindex = (int)if_nametoindex(l->local);
		if (l->ifindex <= 0)
			goto out;
		name_pool_record(NAME_KIND_NETDEV, l->local,
				 strlen(l->local));

		/* 10.55.i.1/24, gateway 10.55.i.2 (v4);
		 * fc55:i::1/64, gateway fc55:i::2 (v6). */
		l->addr4_he = 0x0a370001U | (i << 8);	/* 10.55.i.1 */
		l->gw4_he   = 0x0a370002U | (i << 8);	/* 10.55.i.2 */
		l->addr6.s6_addr[0] = 0xfc;
		l->addr6.s6_addr[1] = 0x55;
		l->addr6.s6_addr[3] = (unsigned char)i;
		l->addr6.s6_addr[15] = 0x01;
		l->gw6 = l->addr6;
		l->gw6.s6_addr[15] = 0x02;

		/* Bring the local end up; leave the peer down. */
		if (rtnl_setlink_up(&ctx, l->ifindex) != 0)
			goto out;

		if (v6) {
			if (mlr_add_addr6(&ctx, l->ifindex, &l->addr6) != 0)
				goto out;
		} else {
			if (mlr_add_addr4(&ctx, l->ifindex, l->addr4_he) != 0)
				goto out;
		}
	}

	__atomic_add_fetch(
		&shm->stats.multipath_linkdown_rebalance.legs_ok,
		1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Prime the sysctls to 1 so the first-pass weight sum can be
	 * zero, and open write handles for the flip worker. */
	fd_a = mlr_open_sysctl(v6, legs[0].local);
	fd_b = mlr_open_sysctl(v6, legs[1].local);
	mlr_write_sysctl(fd_a, '1');
	mlr_write_sysctl(fd_b, '1');

	/* Install the multipath route -- num_path == 2 arms the
	 * rebalance.  A kernel without CONFIG_IP_ROUTE_MULTIPATH /
	 * CONFIG_IPV6 returns an error here; that is benign coverage. */
	if (mlr_build_route(&ctx, v6, legs, false) != 0)
		goto out;
	route_installed = true;
	__atomic_add_fetch(
		&shm->stats.multipath_linkdown_rebalance.route_ok,
		1, __ATOMIC_RELAXED);

	worker = fork();
	if (worker < 0) {
		__atomic_add_fetch(
			&shm->stats.multipath_linkdown_rebalance.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	if (worker == 0) {
		/* The worker only needs the sysctl fds; drop the rtnl fd. */
		nl_close(&ctx);
		mlr_flip_worker(fd_a, fd_b);
		/* unreachable */
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/* Parent replace loop: every REPLACE re-runs the two-pass
	 * rebalance, racing the worker's sysctl flips. */
	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}
	for (i = 0; i < MLR_REPLACE_ITERS; i++) {
		if ((unsigned long long)ns_since(&t0) >= MLR_WALL_NS)
			break;
		if (mlr_build_route(&ctx, v6, legs, true) == 0)
			__atomic_add_fetch(
				&shm->stats.multipath_linkdown_rebalance.rebalance_triggers,
				1, __ATOMIC_RELAXED);
	}

	mlr_reap_worker(worker);
	worker = -1;
	__atomic_add_fetch(
		&shm->stats.multipath_linkdown_rebalance.completed_ok,
		1, __ATOMIC_RELAXED);

out:
	if (worker > 0) {
		(void)kill(worker, SIGKILL);
		(void)waitpid_eintr(worker, NULL, 0);
	}
	if (fd_a >= 0) {
		close(fd_a);
		direct_calls++;
	}
	if (fd_b >= 0) {
		close(fd_b);
		direct_calls++;
	}
	if (ctx.fd >= 0) {
		(void)route_installed;	/* route reaped with the netns */
		for (i = 0; i < MLR_LEGS; i++)
			if (legs[i].ifindex > 0)
				(void)rtnl_dellink(&ctx, legs[i].ifindex);
		nl_close(&ctx);
	}
	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return 0;
}

bool multipath_linkdown_rebalance(struct childdata *child)
{
	struct mlr_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.multipath_linkdown_rebalance.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET,
			      multipath_linkdown_rebalance_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(
			&shm->stats.multipath_linkdown_rebalance.setup_failed,
			1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0)
		__atomic_add_fetch(
			&shm->stats.multipath_linkdown_rebalance.setup_failed,
			1, __ATOMIC_RELAXED);

	return true;
}

#else  /* !__has_include(<linux/veth.h>) */

bool multipath_linkdown_rebalance(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.multipath_linkdown_rebalance.runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(
		&shm->stats.multipath_linkdown_rebalance.setup_failed, 1,
		__ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/veth.h>) */

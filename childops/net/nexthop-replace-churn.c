/*
 * nexthop_replace_churn - race NLM_F_REPLACE on a single nexthop id
 * against unlocked IPv6 route add/del walking f6i_list.  Targets the
 * bug class where the nexthop replace notifier walks fib6_info->
 * nh_list without holding the f6i write lock, racing fib6_purge_rt()
 * on a concurrent RTM_DELROUTE (KASAN slab-use-after-free splat).
 *
 * Sequence (per invocation, inside a userns_run_in_ns grandchild):
 *   1. Bring lo up in the fresh netns.
 *   2. Create NHRC_MEMBERS singleton nh ids on lo for the group
 *      arm, plus a target nh id we will REPLACE in the hot loop.
 *   3. Install a sentinel IPv6 /128 route bound to the target via
 *      RTA_NH_ID so the kernel's nh->f6i_list is non-empty when the
 *      replace notifier fires.
 *   4. fork(): child hammers RTM_NEWROUTE / RTM_DELROUTE on random
 *      /128 destinations pointed at the target; parent hammers
 *      RTM_NEWNEXTHOP + NLM_F_REPLACE on the target, alternating
 *      single-nh (NHA_OIF + NHA_GATEWAY churn) and NHA_GROUP forms
 *      referencing the pre-created members (so group membership
 *      genuinely mutates every replace).
 *   5. Parent SIGKILLs the child at a wall deadline; the grandchild
 *      _exit()s and the kernel reaps every route/nh with the netns.
 *
 * All addresses live in ULA (fd00::/8) inside the private netns; the
 * outer trinity child never leaves its own credentials/netns, so a
 * runaway fdxx::/128 install cannot leak to the host table.
 *
 * Per-invocation self-bounded.  All sockets are O_CLOEXEC; SO_RCVTIMEO
 * is set on every rtnl fd; the fork worker runs a bounded outer loop
 * plus a wall-clock cap, so a wedged netlink path can't hold the
 * grandchild past its parent's SIGKILL.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"

/*
 * linux/nexthop.h landed in 5.3.  Sysroots older than that ship neither
 * the header nor struct nhmsg / NHA_* / RTM_NEWNEXTHOP.  Stub the whole
 * childop when the header is missing so the build stays clean.
 */
#if __has_include(<linux/nexthop.h>)

#include <linux/nexthop.h>

/* RTA_NH_ID landed alongside NHA_ID; supply a stable value when a
 * sysroot pre-dates the rtnetlink.h refresh but does have nexthop.h. */
#ifndef RTA_NH_ID
#define RTA_NH_ID			27
#endif

#define NHRC_BUF			2048
#define NHRC_TARGET_ID			0xC0DE0001U
#define NHRC_MEMBER_BASE		0xC0DE0100U
#define NHRC_MEMBERS			6U
#define NHRC_REPLACE_ITERS		48U
#define NHRC_ROUTE_ITERS		64U
#define NHRC_WALL_NS			(150ULL * 1000ULL * 1000ULL)
#define NHRC_REAP_WALL_NS		(250ULL * 1000ULL * 1000ULL)

/* userns_run_in_ns() returned -EPERM: hardened policy refused
 * CLONE_NEWUSER.  Latch the op off for the remainder of this child's
 * lifetime -- without a private netns we MUST NOT touch the host
 * IPv6 FIB / nexthop tables. */
static bool ns_unsupported;

struct nhrc_ctx {
	struct childdata *child;
};

/*
 * Build & send RTM_NEWNEXTHOP creating a single-nh entry with a fixed
 * NHA_ID bound to `oif` (with an optional NHA_GATEWAY).  `flags` picks
 * NLM_F_CREATE|NLM_F_EXCL for the initial install or NLM_F_REPLACE for
 * the hot loop.  Returns nl_send_recv() convention.
 */
static int build_nh_single(struct nl_ctx *ctx, __u32 nh_id, int oif,
			   const struct in6_addr *gw, __u16 extra_flags)
{
	unsigned char buf[NHRC_BUF];
	struct nlmsghdr *nlh;
	struct nhmsg *nhm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWNEXTHOP;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	nhm = (struct nhmsg *)NLMSG_DATA(nlh);
	nhm->nh_family   = AF_INET6;
	nhm->nh_protocol = RTPROT_STATIC;
	nhm->nh_scope    = RT_SCOPE_UNIVERSE;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nhm));

	off = nla_put_u32(buf, off, sizeof(buf), NHA_ID, nh_id);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), NHA_OIF, (__u32)oif);
	if (!off)
		return -EIO;
	if (gw) {
		off = nla_put(buf, off, sizeof(buf), NHA_GATEWAY, gw,
			      sizeof(*gw));
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build & send RTM_NEWNEXTHOP creating a group nh with a fixed NHA_ID
 * that references `count` member nh ids (weight 1 each).  `flags` is
 * NLM_F_CREATE|NLM_F_EXCL or NLM_F_REPLACE.
 */
static int build_nh_group(struct nl_ctx *ctx, __u32 nh_id,
			  const __u32 *members, unsigned int count,
			  __u16 extra_flags)
{
	unsigned char buf[NHRC_BUF];
	struct nexthop_grp grp[NHRC_MEMBERS];
	struct nlmsghdr *nlh;
	struct nhmsg *nhm;
	unsigned int i;
	size_t off;

	if (count == 0 || count > NHRC_MEMBERS)
		return -EIO;

	memset(buf, 0, sizeof(buf));
	memset(grp, 0, sizeof(grp));
	for (i = 0; i < count; i++) {
		grp[i].id = members[i];
		grp[i].weight = 0;	/* kernel treats 0 as weight 1 */
	}

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWNEXTHOP;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	nhm = (struct nhmsg *)NLMSG_DATA(nlh);
	nhm->nh_family   = AF_UNSPEC;
	nhm->nh_protocol = RTPROT_STATIC;
	nhm->nh_scope    = RT_SCOPE_UNIVERSE;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nhm));

	off = nla_put_u32(buf, off, sizeof(buf), NHA_ID, nh_id);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), NHA_GROUP, grp,
		      count * sizeof(grp[0]));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build & send RTM_DELNEXTHOP keyed on NHA_ID.
 */
static int build_nh_del(struct nl_ctx *ctx, __u32 nh_id)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct nhmsg *nhm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELNEXTHOP;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	nhm = (struct nhmsg *)NLMSG_DATA(nlh);
	nhm->nh_family = AF_UNSPEC;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nhm));
	off = nla_put_u32(buf, off, sizeof(buf), NHA_ID, nh_id);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build & send RTM_NEWROUTE / RTM_DELROUTE for an AF_INET6 /128 route
 * whose sole nexthop attribute is RTA_NH_ID = nh_id.  This is the
 * caller that grafts fib6_info onto nh->f6i_list; without RTA_NH_ID
 * the route never enters the list and the race window doesn't open.
 */
static int build_route6(struct nl_ctx *ctx, int cmd,
			const struct in6_addr *dst, __u32 nh_id)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = (unsigned short)cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (cmd == RTM_NEWROUTE)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET6;
	rtm->rtm_dst_len  = 128;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	off = nla_put(buf, off, sizeof(buf), RTA_DST, dst, sizeof(*dst));
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), RTA_NH_ID, nh_id);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Populate a ULA IPv6 address (fd00:<r16>:<r16>:<r16>::<r16>) into out.
 * Kept inside the netns; every /128 lives in fd00::/8 so a stray leak
 * would still be unrouteable on the host.
 */
static void nhrc_pick_ula(struct in6_addr *out)
{
	__u32 r0 = rand32();
	__u32 r1 = rand32();
	__u32 r2 = rand32();

	memset(out, 0, sizeof(*out));
	out->s6_addr[0] = 0xfd;
	out->s6_addr[1] = (unsigned char)(r0 & 0xff);
	out->s6_addr[2] = (unsigned char)((r0 >> 8) & 0xff);
	out->s6_addr[3] = (unsigned char)((r0 >> 16) & 0xff);
	out->s6_addr[4] = (unsigned char)((r1) & 0xff);
	out->s6_addr[5] = (unsigned char)((r1 >> 8) & 0xff);
	out->s6_addr[14] = (unsigned char)(r2 & 0xff);
	out->s6_addr[15] = (unsigned char)((r2 >> 8) & 0xff) | 0x01;
}

/*
 * Child worker: hammer RTM_NEWROUTE / RTM_DELROUTE with RTA_NH_ID on
 * the target nh id.  Every add/del pair walks fib6_info->nh_list
 * insertion + fib6_purge_rt() removal in the same routing table the
 * parent's REPLACE notifier is walking.  Bounded outer count + wall
 * deadline; _exit()s so the grandchild's rtnl socket dies with it.
 */
static void nhrc_route_worker(void)
{
	CHILDOP_GRANDCHILD_ENTER();
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		/*
		 * Grandchild after fork(): this_child() returns the
		 * COW-inherited parent slot (non-NULL), so nl_open()'s
		 * this_child() fallback would fire and attribute
		 * transport calls to the parent's op_type.  Set
		 * caller_op explicitly so the worker's RTM_NEWROUTE /
		 * RTM_DELROUTE burst is attributed correctly via
		 * nl_close() -- the explicit value wins the early-exit
		 * in nl_open() and prevents any mismatch from the
		 * COW-inherited parent slot.
		 */
		.caller_op = CHILD_OP_NEXTHOP_REPLACE_CHURN,
	};
	struct timespec t0;
	unsigned int i;

	if (nl_open(&ctx, &opts) < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < NHRC_ROUTE_ITERS; i++) {
		struct in6_addr dst;

		if ((unsigned long long)ns_since(&t0) >= NHRC_WALL_NS)
			break;

		nhrc_pick_ula(&dst);

		if (build_route6(&ctx, RTM_NEWROUTE, &dst,
				 NHRC_TARGET_ID) == 0) {
			__atomic_add_fetch(
				&shm->stats.nexthop_replace_churn.route_add_ok,
				1, __ATOMIC_RELAXED);
			if (build_route6(&ctx, RTM_DELROUTE, &dst,
					 NHRC_TARGET_ID) == 0)
				__atomic_add_fetch(
					&shm->stats.nexthop_replace_churn.route_del_ok,
					1, __ATOMIC_RELAXED);
		}
	}

	nl_close(&ctx);
	_exit(0);
}

/*
 * Reap the route-worker child.  Retries through EINTR; after
 * NHRC_REAP_WALL_NS a SIGKILL is delivered so a wedged worker cannot
 * outrun the outer trinity SIGALRM(1).
 */
static void nhrc_reap_worker(pid_t pid)
{
	struct timespec deadline;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid_eintr(pid, NULL, 0);
		return;
	}
	deadline.tv_nsec += (long)NHRC_REAP_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

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
		    (now.tv_sec > deadline.tv_sec ||
		     (now.tv_sec == deadline.tv_sec &&
		      now.tv_nsec >= deadline.tv_nsec))) {
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			return;
		}
		(void)usleep(2000);
	}
}

/*
 * Parent replace loop: on each iteration alternate a single-nh
 * REPLACE (mutates NHA_OIF-still-lo + fresh NHA_GATEWAY) with a
 * group REPLACE (mutates the referenced member set).  Both variants
 * fire the __nexthop_replace_notify() path that walks nh->f6i_list;
 * the sibling worker's route churn is what turns the walk into a
 * concurrent access.
 */
static void nhrc_replace_loop(struct nl_ctx *ctx, int lo_ifindex,
			      const __u32 *members)
{
	struct timespec t0;
	unsigned int i;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < NHRC_REPLACE_ITERS; i++) {
		int rc;

		if ((unsigned long long)ns_since(&t0) >= NHRC_WALL_NS)
			break;

		if ((i & 1U) == 0) {
			struct in6_addr gw;

			nhrc_pick_ula(&gw);
			rc = build_nh_single(ctx, NHRC_TARGET_ID, lo_ifindex,
					     &gw, NLM_F_REPLACE);
			if (rc == 0)
				__atomic_add_fetch(
					&shm->stats.nexthop_replace_churn.replace_single_ok,
					1, __ATOMIC_RELAXED);
		} else {
			__u32 subset[NHRC_MEMBERS];
			unsigned int j, count;

			count = 2U + rnd_modulo_u32(NHRC_MEMBERS - 1U);
			if (count > NHRC_MEMBERS)
				count = NHRC_MEMBERS;
			for (j = 0; j < count; j++)
				subset[j] = members[j];

			rc = build_nh_group(ctx, NHRC_TARGET_ID, subset, count,
					    NLM_F_REPLACE);
			if (rc == 0)
				__atomic_add_fetch(
					&shm->stats.nexthop_replace_churn.replace_group_ok,
					1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Per-invocation body run inside the userns_run_in_ns grandchild.  The
 * grandchild's userns + netns are torn down on _exit() so every route,
 * nexthop, and socket left behind is reaped by the kernel along with
 * the namespace.  Return value is ignored by the helper.
 */
static int nexthop_replace_churn_in_ns(void *arg)
{
	struct nhrc_ctx *cctx = (struct nhrc_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	struct in6_addr sentinel_dst;
	__u32 members[NHRC_MEMBERS];
	unsigned int i;
	int lo_ifindex;
	bool sentinel_installed = false;
	bool target_installed = false;
	unsigned int members_installed = 0;
	pid_t worker = -1;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);
		return 0;
	}

	rtnl_bring_lo_up(&ctx);
	lo_ifindex = (int)if_nametoindex("lo");
	if (lo_ifindex <= 0) {
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}

	for (i = 0; i < NHRC_MEMBERS; i++) {
		int rc;

		members[i] = NHRC_MEMBER_BASE + i;
		rc = build_nh_single(&ctx, members[i], lo_ifindex, NULL,
				     NLM_F_CREATE | NLM_F_EXCL);
		if (rc != 0) {
			/* Kernel without CONFIG_IPV6_MULTIPLE_TABLES or
			 * nexthop support returns -EAFNOSUPPORT / -EOPNOTSUPP
			 * on the first install -- bail cleanly, the grandchild
			 * teardown reaps the partial state. */
			__atomic_add_fetch(
				&shm->stats.nexthop_replace_churn.setup_failed,
				1, __ATOMIC_RELAXED);
			goto out;
		}
		members_installed++;
	}

	if (build_nh_single(&ctx, NHRC_TARGET_ID, lo_ifindex, NULL,
			    NLM_F_CREATE | NLM_F_EXCL) != 0) {
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	target_installed = true;
	__atomic_add_fetch(&shm->stats.nexthop_replace_churn.nh_setup_ok,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	nhrc_pick_ula(&sentinel_dst);
	if (build_route6(&ctx, RTM_NEWROUTE, &sentinel_dst,
			 NHRC_TARGET_ID) != 0)
		goto out;
	sentinel_installed = true;
	__atomic_add_fetch(&shm->stats.nexthop_replace_churn.sentinel_ok,
			   1, __ATOMIC_RELAXED);

	worker = fork();
	if (worker < 0) {
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	if (worker == 0) {
		nl_close(&ctx);
		nhrc_route_worker();
		/* unreachable */
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	nhrc_replace_loop(&ctx, lo_ifindex, members);

	nhrc_reap_worker(worker);
	worker = -1;

out:
	if (worker > 0) {
		(void)kill(worker, SIGKILL);
		(void)waitpid_eintr(worker, NULL, 0);
	}
	if (ctx.fd >= 0) {
		if (sentinel_installed)
			(void)build_route6(&ctx, RTM_DELROUTE,
					   &sentinel_dst, NHRC_TARGET_ID);
		if (target_installed) {
			if (build_nh_del(&ctx, NHRC_TARGET_ID) == 0)
				__atomic_add_fetch(
					&shm->stats.nexthop_replace_churn.teardown_ok,
					1, __ATOMIC_RELAXED);
		}
		for (i = 0; i < members_installed; i++)
			(void)build_nh_del(&ctx, members[i]);
		nl_close(&ctx);
	}

	return 0;
}

bool nexthop_replace_churn(struct childdata *child)
{
	struct nhrc_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nexthop_replace_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, nexthop_replace_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0)
		__atomic_add_fetch(
			&shm->stats.nexthop_replace_churn.setup_failed,
			1, __ATOMIC_RELAXED);

	return true;
}

#else  /* !__has_include(<linux/nexthop.h>) */

bool nexthop_replace_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.nexthop_replace_churn.runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.nexthop_replace_churn.setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/nexthop.h>) */

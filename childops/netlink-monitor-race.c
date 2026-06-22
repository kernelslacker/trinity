/*
 * netlink_monitor_race - rtnetlink broadcast monitor + concurrent rtnl
 * rule mutation, targeting netlink_broadcast_filtered races.
 *
 * Flat single-syscall fuzzing of NETLINK_ROUTE rarely assembles the
 * full multi-step setup that opens the broadcast path: a bound monitor
 * socket with non-zero nl_groups, NETLINK_LISTEN_ALL_NSID enabled,
 * NETLINK_BROADCAST_ERROR enabled, AND another socket actively
 * mutating the rtnl objects whose change events feed those groups.
 * Without all four pieces in flight at once, the rcu / nspath race
 * windows in netlink_broadcast_filtered, the NETLINK_LISTEN_ALL_NSID
 * peernet path, and the per-group membership add/drop machinery are
 * never exercised against a live subscriber list.
 *
 * Sequence (per invocation):
 *   1. Enter a private net namespace so any mutation we make never
 *      touches the host's main routing table.  When the parent
 *      already provisioned one (shm->isolation.net_ready set --
 *      root-started, --no-startup-isolation unset, parent unshare +
 *      lo-up succeeded) we inherit it via fork() and skip the per-
 *      childop unshare entirely; loopback is already UP with
 *      127.0.0.1/::1 assigned, so the address/route control surface
 *      is reachable.  Otherwise we fall back to a per-childop
 *      unshare(CLONE_NEWNET); EPERM (the post-drop_privs non-root
 *      case) latches the op off for the rest of this child's
 *      lifetime, exactly as before the gate existed.  lo-only (no
 *      veth peer day 1) keeps real two-endpoint datapaths out of
 *      reach -- this op is single-socket control-plane churn and is
 *      not affected; a veth-pair follow-up will lift the limit for
 *      datapath-driven ops.
 *   2. Open `mon` socket: AF_NETLINK / NETLINK_ROUTE, O_CLOEXEC,
 *      SO_RCVTIMEO=1s, bind with nl_groups carrying a random subset
 *      of RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
 *      RTMGRP_NEIGH | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE.
 *   3. setsockopt(mon, NETLINK_LISTEN_ALL_NSID, 1) -- attaches the
 *      peernet path.  CVE-2024-26688 lineage.
 *   4. setsockopt(mon, NETLINK_BROADCAST_ERROR, 1) -- promotes
 *      ENOBUFS into recv error returns.
 *   5. Open `mut` socket: a separate AF_NETLINK / NETLINK_ROUTE
 *      writer used to drive RTM_NEWLINK / RTM_NEWADDR / RTM_DELADDR
 *      / RTM_DELLINK against a freshly-created dummy interface.
 *      Each mutation broadcasts to mon's bound groups.
 *   6. Inner loop (small, bounded): mut emits NEWLINK kind=dummy,
 *      NEWADDR ipv4, DELADDR, DELLINK; mon drains with recvmsg
 *      MSG_DONTWAIT in between.
 *   7. Mid-stream: NETLINK_DROP_MEMBERSHIP of one bound group.
 *   8. Mid-stream: NETLINK_ADD_MEMBERSHIP of a different group.
 *      The drop/add pair against an active broadcast walker is the
 *      targeted netlink_broadcast_filtered race window.
 *   9. Final NEWADDR/DELADDR cycle so events fire after the
 *      membership churn.
 *
 * CVE class: CVE-2022-1972 (netlink rcu UAF on broadcast),
 * CVE-2022-3635 (netlink_listen mishandling), CVE-2024-26688
 * (NETLINK_LISTEN_ALL_NSID nspath race).  Also exercises the
 * NETLINK_LIST_MEMBERSHIPS getsockopt path.  Subsystems reached:
 * net/netlink/af_netlink.c (membership/broadcast), net/core/
 * rtnetlink.c (event emission), net/netlink/genetlink.c (shared
 * nlmsg paths).
 *
 * Self-bounding: NETLINK_MUT_BURST (8) mutations per invocation, one
 * cycle per call.  All sockets are O_CLOEXEC and SO_RCVTIMEO=1s so an
 * unresponsive netlink path can't wedge the child past the alarm(1)
 * cap.  Failure on every step (EPERM in the host namespace, ENODEV,
 * EINVAL, ENOPROTOOPT on older kernels lacking LISTEN_ALL_NSID) is
 * benign coverage rather than childop failure.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "compat.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef NETLINK_BROADCAST_ERROR
#define NETLINK_BROADCAST_ERROR	4
#endif
#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP	1
#endif
#ifndef NETLINK_DROP_MEMBERSHIP
#define NETLINK_DROP_MEMBERSHIP	2
#endif
#ifndef NETLINK_LIST_MEMBERSHIPS
#define NETLINK_LIST_MEMBERSHIPS 9
#endif

#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1
#define MON_DRAIN_BYTES		4096
#define NETLINK_MUT_BURST	8

/* The set of group ids (1-based, as required by NETLINK_ADD/DROP_
 * MEMBERSHIP) corresponding to the RTMGRP_* mask bits we bind on.
 * RTMGRP_LINK (0x1) is group 1, RTMGRP_IPV4_IFADDR (0x10) is group 5,
 * etc.  Trinity needs the group id (not the mask bit) for the
 * setsockopt path.  Keep this short -- larger group ids exist but
 * these are the ones whose events we actually drive below. */
static const __u32 monitor_group_ids[] = {
	RTNLGRP_LINK,			/* RTMGRP_LINK */
	RTNLGRP_NEIGH,			/* RTMGRP_NEIGH */
	RTNLGRP_IPV4_IFADDR,		/* RTMGRP_IPV4_IFADDR */
	RTNLGRP_IPV4_ROUTE,		/* RTMGRP_IPV4_ROUTE */
	RTNLGRP_IPV6_IFADDR,		/* RTMGRP_IPV6_IFADDR */
	RTNLGRP_IPV6_ROUTE,		/* RTMGRP_IPV6_ROUTE */
};
#define NR_MONITOR_GROUPS	(sizeof(monitor_group_ids) / sizeof(monitor_group_ids[0]))

/* Latched per-child on the fallback path only: shm->isolation.net_ready
 * was false and the per-childop unshare(CLONE_NEWNET) then returned
 * EPERM (or any other fatal error).  Trinity doesn't grant
 * CAP_SYS_ADMIN inside the host namespace under default execution, and
 * we MUST NOT touch the host's main routing table -- so when we can't
 * enter a private netns we permanently disable the op for this child.
 * Never latches when the parent provisioned the netns up front (we
 * already inherit it via fork() and never attempt the per-childop
 * unshare). */
static bool ns_unsupported;

/* Latched once this child has a private netns to operate in -- either
 * inherited from the parent (shm->isolation.net_ready) or obtained via
 * a successful per-childop unshare(CLONE_NEWNET) on the fallback path.
 * The trinity child process is long-lived; we only need to confirm the
 * private namespace once and reuse it across subsequent invocations.
 * Re-unsharing each call would just leak namespaces. */
static bool ns_ready;

/*
 * Build & send RTM_NEWLINK creating a dummy dev named `name`.  Returns
 * 0 on accept, negated errno on rejection, or -EIO on local failure.
 */
static int build_dummy_link(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	size_t li_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;

	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR / RTM_DELADDR for an IPv4 /24 link-local address on
 * ifindex.  Pass `cmd` = RTM_NEWADDR or RTM_DELADDR.  Returns the
 * netlink ack errno.  The address bits in `addr` are picked by the
 * caller so add/del symmetry is trivial.
 */
static int build_addr(struct nl_ctx *ctx, int cmd, int ifindex, __u32 addr)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = (unsigned short)cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (cmd == RTM_NEWADDR)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Drain pending broadcast events from `mon` non-blockingly.  Returns
 * the number of times a recv() returned > 0; caller bumps the
 * recv_drained stat by that count.  Stops at the first EAGAIN /
 * EWOULDBLOCK / error or after a small fixed number of iterations
 * to bound the work per call.
 */
static unsigned int drain_monitor(struct nl_ctx *mon)
{
	unsigned char rbuf[MON_DRAIN_BYTES];
	unsigned int got = 0;
	int i;

	for (i = 0; i < 8; i++) {
		ssize_t n = recv(mon->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n <= 0)
			break;
		got++;
	}
	return got;
}

/*
 * Build a random RTMGRP_* mask from the supported group set.  Always
 * returns at least RTMGRP_LINK so the bind has something to attach
 * the socket to and the broadcast path is non-trivially exercised.
 */
static __u32 random_group_mask(void)
{
	__u32 mask = RTMGRP_LINK;
	__u32 r = rand32();

	if (r & 0x1)  mask |= RTMGRP_IPV4_IFADDR;
	if (r & 0x2)  mask |= RTMGRP_IPV6_IFADDR;
	if (r & 0x4)  mask |= RTMGRP_NEIGH;
	if (r & 0x8)  mask |= RTMGRP_IPV4_ROUTE;
	if (r & 0x10) mask |= RTMGRP_IPV6_ROUTE;
	return mask;
}

/*
 * Per-invocation state shared across the phase helpers below.  Holds
 * the two netlink fds (monitor + mutator), the freshly-created dummy
 * interface's ifindex + address, and the teardown latches so the out:
 * label can issue the correct DELADDR / DELLINK on the way out without
 * threading six args through each helper.
 */
struct netlink_monitor_race_iter_ctx {
	struct nl_ctx	mon;
	struct nl_ctx	mut;
	int		ifindex;
	__u32		addr;
	bool		link_added;
	bool		addr_added;
};

/*
 * Phase: per-child netns setup.  Gated on shm->isolation.net_ready:
 * when the parent provisioned the netns at startup we inherit it via
 * fork() (lo already UP, 127.0.0.1/::1 already assigned) and just
 * latch ns_ready.  Otherwise we fall back to a per-childop
 * unshare(CLONE_NEWNET) -- the pre-isolation code path, unchanged
 * byte-for-byte: EPERM (post-drop_privs non-root) latches
 * ns_unsupported so the rest of the child's lifetime pays the EFAIL
 * once.  Returns 0 on success; -1 means caller should return true
 * immediately (no fds were opened, so no cleanup is needed).
 */
static int netlink_monitor_race_iter_setup_netns(void)
{
	if (ns_ready)
		return 0;

	if (__atomic_load_n(&shm->isolation.net_ready, __ATOMIC_RELAXED)) {
		ns_ready = true;
		return 0;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ns_ready = true;
	return 0;
}

/*
 * Phase: open the monitor netlink socket with a randomised RTMGRP_*
 * bind, then attach NETLINK_LISTEN_ALL_NSID (CVE-2024-26688 lineage)
 * and NETLINK_BROADCAST_ERROR.  Returns 0 on success; -1 means the
 * monitor open failed and the caller should return true immediately --
 * the mutator fd hasn't been opened yet so there is nothing to clean
 * up via the out: label.
 */
static int netlink_monitor_race_iter_open_monitor(struct netlink_monitor_race_iter_ctx *ctx)
{
	struct nl_open_opts mon_opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = RTNL_RECV_TIMEO_S,
	};
	int one = 1;

	/* The bind-time .groups subscription is the race-timing-critical
	 * piece this childop hangs on: the monitor must be a live
	 * broadcast subscriber for the mutator's NEWLINK / NEWADDR events
	 * before those events fire.  nl_open() bind()s with sa.nl_groups
	 * = opts->groups in the same syscall the per-file rtnl_open() did,
	 * preserving the atomic-with-bind subscribe semantics. */
	mon_opts.groups = random_group_mask();

	if (nl_open(&ctx->mon, &mon_opts) < 0) {
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mon_open,
			   1, __ATOMIC_RELAXED);

	/* Attach the peernet path -- CVE-2024-26688 lineage.  ENOPROTOOPT
	 * on older kernels is fine; we still hit the broadcast race below. */
	(void)setsockopt(ctx->mon.fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID,
			 &one, sizeof(one));

	/* Promote ENOBUFS into recv error returns so a heavy broadcast
	 * burst surfaces as an actual error rather than silent drops. */
	(void)setsockopt(ctx->mon.fd, SOL_NETLINK, NETLINK_BROADCAST_ERROR,
			 &one, sizeof(one));

	return 0;
}

/*
 * Phase: open the mutator netlink socket, create the fresh dummy
 * interface that all subsequent RTM_NEWADDR / RTM_DELADDR / RTM_DELLINK
 * traffic targets, resolve its ifindex, and seed the link-local IPv4
 * address that the burst phases recycle.  Returns 0 on success; -1
 * means the caller should goto out -- mut may already be open and the
 * dummy link may already exist, so the teardown side has work to do.
 */
static int netlink_monitor_race_iter_open_mutator(struct netlink_monitor_race_iter_ctx *ctx)
{
	struct nl_open_opts mut_opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = RTNL_RECV_TIMEO_S,
	};
	char dev_name[IFNAMSIZ];

	if (nl_open(&ctx->mut, &mut_opts) < 0) {
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_open,
			   1, __ATOMIC_RELAXED);

	snprintf(dev_name, sizeof(dev_name), "trnlmon%u",
		 (unsigned int)(rand32() & 0xffffu));

	if (build_dummy_link(&ctx->mut, dev_name) != 0)
		return -1;
	ctx->link_added = true;
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
			   1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(dev_name);
	if (ctx->ifindex == 0)
		return -1;

	ctx->addr = htonl(0xa9fe0000u | (rand32() & 0x0000fffeu) | 1u);
	return 0;
}

/*
 * Phase: drive NETLINK_MUT_BURST RTM_NEWADDR / RTM_DELADDR cycles
 * against the freshly-created dummy interface, draining mon's pending
 * broadcasts in between each mutation.  Each address mutation broadcasts
 * to mon's bound groups, so the recv-side processing happens concurrently
 * with the next send -- the bug-class race window this op exists to open.
 */
static void netlink_monitor_race_iter_address_burst(struct netlink_monitor_race_iter_ctx *ctx)
{
	unsigned int drained;
	unsigned int i;

	for (i = 0; i < NETLINK_MUT_BURST; i++) {
		if (build_addr(&ctx->mut, RTM_NEWADDR, ctx->ifindex, ctx->addr) == 0) {
			ctx->addr_added = true;
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
					   1, __ATOMIC_RELAXED);
		}

		drained = drain_monitor(&ctx->mon);
		if (drained)
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
					   drained, __ATOMIC_RELAXED);

		if (ctx->addr_added) {
			if (build_addr(&ctx->mut, RTM_DELADDR, ctx->ifindex, ctx->addr) == 0) {
				ctx->addr_added = false;
				__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		drained = drain_monitor(&ctx->mon);
		if (drained)
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
					   drained, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: mid-stream NETLINK_DROP_MEMBERSHIP + NETLINK_ADD_MEMBERSHIP
 * against an active subscriber list.  The drop must be a group we
 * actually bound to (so the kernel takes the membership-remove path);
 * the add can be any of the supported groups (re-adding an already-held
 * one still exercises the membership-grow path).  The drop/add pair
 * against an active broadcast walker is the targeted
 * netlink_broadcast_filtered race window.
 */
static void netlink_monitor_race_iter_membership_churn(struct netlink_monitor_race_iter_ctx *ctx)
{
	__u32 drop_grp = monitor_group_ids[rand32() % NR_MONITOR_GROUPS];
	__u32 add_grp  = monitor_group_ids[rand32() % NR_MONITOR_GROUPS];

	if (setsockopt(ctx->mon.fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
		       &drop_grp, sizeof(drop_grp)) == 0)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_group_drop,
				   1, __ATOMIC_RELAXED);

	if (setsockopt(ctx->mon.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &add_grp, sizeof(add_grp)) == 0)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_group_add,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: final RTM_NEWADDR + drain after the membership churn.  This
 * is the broadcast path running against a freshly-mutated subscriber
 * set -- the after-shot of the drop/add race window.  The DELADDR for
 * this NEWADDR happens at the out: cleanup via the addr_added latch.
 */
static void netlink_monitor_race_iter_final_burst(struct netlink_monitor_race_iter_ctx *ctx)
{
	unsigned int drained;

	if (build_addr(&ctx->mut, RTM_NEWADDR, ctx->ifindex, ctx->addr) == 0) {
		ctx->addr_added = true;
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
				   1, __ATOMIC_RELAXED);
	}

	drained = drain_monitor(&ctx->mon);
	if (drained)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
				   drained, __ATOMIC_RELAXED);
}

bool netlink_monitor_race(struct childdata *child)
{
	struct netlink_monitor_race_iter_ctx ctx = {
		.mon = { .fd = -1 },
		.mut = { .fd = -1 },
	};

	__atomic_add_fetch(&shm->stats.netlink_monitor_race_runs, 1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported)
		return true;

	if (netlink_monitor_race_iter_setup_netns() != 0) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (netlink_monitor_race_iter_open_monitor(&ctx) != 0)
		return true;

	if (netlink_monitor_race_iter_open_mutator(&ctx) != 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	netlink_monitor_race_iter_address_burst(&ctx);
	netlink_monitor_race_iter_membership_churn(&ctx);
	netlink_monitor_race_iter_final_burst(&ctx);

out:
	if (ctx.mut.fd >= 0) {
		if (ctx.addr_added)
			(void)build_addr(&ctx.mut, RTM_DELADDR, ctx.ifindex, ctx.addr);
		if (ctx.link_added && ctx.ifindex > 0)
			(void)rtnl_dellink(&ctx.mut, ctx.ifindex);
		nl_close(&ctx.mut);
	}
	nl_close(&ctx.mon);

	return true;
}

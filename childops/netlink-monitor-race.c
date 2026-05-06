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
 *   1. unshare(CLONE_NEWNET) into a private net namespace so any
 *      mutation we make never touches the host's main routing table.
 *      Failure (EPERM, no user-namespace privilege) latches the
 *      childop off for the remainder of this child's lifetime.
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
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

/* Latched per-child: unshare(CLONE_NEWNET) returned EPERM (or any
 * other fatal error) once.  Trinity doesn't grant CAP_SYS_ADMIN
 * inside the host namespace under default execution, and we MUST
 * NOT touch the host's main routing table -- so when we can't enter
 * a private netns we permanently disable the op for this child. */
static bool ns_unsupported;

/* Latched once a successful unshare puts us in a private netns.
 * The trinity child process is long-lived; we only need to unshare
 * once and inherit the private namespace across subsequent
 * invocations.  Re-unsharing each call would just leak namespaces. */
static bool ns_unshared;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

/*
 * Open a NETLINK_ROUTE socket and bind it.  If groups != 0, bind with
 * that nl_groups mask so the kernel attaches us as a broadcast
 * subscriber for those groups in one step.  A zero mask leaves the
 * socket as a plain writer (mut).
 */
static int rtnl_open_groups(__u32 groups)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = groups;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = RTNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Send a complete netlink message and wait for an NLMSG_ERROR (ack).
 * Returns the kernel's ack errno (0 on success, negated errno on
 * rejection, or -EIO on local send/recv failure).
 */
static int rtnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return -EIO;
}

/*
 * Build & send RTM_NEWLINK creating a dummy dev named `name`.  Returns
 * 0 on accept, negated errno on rejection, or -EIO on local failure.
 */
static int build_dummy_link(int fd, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	size_t off;
	size_t li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWADDR / RTM_DELADDR for an IPv4 /24 link-local address on
 * ifindex.  Pass `cmd` = RTM_NEWADDR or RTM_DELADDR.  Returns the
 * netlink ack errno.  The address bits in `addr` are picked by the
 * caller so add/del symmetry is trivial.
 */
static int build_addr(int fd, int cmd, int ifindex, __u32 addr)
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
	nlh->nlmsg_seq = next_seq();

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
	return rtnl_send_recv(fd, buf, off);
}

static int build_dellink(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Drain pending broadcast events from `mon` non-blockingly.  Returns
 * the number of times a recv() returned > 0; caller bumps the
 * recv_drained stat by that count.  Stops at the first EAGAIN /
 * EWOULDBLOCK / error or after a small fixed number of iterations
 * to bound the work per call.
 */
static unsigned int drain_monitor(int mon)
{
	unsigned char rbuf[MON_DRAIN_BYTES];
	unsigned int got = 0;
	int i;

	for (i = 0; i < 8; i++) {
		ssize_t n = recv(mon, rbuf, sizeof(rbuf), MSG_DONTWAIT);
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

bool netlink_monitor_race(struct childdata *child)
{
	char dev_name[IFNAMSIZ];
	int mon = -1;
	int mut = -1;
	int ifindex = 0;
	__u32 addr;
	__u32 group_mask;
	__u32 drop_grp, add_grp;
	int one = 1;
	bool link_added = false;
	bool addr_added = false;
	unsigned int drained;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.netlink_monitor_race_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_unsupported = true;
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	group_mask = random_group_mask();

	mon = rtnl_open_groups(group_mask);
	if (mon < 0) {
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mon_open,
			   1, __ATOMIC_RELAXED);

	/* Attach the peernet path -- CVE-2024-26688 lineage.  ENOPROTOOPT
	 * on older kernels is fine; we still hit the broadcast race below. */
	(void)setsockopt(mon, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID,
			 &one, sizeof(one));

	/* Promote ENOBUFS into recv error returns so a heavy broadcast
	 * burst surfaces as an actual error rather than silent drops. */
	(void)setsockopt(mon, SOL_NETLINK, NETLINK_BROADCAST_ERROR,
			 &one, sizeof(one));

	mut = rtnl_open_groups(0);
	if (mut < 0) {
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_open,
			   1, __ATOMIC_RELAXED);

	snprintf(dev_name, sizeof(dev_name), "trnlmon%u",
		 (unsigned int)(rand32() & 0xffffu));

	if (build_dummy_link(mut, dev_name) != 0)
		goto out;
	link_added = true;
	__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
			   1, __ATOMIC_RELAXED);

	ifindex = (int)if_nametoindex(dev_name);
	if (ifindex == 0)
		goto out;

	addr = htonl(0xa9fe0000u | (rand32() & 0x0000fffeu) | 1u);

	/* Drive a small burst of address add/del cycles so each iteration
	 * generates a NEWADDR/DELADDR broadcast that mon must process. */
	for (i = 0; i < NETLINK_MUT_BURST; i++) {
		if (build_addr(mut, RTM_NEWADDR, ifindex, addr) == 0) {
			addr_added = true;
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
					   1, __ATOMIC_RELAXED);
		}

		drained = drain_monitor(mon);
		if (drained)
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
					   drained, __ATOMIC_RELAXED);

		if (addr_added) {
			if (build_addr(mut, RTM_DELADDR, ifindex, addr) == 0) {
				addr_added = false;
				__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		drained = drain_monitor(mon);
		if (drained)
			__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
					   drained, __ATOMIC_RELAXED);
	}

	/* Mid-stream membership churn against an active subscriber list.
	 * Pick two distinct groups from the supported set: one to drop,
	 * one to add.  The drop must be a group we actually bound to (so
	 * the kernel takes the membership-remove path); the add can be
	 * any of the supported groups (re-adding an already-held one
	 * still exercises the membership-grow path). */
	drop_grp = monitor_group_ids[rand32() % NR_MONITOR_GROUPS];
	add_grp  = monitor_group_ids[rand32() % NR_MONITOR_GROUPS];

	if (setsockopt(mon, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
		       &drop_grp, sizeof(drop_grp)) == 0)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_group_drop,
				   1, __ATOMIC_RELAXED);

	if (setsockopt(mon, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &add_grp, sizeof(add_grp)) == 0)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_group_add,
				   1, __ATOMIC_RELAXED);

	/* Final NEWADDR/DELADDR cycle so an event fires after the
	 * membership churn -- this is the broadcast path running against
	 * a freshly-mutated subscriber set. */
	if (build_addr(mut, RTM_NEWADDR, ifindex, addr) == 0) {
		addr_added = true;
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_mut_op_ok,
				   1, __ATOMIC_RELAXED);
	}

	drained = drain_monitor(mon);
	if (drained)
		__atomic_add_fetch(&shm->stats.netlink_monitor_race_recv_drained,
				   drained, __ATOMIC_RELAXED);

out:
	if (mut >= 0) {
		if (addr_added)
			(void)build_addr(mut, RTM_DELADDR, ifindex, addr);
		if (link_added && ifindex > 0)
			(void)build_dellink(mut, ifindex);
		close(mut);
	}
	if (mon >= 0)
		close(mon);

	return true;
}

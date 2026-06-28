#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>


#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>

#include "isolation.h"
#include "params.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"

/*
 * One-shot NETLINK_ROUTE socket helpers for the parent's lo
 * provisioning sequence.  Deliberately self-contained -- the
 * include/childops-netlink.h scaffolding is scoped to childops/ and
 * pulling it into the isolation spine would invert the layering.
 * The wire envelope here is the same shape the childops/ helpers
 * use (SOCK_RAW + bind to AF_NETLINK port 0 + sendmsg/recv on a
 * synchronous NLM_F_ACK reply), just stripped to the three messages
 * this file actually needs: RTM_NEWLINK lo IFF_UP, and two
 * RTM_NEWADDR (127.0.0.1/8 and ::1/128).
 *
 * Returns an open fd on success or -1 with errno preserved.  No
 * SO_RCVTIMEO -- we issue exactly three requests on a quiescent
 * socket in trusted single-threaded init context, and the kernel
 * acks each synchronously; a missing ack would be a kernel bug,
 * not a contention case the timeout would help with.
 */
static int privnet_open_route(void)
{
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int saved = errno;

		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

/*
 * Send a single nlmsg_len-sized request and wait for the matching
 * NLMSG_ERROR ack.  Returns 0 on positive ack, negated errno on
 * kernel-side rejection (so the caller can recognise -EEXIST), or
 * -EIO on local sendmsg/recv failure or a malformed reply shape.
 */
static int privnet_send_ack(int fd, void *msg, size_t len)
{
	unsigned char rbuf[1024];
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -EIO;

	err = (struct nlmsgerr *)NLMSG_DATA(nlh);
	return err->error;
}

/*
 * RTM_NEWLINK with ifi_flags=IFF_UP / ifi_change=IFF_UP on ifindex.
 * No other flag bits are touched.  Returns privnet_send_ack()'s
 * convention.
 */
static int privnet_bring_link_up(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_len   = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	return privnet_send_ack(fd, buf, nlh->nlmsg_len);
}

/*
 * RTM_NEWADDR adding `addr` (addrlen bytes) to ifindex at /prefixlen,
 * family AF_INET or AF_INET6, scope RT_SCOPE_HOST (the right scope for
 * loopback per ifa_scope rules in net/ipv{4,6}/devinet.c).  Both
 * IFA_LOCAL and IFA_ADDRESS carry the same value -- for a point-to-
 * point peer they would differ, but loopback is symmetric.
 *
 * EEXIST is intentionally absorbed as success: the kernel auto-assigns
 * ::1/128 to lo on its first IFF_UP via addrconf, so a second explicit
 * RTM_NEWADDR for ::1 races the kernel's own install and would
 * otherwise spuriously fail the latch.
 */
static int privnet_add_loopback_addr(int fd, int ifindex, int family,
				     unsigned char prefixlen,
				     const void *addr, size_t addrlen)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	struct nlattr *nla;
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = (unsigned char)family;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_HOST;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFA_LOCAL;
	nla->nla_len  = (unsigned short)(NLA_HDRLEN + addrlen);
	memcpy(buf + off + NLA_HDRLEN, addr, addrlen);
	off += NLA_ALIGN(nla->nla_len);

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFA_ADDRESS;
	nla->nla_len  = (unsigned short)(NLA_HDRLEN + addrlen);
	memcpy(buf + off + NLA_HDRLEN, addr, addrlen);
	off += NLA_ALIGN(nla->nla_len);

	nlh->nlmsg_len = (__u32)off;

	rc = privnet_send_ack(fd, buf, off);
	if (rc == -EEXIST)
		return 0;
	return rc;
}

/*
 * Provision the parent's freshly-private netns.  Conservative
 * day-1 default: bring `lo` UP and assign 127.0.0.1/8 + ::1/128 so
 * the netns has a usable single-endpoint loopback for the
 * socket/bind/listen/netlink/route/sock_diag childops to drive
 * against.  No veth pair and no spawned peer responder -- the
 * veth+peer two-endpoint datapath arrives in a follow-up.
 *
 * Returns 0 on success, -1 on any failure with errno preserved.
 * The caller's failure envelope is the same degrade-to-host path
 * the bare unshare uses: leave shm->isolation.net_ready=false and
 * children fall back to today's per-child unshare path.
 */
static int setup_private_net(void)
{
	struct in_addr  v4_loop = { .s_addr = htonl(INADDR_LOOPBACK) };
	struct in6_addr v6_loop = IN6ADDR_LOOPBACK_INIT;
	int fd, lo_idx, rc;
	int saved;

	lo_idx = (int)if_nametoindex("lo");
	if (lo_idx <= 0) {
		errno = ENODEV;
		return -1;
	}

	fd = privnet_open_route();
	if (fd < 0)
		return -1;

	rc = privnet_bring_link_up(fd, lo_idx);
	if (rc != 0) {
		saved = (rc < 0) ? -rc : EIO;
		close(fd);
		errno = saved;
		return -1;
	}

	rc = privnet_add_loopback_addr(fd, lo_idx, AF_INET, 8,
				       &v4_loop, sizeof(v4_loop));
	if (rc != 0) {
		saved = (rc < 0) ? -rc : EIO;
		close(fd);
		errno = saved;
		return -1;
	}

	rc = privnet_add_loopback_addr(fd, lo_idx, AF_INET6, 128,
				       &v6_loop, sizeof(v6_loop));
	if (rc != 0) {
		saved = (rc < 0) ? -rc : EIO;
		close(fd);
		errno = saved;
		return -1;
	}

	close(fd);
	return 0;
}

/*
 * Parent-side setup-then-drop spine.  Runs from init_pre_fork() after
 * do_uid0_check() and before any fork; the parent is still root here
 * by construction (auto-drop is per-child, in init_child_setup_sandbox).
 *
 * Three latches publish to children via shm:
 *
 *   isolation.net_ready -- unshare(CLONE_NEWNET) succeeded AND the
 *     follow-on setup_private_net() brought lo UP and assigned
 *     127.0.0.1/8 + ::1/128.  Children skip per-child unshare(CLONE_
 *     NEWNET) and inherit the parent's provisioned netns.
 *
 *   isolation.mnt_ready -- unshare(CLONE_NEWNS) plus the MS_REC|
 *     MS_PRIVATE remount of '/' both succeeded.  Children skip the
 *     per-child unshare(CLONE_NEWNS) + private-remount dance and
 *     inherit the parent's private mount ns.
 *
 *   isolation.netns_fd -- /proc/self/ns/net opened once net_ready
 *     latches.  Best-effort freebie for childops driving the BPF link
 *     API attach types whose target_fd is a netns handle (sk_lookup,
 *     flow_dissector, sk_reuseport).  Stays -1 if net_ready latched
 *     false or the open failed; consumers MUST gate on net_ready
 *     before reading.
 *
 * net_ready and mnt_ready are INDEPENDENT: MS_PRIVATE failing leaves
 * mnt_ready=false but does not block net provisioning, and lo bring-up
 * failing leaves net_ready=false but does not retract a latched
 * mnt_ready.  Either latch false routes the matching half through the
 * existing per-child unshare path.
 *
 * Degrade-to-host on any failure: leave the affected latch at the
 * zero value create_shm() memset, log once, return.  Children then
 * take the existing per-child unshare path for whichever half
 * degraded -- behaviour matches today's non-root run.
 *
 * Default: MS_REC|MS_PRIVATE only -- a writable scratch subtree
 * arrives with the scratch block pool; '/'-read-only is a
 * follow-up hardening pass, not day-1.
 *
 * Default: lo-only, no spawned peer.  Single-endpoint
 * loopback unlocks the netlink/route/netfilter/tc/sock_diag surface;
 * veth + minimal peer responder for real two-endpoint datapaths are
 * the follow-up.
 */
void setup_startup_isolation(void)
{
	int netns_fd;

	/*
	 * Non-root: never even attempt the syscalls.  The whole point of
	 * the gate is that every dev / claw build runs unprivileged and
	 * must see byte-for-byte today's behaviour -- same per-child
	 * unshare path in init_child_setup_sandbox, no new syscalls
	 * attempted from the parent.
	 */
	if (orig_uid != 0)
		return;

	/* Operator opt-out: forces today's behaviour even when launched
	 * as root.  Useful for debugging the per-child unshare path or
	 * running on a host where parent-side ns provisioning misbehaves. */
	if (no_startup_isolation)
		return;

	/*
	 * Enter a private net + mount ns in one shot.  If the kernel
	 * lacks CONFIG_NET_NS / CONFIG_NAMESPACES (ENOSYS) or a container
	 * sandbox blocks the unshare (EPERM), degrade silently.  The
	 * parent is the only caller, runs exactly once, and the failure
	 * envelope is "behave as today" -- no retry, no panic.
	 */
	if (unshare(CLONE_NEWNET | CLONE_NEWNS) != 0) {
		output(0, "startup isolation: unshare(CLONE_NEWNET|CLONE_NEWNS) failed (errno=%d) -- degrading to per-child unshare path\n",
			errno);
		return;
	}

	/*
	 * Mount-ns half.  Without an explicit MS_REC|MS_PRIVATE remount
	 * the new mount ns inherits the host's propagation mode (MS_SHARED
	 * on most distros), so any later mount() the children issue would
	 * propagate back into the host's mount tree -- defeating the whole
	 * containment story.  If the remount itself is refused we cannot
	 * safely advertise the mount ns to children (they'd skip the
	 * per-child MS_PRIVATE dance and let mount churn escape), so leave
	 * mnt_ready false and log.  The unshare cannot be undone; the
	 * parent stays in a private (but propagating) mount ns for the rest
	 * of the run, which is harmless because the parent never issues
	 * fuzzed mounts.  Net-side provisioning continues regardless --
	 * the two halves latch independently.
	 */
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		output(0, "startup isolation: MS_REC|MS_PRIVATE remount of '/' failed (errno=%d) -- mnt_ready stays false, net provisioning continues\n",
			errno);
	} else {
		__atomic_store_n(&shm->isolation.mnt_ready, true, __ATOMIC_RELAXED);
	}

	/*
	 * Net-ns half.  The bare unshare leaves lo DOWN with no addresses,
	 * which is not useful to the socket/bind/listen/netlink/route/
	 * sock_diag surface and is not what childops are coded to expect
	 * when they see net_ready=true.  Bring lo UP and assign
	 * 127.0.0.1/8 + ::1/128 here; only latch net_ready=true once that
	 * provisioning lands so the latch's meaning is "the netns is
	 * usable", not just "we entered one".
	 */
	if (setup_private_net() != 0) {
		output(0, "startup isolation: setup_private_net failed (errno=%d) -- net_ready stays false, children fall back to per-child unshare\n",
			errno);
		return;
	}

	/*
	 * BPF-link attach types whose target_fd is a netns handle
	 * (sk_lookup, flow_dissector, sk_reuseport) need a /proc/self/ns/
	 * net fd at link_create time.  Open it once here and stash in shm
	 * so every child draws from one shared fd instead of opening the
	 * same procfs path per call.  Best-effort: a failure here doesn't
	 * unprovision the netns, so net_ready still latches and consumers
	 * that find netns_fd == -1 just skip the attach type.
	 */
	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (netns_fd < 0) {
		output(0, "startup isolation: open(/proc/self/ns/net) failed (errno=%d) -- net_ready latched without BPF-link netns_fd freebie\n",
			errno);
		/* shm->isolation.netns_fd already -1 from create_shm(). */
	} else {
		shm->isolation.netns_fd = netns_fd;
	}

	/*
	 * Publish.  RELAXED matches the no_private_ns / no_pidns latch
	 * convention already used for sibling state in init_child_setup_
	 * sandbox; the cross-process happens-before edge to the child
	 * readers is provided by fork() itself, which is sequenced strictly
	 * after init_pre_fork() returns.
	 */
	__atomic_store_n(&shm->isolation.net_ready, true, __ATOMIC_RELAXED);

	output(0, "startup isolation: parent-provisioned netns (lo up, 127.0.0.1+::1) %s ready (children inherit, per-child unshare skipped)\n",
		__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED) ?
			"+ mount ns" : "(mount ns degraded)");
}

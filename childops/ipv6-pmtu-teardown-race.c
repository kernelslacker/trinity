/*
 * ipv6_pmtu_teardown_race - race ICMPv6 PKT_TOOBIG processing against
 * concurrent netdev teardown of the route's egress device.
 *
 * Bug surface: fib6_mtu() walks rt->rt6i_idev->cnf for the route's
 * device-level MTU.  rt6i_idev can be cleared from under the read by
 * the netdev unregister path (in6_dev_finish_destroy via NETDEV_DOWN /
 * RTM_DELLINK) while a concurrent rt6_update_pmtu invocation, kicked
 * off by an in-flight ICMPv6 PKT_TOOBIG, is mid-walk through the same
 * route.  Upstream commit 5ad509c1fdad fixed it by reading rt6i_idev
 * once into a local and null-checking before deref; the fuzz target is
 * the pre-fix race window.
 *
 * Setup (latched, per process):
 *   1. unshare(CLONE_NEWNET) probe.  EPERM/ENOSYS latches the op off
 *      for the rest of the trinity child's life.
 *
 * Per outer iteration (BUDGETED, base 2, cap 6):
 *   1. open /proc/self/ns/net anchor; unshare(CLONE_NEWNET).
 *   2. Bring lo up.  Create N=4 veth pairs rN/pN via rtnetlink:
 *      RTM_NEWLINK type=veth + IFLA_LINKINFO/IFLA_INFO_DATA/VETH_INFO_PEER.
 *   3. Per pair: RTM_NEWADDR ipv6 fc01::N/64 on rN; RTM_NEWLINK setlink
 *      IFF_UP for rN; RTM_NEWROUTE ipv6 dst=fc01:N::/48 gw=fc01::N+1
 *      oif=rN.  These give four routes whose ->rt6i_idev points at a
 *      device we can DELLINK out from under the PMTU walker.
 *   4. fork worker A (PTB sender): AF_INET6 SOCK_RAW IPPROTO_ICMPV6,
 *      tight sendto() loop emitting ICMPV6_PKT_TOOBIG (type 2 code 0)
 *      toward fc01:0::1, fc01:1::1, fc01:2::1, fc01:3::1 round-robin.
 *      The MTU advertised in the PTB body rotates 576..9000 to keep
 *      the rt6_update_pmtu lookup hot rather than caching a single
 *      value.  Each PTB enters icmpv6_notify -> rt6_pmtu_discovery and
 *      drives the fib6_mtu read on the matching route.
 *   5. fork worker B (DELLINK round-robin): tight RTM_DELLINK loop
 *      followed by RTM_NEWLINK recreate of the same name; cycles r0..r3
 *      so every route's egress device is repeatedly torn down and
 *      replaced.  The DELLINK path triggers in6_dev_finish_destroy on
 *      the down-going device, clearing rt6i_idev on routes that still
 *      reference it.
 *   6. Both workers self-bound to 200ms wall-clock via clock_gettime
 *      checks inside their inner loops; the parent waits up to ~250ms
 *      then SIGKILLs any laggard and waitpid-reaps both.
 *   7. setns back to the anchor; close anchor fd.  The doomed netns
 *      cleans up via cleanup_net once the worker fds drop.
 *
 * Latch:
 *   ns_unsupported_ipv6_pmtu_race -- master gate; set on first failure
 *   of the probe-phase unshare or the per-iter anchor open.  Mirrors
 *   the latch shape used by netns_teardown_churn / handshake_req_abort.
 *
 * Brick safety: every netlink and socket op runs inside a private
 * netns the child just unshared; the host's network state is untouched.
 * The doomed netns is collected by cleanup_net once iter_one's setns
 * back to anchor drops the last ref from this trinity child.
 *
 * Stats:
 *   ipv6_pmtu_race_runs        - total invocations
 *   ipv6_pmtu_race_setup_failed- probe / anchor / unshare / worker fork failed
 *   ipv6_pmtu_race_ptb_sent_ok - sendto(ICMPV6_PKT_TOOBIG) returned >=0
 *   ipv6_pmtu_race_dellink_ok  - RTM_DELLINK ack 0 from worker B
 *   ipv6_pmtu_race_completed_ok- iter_one reached setns-back + close cleanly
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>) && \
    __has_include(<linux/rtnetlink.h>) && __has_include(<linux/veth.h>)

#include <arpa/inet.h>
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

#include "jitter.h"
#include "random.h"

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER			1
#endif
#ifndef ICMPV6_PKT_TOOBIG
#define ICMPV6_PKT_TOOBIG		2
#endif

static bool ns_unsupported_ipv6_pmtu_race;
static bool ipv6_pmtu_race_probed;

#define V6PMTU_OUTER_BASE		1U
#define V6PMTU_OUTER_CAP		3U
#define V6PMTU_NUM_PAIRS		4U
#define V6PMTU_WORKER_WALL_NS		(200ULL * 1000ULL * 1000ULL)
#define V6PMTU_PARENT_WALL_NS		(250ULL * 1000ULL * 1000ULL)
#define V6PMTU_RTNL_BUF			512U

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * Send a fully formed nlmsghdr and consume one ack.  Returns 0 on
 * positive ack, the negated kernel errno on rejection, or -EIO on
 * local sendmsg/recv failure.  Best-effort across the childop -- a
 * negative return from any single call just leaves the corresponding
 * bump unincremented; the rest of the iteration still runs.
 */
static int rtnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[256];
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
	return 0;
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

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * RTM_NEWLINK type=veth name=<name> peer=<peer>.  Mirrors the shape
 * used by bridge-fdb-stp.c / bridge-vlan-churn.c: nested IFLA_LINKINFO
 * with IFLA_INFO_KIND=veth + IFLA_INFO_DATA holding VETH_INFO_PEER
 * whose payload starts with an ifinfomsg followed by IFLA_IFNAME for
 * the peer.
 */
static int build_veth_create(int fd, const char *name, const char *peer)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	struct nlattr *linkinfo, *infodata, *peer_attr;
	size_t off, li_off, id_off, peer_off;

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
	if (!off) return -EIO;

	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;

	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off) return -EIO;

	peer_off = off;
	off = nla_put(buf, off, sizeof(buf), VETH_INFO_PEER, NULL, 0);
	if (!off) return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off) return -EIO;

	peer_attr = (struct nlattr *)(buf + peer_off);
	peer_attr->nla_len = (unsigned short)(off - peer_off);
	infodata = (struct nlattr *)(buf + id_off);
	infodata->nla_len = (unsigned short)(off - id_off);
	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_addaddr_v6(int fd, int ifindex, const struct in6_addr *addr,
			    __u8 prefixlen)
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
	nlh->nlmsg_seq   = next_seq();

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
	return rtnl_send_recv(fd, buf, off);
}

static int build_setlink_up(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWROUTE ipv6 dst/<plen> gw=<gw> oif=<ifindex>.  RTPROT_BOOT and
 * RT_SCOPE_UNIVERSE keep the route eligible for the regular fib6
 * lookup; type RTN_UNICAST is required so rt6_update_pmtu treats it as
 * a normal forwarding entry.
 */
static int build_newroute_v6(int fd, const struct in6_addr *dst, __u8 plen,
			     const struct in6_addr *gw, int ifindex)
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
	nlh->nlmsg_seq   = next_seq();

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
	return rtnl_send_recv(fd, buf, off);
}

static int build_dellink_byname(int fd, const char *name)
{
	unsigned char buf[V6PMTU_RTNL_BUF];
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

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static void bring_lo_up(int fd)
{
	unsigned int lo_idx = if_nametoindex("lo");

	if (lo_idx == 0)
		return;
	(void)build_setlink_up(fd, (int)lo_idx);
}

/*
 * Build the four (rN, pN) veth pairs, assign fc01::N/64 to rN, bring
 * rN up, install the fc01:N::/48 route via fc01::N+1 dev rN.  Best
 * effort: any single rtnl rejection just skips that pair's downstream
 * setup; the worker forks still run against whatever subset succeeded.
 */
static void setup_pairs(int fd, char names[V6PMTU_NUM_PAIRS][8])
{
	unsigned int n;

	for (n = 0; n < V6PMTU_NUM_PAIRS; n++) {
		struct in6_addr addr, gw, dst;
		char peer[8];
		unsigned int rifx;

		(void)snprintf(names[n], sizeof(names[n]), "tr6r%u", n);
		(void)snprintf(peer, sizeof(peer), "tr6p%u", n);
		if (build_veth_create(fd, names[n], peer) != 0)
			continue;

		rifx = if_nametoindex(names[n]);
		if (rifx == 0)
			continue;

		memset(&addr, 0, sizeof(addr));
		addr.s6_addr[0] = 0xfc;
		addr.s6_addr[1] = 0x01;
		addr.s6_addr[15] = (uint8_t)n;
		(void)build_addaddr_v6(fd, (int)rifx, &addr, 64);
		(void)build_setlink_up(fd, (int)rifx);

		memset(&dst, 0, sizeof(dst));
		dst.s6_addr[0] = 0xfc;
		dst.s6_addr[1] = 0x01;
		dst.s6_addr[5] = (uint8_t)n;	/* fc01:0:N::/48 */

		memset(&gw, 0, sizeof(gw));
		gw.s6_addr[0] = 0xfc;
		gw.s6_addr[1] = 0x01;
		gw.s6_addr[15] = (uint8_t)(n + 1);
		(void)build_newroute_v6(fd, &dst, 48, &gw, (int)rifx);
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
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_ptb_sent_ok,
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
	int fd;
	struct timespec start, now;
	unsigned int i = 0;

	fd = rtnl_open();
	if (fd < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		unsigned int n = i % V6PMTU_NUM_PAIRS;
		char peer[8];

		(void)snprintf(peer, sizeof(peer), "tr6p%u", n);
		if (build_dellink_byname(fd, names[n]) == 0)
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_dellink_ok,
					   1, __ATOMIC_RELAXED);

		(void)build_veth_create(fd, names[n], peer);

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

	(void)close(fd);
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

		r = waitpid(pid, &status, WNOHANG);
		if (r == pid)
			return;
		if (r < 0 && errno != EINTR && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			(void)waitpid(pid, &status, 0);
			return;
		}
		(void)usleep(2000);
	}
}

static void iter_one(void)
{
	int nsfd, rtnl;
	char names[V6PMTU_NUM_PAIRS][8];
	pid_t a, b;
	struct timespec deadline;

	nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (nsfd < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		(void)close(nsfd);
		return;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out_setns;
	}

	bring_lo_up(rtnl);
	setup_pairs(rtnl, names);
	(void)close(rtnl);

	a = fork();
	if (a < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out_setns;
	}
	if (a == 0)
		worker_ptb();

	b = fork();
	if (b < 0) {
		(void)kill(a, SIGKILL);
		(void)waitpid(a, NULL, 0);
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out_setns;
	}
	if (b == 0)
		worker_dellink(names);

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

	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_completed_ok,
			   1, __ATOMIC_RELAXED);

out_setns:
	if (setns(nsfd, CLONE_NEWNET) < 0)
		ns_unsupported_ipv6_pmtu_race = true;
	(void)close(nsfd);
}

static void probe_v6_pmtu(void)
{
	int probe_fd;

	ipv6_pmtu_race_probed = true;

	probe_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (probe_fd < 0) {
		ns_unsupported_ipv6_pmtu_race = true;
		return;
	}
	if (unshare(CLONE_NEWNET) < 0) {
		ns_unsupported_ipv6_pmtu_race = true;
		(void)close(probe_fd);
		return;
	}
	if (setns(probe_fd, CLONE_NEWNET) < 0)
		ns_unsupported_ipv6_pmtu_race = true;
	(void)close(probe_fd);
}

bool ipv6_pmtu_teardown_race(struct childdata *child)
{
	unsigned int outer, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_ipv6_pmtu_race) {
		__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!ipv6_pmtu_race_probed) {
		probe_v6_pmtu();
		if (ns_unsupported_ipv6_pmtu_race) {
			__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	outer = BUDGETED(CHILD_OP_IPV6_PMTU_TEARDOWN_RACE,
			 JITTER_RANGE(V6PMTU_OUTER_BASE));
	if (outer > V6PMTU_OUTER_CAP)
		outer = V6PMTU_OUTER_CAP;
	if (outer == 0U)
		outer = 1U;

	for (i = 0; i < outer; i++)
		iter_one();

	return true;
}

#else  /* missing sched.h / netlink.h / rtnetlink.h / veth.h */

bool ipv6_pmtu_teardown_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.ipv6_pmtu_race_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif

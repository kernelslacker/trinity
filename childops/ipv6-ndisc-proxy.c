/*
 * ipv6_ndisc_proxy - drive the proxy_ndp NS receive path that upstream
 * commit 7aaa8f5e45a9 fixed.
 *
 * ip6_forward_proxy_check() calls pskb_may_pull() to widen the linear
 * region of the incoming NS skb.  pskb_may_pull may reallocate
 * skb->head when the requested span lies in the non-linear paged
 * region; pre-pull pointers into the old head are then stale and the
 * subsequent dereference is a UAF.  The window only opens when (a) a
 * proxy_ndp pneigh entry covers the NS target, (b) the NS lands on
 * the proxied interface, and (c) the NS payload spans a linear/
 * non-linear boundary so pskb_may_pull actually performs a realloc
 * rather than a no-op.  Random netlink/socket fuzzing hits none of
 * those preconditions in combination, so this op assembles the lot.
 *
 * Sequence (per child, latched once):
 *   1. unshare(CLONE_NEWNET) into a private netns.
 *   2. RTM_NEWLINK kind=veth pair vp0/vp1; addr fc00::1 on vp0,
 *      fc00::2 on vp1; bring lo, vp0, vp1 up.
 *   3. Write '1' to /proc/sys/net/ipv6/conf/vp0/proxy_ndp to enable
 *      the per-dev proxy.
 *   4. RTM_NEWNEIGH NTF_PROXY for fc00::3 dev vp0 — installs the
 *      pneigh entry that ip6_forward_proxy_check consults.
 *
 * Per outer iteration (BUDGETED + JITTER, base 6, ~200ms wall cap):
 *   - Open AF_PACKET / SOCK_RAW / ETH_P_IPV6 bound to vp1.
 *   - Build an Ethernet+IPv6+HBH+ICMPv6 NS frame for target fc00::3.
 *     The HBH pad option length is rotated each iteration so the IPv6
 *     payload_len varies across the linear/non-linear pull boundary,
 *     forcing pskb_may_pull to actually realloc skb->head on the
 *     receiver side rather than no-op out.
 *   - sendto() onto vp1; vp0 receives and the kernel walks
 *     ip6_forward_proxy_check / ndisc_recv_ns.
 *
 * Self-bounding: rtnl recv has SO_RCVTIMEO=1s, AF_PACKET sends are
 * MSG_DONTWAIT, the inner loop wall-caps via clock_gettime on
 * STORM_BUDGET_NS so even a backed-up tx queue can't hold us past
 * child.c's SIGALRM(1s).  Loopback only (private netns).
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER		1
#endif
#ifndef NDA_DST
#define NDA_DST			1
#endif
#ifndef NTF_PROXY
#define NTF_PROXY		(1 << 3)
#endif
#ifndef NUD_PERMANENT
#define NUD_PERMANENT		0x80
#endif

#define NDP_OUTER_BASE		6U
#define NDP_OUTER_CAP		32U
#define NDP_STORM_BUDGET_NS	200000000L

static bool ns_unsupported_ipv6_ndisc_proxy;
static bool ns_setup_done;
static bool ns_setup_failed_latched;
static int g_vp1_ifindex;
static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
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

static int rtnl_send_recv(int fd, void *msg, size_t len)
{
	unsigned char rbuf[512];
	struct nlmsghdr *nlh;
	ssize_t n;

	if (send(fd, msg, len, 0) < 0)
		return -EIO;
	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;
	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
	return 0;
}

/*
 * RTM_NEWLINK kind=veth with VETH_INFO_PEER carrying the peer name.
 * Mirrors bridge-fdb-stp's veth builder — minimal nesting, distinct
 * peer name so the two ends are addressable.
 */
static int veth_create(int fd, const char *a, const char *b)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	struct nlattr *li, *id, *peer;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put(buf, off, sizeof(buf), IFLA_IFNAME, a, strlen(a) + 1);
	if (!off) return -EIO;
	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth", 5);
	if (!off) return -EIO;
	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off) return -EIO;
	peer_off = off;
	off = nla_put(buf, off, sizeof(buf), VETH_INFO_PEER, NULL, 0);
	if (!off) return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf)) return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put(buf, off, sizeof(buf), IFLA_IFNAME, b, strlen(b) + 1);
	if (!off) return -EIO;

	peer = (struct nlattr *)(buf + peer_off);
	peer->nla_len = (unsigned short)(off - peer_off);
	id = (struct nlattr *)(buf + id_off);
	id->nla_len = (unsigned short)(off - id_off);
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int link_up(int fd, int idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int addr6_add(int fd, int idx, const struct in6_addr *a)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = 64;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, a, sizeof(*a));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, a, sizeof(*a));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWNEIGH NTF_PROXY for `target` on dev idx — installs the
 * pneigh entry that ip6_forward_proxy_check matches against.
 */
static int proxy_neigh_add(int fd, int idx, const struct in6_addr *target)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ndmsg *ndm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();
	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_INET6;
	ndm->ndm_ifindex = idx;
	ndm->ndm_state   = NUD_PERMANENT;
	ndm->ndm_flags   = NTF_PROXY;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));
	off = nla_put(buf, off, sizeof(buf), NDA_DST, target, sizeof(*target));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static bool sysfs_write_one(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return false;
	n = write(fd, val, strlen(val));
	close(fd);
	return n > 0;
}

/*
 * One-shot per-child setup: unshare, build the veth pair, addrs and
 * proxy state.  Latches ns_unsupported_ipv6_ndisc_proxy on any
 * structural failure so subsequent invocations short-circuit.  Stores
 * vp1's ifindex in g_vp1_ifindex so the per-iteration sender can bind
 * AF_PACKET without re-resolving the name on every call.
 */
static bool do_setup(void)
{
	struct in6_addr a1, a2, target;
	int rtnl, lo_idx, vp0_idx, vp1_idx;
	bool ok = false;

	if (unshare(CLONE_NEWNET) < 0)
		return false;
	rtnl = rtnl_open();
	if (rtnl < 0)
		return false;

	lo_idx = (int)if_nametoindex("lo");
	if (lo_idx > 0)
		(void)link_up(rtnl, lo_idx);

	if (veth_create(rtnl, "vp0", "vp1") != 0)
		goto out;
	vp0_idx = (int)if_nametoindex("vp0");
	vp1_idx = (int)if_nametoindex("vp1");
	if (vp0_idx <= 0 || vp1_idx <= 0)
		goto out;

	memset(&a1, 0, sizeof(a1));
	a1.s6_addr[0] = 0xfc; a1.s6_addr[15] = 0x01;
	memset(&a2, 0, sizeof(a2));
	a2.s6_addr[0] = 0xfc; a2.s6_addr[15] = 0x02;
	memset(&target, 0, sizeof(target));
	target.s6_addr[0] = 0xfc; target.s6_addr[15] = 0x03;

	(void)addr6_add(rtnl, vp0_idx, &a1);
	(void)addr6_add(rtnl, vp1_idx, &a2);
	(void)link_up(rtnl, vp0_idx);
	(void)link_up(rtnl, vp1_idx);

	/* Both arms of the proxy_ndp gate: per-dev knob (vp0) plus the
	 * /all/ knob — kernels differ on which one ip6_forward consults
	 * for the proxy check, so flip both. */
	if (sysfs_write_one("/proc/sys/net/ipv6/conf/vp0/proxy_ndp", "1") ||
	    sysfs_write_one("/proc/sys/net/ipv6/conf/all/proxy_ndp", "1"))
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy_proxy_enable_ok,
				   1, __ATOMIC_RELAXED);

	(void)proxy_neigh_add(rtnl, vp0_idx, &target);

	g_vp1_ifindex = vp1_idx;
	ok = true;
out:
	close(rtnl);
	return ok;
}

/*
 * Build and inject one Ethernet+IPv6+HBH+ICMPv6 NS frame into vp1.
 * The HBH pad length is rotated so the receiver-side pskb_may_pull
 * span varies across iterations — the realloc-inducing pull is what
 * the bug needs.
 */
static bool send_one_ns(int raw, int ifindex, unsigned int rot)
{
	unsigned char frame[256];
	struct sockaddr_ll sll;
	struct ip6_hdr *ip6;
	unsigned char *p;
	struct nd_neighbor_solicit *ns;
	unsigned int hbh_pad;	/* PadN data length, multiples of 6 keep HBH 8-aligned */
	unsigned int hbh_len;	/* total HBH ext-hdr length in bytes */
	unsigned int icmp_off, payload_len;
	ssize_t n;

	memset(frame, 0, sizeof(frame));

	hbh_pad = (rot % 8) * 6;	/* 0..42 bytes of PadN payload */
	hbh_len = 8 + (hbh_pad ? ((hbh_pad + 5) & ~7U) : 0);
	icmp_off = 14 + sizeof(*ip6) + hbh_len;
	payload_len = hbh_len + sizeof(*ns);

	if (icmp_off + sizeof(*ns) > sizeof(frame))
		return false;

	/* Ethernet: dst all-nodes multicast (33:33:00:...:01), src locally-
	 * administered unicast.  The bridge-style flood lets vp0 ingest
	 * regardless of MAC learning state. */
	frame[0] = 0x33; frame[1] = 0x33; frame[5] = 0x01;
	frame[6] = 0x02; generate_rand_bytes(frame + 7, 5);
	frame[12] = 0x86; frame[13] = 0xdd;

	ip6 = (struct ip6_hdr *)(frame + 14);
	ip6->ip6_flow = htonl(0x60000000U);
	ip6->ip6_plen = htons((uint16_t)payload_len);
	ip6->ip6_nxt  = 0;	/* IPPROTO_HOPOPTS */
	ip6->ip6_hlim = 255;	/* NDISC requires hop limit 255 */
	ip6->ip6_src.s6_addr[0]  = 0xfc; ip6->ip6_src.s6_addr[15]  = 0x02;
	ip6->ip6_dst.s6_addr[0]  = 0xff; ip6->ip6_dst.s6_addr[1]  = 0x02;
	ip6->ip6_dst.s6_addr[15] = 0x01;

	/* HBH: next=ICMPv6(58), hdrlen in 8-byte units minus 1, then a
	 * single PadN option to inflate the linear-pull span. */
	p = frame + 14 + sizeof(*ip6);
	p[0] = IPPROTO_ICMPV6;
	p[1] = (unsigned char)((hbh_len / 8) - 1);
	if (hbh_pad) {
		p[2] = 1;	/* PadN */
		p[3] = (unsigned char)hbh_pad;
		/* remainder already zero from memset */
	} else {
		p[2] = 0;	/* Pad1 */
		p[3] = 0;
		p[4] = 0;
		p[5] = 0;
	}

	ns = (struct nd_neighbor_solicit *)(frame + icmp_off);
	ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_hdr.icmp6_code = 0;
	ns->nd_ns_hdr.icmp6_cksum = 0;	/* zero — kernel will drop on bad cksum, fine for the path we want */
	ns->nd_ns_target.s6_addr[0]  = 0xfc;
	ns->nd_ns_target.s6_addr[15] = 0x03;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, frame, 6);

	n = sendto(raw, frame, icmp_off + sizeof(*ns), MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll));
	return n > 0;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

bool ipv6_ndisc_proxy(struct childdata *child)
{
	struct timespec t0;
	int raw;
	unsigned int iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ipv6_ndisc_proxy)
		return true;

	if (!ns_setup_done) {
		if (ns_setup_failed_latched || !do_setup()) {
			ns_setup_failed_latched = true;
			ns_unsupported_ipv6_ndisc_proxy = true;
			__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_setup_done = true;
	}

	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (raw < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	{
		struct sockaddr_ll bnd;

		memset(&bnd, 0, sizeof(bnd));
		bnd.sll_family   = AF_PACKET;
		bnd.sll_protocol = htons(ETH_P_IPV6);
		bnd.sll_ifindex  = g_vp1_ifindex;
		(void)bind(raw, (struct sockaddr *)&bnd, sizeof(bnd));
	}

	iters = BUDGETED(CHILD_OP_IPV6_NDISC_PROXY,
			 JITTER_RANGE(NDP_OUTER_BASE));
	if (iters > NDP_OUTER_CAP)
		iters = NDP_OUTER_CAP;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= NDP_STORM_BUDGET_NS)
			break;
		if (send_one_ns(raw, g_vp1_ifindex, rand32()))
			__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy_ns_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	close(raw);
	return true;
}

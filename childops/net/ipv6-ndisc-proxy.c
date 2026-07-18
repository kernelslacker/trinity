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
 * Sequence (per invocation):
 *   1. Enter a private net namespace via userns_run_in_ns(): a
 *      transient grandchild fork installs an identity user namespace
 *      plus a fresh CLONE_NEWNET, runs the body below, and _exit()s
 *      so the kernel reaps the veth pair, proxy_ndp pneigh entry,
 *      raw AF_PACKET socket and the sysfs handles with the
 *      grandchild's netns.  The persistent fuzz child never touches
 *      its own credentials or namespace stack, so the cap-drop oracle
 *      keeps observing the host credential profile.  Helper -EPERM
 *      (hardened userns policy refused CLONE_NEWUSER) latches the
 *      childop off for the remainder of this child's lifetime;
 *      -EAGAIN (transient setup failure: fork, id-map write,
 *      secondary unshare) skips the iteration without latching.
 *   2. Bring lo up inside the grandchild's netns, then RTM_NEWLINK
 *      kind=veth pair vp0/vp1; addr fc00::1 on vp0, fc00::2 on vp1;
 *      bring vp0/vp1 up.
 *   3. Write '1' to /proc/sys/net/ipv6/conf/vp0/proxy_ndp to enable
 *      the per-dev proxy.
 *   4. RTM_NEWNEIGH NTF_PROXY for fc00::3 dev vp0 — installs the
 *      pneigh entry that ip6_forward_proxy_check consults.
 *   5. Open AF_PACKET / SOCK_RAW / ETH_P_IPV6 bound to vp1, then run a
 *      BUDGETED+JITTER (base 6, ~200 ms wall cap) loop emitting
 *      Ethernet+IPv6+HBH+ICMPv6 NS frames for target fc00::3.  The
 *      HBH pad option length is rotated each iteration so the IPv6
 *      payload_len varies across the linear/non-linear pull boundary,
 *      forcing pskb_may_pull to actually realloc skb->head on the
 *      receiver side rather than no-op out.
 *
 * Self-bounding: rtnl recv has SO_RCVTIMEO=1s, AF_PACKET sends are
 * MSG_DONTWAIT, the inner loop wall-caps via clock_gettime on
 * STORM_BUDGET_NS so even a backed-up tx queue can't hold us past
 * child.c's SIGALRM(1s).  Loopback only (private netns).
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "kernel/neighbour.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
#define NDP_OUTER_BASE		6U
#define NDP_OUTER_CAP		32U
#define NDP_STORM_BUDGET_NS	200000000L

/* Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we MUST NOT touch the host's main veth /
 * neighbour / proxy_ndp tables, so the op stays disabled for the
 * remainder of this child's lifetime.  Transient setup failures
 * (helper return -EAGAIN) do not set this — they may not recur on the
 * next iteration. */
static bool ns_userns_unsupported_ipv6_ndisc_proxy;

/*
 * RTM_NEWLINK kind=veth with VETH_INFO_PEER carrying the peer name.
 * Mirrors bridge-fdb-stp's veth builder — minimal nesting, distinct
 * peer name so the two ends are addressable.
 */
static int veth_create(struct nl_ctx *ctx, const char *a, const char *b)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
	if (!off) return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth", 5);
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off) return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf)) return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off) return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int link_up(struct nl_ctx *ctx, int idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int addr6_add(struct nl_ctx *ctx, int idx, const struct in6_addr *a)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
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
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWNEIGH NTF_PROXY for `target` on dev idx — installs the
 * pneigh entry that ip6_forward_proxy_check matches against.
 */
static int proxy_neigh_add(struct nl_ctx *ctx, int idx,
			   const struct in6_addr *target)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ndmsg *ndm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_INET6;
	ndm->ndm_ifindex = idx;
	ndm->ndm_state   = NUD_PERMANENT;
	ndm->ndm_flags   = NTF_PROXY;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));
	off = nla_put(buf, off, sizeof(buf), NDA_DST, target, sizeof(*target));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
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

/*
 * Per-invocation state handed to the in-ns callback so per-op stats
 * stay indexed against the right childop slot.
 */
struct ipv6_ndisc_proxy_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the veth
 * pair, proxy_ndp pneigh entry, raw AF_PACKET socket and any sysfs
 * handles left behind are reaped by the kernel along with the
 * namespace.  Return value is ignored by the helper.
 */
static int ipv6_ndisc_proxy_in_ns(void *arg)
{
	struct ipv6_ndisc_proxy_ctx *cctx = (struct ipv6_ndisc_proxy_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx ctx = NL_CTX_INIT;
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	struct in6_addr a1, a2, target;
	struct timespec t0;
	int lo_idx, vp0_idx, vp1_idx;
	int raw = -1;
	unsigned int iters, i;

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	lo_idx = (int)if_nametoindex("lo");
	if (lo_idx > 0)
		(void)link_up(&ctx, lo_idx);

	if (veth_create(&ctx, "vp0", "vp1") != 0) {
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		nl_close(&ctx);
		return 0;
	}
	vp0_idx = (int)if_nametoindex("vp0");
	vp1_idx = (int)if_nametoindex("vp1");
	if (vp0_idx <= 0 || vp1_idx <= 0) {
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		nl_close(&ctx);
		return 0;
	}

	/* Kernel confirmed vp0 names a real device; publish it via the
	 * NETDEV name pool so sibling childops and per-syscall fuzzers
	 * drawing this kind can land a HIT on dev_get_by_name /
	 * SO_BINDTODEVICE instead of always-fresh-random ENODEV.  Record
	 * the pair primary only — the per-kind ring is 16 slots and
	 * recording both leaves would thrash it. */
	name_pool_record(NAME_KIND_NETDEV, "vp0", strlen("vp0"));

	memset(&a1, 0, sizeof(a1));
	a1.s6_addr[0] = 0xfc; a1.s6_addr[15] = 0x01;
	memset(&a2, 0, sizeof(a2));
	a2.s6_addr[0] = 0xfc; a2.s6_addr[15] = 0x02;
	memset(&target, 0, sizeof(target));
	target.s6_addr[0] = 0xfc; target.s6_addr[15] = 0x03;

	(void)addr6_add(&ctx, vp0_idx, &a1);
	(void)addr6_add(&ctx, vp1_idx, &a2);
	(void)link_up(&ctx, vp0_idx);
	(void)link_up(&ctx, vp1_idx);

	/* Both arms of the proxy_ndp gate: per-dev knob (vp0) plus the
	 * /all/ knob — kernels differ on which one ip6_forward consults
	 * for the proxy check, so flip both. */
	if (sysfs_write_one("/proc/sys/net/ipv6/conf/vp0/proxy_ndp", "1") ||
	    sysfs_write_one("/proc/sys/net/ipv6/conf/all/proxy_ndp", "1"))
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.proxy_enable_ok,
				   1, __ATOMIC_RELAXED);

	(void)proxy_neigh_add(&ctx, vp0_idx, &target);

	nl_close(&ctx);

	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (raw < 0) {
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	{
		struct sockaddr_ll bnd;

		memset(&bnd, 0, sizeof(bnd));
		bnd.sll_family   = AF_PACKET;
		bnd.sll_protocol = htons(ETH_P_IPV6);
		bnd.sll_ifindex  = vp1_idx;
		(void)bind(raw, (struct sockaddr *)&bnd, sizeof(bnd));
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_IPV6_NDISC_PROXY,
			 JITTER_RANGE(NDP_OUTER_BASE));
	if (iters > NDP_OUTER_CAP)
		iters = NDP_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= NDP_STORM_BUDGET_NS)
			break;
		if (send_one_ns(raw, vp1_idx, rand32()))
			__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.ns_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	close(raw);
	return 0;
}

bool ipv6_ndisc_proxy(struct childdata *child)
{
	struct ipv6_ndisc_proxy_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_userns_unsupported_ipv6_ndisc_proxy)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ipv6_ndisc_proxy_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_userns_unsupported_ipv6_ndisc_proxy = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern ipv6_ndisc_proxy_in_ns above uses for
		 * its per-op writes. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.ipv6_ndisc_proxy.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

/*
 * ip4_udp_cork_splice - IPv4 twin of ip6_udp_cork_splice.  Stresses the
 * IPv4 UDP corked + paged-splice send path through __ip_append_data()'s
 * continuation-skb length accounting.  A corked datagram that fills the
 * path MTU exactly, followed by a MSG_SPLICE_PAGES flush, drives the
 * second append down the paged continuation branch, where the copy
 * length (datalen minus the continuation gap minus the paged length) is
 * computed.  If that arithmetic ever lets a negative result through,
 * skb_copy_and_csum_bits() writes past skb->end into skb_shared_info --
 * an out-of-bounds write.  The childop stresses this accounting rather
 * than asserting any particular outcome: it drives the exact path where
 * a miscomputed (negative) copy length would overrun, so a kernel that
 * mis-accounts here is exercised where it matters, and one that accounts
 * correctly handles the sequence benignly (no crash, no misbehaviour).
 *
 * Same shape as the IPv6 variant (upstream commit c04d9ece23de fixed the
 * v6 leg; eca856950f7c fixed the equivalent v4 leg in __ip_append_data
 * -- see net/ipv4/ip_output.c:1079-1162).  Reachability is exact-or-
 * nothing (it either gets the math right or misses silently), so the
 * setup is deliberate rather than fuzzed:
 *   - lo path MTU must be small enough that a legal UDP datagram needs
 *     two IP fragments.  Default lo MTU 65536 rides one fragment with
 *     no continuation, so bring lo down to a small value picked per
 *     invocation from cork_splice_mtus[] (needs CAP_NET_ADMIN, granted
 *     by the userns bootstrap inside the private netns).
 *   - IPv4 @ picked mtu: fragheaderlen 20, maxfraglen
 *     ((mtu-20)&~7)+20-8.  p1 is derived to fill the MTU exactly at
 *     mtu - iphdr(20) - udphdr(8), with MSG_MORE so the cork holds
 *     (a single uncorked >MTU send fragments cleanly and never builds
 *     a continuation skb).
 *   - P2 is a 1-byte MSG_SPLICE_PAGES flush; the continuation skb then
 *     takes the paged branch (MSG_SPLICE_PAGES + lo's NETIF_F_SG), with
 *     a continuation gap of (mtu - maxfraglen) bytes.
 *
 * The send iov points at a touched, page-aligned anonymous mmap region
 * so the pages are pinnable, matching what real splice callers pass.
 *
 * Self-bounding: one full sequence per invocation inside a transient
 * userns_run_in_ns(CLONE_NEWNET) grandchild that _exit()s, so links,
 * addrs and sockets are reaped with the netns.  Latch
 * CHILDOP_LATCH_NS_UNSUPPORTED on -EPERM from the helper (hardened
 * userns policy); do NOT latch on -EAGAIN (transient fork / id-map /
 * unshare failure that may not recur).
 */


#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/in.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
/* Per-invocation MTU picks: both IPv4-valid (min 576) and both yield a
 * nonzero continuation gap, so the two-send sequence exercises the
 * paged continuation branch at every value.  p1 is derived from the
 * picked mtu inside the body so the first datagram fills the MTU
 * exactly; see the file header for the derivation -- do not decouple
 * p1 from mtu. */
static const uint32_t cork_splice_mtus[] = { 1280, 1500 };
#define CORK_SPLICE_MTU_MAX	1500U
#define CORK_SPLICE_P2		1U	/* tail byte; anything >0 works */

/* Anonymous mmap region backing both sends.  One page is plenty at any
 * picked MTU: max p1 (1472 at mtu 1500) plus p2 (1) fits comfortably.
 * Both payloads live at &region[0] and &region[p1]. */
#define CORK_SPLICE_MMAP_BYTES	4096U

#define RTNL_BUF_BYTES		256

/* Latched per-child: userns_run_in_ns() reported -EPERM, so the
 * grandchild's CLONE_NEWUSER was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private user+net namespace we cannot lower the loopback MTU
 * (needs CAP_NET_ADMIN) and the stress path cannot run, so the op stays
 * disabled for the rest of this child's lifetime.  Transient helper
 * failures (-EAGAIN) do NOT set this -- they may not recur. */
static bool ns_unsupported;

struct ip4_udp_cork_splice_ctx {
	struct childdata *child;
};

/*
 * RTM_NEWLINK setlink on lo carrying IFLA_MTU = mtu.  No shared helper
 * exists (grep IFLA_MTU childops/ = 0 across the whole tree), so this
 * is written fresh against nl_send_recv + nla_put_u32.  Returns 0 on
 * ack, negated errno on rejection.
 */
static int lo_set_mtu(struct nl_ctx *ctx, int ifindex, __u32 mtu)
{
	unsigned char buf[RTNL_BUF_BYTES];
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
	/* ifi_change stays 0 -- we're not flipping any flag bits, only
	 * attaching a new IFLA_MTU value. */

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MTU, mtu);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR ipv4 /8 on lo carrying 127.0.0.1.  A fresh netns already
 * brings 127.0.0.1 up on lo once the interface is UP, so EEXIST here is
 * benign coverage and the caller ignores the return value.
 */
static int lo_add_v4_loopback(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	struct in_addr addr;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 8;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_HOST;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	addr.s_addr = htonl(INADDR_LOOPBACK);
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
 * Body: run inside the private CLONE_NEWNET grandchild.  Bring lo up,
 * force its MTU to the per-invocation pick, wire an AF_INET datagram
 * pair on 127.0.0.1, and emit the two-send sequence that produces an
 * (mtu - maxfraglen)-byte continuation gap in the continuation skb.
 * All fds are O_CLOEXEC; the grandchild's exit reaps everything.
 * Return value is ignored by the helper.
 */
static int ip4_udp_cork_splice_in_ns(void *arg)
{
	struct ip4_udp_cork_splice_ctx *cctx = (struct ip4_udp_cork_splice_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	unsigned char *region = MAP_FAILED;
	struct sockaddr_in sin_rx;
	socklen_t slen;
	int tx = -1, rx = -1;
	int lo_idx;
	int dont = 0;	/* IP_PMTUDISC_DONT */
	ssize_t n;
	const uint32_t mtu = cork_splice_mtus[rnd_modulo_u32(ARRAY_SIZE(cork_splice_mtus))];
	const uint32_t p1  = mtu - 20 - 8;	/* fills MTU: iphdr(20) + udphdr(8) */

	/* op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check before we use
	 * it as an index into the per-op stats arrays.  See vrf_fib_churn
	 * for the same guard pattern. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&ctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	rtnl_bring_lo_up(&ctx);

	lo_idx = (int)if_nametoindex("lo");
	if (lo_idx <= 0) {
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (lo_set_mtu(&ctx, lo_idx, mtu) != 0) {
		/* Without the small path MTU the datagram rides one
		 * fragment, continuation gap = 0, and the continuation
		 * branch isn't taken.  Bail out rather than emit useless
		 * traffic. */
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.mtu_set,
			   1, __ATOMIC_RELAXED);

	/* Best-effort -- lo in a fresh netns usually already has 127.0.0.1
	 * once IFF_UP is on.  EEXIST is benign. */
	(void)lo_add_v4_loopback(&ctx, lo_idx);

	rx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (rx < 0)
		goto out;
	memset(&sin_rx, 0, sizeof(sin_rx));
	sin_rx.sin_family      = AF_INET;
	sin_rx.sin_port        = 0;
	sin_rx.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(rx, (struct sockaddr *)&sin_rx, sizeof(sin_rx)) < 0)
		goto out;
	slen = sizeof(sin_rx);
	if (getsockname(rx, (struct sockaddr *)&sin_rx, &slen) < 0)
		goto out;

	tx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (tx < 0)
		goto out;
	/* Turn off PMTUD so the kernel does not cache a different PMTU
	 * for 127.0.0.1 or emit ICMP frag-needed back at us.  DF still
	 * gets cleared on the wire but on lo that is moot. */
	(void)setsockopt(tx, IPPROTO_IP, IP_MTU_DISCOVER,
			 &dont, sizeof(dont));
	if (connect(tx, (struct sockaddr *)&sin_rx, sizeof(sin_rx)) < 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Touched page-aligned anonymous mmap so the pages are pinnable
	 * for iov_iter_extract_pages().  MAP_POPULATE nudges the fault
	 * in eagerly; the memset touches every byte so no CoW zero-page
	 * survives to the pin. */
	region = mmap(NULL, CORK_SPLICE_MMAP_BYTES,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (region == MAP_FAILED)
		goto out;
	memset(region, 'F', CORK_SPLICE_MMAP_BYTES);

	/* First send: FILLS the MTU exactly.  MSG_MORE corks so the
	 * kernel does not flush until the follow-up send arrives; the
	 * MSG_SPLICE_PAGES flag takes the paged branch in the
	 * ip_generic_getfrag / __ip_append_data machinery.
	 *
	 * p1 is derived (mtu - iphdr - udphdr) so the first skb lands
	 * on the MTU boundary at every picked mtu.  Any other value
	 * would send a generic datagram: the continuation skb's length
	 * accounting looks correct and the childop silently observes
	 * zero coverage of the paged continuation branch.  Do NOT
	 * decouple p1 from mtu. */
	{
		struct iovec iov;
		struct msghdr mh;

		iov.iov_base = region;
		iov.iov_len  = p1;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov    = &iov;
		mh.msg_iovlen = 1;

		n = sendmsg(tx, &mh,
			    MSG_MORE | MSG_SPLICE_PAGES | MSG_DONTWAIT);
		if (n != (ssize_t)p1) {
			/* Kernel refused the corked splice-pages send.
			 * Common on stripped configs (no NETIF_F_SG on lo
			 * in exotic builds, or MSG_SPLICE_PAGES rejected).
			 * Benign coverage -- the trigger requires both
			 * sends to land. */
			__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.p1_rejected,
					   1, __ATOMIC_RELAXED);
			goto drain;
		}
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.p1_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* Second send: no MSG_MORE, so the datagram is flushed.  The
	 * continuation skb sees continuation gap = mtu - maxfraglen; the
	 * paged path then computes copy = datalen - contgap - pagedlen.
	 * If that accounting ever underflows, skb_copy_and_csum_bits
	 * writes past skb->end into skb_shared_info -- an out-of-bounds
	 * write. */
	{
		struct iovec iov;
		struct msghdr mh;

		iov.iov_base = region + p1;
		iov.iov_len  = CORK_SPLICE_P2;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov    = &iov;
		mh.msg_iovlen = 1;

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		n = sendmsg(tx, &mh, MSG_SPLICE_PAGES | MSG_DONTWAIT);
		if (n >= 0)
			__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.p2_ok,
					   1, __ATOMIC_RELAXED);
	}

drain:
	/* Drain whatever the rx socket got so lingering bytes do not
	 * pile up in the receive queue.  Best-effort; MSG_DONTWAIT so
	 * we never block if the send never made it through. */
	{
		unsigned char rxbuf[CORK_SPLICE_MTU_MAX];
		(void)recv(rx, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
	}

out:
	if (region != MAP_FAILED)
		(void)munmap(region, CORK_SPLICE_MMAP_BYTES);
	if (tx >= 0)
		close(tx);
	if (rx >= 0)
		close(rx);
	if (ctx.fd >= 0)
		nl_close(&ctx);

	return 0;
}

bool ip4_udp_cork_splice(struct childdata *child)
{
	struct ip4_udp_cork_splice_ctx cctx = { .child = child };
	int rc;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ip4_udp_cork_splice_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map
		 * write, secondary unshare).  Skip this iteration
		 * without latching -- the failure is not policy and may
		 * not recur. */
		__atomic_add_fetch(&shm->stats.ip4_udp_cork_splice.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

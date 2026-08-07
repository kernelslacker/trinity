/*
 * fnhe_pmtu_mtu_race — race IPv4 PMTU exception table updates against
 * concurrent nexthop MTU synchronisation.
 *
 * Bug class: net/ipv4/route.c:fib_nhc_update_mtu() walks the per-nexthop
 * fnhe (fib_nh_exception) table under RTNL using rcu_dereference_protected()
 * with a constant-true lockdep condition and without holding fnhe_lock.
 * RTNL does NOT serialise that walk against update_or_create_fnhe() which
 * holds fnhe_lock and calls fnhe_remove_oldest() → kfree_rcu on eviction.
 *
 *   CPU 0                              CPU 1
 *   fib_nhc_update_mtu()               update_or_create_fnhe()
 *     load fnhe ptr (no lock)            spin_lock_bh(&fnhe_lock)
 *                                        fnhe_remove_oldest() → kfree_rcu
 *     <quiescent state>
 *     access fnhe after grace period     ← UAF, KASAN-visible
 *
 * Reporter: Chengfeng Ye, LKML 2026-08-06; Fixes: af7d6cce5369;
 * Cc: stable@vger.kernel.org.
 *
 * Mechanism:
 *   (a) userns_run_in_ns(CLONE_NEWNET) gives us a private netns with
 *       CAP_NET_ADMIN/CAP_NET_RAW.  All setup, workers, and teardown
 *       live inside the grandchild; its _exit() reaps the entire netns.
 *   (b) Create a veth pair (fhv0 / fhv1): fhv0 = 192.168.42.1/24,
 *       fhv1 = 192.168.42.2/24.  Both brought IFF_UP.  A default route
 *       (0.0.0.0/0) is installed via gateway 192.168.42.2 on fhv0.  Lo
 *       is brought up so 127.0.0.1 is valid for the raw-socket anchor.
 *   (c) Populate side (worker A): for each of FNHE_INJECT_COUNT
 *       sequential destination addresses in the 10.x.x.x space, craft an
 *       ICMP type=3/code=4 (frag-needed) with inner IP dst = that address
 *       and inject it via a raw socket.  The kernel's icmp_unreach() →
 *       ip_rt_frag_needed() → __ip_rt_update_pmtu() →
 *       update_or_create_fnhe() path installs one fnhe entry per distinct
 *       daddr under the same nexthop (192.168.42.2 via fhv0).  With
 *       FNHE_HASH_SIZE = 2048 and FNHE_INJECT_COUNT = 14336 (7 × 2048),
 *       by birthday-paradox several buckets accumulate > 9 entries,
 *       forcing repeated fnhe_remove_oldest() calls.  evictions_observed
 *       is set when exceptions_installed exceeds FNHE_EVICTION_THRESHOLD
 *       (= FNHE_HASH_SIZE × FNHE_RECLAIM_DEPTH = 2048 × 5 = 10240), at
 *       which point fnhe_remove_oldest() MUST have fired (pigeonhole).
 *   (d) Race side (worker B, concurrent with A): tight-loop SIOCSIFMTU on
 *       fhv0, alternating between 1280 and 1500 bytes.  Each successful
 *       ioctl drives dev_set_mtu() → fib_sync_mtu() → fib_nhc_update_mtu()
 *       which walks nhc->nhc_exceptions (the fnhe table) without fnhe_lock.
 *   (e) Negative control: on FNHE_NEG_CTRL_PERIOD-th iterations, worker A
 *       is skipped (table stays empty).  Worker B still runs.  A healthy
 *       race detector should see nothing on the empty table.
 *
 * Sizing note (FNHE_HASH_SIZE and FNHE_RECLAIM_DEPTH are compile-time
 * kernel constants; see include/net/ip_fib.h):
 *   FNHE_HASH_SIZE  = 1 << FNHE_HASH_SHIFT = 1 << 11 = 2048
 *   FNHE_RECLAIM_DEPTH = 5; eviction threshold = 5..9 (randomised).
 * With 14336 entries across 2048 buckets, expected max bucket depth ≈ 14,
 * and every bucket has on average 7 entries → eviction fires on most
 * inserts into a non-empty bucket.
 *
 * Latch: userns_run_in_ns() -EPERM permanently gates the op.  Transient
 * failures (return < 0 but ≠ -EPERM) skip the iteration without latching.
 */

#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>) && \
    __has_include(<linux/rtnetlink.h>) && __has_include(<linux/veth.h>)

#include <sched.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "childops/net/crafted-icmp-rx.h"

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH	3
#endif
#ifndef ICMP_FRAG_NEEDED
#define ICMP_FRAG_NEEDED	4
#endif

/*
 * Network constants.  All RFC1918 / well-known; confined to the private
 * netns so no traffic escapes.
 *
 * fhv0 / fhv1: veth pair.  fhv0 stays in the grandchild's initial netns;
 * fhv1 is the peer (also in the same netns — we don't move it; the pair
 * just needs a connected nexthop for routing purposes).
 */
#define FNHE_VETH_A		"fhv0"
#define FNHE_VETH_B		"fhv1"

/* fhv0 address: 192.168.42.1/24 */
#define FNHE_ADDR_A		0xc0a82a01U	/* 192.168.42.1 */
/* fhv1 address: 192.168.42.2/24 (nexthop / gateway) */
#define FNHE_ADDR_B		0xc0a82a02U	/* 192.168.42.2 */
#define FNHE_PREFIX		24U

/* Default route gateway = fhv1 address, out through fhv0.
 * All 10.x.x.x destinations will resolve via this route. */
#define FNHE_GW			FNHE_ADDR_B

/*
 * Injection parameters.
 *
 * FNHE_HASH_SIZE = 2048, FNHE_RECLAIM_DEPTH = 5.
 * FNHE_INJECT_COUNT = 7 * 2048 = 14336: expected per-bucket depth = 7;
 * max bucket depth ~ 14.  Well above the 5-9 eviction threshold.
 *
 * FNHE_EVICTION_THRESHOLD = FNHE_HASH_SIZE * FNHE_RECLAIM_DEPTH = 10240.
 * Once injections exceed this value, pigeonhole guarantees at least one
 * bucket has had depth > FNHE_RECLAIM_DEPTH and eviction has fired.
 */
#define FNHE_HASH_SIZE_USERSPACE	2048U
#define FNHE_RECLAIM_DEPTH_USERSPACE	5U
#define FNHE_INJECT_COUNT		(FNHE_HASH_SIZE_USERSPACE * 7U)
#define FNHE_EVICTION_THRESHOLD		(FNHE_HASH_SIZE_USERSPACE * FNHE_RECLAIM_DEPTH_USERSPACE)

/*
 * Worker wall-clock budget.  200 ms for each worker, 250 ms parent guard.
 * Same sizing as ipv6_pmtu_teardown_race.
 */
#define FNHE_WORKER_WALL_NS	(200ULL * 1000ULL * 1000ULL)
#define FNHE_PARENT_WALL_NS	(250ULL * 1000ULL * 1000ULL)

/* Destination base for injected exceptions: 10.0.0.0 onward. */
#define FNHE_DST_BASE		0x0a000000U	/* 10.0.0.0 */

/*
 * Run without injection every FNHE_NEG_CTRL_PERIOD invocations (negative
 * control: empty table + MTU flap should be harmless).
 */
#define FNHE_NEG_CTRL_PERIOD	5U

#define FNHE_RTNL_BUF		512U

/* ------------------------------------------------------------------ */
/* netlink helpers: lo up, veth pair, address, route                    */
/* ------------------------------------------------------------------ */

static void fnhe_bring_lo_up(struct nl_ctx *nl)
{
	rtnl_bring_lo_up(nl);
}

static int fnhe_create_veth(struct nl_ctx *nl)
{
	unsigned char buf[FNHE_RTNL_BUF];
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, FNHE_VETH_A);
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

	/* VETH_INFO_PEER: ifinfomsg + IFLA_IFNAME for peer */
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
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, FNHE_VETH_B);
	if (!off)
		return -EIO;
	nla_nest_end(buf, peer_off, off);

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

static int fnhe_set_link_up(struct nl_ctx *nl, const char *ifname)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family  = AF_UNSPEC;
	ifi->ifi_index   = (int)if_nametoindex(ifname);
	ifi->ifi_flags   = IFF_UP;
	ifi->ifi_change  = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

static int fnhe_add_addr(struct nl_ctx *nl, const char *ifname,
			 __u32 addr_he, __u8 prefixlen)
{
	unsigned char buf[128];
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
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)if_nametoindex(ifname);

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

/*
 * Add default route 0.0.0.0/0 via gateway gw_he through oif.
 * RTN_UNICAST so that fib_nhc_update_mtu sees it as a real route.
 */
static int fnhe_add_default_route(struct nl_ctx *nl, __u32 gw_he, int oif)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	__u32 gw_be = htonl(gw_he);
	__u32 oif_u = (unsigned int)oif;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET;
	rtm->rtm_dst_len  = 0;		/* default route */
	rtm->rtm_src_len  = 0;
	rtm->rtm_tos      = 0;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;
	rtm->rtm_flags    = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));
	off = nla_put(buf, off, sizeof(buf), RTA_GATEWAY, &gw_be, 4);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), RTA_OIF, &oif_u, 4);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(nl, buf, off);
}

/* ------------------------------------------------------------------ */
/* Worker A: inject ICMP frag-needed for N distinct daddrs             */
/* ------------------------------------------------------------------ */

/*
 * injection_worker_body — run inside a forked grandchild-worker.
 * Injects FNHE_INJECT_COUNT ICMP frag-needed packets, one per
 * distinct destination address starting at FNHE_DST_BASE, walking
 * sequentially through the 10.x.x.x space.  Each injection drives
 * ip_rt_frag_needed() → update_or_create_fnhe() for the default-route
 * nexthop (192.168.42.2 via fhv0).  Self-bounded at FNHE_WORKER_WALL_NS.
 */
static void __attribute__((noreturn))
injection_worker_body(int op_type, unsigned long start_idx)
{
	struct icmp_inject_ctx ctx;
	struct sockaddr_in local, remote;
	int udp_fd = -1, srv_fd = -1;
	struct timespec deadline;
	unsigned long i;
	unsigned long installed = 0, failed = 0;
	unsigned long worker_dc = 0;
	bool eviction_seen = false;

	/* Compute deadline */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec  = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)FNHE_WORKER_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	/*
	 * Open a UDP socket pair on 127.0.0.1 for the icmp_inject_ctx.
	 * The raw socket inside icmp_inject_ctx sends crafted ICMPs to
	 * 127.0.0.1 (outer daddr), but we override dst_override to
	 * vary inner_dst across the 10.x.x.x range so each injection
	 * installs a distinct fnhe entry.
	 *
	 * Note: ip_rt_frag_needed() resolves inner_dst (10.x.x.x) via
	 * the route table; the default route via fhv0 → 192.168.42.2
	 * provides the nexthop whose fnhe table we populate.
	 */
	srv_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	worker_dc++;
	if (srv_fd < 0)
		goto out;

	memset(&remote, 0, sizeof(remote));
	remote.sin_family      = AF_INET;
	remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	remote.sin_port        = 0;
	worker_dc++; /* bind(srv_fd) */
	if (bind(srv_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0)
		goto out;
	{
		socklen_t sl = sizeof(remote);
		worker_dc++; /* getsockname(srv_fd) */
		if (getsockname(srv_fd, (struct sockaddr *)&remote, &sl) < 0)
			goto out;
	}

	udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	worker_dc++;
	if (udp_fd < 0)
		goto out;

	memset(&local, 0, sizeof(local));
	local.sin_family      = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	local.sin_port        = 0;
	worker_dc++; /* bind(udp_fd) */
	if (bind(udp_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		goto out;
	worker_dc++; /* connect(udp_fd) */
	if (connect(udp_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0)
		goto out;
	{
		socklen_t sl = sizeof(local);
		worker_dc++; /* getsockname(udp_fd) */
		if (getsockname(udp_fd, (struct sockaddr *)&local, &sl) < 0)
			goto out;
	}

	worker_dc++; /* icmp_inject_init: socket(AF_INET,SOCK_RAW,IPPROTO_RAW) */
	if (icmp_inject_init(&ctx, udp_fd, &local, &remote) < 0)
		goto out;

	/*
	 * Main injection loop.  Each iteration targets a different
	 * daddr (inner IP destination) in 10.0.0.0/8.  The fnhe hash
	 * function (siphash_1u32 with a kernel-private key) distributes
	 * these uniformly across 2048 buckets.  With FNHE_INJECT_COUNT =
	 * 14336 (7 × 2048), expected max bucket depth ≈ 14, ensuring
	 * eviction fires on many insertions.
	 */
	for (i = 0; i < FNHE_INJECT_COUNT; i++) {
		struct in_addr dst_override;
		__u32 daddr_he;
		struct timespec now;
		int rc;

		/* Wall-clock bound */
		if ((i & 0xffU) == 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
				if (now.tv_sec > deadline.tv_sec ||
				    (now.tv_sec == deadline.tv_sec &&
				     now.tv_nsec >= deadline.tv_nsec))
					break;
			}
		}

		/* Cycle through 10.0.0.0 + (start_idx + i) (mod 2^24) */
		daddr_he = FNHE_DST_BASE |
			   ((start_idx + i) & 0x00ffffffU);
		/* Skip 10.0.0.0 (network addr) */
		if ((daddr_he & 0xffffffU) == 0)
			daddr_he++;

		dst_override.s_addr = htonl(daddr_he);

		rc = icmp_inject_error(&ctx,
				       ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				       1280,
				       dst_override);
		if (rc == 0) {
			installed++;
			/* Pigeonhole: once installed > FNHE_HASH_SIZE *
			 * FNHE_RECLAIM_DEPTH, at least one bucket must have
			 * exceeded FNHE_RECLAIM_DEPTH and eviction fired. */
			if (!eviction_seen &&
			    installed > FNHE_EVICTION_THRESHOLD) {
				eviction_seen = true;
				__atomic_add_fetch(
					&shm->stats.fnhe_pmtu_mtu_race.evictions_observed,
					1, __ATOMIC_RELAXED);
			}
		} else {
			failed++;
		}
	}

	/* Each icmp_inject_error() call issues one sendto(). */
	worker_dc += installed + failed;

	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.exceptions_installed,
			   installed, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.inject_failed,
			   failed, __ATOMIC_RELAXED);

	if (installed == 0) {
		/* check-static: child-output-ok */
		outputerr("[fnhe-pmtu-mtu-race] WARNING: "
			  "zero injections installed -- "
			  "check inject_failed counter\n");
	} else if (!eviction_seen) {
		/* check-static: child-output-ok */
		outputerr("[fnhe-pmtu-mtu-race] WARNING: "
			  "evictions_observed=0 this invocation, "
			  "installed=%lu below threshold %lu -- "
			  "fnhe table may be too small; "
			  "see fnhe-pmtu-mtu-race childop notes\n",
			  installed,
			  (unsigned long)FNHE_EVICTION_THRESHOLD);
	}

	worker_dc++; /* icmp_inject_cleanup: close(raw_fd) */
	icmp_inject_cleanup(&ctx);
out:
	if (udp_fd >= 0) {
		close(udp_fd);
		worker_dc++;
	}
	if (srv_fd >= 0) {
		close(srv_fd);
		worker_dc++;
	}
	childop_direct_syscalls_add(op_type, worker_dc);
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Worker B: MTU flap on fhv0 via SIOCSIFMTU                           */
/* ------------------------------------------------------------------ */

/*
 * mtu_flap_worker_body — throttled SIOCSIFMTU flap loop on fhv0.
 * Each successful ioctl drives dev_set_mtu() → fib_sync_mtu() →
 * fib_nhc_update_mtu(), which walks nhc->nhc_exceptions (the fnhe
 * table) without fnhe_lock.
 *
 * Throttling rationale: the original tight loop checked the clock only
 * every 64 iterations, so it acquired the box-wide RTNL mutex O(200 ms /
 * ioctl_latency) times in a burst, serialising every netlink-driven
 * childop fleet-wide (tc_qdisc_churn, xfrm_churn, vlan_filter_churn,
 * seg6 ops, nftables/churn …) behind tens of thousands of global-lock
 * acquisitions.  The race needs *concurrency* with worker A, not maximum
 * lock throughput.  We now check the deadline every iteration and sleep
 * 100 µs between flaps, reducing RTNL acquisitions by ~1000×.
 *
 * MTU ladder: three rungs exercise more arms of fib_nhc_update_mtu():
 *   1280 — below a typical FNHE pmtu  → "new < fnhe_pmtu" arm
 *   1400 — intermediate value         → forces repeated comparisons
 *   1500 — standard Ethernet MTU      → "orig == fnhe_pmtu" arm
 *
 * Note: the genuinely uncovered arm of fib_nhc_update_mtu() is
 * fnhe_mtu_locked == true; reaching it requires a locked FNHE installed
 * via ICMP FRAG_NEEDED with an MTU below ip_rt_min_pmtu -- ICMP
 * injection work outside the scope of this commit.
 *
 * Self-bounded at FNHE_WORKER_WALL_NS.
 */
static void __attribute__((noreturn)) mtu_flap_worker_body(int op_type)
{
	int sock_fd;
	struct ifreq ifr;
	struct timespec deadline;
	unsigned long flaps = 0;
	unsigned long worker_dc = 0;
	static const unsigned int mtu_ladder[] = { 1280, 1400, 1500 };
	unsigned int mi = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec  = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)FNHE_WORKER_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	sock_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	worker_dc++;
	if (sock_fd < 0) {
		childop_direct_syscalls_add(op_type, worker_dc);
		_exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, FNHE_VETH_A, IFNAMSIZ - 1);

	for (;;) {
		struct timespec now;

		/* Check deadline every iteration — not every 64 — so we
		 * don't over-shoot the budget and amplify RTNL contention. */
		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			if (now.tv_sec > deadline.tv_sec ||
			    (now.tv_sec == deadline.tv_sec &&
			     now.tv_nsec >= deadline.tv_nsec))
				break;
		}

		ifr.ifr_mtu = (int)mtu_ladder[mi % 3U];
		if (ioctl(sock_fd, SIOCSIFMTU, &ifr) == 0)
			flaps++;
		worker_dc++; /* ioctl(SIOCSIFMTU) */
		mi++;

		/* 100 µs between flaps: keeps the UAF race live while
		 * reducing global RTNL acquisitions by ~1000× vs busy-loop. */
		nanosleep(&(struct timespec){0, 100000}, NULL);
		worker_dc++; /* nanosleep */
	}

	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.mtu_flaps,
			   flaps, __ATOMIC_RELAXED);
	close(sock_fd);
	worker_dc++; /* close(sock_fd) */
	childop_direct_syscalls_add(op_type, worker_dc);
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Worker reap helper (local; mirrors ipv6_pmtu_teardown_race pattern)  */
/* ------------------------------------------------------------------ */

static void fnhe_reap_with_deadline(pid_t pid, struct timespec *deadline,
				    unsigned long *dc)
{
	for (;;) {
		struct timespec now;
		int status;
		pid_t r;

		r = waitpid_eintr(pid, &status, WNOHANG);
		(*dc)++;
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			(*dc)++;
			(void)waitpid_eintr(pid, &status, 0);
			(*dc)++;
			return;
		}
		(void)usleep(2000);
	}
}

/* ------------------------------------------------------------------ */
/* Per-iteration in-ns body                                             */
/* ------------------------------------------------------------------ */

struct fnhe_pmtu_race_ctx {
	int		op_type;
	unsigned long	iter;		/* global iter counter for daddr rotation */
	unsigned long	direct_calls;
};

static int fnhe_pmtu_mtu_race_in_ns(void *arg)
{
	struct fnhe_pmtu_race_ctx *rctx = (struct fnhe_pmtu_race_ctx *)arg;
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	const int op_type = rctx->op_type;
	const bool valid_op = (op_type >= 0 && op_type < NR_CHILD_OP_TYPES);
	bool neg_ctrl = ((rctx->iter % FNHE_NEG_CTRL_PERIOD) == (FNHE_NEG_CTRL_PERIOD - 1));
	int fhv0_idx;
	pid_t wa = -1, wb = -1;

	/* (b) Open rtnl and bring lo up */
	rctx->direct_calls += 3; /* nl_open: socket+bind+setsockopt(SO_RCVTIMEO) */
	if (nl_open(&nl, &opts) < 0)
		goto out_fail;
	rctx->direct_calls++; /* rtnl_bring_lo_up: nl_send_recv */
	fnhe_bring_lo_up(&nl);

	/* Create veth pair fhv0/fhv1 */
	rctx->direct_calls++; /* fnhe_create_veth: nl_send_recv */
	if (fnhe_create_veth(&nl) != 0)
		goto out_nl;

	/* Bring both ends up */
	rctx->direct_calls++; /* fnhe_set_link_up(fhv0): nl_send_recv */
	if (fnhe_set_link_up(&nl, FNHE_VETH_A) != 0)
		goto out_nl;
	rctx->direct_calls++; /* fnhe_set_link_up(fhv1): nl_send_recv */
	if (fnhe_set_link_up(&nl, FNHE_VETH_B) != 0)
		goto out_nl;

	/* Assign addresses */
	rctx->direct_calls++; /* fnhe_add_addr(fhv0): nl_send_recv */
	if (fnhe_add_addr(&nl, FNHE_VETH_A, FNHE_ADDR_A, FNHE_PREFIX) != 0)
		goto out_nl;
	rctx->direct_calls++; /* fnhe_add_addr(fhv1): nl_send_recv */
	if (fnhe_add_addr(&nl, FNHE_VETH_B, FNHE_ADDR_B, FNHE_PREFIX) != 0)
		goto out_nl;

	/* Install default route via 192.168.42.2 (fhv1) out fhv0.
	 * if_nametoindex() issues socket()+ioctl()+close() internally. */
	rctx->direct_calls += 3; /* if_nametoindex(fhv0): socket+ioctl+close */
	fhv0_idx = (int)if_nametoindex(FNHE_VETH_A);
	if (fhv0_idx <= 0)
		goto out_nl;
	rctx->direct_calls++; /* fnhe_add_default_route: nl_send_recv */
	if (fnhe_add_default_route(&nl, FNHE_GW, fhv0_idx) != 0)
		goto out_nl;

	rctx->direct_calls++; /* nl_close */
	nl_close(&nl);
	nl.fd = -1;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);
	}

	if (neg_ctrl) {
		__atomic_add_fetch(
			&shm->stats.fnhe_pmtu_mtu_race.negative_ctrl_runs,
			1, __ATOMIC_RELAXED);
	}

	/*
	 * Fork worker A (injection) — skip in negative control mode.
	 * Fork worker B (MTU flap) — always.
	 */
	if (!neg_ctrl) {
		rctx->direct_calls++;
		wa = fork();
		if (wa < 0) {
			__atomic_add_fetch(
				&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
				1, __ATOMIC_RELAXED);
			goto out_reap;
		}
		if (wa == 0) {
			unsigned long start = rctx->iter * FNHE_INJECT_COUNT;

			injection_worker_body(op_type, start);
			/* noreturn */
		}
	}

	rctx->direct_calls++;
	wb = fork();
	if (wb < 0) {
		__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out_reap;
	}
	if (wb == 0) {
		mtu_flap_worker_body(op_type);
		/* noreturn */
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.data_path[op_type],
				   1, __ATOMIC_RELAXED);
	}

out_reap:
	{
		struct timespec deadline;

		if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
			deadline.tv_sec  = 0;
			deadline.tv_nsec = 0;
		}
		deadline.tv_nsec += (long)FNHE_PARENT_WALL_NS;
		while (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_nsec -= 1000000000L;
			deadline.tv_sec  += 1;
		}

		if (wa > 0)
			fnhe_reap_with_deadline(wa, &deadline, &rctx->direct_calls);
		if (wb > 0)
			fnhe_reap_with_deadline(wb, &deadline, &rctx->direct_calls);
	}

	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.completed_ok,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		childop_direct_syscalls_add(op_type, rctx->direct_calls);
	return 0;

out_nl:
	nl_close(&nl);
out_fail:
	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		childop_direct_syscalls_add(op_type, rctx->direct_calls);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Childop entry point                                                  */
/* ------------------------------------------------------------------ */

/*
 * Per-child latch: set when userns_run_in_ns() returns -EPERM
 * (hardened userns policy; cannot obtain CAP_NET_ADMIN/CAP_NET_RAW
 * for veth + raw socket setup).  Process-local so it lives with the
 * child and the grandchild's _exit() doesn't reset it accidentally.
 */
static bool ns_unsupported_fnhe_pmtu;

bool fnhe_pmtu_mtu_race(struct childdata *child)
{
	struct fnhe_pmtu_race_ctx rctx = {
		.op_type      = child->op_type,
		.direct_calls = 0,
	};
	static unsigned long s_iter;
	int rc;

	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_fnhe_pmtu) {
		__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rctx.iter = s_iter++;

	rc = userns_run_in_ns(CLONE_NEWNET, fnhe_pmtu_mtu_race_in_ns, &rctx);
	if (rc == -EPERM) {
		ns_unsupported_fnhe_pmtu = true;
		{
			const int op = child->op_type;

			if (op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_NS_UNSUPPORTED,
					__ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure — skip, don't latch. */
		__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
				   1, __ATOMIC_RELAXED);
	}

	return true;
}

#else  /* missing sched.h / netlink.h / rtnetlink.h / veth.h */

bool fnhe_pmtu_mtu_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.fnhe_pmtu_mtu_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include guards */

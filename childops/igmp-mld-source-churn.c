/*
 * igmp_mld_source_churn - IGMPv3 / MLDv2 source-filter mutation churn
 * vs. live multicast traffic.
 *
 * Random syscall fuzzing essentially never reaches the source-filter
 * state machine in net/ipv4/igmp.c (ip_mc_msfilter, ip_mc_source) or
 * its IPv6 twin in net/ipv6/mcast.c (ip6_mc_msfilter, ip6_mc_source)
 * because those branches only fire when an EXISTING per-socket
 * membership has its include / exclude source list mutated while
 * datagrams are concurrently arriving on the bound group.  Building
 * that precondition takes:
 *
 *   - one AF_INET / AF_INET6 SOCK_DGRAM sender connected to a
 *     multicast group;
 *   - a second SOCK_DGRAM receiver bound to the same group:port,
 *     SO_REUSEADDR + IP_MULTICAST_LOOP=1 so loopback delivery actually
 *     fires;
 *   - one or more MCAST_JOIN_SOURCE_GROUP calls (INCLUDE filter with
 *     two named sources) -- this primes the per-socket inet_sock
 *     mc_list / ipv6_mc_socklist with a real ip_sf_socklist;
 *   - a primed datagram burst on the sender so the kernel's
 *     ip_check_mc_rcu / ip6_mc_input path is actively walking that
 *     filter;
 *   - and only THEN does a mutation (LEAVE_SOURCE / BLOCK_SOURCE /
 *     IP_MSFILTER bulk replace / full IP_DROP_MEMBERSHIP) reach
 *     ip_mc_source / ip_mc_msfilter (and v6 equivalents) with the
 *     racing receive path actually traversing the just-edited list.
 *
 * Random fuzzing of MCAST_* setsockopts on cold sockets returns
 * -EADDRNOTAVAIL or -EINVAL in the very first validation step and
 * never gets to the realloc / list-rcu publish window, so those code
 * paths stay un-exercised.
 *
 * Sequence (per BUDGETED + JITTER iteration, 200 ms wall cap; per-
 * iteration the family alternates iter%2 between AF_INET / AF_INET6 so
 * both stacks see the four race shapes across the outer loop):
 *
 *   1.  send_s = socket(AF_INET[6], SOCK_DGRAM); apply 100 ms
 *       SO_RCVTIMEO/SO_SNDTIMEO; connect to the SSM group:port
 *       (239.x.y.z:1234 / ff1e::42:1234).
 *   2.  recv_s = socket(AF_INET[6], SOCK_DGRAM); SO_REUSEADDR,
 *       IP{,V6}_MULTICAST_LOOP=1, bind to that group:port.
 *   3.  setsockopt MCAST_JOIN_SOURCE_GROUP src=A (IGMPv3 SSM include
 *       filter add).  This is the structural-support probe -- on
 *       -EPERM / -ENOSYS / -EOPNOTSUPP / -ENOPROTOOPT / -EAFNOSUPPORT
 *       latch ns_unsupported_igmp_mld_source_churn for the rest of the
 *       child's life and short-circuit subsequent invocations.
 *   4.  setsockopt MCAST_JOIN_SOURCE_GROUP src=B (extends the include
 *       filter ip_sf_socklist).
 *   5.  prime traffic: send 1-2 datagrams on send_s.  Loopback runs
 *       ip_mc_filter_rcu / ip6_mc_filter against the freshly-built
 *       per-socket source list.
 *   6.  RACE per iter % 4:
 *         A: setsockopt MCAST_LEAVE_SOURCE_GROUP src=A mid-stream
 *            (filter shrink under concurrent rx walk);
 *         B: setsockopt MCAST_BLOCK_SOURCE src=B (INCLUDE -> EXCLUDE
 *            transition: ip_mc_source flips the filter mode and the
 *            per-source state in one shot);
 *         C: setsockopt IP_MSFILTER (or MCAST_MSFILTER) bulk replace
 *            with a longer source list (rotates through small ~1,
 *            medium ~8, larger ~32 set sizes per outer loop) -- this
 *            is the path that actually exercises the kmalloc /
 *            ip_mc_socklist realloc + RCU publish in
 *            ip_mc_msfilter;
 *         D: setsockopt IP_DROP_MEMBERSHIP -- full leave race vs the
 *            in-flight sender, drives ip_mc_leave_group while traffic
 *            is still hitting the old filter.
 *   7.  second datagram burst on send_s while the race is in flight.
 *   8.  close both sockets in randomised order.
 *
 * Per-syscall SO_RCVTIMEO/SO_SNDTIMEO 100 ms keeps a wedged loopback
 * recv from punching through the SIGALRM(1s) cap inherited from
 * child.c; the BUDGETED outer loop is base 4 / floor 8 / cap 16 with
 * JITTER and a 200 ms wall-clock break.
 *
 * Header gates: __has_include(<netinet/in.h>) / <sys/socket.h> /
 * <linux/in.h> / <linux/in6.h>.  MCAST_JOIN_SOURCE_GROUP (46),
 * MCAST_LEAVE_SOURCE_GROUP (47), MCAST_BLOCK_SOURCE (43),
 * MCAST_UNBLOCK_SOURCE (44), MCAST_MSFILTER (48), IP_MSFILTER (41),
 * IP_ADD_SOURCE_MEMBERSHIP (39), IP_DROP_SOURCE_MEMBERSHIP (40),
 * IPV6_MULTICAST_LOOP (19) are #define-fallback supplied at their
 * stable UAPI integer values when missing on the build host -- the
 * kernel returns ENOPROTOOPT and the cap-gate latches.
 *
 * Brick-safety:
 *   - All sockets are unprivileged userspace SOCK_DGRAM; nothing
 *     touches the routing table or interface state.
 *   - IP_MULTICAST_LOOP is on so packets stay on lo; no physical
 *     network egress.
 *   - SSM groups in 232.0.0.0/8 (specifically 232.42.x.y) and
 *     ff3e::42:* IPv6 SSM range stay inside the local stack.
 *   - BUDGETED outer loop with 200 ms wall cap and per-syscall 100 ms
 *     timeouts -- can't wedge past the SIGALRM(1s) cap.
 */

#if __has_include(<netinet/in.h>) && __has_include(<sys/socket.h>) && \
	__has_include(<linux/in.h>) && __has_include(<linux/in6.h>)

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/in.h>
#include <linux/in6.h>

#include "child.h"
#include "errno-classify.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Stable UAPI integers; supplied as fallbacks for stripped sysroots
 * that omit MCAST_* / IP_MSFILTER from <netinet/in.h> + <linux/in.h>.
 * The kernel returns -ENOPROTOOPT on an unknown setsockopt and the
 * ns_unsupported_igmp_mld_source_churn cap-gate latches.
 */
#ifndef IP_ADD_SOURCE_MEMBERSHIP
#define IP_ADD_SOURCE_MEMBERSHIP	39
#endif
#ifndef IP_DROP_SOURCE_MEMBERSHIP
#define IP_DROP_SOURCE_MEMBERSHIP	40
#endif
#ifndef IP_MSFILTER
#define IP_MSFILTER			41
#endif
#ifndef MCAST_BLOCK_SOURCE
#define MCAST_BLOCK_SOURCE		43
#endif
#ifndef MCAST_UNBLOCK_SOURCE
#define MCAST_UNBLOCK_SOURCE		44
#endif
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP		46
#endif
#ifndef MCAST_LEAVE_SOURCE_GROUP
#define MCAST_LEAVE_SOURCE_GROUP	47
#endif
#ifndef MCAST_MSFILTER
#define MCAST_MSFILTER			48
#endif
#ifndef IPV6_MULTICAST_LOOP
#define IPV6_MULTICAST_LOOP		19
#endif

/* MCAST_INCLUDE / MCAST_EXCLUDE source-filter modes used by
 * struct group_filter / IP_MSFILTER.  Defined in <netinet/in.h> as an
 * enum on glibc; provide integer fallbacks if absent. */
#ifndef MCAST_INCLUDE
#define MCAST_INCLUDE			1
#endif
#ifndef MCAST_EXCLUDE
#define MCAST_EXCLUDE			0
#endif

#define IMC_OUTER_BASE			4U
#define IMC_OUTER_FLOOR			8U
#define IMC_OUTER_CAP			16U
#define IMC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define IMC_TIMEO_MS			100
#define IMC_PORT			1234
#define IMC_LARGE_SRCS			32U

static bool ns_unsupported_igmp_mld_source_churn;

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static void apply_timeouts(int s)
{
	struct timeval tv;

	tv.tv_sec  = 0;
	tv.tv_usec = IMC_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/*
 * Build a struct group_source_req for MCAST_JOIN_SOURCE_GROUP /
 * MCAST_LEAVE_SOURCE_GROUP / MCAST_BLOCK_SOURCE.  v4 caller passes
 * AF_INET + a 32-bit group/source; v6 caller passes AF_INET6 + a full
 * struct in6_addr (we read 16 bytes from src/grp_v6).
 */
static void fill_gsr_v4(struct group_source_req *gsr, unsigned int ifindex,
			__u32 grp_be, __u32 src_be)
{
	struct sockaddr_in *sg = (struct sockaddr_in *)&gsr->gsr_group;
	struct sockaddr_in *ss = (struct sockaddr_in *)&gsr->gsr_source;

	memset(gsr, 0, sizeof(*gsr));
	gsr->gsr_interface = ifindex;
	sg->sin_family = AF_INET;
	sg->sin_addr.s_addr = grp_be;
	ss->sin_family = AF_INET;
	ss->sin_addr.s_addr = src_be;
}

static void fill_gsr_v6(struct group_source_req *gsr, unsigned int ifindex,
			const struct in6_addr *grp_v6,
			const struct in6_addr *src_v6)
{
	struct sockaddr_in6 *sg = (struct sockaddr_in6 *)&gsr->gsr_group;
	struct sockaddr_in6 *ss = (struct sockaddr_in6 *)&gsr->gsr_source;

	memset(gsr, 0, sizeof(*gsr));
	gsr->gsr_interface = ifindex;
	sg->sin6_family = AF_INET6;
	memcpy(&sg->sin6_addr, grp_v6, sizeof(*grp_v6));
	ss->sin6_family = AF_INET6;
	memcpy(&ss->sin6_addr, src_v6, sizeof(*src_v6));
}

/*
 * Pick the source-list size for this iteration: rotates 1, ~8, ~32 so
 * the realloc path inside ip_mc_msfilter actually fires across the
 * outer loop instead of always landing in the small-list short-circuit.
 */
static unsigned int rotate_filter_size(unsigned int iter_idx)
{
	switch (iter_idx % 3U) {
	case 0:  return 1U;
	case 1:  return 8U;
	default: return IMC_LARGE_SRCS;
	}
}

/*
 * Allocate + populate a struct group_filter with @nsrc synthetic
 * sources (10.0.iter.k for v4, 2001:db8::iter:k for v6).  Caller frees.
 * Returns NULL on allocation failure.
 */
static struct group_filter *build_filter_v4(unsigned int ifindex,
					    __u32 grp_be, unsigned int nsrc,
					    unsigned int salt)
{
	size_t sz = GROUP_FILTER_SIZE(nsrc);
	struct group_filter *gf;
	struct sockaddr_in *sg;
	unsigned int i;

	if (nsrc == 0)
		nsrc = 1;
	gf = calloc(1, sz);
	if (!gf)
		return NULL;
	gf->gf_interface = ifindex;
	gf->gf_fmode     = MCAST_INCLUDE;
	gf->gf_numsrc    = nsrc;
	sg = (struct sockaddr_in *)&gf->gf_group;
	sg->sin_family      = AF_INET;
	sg->sin_addr.s_addr = grp_be;

	for (i = 0; i < nsrc; i++) {
		struct sockaddr_in *ss =
			(struct sockaddr_in *)&gf->gf_slist[i];
		__u32 a = htonl(0x0a000000U | ((salt & 0xff) << 8) |
				(i & 0xff));
		ss->sin_family      = AF_INET;
		ss->sin_addr.s_addr = a;
	}
	return gf;
}

static struct group_filter *build_filter_v6(unsigned int ifindex,
					    const struct in6_addr *grp_v6,
					    unsigned int nsrc,
					    unsigned int salt)
{
	size_t sz = GROUP_FILTER_SIZE(nsrc);
	struct group_filter *gf;
	struct sockaddr_in6 *sg;
	unsigned int i;

	if (nsrc == 0)
		nsrc = 1;
	gf = calloc(1, sz);
	if (!gf)
		return NULL;
	gf->gf_interface = ifindex;
	gf->gf_fmode     = MCAST_INCLUDE;
	gf->gf_numsrc    = nsrc;
	sg = (struct sockaddr_in6 *)&gf->gf_group;
	sg->sin6_family = AF_INET6;
	memcpy(&sg->sin6_addr, grp_v6, sizeof(*grp_v6));

	for (i = 0; i < nsrc; i++) {
		struct sockaddr_in6 *ss =
			(struct sockaddr_in6 *)&gf->gf_slist[i];
		ss->sin6_family = AF_INET6;
		ss->sin6_addr.s6_addr[0]  = 0x20;
		ss->sin6_addr.s6_addr[1]  = 0x01;
		ss->sin6_addr.s6_addr[2]  = 0x0d;
		ss->sin6_addr.s6_addr[3]  = 0xb8;
		ss->sin6_addr.s6_addr[12] = (unsigned char)(salt & 0xff);
		ss->sin6_addr.s6_addr[14] = (unsigned char)((i >> 8) & 0xff);
		ss->sin6_addr.s6_addr[15] = (unsigned char)(i & 0xff);
	}
	return gf;
}

static void send_burst(int s, unsigned int n)
{
	static const unsigned char payload[16] = { 0 };
	unsigned int i;

	for (i = 0; i < n; i++) {
		ssize_t r = send(s, payload, sizeof(payload), MSG_DONTWAIT);

		if (r > 0)
			__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_send_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Per-iteration scratch carried across the igmp_source_iter_v4_<phase>
 * helpers.  Lifetime is one iter_one_v4() invocation; avoids threading
 * the two fds, three preshaped addresses, the two group_source_req
 * structures, and the bulk-filter pointer through every helper
 * signature.  Sentinel values (-1 / NULL) on the fds and gf so the
 * out: cleanup path can act selectively.
 */
struct igmp_source_iter_v4_ctx {
	int			send_s;
	int			recv_s;
	__u32			grp_be;
	__u32			src_a_be;
	__u32			src_b_be;
	struct group_source_req	gsr_a;
	struct group_source_req	gsr_b;
	struct group_filter    *gf;
	unsigned int		iter_idx;
	unsigned int		salt;
};

/*
 * Phase 1 (v4): open the connected SOCK_DGRAM sender, apply the 100 ms
 * SO_{RCV,SND}TIMEO, and connect() to the SSM group:port.  On any
 * socket/connect failure bumps setup_failed and returns -1; caller does
 * `goto out` so the (possibly opened) send_s gets closed by the shared
 * cleanup path.
 */
static int igmp_source_iter_v4_setup_send(struct igmp_source_iter_v4_ctx *it)
{
	struct sockaddr_in addr;

	it->send_s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (it->send_s < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	apply_timeouts(it->send_s);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(IMC_PORT);
	addr.sin_addr.s_addr = it->grp_be;
	if (connect(it->send_s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 2 (v4): open the SOCK_DGRAM receiver, apply timeouts, set
 * SO_REUSEADDR + IP_MULTICAST_LOOP so loopback delivery fires, then
 * bind to the SSM group:port.  -1 return on socket/bind failure; caller
 * routes through out: so the partially-opened recv_s is closed.
 */
static int igmp_source_iter_v4_setup_recv(struct igmp_source_iter_v4_ctx *it)
{
	struct sockaddr_in addr;
	int yes = 1;

	it->recv_s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (it->recv_s < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	apply_timeouts(it->recv_s);
	(void)setsockopt(it->recv_s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	(void)setsockopt(it->recv_s, IPPROTO_IP, IP_MULTICAST_LOOP,
			 &yes, sizeof(yes));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(IMC_PORT);
	addr.sin_addr.s_addr = it->grp_be;
	if (bind(it->recv_s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 3 (v4): structural-support probe via MCAST_JOIN_SOURCE_GROUP on
 * src_a (latches ns_unsupported_igmp_mld_source_churn on EPERM /
 * ENOSYS / EOPNOTSUPP / ENOPROTOOPT / EAFNOSUPPORT), then extend the
 * filter with src_b.  Both gsr_a and gsr_b are filled into the ctx so
 * the race phase can hand them to MCAST_LEAVE_SOURCE_GROUP /
 * MCAST_BLOCK_SOURCE without re-deriving them.
 */
static int igmp_source_iter_v4_join(struct igmp_source_iter_v4_ctx *it)
{
	fill_gsr_v4(&it->gsr_a, 0U, it->grp_be, it->src_a_be);
	if (setsockopt(it->recv_s, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
		       &it->gsr_a, sizeof(it->gsr_a)) < 0) {
		int e = errno;

		if (is_syscall_unsupported(e) || is_proto_family_unsupported(e))
			ns_unsupported_igmp_mld_source_churn = true;
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_join_ok,
			   1, __ATOMIC_RELAXED);

	fill_gsr_v4(&it->gsr_b, 0U, it->grp_be, it->src_b_be);
	if (setsockopt(it->recv_s, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP,
		       &it->gsr_b, sizeof(it->gsr_b)) == 0)
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_join_ok,
				   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 4 (v4): one of the four race-letter mutations against the
 * recv_s filter while the sender's burst is in flight.  A = shrink
 * (MCAST_LEAVE_SOURCE_GROUP), B = INCLUDE->EXCLUDE flip
 * (MCAST_BLOCK_SOURCE), C = bulk replace (MCAST_MSFILTER, exercises
 * the ip_mc_msfilter realloc + rcu publish path; allocates ctx->gf
 * which the teardown phase frees), D = full leave (IP_DROP_MEMBERSHIP).
 */
static void igmp_source_iter_v4_race(struct igmp_source_iter_v4_ctx *it)
{
	unsigned int race_letter = (it->iter_idx >> 1) & 3U;
	unsigned int nsrc;
	int rc;

	switch (race_letter) {
	case 0:
		/* RACE A: filter shrink mid-stream. */
		if (setsockopt(it->recv_s, IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP,
			       &it->gsr_a, sizeof(it->gsr_a)) == 0)
			__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_leave_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 1:
		/* RACE B: INCLUDE -> EXCLUDE flip via BLOCK_SOURCE. */
		if (setsockopt(it->recv_s, IPPROTO_IP, MCAST_BLOCK_SOURCE,
			       &it->gsr_b, sizeof(it->gsr_b)) == 0)
			__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_block_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 2:
		/* RACE C: bulk replace via MCAST_MSFILTER -- exercises the
		 * ip_mc_msfilter realloc + rcu publish path. */
		nsrc = rotate_filter_size(it->iter_idx);
		it->gf = build_filter_v4(0U, it->grp_be, nsrc, it->salt);
		if (it->gf) {
			rc = setsockopt(it->recv_s, IPPROTO_IP, MCAST_MSFILTER,
					it->gf, GROUP_FILTER_SIZE(nsrc));
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_msfilter_ok,
						   1, __ATOMIC_RELAXED);
		}
		break;
	case 3:
		/* RACE D: full leave race vs in-flight sender. */
		{
			struct ip_mreqn mreq;

			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr.s_addr = it->grp_be;
			if (setsockopt(it->recv_s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
				       &mreq, sizeof(mreq)) == 0)
				__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_drop_ok,
						   1, __ATOMIC_RELAXED);
		}
		break;
	}
}

/*
 * Phase 5 (v4): free any bulk-filter buffer the race phase allocated,
 * then close send_s + recv_s in iter_idx-randomised order so teardown
 * isn't always recv-first.  Sentinel-aware so the same helper backs
 * both the teardown: success-path and the out: short-circuit path.
 */
static void igmp_source_iter_v4_teardown(struct igmp_source_iter_v4_ctx *it)
{
	free(it->gf);
	it->gf = NULL;
	/* Random close order so teardown isn't always recv-first. */
	if ((it->iter_idx & 1U) == 0U) {
		if (it->recv_s >= 0) { close(it->recv_s); it->recv_s = -1; }
		if (it->send_s >= 0) { close(it->send_s); it->send_s = -1; }
	} else {
		if (it->send_s >= 0) { close(it->send_s); it->send_s = -1; }
		if (it->recv_s >= 0) { close(it->recv_s); it->recv_s = -1; }
	}
}

/*
 * One IPv4 join+race+teardown cycle.  Returns immediately if the cap-
 * gate has latched.  Updates ns_unsupported_igmp_mld_source_churn on
 * structural failures from the first MCAST_JOIN_SOURCE_GROUP probe.
 */
static void iter_one_v4(unsigned int iter_idx, const struct timespec *t_outer)
{
	struct igmp_source_iter_v4_ctx it = {
		.send_s   = -1,
		.recv_s   = -1,
		.gf       = NULL,
		.iter_idx = iter_idx,
		.salt     = (unsigned int)(rand32() & 0xffu),
	};

	if ((unsigned long long)ns_since(t_outer) >= IMC_WALL_CAP_NS)
		return;

	/* SSM group 232.42.salt.1; sources 10.0.salt.{2,3}. */
	it.grp_be   = htonl(0xe82a0000U | ((it.salt & 0xff) << 8) | 0x01U);
	it.src_a_be = htonl(0x0a000000U | ((it.salt & 0xff) << 8) | 0x02U);
	it.src_b_be = htonl(0x0a000000U | ((it.salt & 0xff) << 8) | 0x03U);

	if (igmp_source_iter_v4_setup_send(&it) != 0)
		goto out;
	if (igmp_source_iter_v4_setup_recv(&it) != 0)
		goto out;
	if (igmp_source_iter_v4_join(&it) != 0)
		goto out;

	send_burst(it.send_s, 2);

	if ((unsigned long long)ns_since(t_outer) >= IMC_WALL_CAP_NS)
		goto teardown;

	igmp_source_iter_v4_race(&it);

	send_burst(it.send_s, 2);

teardown:
	igmp_source_iter_v4_teardown(&it);
	return;

out:
	free(it.gf);
	if (it.send_s >= 0)
		close(it.send_s);
	if (it.recv_s >= 0)
		close(it.recv_s);
}

/*
 * Per-iteration scratch carried across the mld_source_iter_v6_<phase>
 * helpers.  v6 mirror of struct igmp_source_iter_v4_ctx -- kept as a
 * distinct type with a distinct prefix so a future reader cannot mis-
 * route a v4 helper into a v6 caller (and vice versa) at the call
 * site.  Sentinel values (-1 / NULL) on the fds and gf.
 */
struct mld_source_iter_v6_ctx {
	int			send_s;
	int			recv_s;
	struct in6_addr		grp_v6;
	struct in6_addr		src_a_v6;
	struct in6_addr		src_b_v6;
	struct group_source_req	gsr_a;
	struct group_source_req	gsr_b;
	struct group_filter    *gf;
	unsigned int		iter_idx;
	unsigned int		salt;
};

/*
 * Phase 1 (v6): open the connected SOCK_DGRAM sender on AF_INET6,
 * apply 100 ms SO_{RCV,SND}TIMEO, and connect() to the MLDv2 group:port
 * (ff3e::42:salt).  Returns -1 on socket/connect failure; caller routes
 * to out: so the (possibly opened) send_s lands in the shared cleanup.
 */
static int mld_source_iter_v6_setup_send(struct mld_source_iter_v6_ctx *it)
{
	struct sockaddr_in6 addr;

	it->send_s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (it->send_s < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	apply_timeouts(it->send_s);

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port   = htons(IMC_PORT);
	memcpy(&addr.sin6_addr, &it->grp_v6, sizeof(it->grp_v6));
	if (connect(it->send_s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 2 (v6): open the AF_INET6 SOCK_DGRAM receiver, apply timeouts,
 * set SO_REUSEADDR + IPV6_MULTICAST_LOOP so loopback delivery fires,
 * then bind to the MLDv2 group:port.  -1 return on socket/bind failure
 * routes through the caller's out: cleanup.
 */
static int mld_source_iter_v6_setup_recv(struct mld_source_iter_v6_ctx *it)
{
	struct sockaddr_in6 addr;
	int yes = 1;

	it->recv_s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (it->recv_s < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	apply_timeouts(it->recv_s);
	(void)setsockopt(it->recv_s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	(void)setsockopt(it->recv_s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			 &yes, sizeof(yes));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port   = htons(IMC_PORT);
	if (bind(it->recv_s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 3 (v6): structural-support probe via MCAST_JOIN_SOURCE_GROUP on
 * src_a (latches ns_unsupported_igmp_mld_source_churn on the
 * unsupported-syscall / unsupported-family errno families), then extend
 * the include filter with src_b.  Both gsr_a and gsr_b stay live in
 * the ctx so the race phase hands them to MCAST_LEAVE_SOURCE_GROUP /
 * MCAST_BLOCK_SOURCE without re-deriving the sockaddrs.
 */
static int mld_source_iter_v6_join(struct mld_source_iter_v6_ctx *it)
{
	fill_gsr_v6(&it->gsr_a, 0U, &it->grp_v6, &it->src_a_v6);
	if (setsockopt(it->recv_s, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
		       &it->gsr_a, sizeof(it->gsr_a)) < 0) {
		int e = errno;

		if (is_syscall_unsupported(e) || is_proto_family_unsupported(e))
			ns_unsupported_igmp_mld_source_churn = true;
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_join_ok,
			   1, __ATOMIC_RELAXED);

	fill_gsr_v6(&it->gsr_b, 0U, &it->grp_v6, &it->src_b_v6);
	if (setsockopt(it->recv_s, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
		       &it->gsr_b, sizeof(it->gsr_b)) == 0)
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_join_ok,
				   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * IPv6 mirror of iter_one_v4.  Hits ip6_mc_source / ip6_mc_msfilter
 * (net/ipv6/mcast.c) instead of the v4 paths.  SSM group ff3e::42:salt.
 */
static void iter_one_v6(unsigned int iter_idx, const struct timespec *t_outer)
{
	struct mld_source_iter_v6_ctx it = {
		.send_s   = -1,
		.recv_s   = -1,
		.gf       = NULL,
		.iter_idx = iter_idx,
		.salt     = (unsigned int)(rand32() & 0xffu),
	};
	unsigned int race_letter = (iter_idx >> 1) & 3U;
	unsigned int nsrc;
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= IMC_WALL_CAP_NS)
		return;

	memset(&it.grp_v6, 0, sizeof(it.grp_v6));
	it.grp_v6.s6_addr[0]  = 0xff;
	it.grp_v6.s6_addr[1]  = 0x3e;
	it.grp_v6.s6_addr[12] = 0x00;
	it.grp_v6.s6_addr[13] = 0x42;
	it.grp_v6.s6_addr[14] = (unsigned char)((it.salt >> 8) & 0xff);
	it.grp_v6.s6_addr[15] = (unsigned char)(it.salt & 0xff);

	memset(&it.src_a_v6, 0, sizeof(it.src_a_v6));
	it.src_a_v6.s6_addr[0]  = 0x20;
	it.src_a_v6.s6_addr[1]  = 0x01;
	it.src_a_v6.s6_addr[2]  = 0x0d;
	it.src_a_v6.s6_addr[3]  = 0xb8;
	it.src_a_v6.s6_addr[12] = (unsigned char)(it.salt & 0xff);
	it.src_a_v6.s6_addr[15] = 0x02;

	memcpy(&it.src_b_v6, &it.src_a_v6, sizeof(it.src_b_v6));
	it.src_b_v6.s6_addr[15] = 0x03;

	if (mld_source_iter_v6_setup_send(&it) != 0)
		goto out;
	if (mld_source_iter_v6_setup_recv(&it) != 0)
		goto out;
	if (mld_source_iter_v6_join(&it) != 0)
		goto out;

	send_burst(it.send_s, 2);

	if ((unsigned long long)ns_since(t_outer) >= IMC_WALL_CAP_NS)
		goto teardown;

	switch (race_letter) {
	case 0:
		if (setsockopt(it.recv_s, IPPROTO_IPV6, MCAST_LEAVE_SOURCE_GROUP,
			       &it.gsr_a, sizeof(it.gsr_a)) == 0)
			__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_leave_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 1:
		if (setsockopt(it.recv_s, IPPROTO_IPV6, MCAST_BLOCK_SOURCE,
			       &it.gsr_b, sizeof(it.gsr_b)) == 0)
			__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_block_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 2:
		nsrc = rotate_filter_size(it.iter_idx);
		it.gf = build_filter_v6(0U, &it.grp_v6, nsrc, it.salt);
		if (it.gf) {
			rc = setsockopt(it.recv_s, IPPROTO_IPV6, MCAST_MSFILTER,
					it.gf, GROUP_FILTER_SIZE(nsrc));
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_msfilter_ok,
						   1, __ATOMIC_RELAXED);
		}
		break;
	case 3:
		{
			struct ipv6_mreq mreq;

			memset(&mreq, 0, sizeof(mreq));
			memcpy(&mreq.ipv6mr_multiaddr, &it.grp_v6, sizeof(it.grp_v6));
			if (setsockopt(it.recv_s, IPPROTO_IPV6,
				       IPV6_DROP_MEMBERSHIP,
				       &mreq, sizeof(mreq)) == 0)
				__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_drop_ok,
						   1, __ATOMIC_RELAXED);
		}
		break;
	}

	send_burst(it.send_s, 2);

teardown:
	free(it.gf);
	it.gf = NULL;
	if ((it.iter_idx & 1U) == 0U) {
		if (it.recv_s >= 0) { close(it.recv_s); it.recv_s = -1; }
		if (it.send_s >= 0) { close(it.send_s); it.send_s = -1; }
	} else {
		if (it.send_s >= 0) { close(it.send_s); it.send_s = -1; }
		if (it.recv_s >= 0) { close(it.recv_s); it.recv_s = -1; }
	}
	return;

out:
	free(it.gf);
	if (it.send_s >= 0)
		close(it.send_s);
	if (it.recv_s >= 0)
		close(it.recv_s);
}

bool igmp_mld_source_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_igmp_mld_source_churn) {
		__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_IGMP_MLD_SOURCE_CHURN,
			       JITTER_RANGE(IMC_OUTER_BASE));
	if (outer_iters < IMC_OUTER_FLOOR)
		outer_iters = IMC_OUTER_FLOOR;
	if (outer_iters > IMC_OUTER_CAP)
		outer_iters = IMC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= IMC_WALL_CAP_NS)
			break;

		if ((i & 1U) == 0U)
			iter_one_v4(i, &t_outer);
		else
			iter_one_v6(i, &t_outer);

		if (ns_unsupported_igmp_mld_source_churn)
			break;
	}

	return true;
}

#else  /* missing one of <netinet/in.h> / <sys/socket.h> / <linux/in.h> / <linux/in6.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool igmp_mld_source_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.igmp_mld_source_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif

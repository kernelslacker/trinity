/*
 * ipfrag_source_churn — many-distinct-source IPv4 fragment pairs
 * driven into the per-net inetpeer rbtree.
 *
 * Targets the lockless inet_getpeer() lookup race fixed upstream by
 * commit 67ef49047d31.  inet_getpeer() walks the per-net inetpeer
 * rbtree under a seqlock and historically returned the matched node
 * without re-checking the sequence counter; a concurrent writer
 * rebalancing the tree can leave the looked-up node freed or reused
 * before the caller dereferences it.  Reaching the race needs
 *
 *   (a) high source-address cardinality so unique inetpeer nodes are
 *       inserted and reclaimed under load, and
 *   (b) concurrent readers and writers on the same per-net rbtree.
 *
 * The IPv4 stack consults inet_getpeer on both egress (ip_select_ident
 * for non-atomic ids, redirect throttling) and on ingress for several
 * features that key off the source address.  Random syscall fuzzing
 * never reaches that surface with high cardinality: the egress source
 * is whatever the route lookup picks, so a generic fuzzer churns one
 * peer entry, not thousands.
 *
 * Per invocation (driven by userns_run_in_ns):
 *   - Enter a private net namespace via a transient grandchild that
 *     installs an identity user namespace plus a fresh CLONE_NEWNET,
 *     runs the body below, and _exit()s so the kernel reaps the netns
 *     and every fd opened against it.  The persistent fuzz child
 *     never changes its own credentials or namespace stack, so the
 *     cap-drop oracle keeps observing the host credential profile.
 *     Helper -EPERM (hardened userns policy refused CLONE_NEWUSER)
 *     latches the childop off for the rest of the child's lifetime;
 *     a transient setup failure skips the iteration without latching.
 *   - In the grandchild: bring lo up and assign 127.0.0.1/8 so the
 *     loopback route exists.
 *   - SOCK_DGRAM listener bound to 127.0.0.1:0 — destination port for
 *     the synthetic UDP fragment pairs.  Receive buffer pinned small;
 *     we never drain it, the kernel drops on overrun.
 *   - Raw sender: SOCK_RAW with IPPROTO_RAW (IP_HDRINCL implicit) so
 *     the source IPv4 address in each emitted header is what the
 *     kernel ultimately keys inet_getpeer on.  CAP_NET_RAW in the
 *     grandchild's user namespace lets the raw open succeed regardless
 *     of the persistent child's cap-drop state.
 *
 * Per outer iteration (BUDGETED, base 8, cap 64, 250 ms wall cap):
 *   - src_ip = 10.<rot>.<i>.<i&0xff>: a rotating /16 base XORed with
 *     a 16-bit inner counter so a long-running child sweeps up to 65k
 *     distinct sources through the per-net inetpeer rbtree, with the
 *     /16 base re-rolled every full sweep so different /16 swathes of
 *     10.0.0.0/8 are visited across the child's life.
 *   - Build a (saddr, daddr=127.0.0.1, id) fragment pair: first packet
 *     carries 16 bytes of payload with IP_MF set and offset 0; second
 *     packet carries 8 bytes with MF clear and offset 2 (== 16 bytes
 *     in the 8-byte units the IPv4 frag_off field is encoded in).
 *     Same id+saddr+daddr+protocol so the receive-side queue lookup
 *     hits the bucket the first frag inserted.
 *   - sendto() both packets via the raw socket, MSG_DONTWAIT.
 *
 * The pair never has to reassemble cleanly; the inetpeer touch
 * happens during fragment intake before the synthetic UDP datagram
 * would be delivered (its checksum will not validate).
 *
 * Self-bounding: BUDGETED outer loop with a 250 ms CLOCK_MONOTONIC
 * wall cap; raw sends are MSG_DONTWAIT so a backed-up tx queue can't
 * hold us past child.c's SIGALRM(1s).  Per-child CLONE_NEWNET keeps
 * the inetpeer rbtree churn isolated from the host net stack.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#ifndef IP_MF
#define IP_MF			0x2000
#endif
#ifndef IP_HDRINCL
#define IP_HDRINCL		3
#endif

#define IPF_OUTER_BASE		8U
#define IPF_OUTER_CAP		64U
#define IPF_WALL_CAP_NS		(250ULL * 1000ULL * 1000ULL)
#define IPF_FRAG1_PAYLOAD	16U	/* 8-byte aligned for the first frag. */
#define IPF_FRAG2_PAYLOAD	8U
#define IPF_LISTEN_RCVBUF	4096

static bool ns_unsupported_ipfrag;
static uint16_t ipfrag_id_counter;
static uint32_t ipfrag_inner_idx;
static uint32_t ipfrag_rot_base;
static bool ipfrag_rot_base_init;

static void warn_once_unsupported_ipfrag(const char *reason, int err)
{
	if (ns_unsupported_ipfrag)
		return;
	ns_unsupported_ipfrag = true;
	/* check-static: child-output-ok */
	outputerr("ipfrag_source_churn: %s failed (errno=%d), latching unsupported_ipfrag\n",
		  reason, err);
}

/* Bring lo up and bind 127.0.0.1/8 so the loopback route exists in
 * the freshly-unshared netns.  Returns 0 on success, -1 otherwise. */
static int bring_lo_up_with_addr(void)
{
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	struct ifreq ifr;
	struct sockaddr_in *sin;
	int rc = -1;

	if (s < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
		goto out;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	sin = (struct sockaddr_in *)&ifr.ifr_netmask;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xff000000U);
	if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0)
		goto out;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		goto out;
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		goto out;

	rc = 0;
out:
	close(s);
	return rc;
}

static int open_listener(uint16_t *port_be_out)
{
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	int rcvbuf = IPF_LISTEN_RCVBUF;

	if (s < 0)
		return -1;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(s);
		return -1;
	}
	if (getsockname(s, (struct sockaddr *)&sin, &slen) < 0) {
		close(s);
		return -1;
	}
	*port_be_out = sin.sin_port;
	return s;
}

static int open_sender(void)
{
	int s = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);

	/* SOCK_RAW with IPPROTO_RAW implicitly enables IP_HDRINCL: the
	 * kernel transmits the iphdr we hand it verbatim, so the saddr
	 * cycling drives the inetpeer rbtree directly. */
	return s;
}

static void build_iphdr(struct iphdr *ip, uint32_t saddr_be, uint32_t daddr_be,
			uint16_t id_he, uint16_t frag_off_he, uint16_t tot_len_he,
			uint8_t protocol)
{
	memset(ip, 0, sizeof(*ip));
	ip->version  = 4;
	ip->ihl      = 5;
	ip->tos      = 0;
	ip->tot_len  = htons(tot_len_he);
	ip->id       = htons(id_he);
	ip->frag_off = htons(frag_off_he);
	ip->ttl      = 64;
	ip->protocol = protocol;
	ip->saddr    = saddr_be;
	ip->daddr    = daddr_be;
	ip->check    = 0;	/* kernel fills the IPv4 checksum on raw send */
}

static void send_frag_pair(int send_fd, uint16_t listen_port_be,
			   uint32_t saddr_be, uint16_t id_he)
{
	uint8_t pkt1[sizeof(struct iphdr) + IPF_FRAG1_PAYLOAD];
	uint8_t pkt2[sizeof(struct iphdr) + IPF_FRAG2_PAYLOAD];
	uint32_t daddr_be = htonl(INADDR_LOOPBACK);
	struct sockaddr_in dst;
	ssize_t n;

	memset(pkt1 + sizeof(struct iphdr), 0xa5, IPF_FRAG1_PAYLOAD);
	memset(pkt2 + sizeof(struct iphdr), 0x5a, IPF_FRAG2_PAYLOAD);

	build_iphdr((struct iphdr *)pkt1, saddr_be, daddr_be, id_he,
		    IP_MF, sizeof(pkt1), IPPROTO_UDP);
	/* Second frag: offset = 16 bytes / 8 = 2 (in 8-byte units),
	 * MF clear, same id+saddr+daddr+protocol. */
	build_iphdr((struct iphdr *)pkt2, saddr_be, daddr_be, id_he,
		    IPF_FRAG1_PAYLOAD / 8U, sizeof(pkt2), IPPROTO_UDP);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = daddr_be;
	dst.sin_port = listen_port_be;

	n = sendto(send_fd, pkt1, sizeof(pkt1), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.ipfrag_packets_sent_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.ipfrag_send_failed, 1,
				   __ATOMIC_RELAXED);

	n = sendto(send_fd, pkt2, sizeof(pkt2), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.ipfrag_packets_sent_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.ipfrag_send_failed, 1,
				   __ATOMIC_RELAXED);
}

/*
 * Per-invocation state handed to the in-ns callback so it can build
 * source addresses + ids from the same rotating pool the persistent
 * child tracks, without needing the rotation counters to be visible
 * across the fork boundary.
 */
struct ipfrag_source_churn_ctx {
	struct childdata *child;
	uint32_t inner_idx_start;
	uint16_t id_counter_start;
	uint32_t rot_base;
	unsigned int outer_iters;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the loopback
 * address, raw sender socket and UDP listener are reaped along with the
 * namespace.  Return value is ignored by the helper.
 */
static int ipfrag_source_churn_in_ns(void *arg)
{
	struct ipfrag_source_churn_ctx *cctx = (struct ipfrag_source_churn_ctx *)arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	int send_fd, listen_fd;
	uint16_t listen_port_be = 0;
	unsigned int i;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (bring_lo_up_with_addr() < 0)
		return 0;

	send_fd = open_sender();
	if (send_fd < 0)
		return 0;

	listen_fd = open_listener(&listen_port_be);
	if (listen_fd < 0) {
		close(send_fd);
		return 0;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < cctx->outer_iters; i++) {
		uint32_t inner = cctx->inner_idx_start + i;
		uint32_t src_be;
		uint16_t id_he;

		if ((unsigned long long)ns_since(&t_outer) >= IPF_WALL_CAP_NS)
			break;

		src_be = htonl(0x0a000000U | cctx->rot_base |
			       (inner & 0xffffU));
		id_he  = (uint16_t)(cctx->id_counter_start + i);

		send_frag_pair(send_fd, listen_port_be, src_be, id_he);
		__atomic_add_fetch(&shm->stats.ipfrag_unique_srcs, 1,
				   __ATOMIC_RELAXED);
	}

	close(listen_fd);
	close(send_fd);
	return 0;
}

bool ipfrag_source_churn(struct childdata *child)
{
	struct ipfrag_source_churn_ctx cctx = { .child = child };
	unsigned int outer_iters;
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.ipfrag_source_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ipfrag)
		return true;

	/* Re-roll the /16 base on first use and every 65536 inner steps so
	 * the child sweeps several /16 swathes of 10.0.0.0/8 across its
	 * life. */
	if (!ipfrag_rot_base_init || (ipfrag_inner_idx & 0xffffU) == 0U) {
		ipfrag_rot_base = (rand32() & 0xffU) << 16;
		ipfrag_rot_base_init = true;
	}

	outer_iters = BUDGETED(CHILD_OP_IPFRAG_SOURCE_CHURN,
			       JITTER_RANGE(IPF_OUTER_BASE));
	if (outer_iters > IPF_OUTER_CAP)
		outer_iters = IPF_OUTER_CAP;

	cctx.inner_idx_start  = ipfrag_inner_idx;
	cctx.id_counter_start = ipfrag_id_counter;
	cctx.rot_base         = ipfrag_rot_base;
	cctx.outer_iters      = outer_iters;

	rc = userns_run_in_ns(CLONE_NEWNET, ipfrag_source_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_ipfrag("userns_run_in_ns(CLONE_NEWNET)",
					     EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		return true;
	}

	/* Advance the rotation counters to keep distinct source addresses
	 * flowing through the per-net inetpeer rbtree across invocations.
	 * The grandchild ran with a snapshot; its writes died with it. */
	ipfrag_inner_idx  += outer_iters;
	ipfrag_id_counter += (uint16_t)outer_iters;

	return true;
}

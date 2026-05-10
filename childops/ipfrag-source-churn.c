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
 * Per child (latched once on first invocation):
 *   - unshare(CLONE_NEWNET) into a private netns; bring lo up and
 *     assign 127.0.0.1/8 so the loopback route exists.
 *   - SOCK_DGRAM listener bound to 127.0.0.1:0 — destination port for
 *     the synthetic UDP fragment pairs.  Receive buffer pinned small;
 *     we never drain it, the kernel drops on overrun.
 *   - Raw sender: SOCK_RAW with IPPROTO_RAW (IP_HDRINCL implicit) so
 *     the source IPv4 address in each emitted header is what the
 *     kernel ultimately keys inet_getpeer on.  EPERM / EACCES on the
 *     raw socket open latches ns_unsupported_ipfrag for the rest of
 *     the child's life.
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
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

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
static bool setup_done;
static int ipfrag_send_fd = -1;
static int ipfrag_listen_fd = -1;
static uint16_t ipfrag_listen_port_be;
static uint16_t ipfrag_id_counter;
static uint32_t ipfrag_inner_idx;
static uint32_t ipfrag_rot_base;

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
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

static void send_frag_pair(uint32_t saddr_be, uint16_t id_he)
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
	dst.sin_port = ipfrag_listen_port_be;

	n = sendto(ipfrag_send_fd, pkt1, sizeof(pkt1), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.ipfrag_packets_sent_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.ipfrag_send_failed, 1,
				   __ATOMIC_RELAXED);

	n = sendto(ipfrag_send_fd, pkt2, sizeof(pkt2), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.ipfrag_packets_sent_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.ipfrag_send_failed, 1,
				   __ATOMIC_RELAXED);
}

bool ipfrag_source_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.ipfrag_source_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ipfrag)
		return true;

	if (!setup_done) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_unsupported_ipfrag = true;
			return true;
		}
		if (bring_lo_up_with_addr() < 0) {
			ns_unsupported_ipfrag = true;
			return true;
		}
		ipfrag_send_fd = open_sender();
		if (ipfrag_send_fd < 0) {
			ns_unsupported_ipfrag = true;
			return true;
		}
		ipfrag_listen_fd = open_listener(&ipfrag_listen_port_be);
		if (ipfrag_listen_fd < 0) {
			close(ipfrag_send_fd);
			ipfrag_send_fd = -1;
			ns_unsupported_ipfrag = true;
			return true;
		}
		ipfrag_rot_base = (rand32() & 0xffU) << 16;
		setup_done = true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_IPFRAG_SOURCE_CHURN,
			       JITTER_RANGE(IPF_OUTER_BASE));
	if (outer_iters > IPF_OUTER_CAP)
		outer_iters = IPF_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		uint32_t src_be;
		uint16_t id_he;

		if ((unsigned long long)ns_since(&t_outer) >= IPF_WALL_CAP_NS)
			break;

		/* Re-roll the /16 base every 65536 inner steps so the child
		 * sweeps several /16 swathes of 10.0.0.0/8 across its life. */
		if ((ipfrag_inner_idx & 0xffffU) == 0U)
			ipfrag_rot_base = (rand32() & 0xffU) << 16;

		src_be = htonl(0x0a000000U | ipfrag_rot_base |
			       (ipfrag_inner_idx & 0xffffU));
		id_he  = (uint16_t)(ipfrag_id_counter++);

		send_frag_pair(src_be, id_he);
		__atomic_add_fetch(&shm->stats.ipfrag_unique_srcs, 1,
				   __ATOMIC_RELAXED);
		ipfrag_inner_idx++;
	}

	return true;
}

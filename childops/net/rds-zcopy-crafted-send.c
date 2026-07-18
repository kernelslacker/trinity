/*
 * rds_zcopy_crafted_send - AF_RDS MSG_ZEROCOPY sendmsg with an iovec
 * crafted so the per-page get_user_pages walk faults partway through.
 * Targets net/rds/message.c rds_message_zcopy_from_user() page-pin
 * flow and the paired rds_message_purge() page-free path on the
 * unwind edge.
 *
 * Path exercised: SO_ZEROCOPY=1 flips SOCK_ZEROCOPY on the AF_RDS
 * sock; rds_sendmsg() then allocates an rds_message and, for the
 * MSG_ZEROCOPY case, calls rds_message_zcopy_from_user() which
 * iov_iter_get_pages()-walks the payload one page at a time and
 * appends each pinned page onto the message page list.  When the
 * walk hits an unmapped page mid-iovec, GUP returns short; the
 * error path put_page()s the just-pinned pages and the caller
 * unwinds via rds_message_put(), which walks the same page list and
 * __free_page()s the remainder.  Any refcount skew across the two
 * walks (a put_page of a page still on the purge list, or a
 * __free_page of a page whose refcount already dropped) surfaces
 * under a page-refcount / KASAN / memory-sanitizer kernel.
 *
 * Per invocation runs directly in the persistent child (no netns
 * hop -- AF_RDS bind on 127.0.0.1 stays inside the initial netns
 * but touches only the socket's own state).  Sequence:
 *   1. socket(AF_RDS, SOCK_SEQPACKET, 0).  On EAFNOSUPPORT /
 *      EPROTONOSUPPORT / ENOPROTOOPT latch rds_unsupported and
 *      no-op for the remainder of the child's lifetime.
 *   2. bind to 127.0.0.1:0 (RDS uses sockaddr_in for AF_INET
 *      transport).
 *   3. setsockopt(SO_ZEROCOPY, 1) to flip SOCK_ZEROCOPY.
 *   4. mmap a small backing region of RDSZC_PAGES pages
 *      (MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE) and memset every
 *      page so COW settles before the pin.
 *   5. Poke a hole: munmap one page in the middle of the region.
 *      The GUP walk pins pages 0..hole-1, then faults on the hole.
 *   6. Build an iovec (RDSZC_MAX_NENTS entries) covering the region,
 *      with jittered per-entry offset and length; sendmsg with
 *      MSG_ZEROCOPY|MSG_DONTWAIT to 127.0.0.1:<random>.
 *   7. Drain the socket error queue best-effort so RDS zcopy
 *      completion cookies do not accumulate.
 *
 * Churn axes: iovec entry count (1..RDSZC_MAX_NENTS), which page the
 * hole punches (1..pages-1), first-entry page offset alignment,
 * total message length (bounded).
 *
 * Bounds: outer iters BUDGETED base RDSZC_OUTER_BASE / cap
 * RDSZC_OUTER_CAP with a RDSZC_WALL_CAP_NS wall cap; the mmap region
 * is at most RDSZC_PAGES pages; the iovec is at most
 * RDSZC_MAX_NENTS entries; teardown munmaps every surviving mapping
 * and closes the socket, so a truncated iteration leaks nothing
 * host-visible.
 *
 * Latch: static rds_unsupported set on the first socket(AF_RDS)
 * failure indicating the transport is unbuilt/unloaded; subsequent
 * invocations bump runs+setup_failed and return.  Mirrors the
 * ns_unsupported_* latch pattern in netns_teardown_churn.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"

#include <netinet/in.h>

/*
 * AF_RDS is UAPI-stable but PF_RDS lives in include/kernel/socket.h
 * with a #define fallback for stripped sysroots.  The socket-level
 * SOL_SOCKET / SO_ZEROCOPY constants are already exposed by
 * <sys/socket.h> everywhere we build.
 */

#define RDSZC_PAGE_BYTES		((size_t)4096)
#define RDSZC_PAGES			8U
#define RDSZC_MAX_NENTS			6U
#define RDSZC_OUTER_BASE		2U
#define RDSZC_OUTER_CAP			6U
#define RDSZC_WALL_CAP_NS		(150ULL * 1000ULL * 1000ULL)
#define RDSZC_DRAIN_CAP			8U
#define RDSZC_DST_PORT_MIN		0xc000U
#define RDSZC_DST_PORT_MASK		0x3fffU

/*
 * Per-process latched gate.  RDS transport availability is static
 * across a child's lifetime -- either CONFIG_RDS is built and the
 * module is present, or every socket() call returns
 * EAFNOSUPPORT/EPROTONOSUPPORT.  Once the first probe has paid the
 * EFAIL we stop retrying.  Mirrors ns_unsupported_* in
 * netns_teardown_churn / msg_zerocopy_churn.
 */
static bool rds_unsupported;

/* Per-invocation scratch.  Fields are (-1 / MAP_FAILED / 0) until
 * their setup phase runs; teardown is safe from any bail point. */
struct rds_zcopy_iter_ctx {
	int		sfd;
	void		*region;	/* base of the RDSZC_PAGES-page mapping */
	size_t		region_len;	/* live extent of the base mapping (may shrink after hole-punch) */
	void		*hole_addr;	/* start of the punched-out page, NULL if no hole */
	unsigned int	hole_idx;	/* index of the punched page within [0, RDSZC_PAGES) */
	struct childdata *child;
};

/*
 * Enable SO_ZEROCOPY on the AF_RDS socket.  Non-fatal on failure --
 * without ZC the sendmsg still exercises rds_message_copy_from_user
 * and can degrade to a normal copy; we bump setup_failed and return
 * -1 so the orchestrator skips the pin-fault burst that has no
 * meaning without SOCK_ZEROCOPY.
 */
static int rds_zcopy_iter_enable_zc(struct rds_zcopy_iter_ctx *it)
{
	int one = 1;

	if (setsockopt(it->sfd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) < 0) {
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_zc_enable_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Create + bind the AF_RDS socket.  Latches rds_unsupported on the
 * transport-absent errnos so subsequent invocations short-circuit.
 * Returns 0 on success (sfd populated), -1 on failure with the
 * setup_failed counter bumped and any allocated fd cleaned up.
 */
static int rds_zcopy_iter_open_sock(struct rds_zcopy_iter_ctx *it)
{
	struct sockaddr_in addr;

	it->sfd = socket(AF_RDS, SOCK_SEQPACKET, 0);
	if (it->sfd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == ENOPROTOOPT) {
			rds_unsupported = true;
			const enum child_op_type op = it->child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = 0;
	if (bind(it->sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_setup_failed,
				   1, __ATOMIC_RELAXED);
		close(it->sfd);
		it->sfd = -1;
		return -1;
	}
	__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_bind_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * mmap a small backing region and memset every page so COW settles
 * before the pin walk.  Returns 0 on success (region populated), -1
 * on failure with setup_failed bumped.
 */
static int rds_zcopy_iter_map_pages(struct rds_zcopy_iter_ctx *it)
{
	it->region_len = RDSZC_PAGE_BYTES * RDSZC_PAGES;
	it->region = mmap(NULL, it->region_len, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (it->region == MAP_FAILED) {
		it->region = NULL;
		it->region_len = 0;
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	/* Force the anon pages present so GUP does not merely demand-fault
	 * on the first pin -- we want the accounting to see real page
	 * refcounts, not a fresh zero page. */
	memset(it->region, 0xa5, it->region_len);
	return 0;
}

/*
 * Punch a hole in the middle of the backing region so the per-page
 * GUP walk pins the leading pages, then faults on the hole.  Skipped
 * (best-effort) if only one page is available -- the fault edge
 * needs at least one mapped page before the hole to observe the
 * partial-pin unwind.  On success sets it->hole_addr / it->hole_idx
 * so teardown does not attempt to munmap an already-freed range.
 */
static void rds_zcopy_iter_punch_hole(struct rds_zcopy_iter_ctx *it)
{
	unsigned int idx;
	void *hole;

	if (RDSZC_PAGES < 2U)
		return;

	/* Pick a hole index in [1, RDSZC_PAGES - 1] so at least one
	 * leading page stays mapped for the pin to reach before the
	 * GUP walk faults.  Bias slightly toward earlier indices so
	 * the unwind walks a small pinned prefix more often than a
	 * long one -- both edges are covered over successive iters. */
	idx = 1U + (rnd_modulo_u32(RDSZC_PAGES - 1U));
	hole = (unsigned char *)it->region + (size_t)idx * RDSZC_PAGE_BYTES;

	if (munmap(hole, RDSZC_PAGE_BYTES) != 0)
		return;
	it->hole_addr = hole;
	it->hole_idx = idx;
	__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_hole_ok,
			   1, __ATOMIC_RELAXED);
}

/*
 * Compose an iovec spanning the (holed) backing region and sendmsg
 * with MSG_ZEROCOPY.  Entry count / per-entry length / first-entry
 * page offset are jittered so successive invocations exercise
 * different pin-walk shapes.  Destination is loopback with a random
 * ephemeral port; no listener is required -- the pin walk runs
 * before route lookup so EDESTADDRREQ / EHOSTUNREACH on the wire
 * still counts as pin-path coverage.  MSG_DONTWAIT keeps the send
 * from stalling if the socket's write buffer is full.
 */
static void rds_zcopy_iter_send_faulting(struct rds_zcopy_iter_ctx *it)
{
	struct msghdr msg;
	struct sockaddr_in dst;
	struct iovec iov[RDSZC_MAX_NENTS];
	unsigned int nents, i;
	size_t off;
	ssize_t r;

	nents = 1U + (rnd_modulo_u32(RDSZC_MAX_NENTS));
	if (nents > RDSZC_MAX_NENTS)
		nents = RDSZC_MAX_NENTS;

	/* First-entry offset within its page: {0, 1, page/2, page-1}
	 * so the pin walk sees both aligned and mid-page starts, which
	 * changes how many pages the first iovec entry crosses. */
	switch (rnd_modulo_u32(4)) {
	case 0:  off = 0; break;
	case 1:  off = 1; break;
	case 2:  off = RDSZC_PAGE_BYTES / 2; break;
	default: off = RDSZC_PAGE_BYTES - 1U; break;
	}

	for (i = 0; i < nents; i++) {
		size_t base = ((size_t)i * RDSZC_PAGES / nents) * RDSZC_PAGE_BYTES;
		size_t len;

		/* Entry length: half a page, whole page, or one-and-a-half
		 * pages so the pin walk crosses page boundaries at varied
		 * counts.  Clamp so we do not run off the end of the region. */
		switch (rnd_modulo_u32(3)) {
		case 0:  len = RDSZC_PAGE_BYTES / 2; break;
		case 1:  len = RDSZC_PAGE_BYTES; break;
		default: len = RDSZC_PAGE_BYTES + RDSZC_PAGE_BYTES / 2; break;
		}
		if (i == 0)
			base += off;
		if (base >= it->region_len) {
			base = 0;
			len = RDSZC_PAGE_BYTES / 4;
		}
		if (base + len > it->region_len)
			len = it->region_len - base;
		iov[i].iov_base = (unsigned char *)it->region + base;
		iov[i].iov_len  = len;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port        = htons((uint16_t)(RDSZC_DST_PORT_MIN |
					       (rand32() & RDSZC_DST_PORT_MASK)));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name    = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_iov     = iov;
	msg.msg_iovlen  = nents;

	r = sendmsg(it->sfd, &msg, MSG_ZEROCOPY | MSG_DONTWAIT | MSG_NOSIGNAL);
	if (r >= 0) {
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_sends_ok,
				   1, __ATOMIC_RELAXED);
	} else if (errno == EFAULT) {
		/* The intended path: GUP hit the hole and unwound via
		 * put_page + rds_message_put page-list free. */
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_sends_efault,
				   1, __ATOMIC_RELAXED);
	} else {
		/* Any other errno (EAGAIN / EDESTADDRREQ / EHOSTUNREACH /
		 * EINVAL / EOPNOTSUPP) is coverage of a rejection edge -- the
		 * pin walk may or may not have run before the reject, but the
		 * counter bump keeps the outcome visible in post-mortem. */
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_sends_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Drain any zcopy completion notifications the kernel queued on
 * sk_error_queue.  Bounded by RDSZC_DRAIN_CAP so a stale-notif flood
 * cannot pin the outer loop past its wall cap.
 */
static void rds_zcopy_iter_drain_errqueue(struct rds_zcopy_iter_ctx *it)
{
	struct msghdr msg;
	struct iovec iov;
	unsigned char ctrl[256];
	unsigned char dummy[64];
	unsigned int i;

	for (i = 0; i < RDSZC_DRAIN_CAP; i++) {
		ssize_t r;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = dummy;
		iov.iov_len  = sizeof(dummy);
		msg.msg_iov  = &iov;
		msg.msg_iovlen    = 1;
		msg.msg_control    = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		r = recvmsg(it->sfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
		if (r < 0)
			break;
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_errqueue_drained,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown: munmap the surviving mapped pages of the backing region
 * (skipping the punched hole so we do not munmap unmapped virt) and
 * close the socket.  Each cleanup is gated so partial-setup bail
 * paths are safe.
 */
static void rds_zcopy_iter_teardown(struct rds_zcopy_iter_ctx *it)
{
	if (it->region != NULL && it->region != MAP_FAILED) {
		if (it->hole_addr != NULL) {
			/* Region was split into a leading run and a trailing
			 * run by the hole.  Unmap each half independently. */
			size_t lead_len = (size_t)it->hole_idx * RDSZC_PAGE_BYTES;
			size_t tail_off = lead_len + RDSZC_PAGE_BYTES;
			if (lead_len > 0)
				(void)munmap(it->region, lead_len);
			if (tail_off < it->region_len)
				(void)munmap((unsigned char *)it->region + tail_off,
					     it->region_len - tail_off);
		} else {
			(void)munmap(it->region, it->region_len);
		}
		it->region = NULL;
		it->region_len = 0;
		it->hole_addr = NULL;
	}
	if (it->sfd >= 0) {
		close(it->sfd);
		it->sfd = -1;
	}
}

/* One full sequence on a freshly-created AF_RDS socket. */
static void iter_one(const struct timespec *t_outer, struct childdata *child)
{
	struct rds_zcopy_iter_ctx it = {
		.sfd = -1,
		.region = NULL,
		.region_len = 0,
		.hole_addr = NULL,
		.hole_idx = 0,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if ((unsigned long long)ns_since(t_outer) >= RDSZC_WALL_CAP_NS)
		return;

	if (rds_zcopy_iter_open_sock(&it) != 0)
		return;

	if (rds_zcopy_iter_enable_zc(&it) != 0)
		goto out;

	if (rds_zcopy_iter_map_pages(&it) != 0)
		goto out;

	rds_zcopy_iter_punch_hole(&it);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	rds_zcopy_iter_send_faulting(&it);

	rds_zcopy_iter_drain_errqueue(&it);

out:
	rds_zcopy_iter_teardown(&it);
}

bool rds_zcopy_crafted_send(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_runs,
			   1, __ATOMIC_RELAXED);

	if (rds_unsupported) {
		__atomic_add_fetch(&shm->stats.rds_zcopy_crafted_send_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_RDS_ZCOPY_CRAFTED_SEND,
			       JITTER_RANGE(RDSZC_OUTER_BASE));
	if (outer_iters > RDSZC_OUTER_CAP)
		outer_iters = RDSZC_OUTER_CAP;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= RDSZC_WALL_CAP_NS)
			break;
		iter_one(&t_outer, child);
		if (rds_unsupported)
			break;
	}

	return true;
}

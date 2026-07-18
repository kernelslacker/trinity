/*
 * msg_zerocopy_churn - rotate a TCP socket through MSG_ZEROCOPY sendmsg +
 * error-queue notif drain + mid-flight page munmap.  Targets the
 * net/ipv4/tcp.c MSG_ZEROCOPY path, net/core/skbuff.c skb_zcopy_*
 * refcounting, and sock_zerocopy_alloc / __skb_complete_tx_timestamp
 * completion plumbing.
 *
 * Bug class: the user-visible MSG_ERRQUEUE "notif done" signal and the
 * kernel-internal "page done" signal racing against munmap while a TX skb
 * still pins the pages (vm_area teardown vs skb-side put_page); a follow-up
 * MSG_ZEROCOPY send at legal-address / illegal-mapping arithmetic (ubuf_info
 * install then get_user_pages EFAULT -- the rollback has to undo the
 * just-installed sk->sk_zckey/uarg); SO_ZEROCOPY=0 toggled while notifs are
 * pending; shutdown draining post-notif.  CVE anchors: CVE-2023-1281 (tcf
 * notif refct race), CVE-2024-26602 (zerocopy_fill_skb_from_iter underflow),
 * CVE-2024-35862 (skb_zerocopy_iter_stream missed bounds when iov shrank
 * -- munmap-mid-flight is the userspace shape).
 *
 * Per iteration (BUDGETED+JITTER, 200 ms wall cap): fresh TCP socket to a
 * one-shot accept-and-exit acceptor on 127.0.0.1, SO_ZEROCOPY=1,
 * SO_RCV/SNDTIMEO=100ms; mmap MAP_POPULATE|ANON|PRIVATE ~256 KiB (pages
 * physically present so the first send doesn't just demand-fault); inner
 * ZC-send loop (BUDGETED 4 / floor 8 / cap 16) sends MSG_ZEROCOPY |
 * MSG_DONTWAIT | MSG_NOSIGNAL, each enqueuing an SO_EE_ORIGIN_ZEROCOPY
 * notif; recvmsg MSG_ERRQUEUE drains + validates sock_extended_err shape;
 * munmap the range (THE RACE); re-send at the now-unmapped address (the
 * EFAULT-rollback edge); SO_ZEROCOPY=0 while notifs may still be pending;
 * shutdown/close.
 *
 * Brick-safety: every mutation on a fresh loopback TCP socket + one-shot
 * acceptor (nothing host-visible); bounded EAGAIN/EBUSY/ENOMEM retry (<=8)
 * so a persistently-blocked send never spins; acceptor WNOHANG-reaped then
 * SIGTERM if it overstays; the post-munmap re-send uses the saved address
 * but the kernel get_user_pages returns EFAULT before host state mutates
 * -- trinity itself never dereferences the unmapped range.
 *
 * Per-process cap-gate latch: ns_unsupported_msg_zerocopy on EOPNOTSUPP /
 * EPERM / ENOTSUPP from the first SO_ZEROCOPY=1 install; subsequent
 * invocations bump runs+setup_failed and return.
 *
 * Header gate: SO_EE_ORIGIN_ZEROCOPY lives in <linux/errqueue.h>; the
 * stable UAPI value (5) is the #define fallback.  MSG_ZEROCOPY /
 * SO_ZEROCOPY come from include/kernel/socket.h.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <linux/errqueue.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"
/* SO_EE_ORIGIN_ZEROCOPY lives in <linux/errqueue.h> on the kernel
 * side; some libc trees still don't surface it.  5 is the UAPI value
 * (matches include/uapi/linux/errqueue.h) and is stable across every
 * kernel that ships MSG_ZEROCOPY. */
#ifndef SO_EE_ORIGIN_ZEROCOPY
#define SO_EE_ORIGIN_ZEROCOPY	5
#endif

/* Per-process latched gate.  Capability / config / kernel-version
 * support for SO_ZEROCOPY is static across a child's lifetime; once
 * the install has paid the EFAIL we stop probing and short-circuit
 * to a runs+setup_failed bump.  Mirrors tcp_ulp_swap_churn /
 * tls_ulp_churn / netns_teardown_churn. */
static bool ns_unsupported_msg_zerocopy;

#define ZC_OUTER_BASE			4U
#define ZC_OUTER_CAP			16U
#define ZC_OUTER_FLOOR			8U
#define ZC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define ZC_RCV_TIMEO_MS			100
#define ZC_SND_TIMEO_MS			100
#define ZC_PAGE_BYTES			(256U * 1024U)
#define ZC_INNER_SENDS			6U
#define ZC_RETRY_CAP			8U
#define ZC_ERRQ_DRAIN_CAP		16U

/* Fork a one-shot loopback acceptor.  Parent gets the connected
 * client fd back; the child accept()s once, drains so the parent's
 * sends don't stall on receive-window watermarks, and exits.  Same
 * shape as the helper in tcp_ulp_swap_churn -- intentionally inlined
 * (different timeouts, different drain budget appropriate for the
 * larger ZC payload size). */
static int open_loopback_pair(pid_t *out_pid)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener;
	int cli = -1;
	int one = 1;
	struct timeval rcv_to, snd_to;
	pid_t pid;

	*out_pid = -1;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto fail;
	if (listen(listener, 1) < 0)
		goto fail;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto fail;

	pid = fork();
	if (pid < 0)
		goto fail;
	if (pid == 0) {
		/* Acceptor child: accept once, drain anything the parent
		 * pushes through the ZC path so the receive window stays
		 * open, then exit. */
		int s;
		unsigned char drain[8192];

		s = accept(listener, NULL, NULL);
		if (s >= 0) {
			ssize_t n;
			int loops = 64;

			while (loops-- > 0) {
				n = recv(s, drain, sizeof(drain),
					 MSG_DONTWAIT);
				if (n <= 0)
					break;
			}
			close(s);
		}
		close(listener);
		_exit(0);
	}

	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (cli < 0) {
		close(listener);
		goto reap;
	}

	rcv_to.tv_sec = 0;
	rcv_to.tv_usec = ZC_RCV_TIMEO_MS * 1000;
	(void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));
	snd_to.tv_sec = 0;
	snd_to.tv_usec = ZC_SND_TIMEO_MS * 1000;
	(void)setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));

	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS) {
		close(cli);
		cli = -1;
		close(listener);
		goto reap;
	}
	close(listener);

	*out_pid = pid;
	return cli;

reap:
	{
		int status;
		(void)kill(pid, SIGTERM);
		(void)waitpid_eintr(pid, &status, 0);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

/* Drain the sk_error_queue of MSG_ZEROCOPY completion notifications
 * via recvmsg(MSG_ERRQUEUE).  Validates the sock_extended_err shape
 * when a cmsg arrives (origin should be SO_EE_ORIGIN_ZEROCOPY for our
 * notifs).  Bumps the drained / empty counters so the post-mortem
 * tells us whether the kernel actually reached the completion path
 * for this kernel/config.  Bounded by ZC_ERRQ_DRAIN_CAP so a flood
 * of stale notifications can't pin the inner loop. */
static void drain_errqueue(int s)
{
	struct msghdr msg;
	struct iovec iov;
	unsigned char ctrl[CMSG_SPACE(sizeof(struct sock_extended_err)) * 4];
	unsigned char dummy[64];
	unsigned int i;
	bool any = false;

	for (i = 0; i < ZC_ERRQ_DRAIN_CAP; i++) {
		ssize_t r;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = dummy;
		iov.iov_len = sizeof(dummy);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		r = recvmsg(s, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
		if (r < 0)
			/* EAGAIN: queue empty.  Other errnos (EBADF /
			 * ENOTCONN / etc.) are terminal for this fd.
			 * Both outcomes -> bail. */
			break;

		any = true;
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.errqueue_drained,
				   1, __ATOMIC_RELAXED);

		/* Walk the cmsg chain and validate any IP_RECVERR /
		 * IPV6_RECVERR sock_extended_err with ee_origin set to
		 * the zerocopy origin.  Read-only; we touch the cmsg
		 * payload but never act on its contents -- the bug
		 * surface is that the cmsg arrives at all (and that the
		 * kernel built it without dereferencing freed pages),
		 * not what's in it. */
		{
			struct cmsghdr *cmh;

			for (cmh = CMSG_FIRSTHDR(&msg); cmh != NULL;
			     cmh = CMSG_NXTHDR(&msg, cmh)) {
				struct sock_extended_err see;

				if (cmh->cmsg_len <
				    CMSG_LEN(sizeof(see)))
					continue;
				memcpy(&see, CMSG_DATA(cmh), sizeof(see));
				/* No assertion: ee_origin may legitimately
				 * be SO_EE_ORIGIN_LOCAL for some kernels'
				 * synthetic completions; the read of the
				 * struct is the validation. */
				(void)see;
			}
		}
	}

	if (!any)
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.errqueue_empty,
				   1, __ATOMIC_RELAXED);
}

/* Send `len` bytes of `pages` with MSG_ZEROCOPY, retrying on
 * EAGAIN/EBUSY/ENOMEM up to ZC_RETRY_CAP times so a transiently-
 * blocked send doesn't escape the brick-safe envelope.  Returns the
 * final send() return value (>=0 on success, -1 with errno preserved
 * on terminal failure). */
static ssize_t zc_send_retry(int s, const void *pages, size_t len)
{
	ssize_t r = -1;
	unsigned int retries;

	for (retries = 0; retries < ZC_RETRY_CAP; retries++) {
		r = send(s, pages, len,
			 MSG_ZEROCOPY | MSG_DONTWAIT | MSG_NOSIGNAL);
		if (r >= 0)
			return r;
		if (errno != EAGAIN && errno != EBUSY && errno != ENOMEM)
			return r;
	}
	return r;
}

/*
 * Phase 1: enable SO_ZEROCOPY on the freshly-created client socket and
 * mmap the backing pages.  The setsockopt is the latch site -- on
 * EOPNOTSUPP / ENOPROTOOPT / EPERM the platform can't reach the
 * MSG_ZEROCOPY path at all and ns_unsupported_msg_zerocopy is set so
 * subsequent invocations short-circuit.  MAP_POPULATE + the memset
 * ensure the pages are physically present before the kernel tries to
 * pin them, otherwise the first send merely demand-faults and the
 * race window we want never opens.  Returns 0 on success with
 * *pages_out set; -1 on failure (counters bumped here).
 */
static int msg_zerocopy_iter_setup(int s, void **pages_out,
				   struct childdata *child)
{
	int one = 1;
	void *pages;

	if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) < 0) {
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
		    errno == EPERM) {
			ns_unsupported_msg_zerocopy = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	pages = mmap(NULL, ZC_PAGE_BYTES, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (pages == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* Touch the pages so MAP_POPULATE didn't silently no-op on a
	 * kernel that ignores the flag.  The write also makes the COW
	 * fault settle before the kernel pins. */
	memset(pages, 0xa5, ZC_PAGE_BYTES);

	*pages_out = pages;
	return 0;
}

/*
 * Phase 2: inner ZC-send loop.  Each successful send queues a
 * SO_EE_ORIGIN_ZEROCOPY notification on sk_error_queue once the kernel
 * is done with the pages.  Bounded by ZC_INNER_SENDS and the outer
 * wall-cap; bails early on EAGAIN (queue full) or a terminal errno.
 * Returns the count of successful sends -- the caller uses it to gate
 * the munmap-race step (no successful pin, no race to drive).
 */
static unsigned int msg_zerocopy_iter_send(int s, const void *pages,
					   const struct timespec *t_outer)
{
	unsigned int sent_count = 0;
	unsigned int i;

	for (i = 0; i < ZC_INNER_SENDS; i++) {
		ssize_t r;

		if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
			break;

		r = zc_send_retry(s, pages, ZC_PAGE_BYTES);
		if (r >= 0) {
			sent_count++;
			__atomic_add_fetch(
				&shm->stats.msg_zerocopy_churn.sends_ok,
				1, __ATOMIC_RELAXED);
		} else if (errno == EFAULT) {
			__atomic_add_fetch(
				&shm->stats.msg_zerocopy_churn.sends_efault,
				1, __ATOMIC_RELAXED);
		} else if (errno == EAGAIN) {
			__atomic_add_fetch(
				&shm->stats.msg_zerocopy_churn.sends_eagain,
				1, __ATOMIC_RELAXED);
			break;
		} else {
			/* Terminal errno (ENOTCONN / EPIPE etc.) -- bail. */
			break;
		}
	}

	return sent_count;
}

/*
 * Phase 3: munmap-race + resend-on-unmapped.  Gated on sent_count > 0
 * -- without a successful pin there's no skb chain to race against.
 * On success the munmap tears down the vma while the skb chain may
 * still pin the underlying pages; on a working kernel the skb-side
 * page reference keeps them alive until the destructor fires.  The
 * follow-up send targets the EFAULT bail in tcp_sendmsg_locked's
 * MSG_ZEROCOPY init (ubuf_info allocated then get_user_pages fails,
 * so the rollback path has to undo the just-installed
 * sk->sk_zckey/uarg state); EFAULT is the expected return and the
 * counted signal.  Sets *pages_inout to MAP_FAILED when the unmap
 * succeeds so the orchestrator out: cleanup doesn't double-unmap.
 */
static void msg_zerocopy_iter_unmap_resend(int s, void **pages_inout,
					   unsigned int sent_count)
{
	void *saved_pages = NULL;
	bool munmapped = false;
	int rc;

	if (sent_count > 0) {
		saved_pages = *pages_inout;
		if (munmap(*pages_inout, ZC_PAGE_BYTES) == 0) {
			munmapped = true;
			*pages_inout = MAP_FAILED;
			__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.munmap_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			saved_pages = NULL;
		}
	}

	if (munmapped && saved_pages != NULL) {
		rc = (int)send(s, saved_pages, ZC_PAGE_BYTES,
			       MSG_ZEROCOPY | MSG_DONTWAIT | MSG_NOSIGNAL);
		if (rc < 0 && errno == EFAULT)
			__atomic_add_fetch(
				&shm->stats.msg_zerocopy_churn.send_after_munmap_caught,
				1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 4: soft teardown of the per-iter zerocopy state -- toggle
 * SO_ZEROCOPY back off mid-flight (Step 8: disable-with-pending-notifs
 * is the historically fragile sk_zckey reset edge), drain anything
 * still queued so the close() doesn't have to walk a deep error queue
 * (and so the post-shutdown sk_error_queue purge path runs against a
 * clean queue at least sometimes), then shutdown(SHUT_RDWR) (Step 9:
 * forces tcp_close through tcp_disconnect, historically buggy against
 * pending zerocopy completions).  Best-effort throughout; the attempt
 * is the coverage.
 */
static void msg_zerocopy_iter_teardown(int s)
{
	int zero = 0;

	if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &zero, sizeof(zero)) == 0)
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.sndzc_disable_ok,
				   1, __ATOMIC_RELAXED);

	drain_errqueue(s);

	(void)shutdown(s, SHUT_RDWR);
}

/* One full sequence on a freshly-created loopback TCP socket. */
static void iter_one(const struct timespec *t_outer, struct childdata *child)
{
	pid_t acceptor = -1;
	int s = -1;
	void *pages = MAP_FAILED;
	unsigned int sent_count = 0;

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		return;

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (msg_zerocopy_iter_setup(s, &pages, child) != 0)
		goto out;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	sent_count = msg_zerocopy_iter_send(s, pages, t_outer);

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	/* Step 5: drain the error queue.  Validates sock_extended_err
	 * shape on each cmsg.  Whether anything actually arrives is
	 * timing-dependent (the completion notifications may not have
	 * reached the queue yet); both outcomes get counter coverage. */
	drain_errqueue(s);

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	msg_zerocopy_iter_unmap_resend(s, &pages, sent_count);

	msg_zerocopy_iter_teardown(s);

out:
	if (pages != MAP_FAILED)
		(void)munmap(pages, ZC_PAGE_BYTES);
	if (s >= 0)
		close(s);
	reap_acceptor(acceptor);
}

bool msg_zerocopy_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_msg_zerocopy) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_MSG_ZEROCOPY_CHURN,
			       JITTER_RANGE(ZC_OUTER_BASE));
	if (outer_iters < ZC_OUTER_FLOOR)
		outer_iters = ZC_OUTER_FLOOR;
	if (outer_iters > ZC_OUTER_CAP)
		outer_iters = ZC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    ZC_WALL_CAP_NS)
			break;
		iter_one(&t_outer, child);
		if (ns_unsupported_msg_zerocopy)
			break;
	}

	return true;
}

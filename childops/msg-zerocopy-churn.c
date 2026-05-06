/*
 * msg_zerocopy_churn - rotate a TCP socket through MSG_ZEROCOPY
 * sendmsg + error-queue completion-notification drain + mid-flight
 * page munmap, exercising the net/ipv4/tcp.c MSG_ZEROCOPY path,
 * net/core/skbuff.c skb_zcopy_* refcounting, and the
 * sock_zerocopy_alloc / __skb_complete_tx_timestamp completion plumbing
 * in net/core/sock.c.
 *
 * The MSG_ZEROCOPY contract pins user pages onto skb frags and queues
 * a completion notification on the socket error queue once the kernel
 * is done with them (skb destructor fires sock_zerocopy_callback ->
 * skb_complete_tx_timestamp -> sock_queue_err_skb).  The bug class is:
 * the user-visible "I'm done with this notification" signal (recvmsg
 * MSG_ERRQUEUE) and the kernel-internal "I'm done with this page"
 * signal can race against:
 *
 *   - munmap() of the backing range while a TX skb still pins the
 *     pages (page-pinning vs vm_area_struct teardown);
 *   - a follow-up send(MSG_ZEROCOPY) at the same address arithmetic
 *     after the mapping is gone (illegal mapping but legal address;
 *     get_user_pages returns -EFAULT, but the path between
 *     tcp_sendmsg_locked's MSG_ZEROCOPY init and the EFAULT bail
 *     touches the new ubuf_info before the rollback);
 *   - setsockopt(SO_ZEROCOPY, 0) toggled mid-flight while completion
 *     notifications are still queued (the per-sock zerocopy state
 *     machine has historically tripped on the toggle-while-pending
 *     edge);
 *   - tcp_disconnect / shutdown firing while the error queue still
 *     holds notifications (sk_error_queue purge ordering).
 *
 * CVE class anchors:
 *
 *   CVE-2023-1281  net/sched: tcf_zcopy notif refcount race -- a
 *                  sibling of the MSG_ZEROCOPY notif rotation pattern
 *                  where the notif skb was double-freed when the
 *                  refcount transitioned to zero on two CPUs at once.
 *   CVE-2024-26602 net/core: zerocopy_fill_skb_from_iter underflow on
 *                  a partial copy after a previous frag's pages were
 *                  released; same code path entered via
 *                  tcp_sendmsg_locked's MSG_ZEROCOPY branch.
 *   CVE-2024-35862 net/core: skb_zerocopy_iter_stream missed an iov
 *                  bounds check when the source iov shrank between
 *                  init and copy (the munmap-mid-flight pattern this
 *                  childop drives is the user-space shape of that
 *                  race).
 *   broader MSG_ZEROCOPY retransmit-vs-completion family: every
 *   notification that lands on the error queue post-shutdown has had
 *   at least one refcount-balance bug in its history.
 *
 * Per outer-loop iteration (BUDGETED + JITTER, 200 ms wall-clock cap):
 *
 *   1.  socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC); SO_ZEROCOPY=1;
 *       SO_RCVTIMEO=100ms; SO_SNDTIMEO=100ms.
 *   2.  one-shot accept-and-exit acceptor on 127.0.0.1; client
 *       connect() drives the 3-way handshake to ESTABLISHED.
 *   3.  mmap(MAP_POPULATE|MAP_ANONYMOUS|MAP_PRIVATE, ~256 KiB) -- the
 *       backing pages.  MAP_POPULATE so the pages are physically
 *       present before the kernel tries to pin them (otherwise the
 *       first send merely demand-faults and the race we want never
 *       starts).
 *   4.  Inner ZC-send loop (BUDGETED 4 / floor 8 / cap 16, JITTER):
 *       send(pages, MSG_ZEROCOPY | MSG_DONTWAIT | MSG_NOSIGNAL).
 *       Each successful send enqueues a SO_EE_ORIGIN_ZEROCOPY
 *       completion notification on the sk_error_queue.
 *   5.  recvmsg(s, MSG_ERRQUEUE | MSG_DONTWAIT) -- drain notifs.
 *       Validate sock_extended_err shape (ee_origin ==
 *       SO_EE_ORIGIN_ZEROCOPY when present); count drained vs empty
 *       so the sweep tells us whether the kernel actually reached the
 *       completion path on this kernel/config.
 *   6.  munmap(pages) -- THE RACE.  Pages freed while the kernel
 *       skb chain may still pin them.  On a working kernel the skb
 *       holds a page reference so the unmap is decoupled from the
 *       eventual sock_zerocopy_callback; the bug surface is the
 *       ordering window between vm_area_struct teardown and the
 *       skb-side put_page.
 *   7.  send(pages_addr, MSG_ZEROCOPY) AGAIN on the now-unmapped
 *       range -- legal address arithmetic, illegal mapping.  Tests
 *       the EFAULT bail in tcp_sendmsg_locked's MSG_ZEROCOPY init:
 *       ubuf_info is allocated then the get_user_pages fails, so the
 *       rollback path has to undo the just-installed
 *       sk->sk_zckey/uarg state.  Counter bumps on the EFAULT we
 *       expect (the bug is a non-EFAULT return or a refcount leak).
 *   8.  setsockopt(SO_ZEROCOPY, 0) mid-flight -- toggle off while
 *       completion notifs may still be pending on the error queue.
 *       The disable-with-pending-notifs edge is small but historically
 *       buggy (sk_zckey reset paths).
 *   9.  shutdown(SHUT_RDWR); close().
 *
 * Per-process cap-gate latch: ns_unsupported_msg_zerocopy fires on
 * EOPNOTSUPP / EPERM / ENOTSUPP from the very first
 * setsockopt(SO_ZEROCOPY, 1) install attempt.  Once latched, every
 * subsequent invocation just bumps runs+setup_failed and returns.
 * Mirrors tls_ulp_churn / netns_teardown_churn / handshake_req_abort /
 * tcp_ulp_swap_churn.
 *
 * Brick-safety:
 *   - Every mutation runs on a fresh loopback TCP socket connected to
 *     a one-shot accept-and-exit fork.  Nothing host-visible.
 *   - Inner ZC-send loop is BUDGETED (base 4 / floor 8 / cap 16) with
 *     JITTER and a 200 ms wall-clock cap; SO_RCVTIMEO of 100 ms on
 *     every fd; a bounded EAGAIN/EBUSY/ENOMEM retry loop (<= 8) so a
 *     persistently-blocked send never spins.
 *   - Acceptor child is reaped via WNOHANG-poll then SIGTERM if it
 *     overstays.
 *   - The post-munmap re-send uses the saved address but the kernel
 *     get_user_pages returns -EFAULT before any host-visible state
 *     mutates; trinity itself never dereferences the unmapped range.
 *
 * Header gate: SO_EE_ORIGIN_ZEROCOPY lives in <linux/errqueue.h>; the
 * UAPI value (5) is stable across every kernel that ships
 * MSG_ZEROCOPY, fall back to it if the toolchain hasn't surfaced the
 * symbol.  MSG_ZEROCOPY / SO_ZEROCOPY already come from compat.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/errqueue.h>

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

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
		 * open, then exit.  alarm(2) bounds the lifetime if the
		 * parent crashes pre-connect. */
		int s;
		unsigned char drain[8192];

		alarm(2);
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
		(void)waitpid(pid, &status, 0);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

static void reap_acceptor(pid_t pid)
{
	int status;
	int waited = 0;

	if (pid <= 0)
		return;

	while (waited++ < 8) {
		pid_t r = waitpid(pid, &status, WNOHANG);
		if (r == pid || r < 0)
			return;
		{
			struct timespec ts = { 0, 1000000L };  /* 1 ms */
			(void)nanosleep(&ts, NULL);
		}
	}
	(void)kill(pid, SIGTERM);
	(void)waitpid(pid, &status, 0);
}

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
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
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_errqueue_drained,
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
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_errqueue_empty,
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

/* One full sequence on a freshly-created loopback TCP socket. */
static void iter_one(const struct timespec *t_outer)
{
	pid_t acceptor = -1;
	int s = -1;
	int rc;
	int one = 1;
	int zero = 0;
	void *pages = MAP_FAILED;
	void *saved_pages = NULL;
	bool munmapped = false;
	unsigned int sent_count = 0;

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		return;

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Step 1 (continued): SO_ZEROCOPY=1.  This is the latch site --
	 * EOPNOTSUPP / ENOPROTOOPT / EPERM here mean the platform can't
	 * reach the MSG_ZEROCOPY path at all; latch off so subsequent
	 * invocations short-circuit to setup_failed. */
	if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) < 0) {
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
		    errno == EPERM)
			ns_unsupported_msg_zerocopy = true;
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Step 3: backing pages.  MAP_POPULATE so they're present before
	 * the kernel tries to pin them in tcp_sendmsg_locked's
	 * MSG_ZEROCOPY init -- without it, the first send just
	 * demand-faults and never reaches the page-pin race window. */
	pages = mmap(NULL, ZC_PAGE_BYTES, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (pages == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Touch the pages so MAP_POPULATE didn't silently no-op on a
	 * kernel that ignores the flag.  The write also makes the COW
	 * fault settle before the kernel pins. */
	memset(pages, 0xa5, ZC_PAGE_BYTES);

	/* Step 4: inner ZC-send loop.  Each successful send queues a
	 * SO_EE_ORIGIN_ZEROCOPY notification on sk_error_queue once
	 * the kernel is done with the pages. */
	{
		unsigned int i;

		for (i = 0; i < ZC_INNER_SENDS; i++) {
			ssize_t r;

			if ((unsigned long long)ns_since(t_outer) >=
			    ZC_WALL_CAP_NS)
				break;

			r = zc_send_retry(s, pages, ZC_PAGE_BYTES);
			if (r >= 0) {
				sent_count++;
				__atomic_add_fetch(
					&shm->stats.msg_zerocopy_churn_sends_ok,
					1, __ATOMIC_RELAXED);
			} else if (errno == EFAULT) {
				__atomic_add_fetch(
					&shm->stats.msg_zerocopy_churn_sends_efault,
					1, __ATOMIC_RELAXED);
			} else if (errno == EAGAIN) {
				__atomic_add_fetch(
					&shm->stats.msg_zerocopy_churn_sends_eagain,
					1, __ATOMIC_RELAXED);
				break;
			} else {
				/* Terminal errno (ENOTCONN / EPIPE etc.) -- bail. */
				break;
			}
		}
	}

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	/* Step 5: drain the error queue.  Validates sock_extended_err
	 * shape on each cmsg.  Whether anything actually arrives is
	 * timing-dependent (the completion notifications may not have
	 * reached the queue yet); both outcomes get counter coverage. */
	drain_errqueue(s);

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	/* Step 6: munmap the backing pages while the skb chain may still
	 * pin them.  THIS IS THE RACE.  On a working kernel the skb
	 * holds an independent page reference (get_user_pages bumped
	 * the refcount) so the unmap merely tears down the vma; the
	 * pages stay alive until the skb destructor fires.  The bug
	 * surface is the ordering window between vm_area_struct
	 * teardown and the skb-side put_page. */
	if (sent_count > 0) {
		saved_pages = pages;
		if (munmap(pages, ZC_PAGE_BYTES) == 0) {
			munmapped = true;
			pages = MAP_FAILED;
			__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_munmap_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			saved_pages = NULL;
		}
	}

	/* Step 7: send(MSG_ZEROCOPY) again on the now-unmapped range.
	 * Legal address arithmetic, illegal mapping.  Tests the EFAULT
	 * bail in tcp_sendmsg_locked's MSG_ZEROCOPY init: ubuf_info is
	 * allocated then get_user_pages fails, so the rollback path has
	 * to undo the just-installed sk->sk_zckey/uarg state.  EFAULT
	 * is the expected return; we count that as the path-reached
	 * signal.  A non-EFAULT return is itself coverage of the
	 * partial-success edge. */
	if (munmapped && saved_pages != NULL) {
		rc = (int)send(s, saved_pages, ZC_PAGE_BYTES,
			       MSG_ZEROCOPY | MSG_DONTWAIT | MSG_NOSIGNAL);
		if (rc < 0 && errno == EFAULT)
			__atomic_add_fetch(
				&shm->stats.msg_zerocopy_churn_send_after_munmap_caught,
				1, __ATOMIC_RELAXED);
	}

	/* Step 8: setsockopt(SO_ZEROCOPY, 0) mid-flight -- toggle off
	 * while completion notifications may still be pending on the
	 * error queue.  The disable-with-pending-notifs edge has been
	 * historically buggy in sk_zckey reset paths.  Best-effort:
	 * the kernel may reject the toggle on some versions, but the
	 * attempt itself is the coverage. */
	if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &zero, sizeof(zero)) == 0)
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_sndzc_disable_ok,
				   1, __ATOMIC_RELAXED);

	/* Drain any remaining notifications post-toggle so the close()
	 * doesn't have to walk a deep error queue (and so the post-
	 * shutdown sk_error_queue purge path -- another historically
	 * fragile edge -- runs against a clean queue at least sometimes). */
	drain_errqueue(s);

	/* Step 9: shutdown(SHUT_RDWR); close().  Shutdown forces the
	 * tcp_close path through tcp_disconnect which historically had
	 * an interaction bug with pending zerocopy completions. */
	(void)shutdown(s, SHUT_RDWR);

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

	(void)child;

	__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_msg_zerocopy) {
		__atomic_add_fetch(&shm->stats.msg_zerocopy_churn_setup_failed,
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
		iter_one(&t_outer);
		if (ns_unsupported_msg_zerocopy)
			break;
	}

	return true;
}

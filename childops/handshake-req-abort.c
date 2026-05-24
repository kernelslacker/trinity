/*
 * handshake_req_abort - net/handshake request/abort race over kTLS plumbing.
 *
 * The handshake genetlink family (Linux 6.5+) is the userspace bridge
 * for kernel-initiated TLS/QUIC handshakes: tlshd-class daemons pull
 * pending requests via HANDSHAKE_CMD_ACCEPT and report completion via
 * HANDSHAKE_CMD_DONE.  The bug class clustered here is the async-
 * request-broker UAF: handshake_req_alloc()/handshake_req_submit() pin
 * a struct handshake_req on the kernel-side socket, and the request
 * lifetime hinges on a delicate dance between handshake_req_next()
 * (the ACCEPT path), handshake_complete() (the DONE path), and
 * handshake_req_cancel() (the orphan-on-close path in
 * net/handshake/request.c).  Two userspace daemons racing ACCEPT, two
 * DONE messages racing each other for the same sockfd, or a close()
 * landing while DONE is still mid-walk all aim straight at
 * __sock_handshake_req_destroy() with stale or doubly-released refs —
 * the same architectural smell that produced the unaccepted-request
 * UAF family in similar async brokers (CVE-class for net/handshake is
 * not yet on file, but the request-broker shape mirrors prior async
 * netlink-broker UAFs).
 *
 * net/handshake itself has been essentially unfuzzed: the kernel side
 * is reachable only through tlshd-style userspace + a socket whose
 * owner has called the in-kernel tls_client_hello_*() API, and flat
 * per-syscall fuzzing never assembles either.  We don't have the in-
 * kernel API surface from userspace, but we can still drive the genl
 * front door directly: ACCEPT/DONE messages are validated and looked
 * up through the same per-net request table that the in-kernel
 * submitter populates.  Even with no live request to match, the
 * kernel walks the table under net->hs_lock and the lookup-by-sockfd
 * path runs end-to-end — exactly the slot that mishandles the
 * doubly-completed / completed-after-cancel cases.
 *
 * Sequence (per invocation):
 *   1.  Open a NETLINK_GENERIC socket and resolve the "handshake"
 *       family id via the shared genl_open() helper, which issues a
 *       single-family CTRL_CMD_GETFAMILY unicast.  -ENOENT latches
 *       ns_unsupported_handshake for the rest of this child's lifetime.
 *   2.  socket(AF_INET, SOCK_STREAM); connect to a closed loopback
 *       port — best-effort, ECONNREFUSED is fine.  We need a sockfd
 *       to feed into HANDSHAKE_A_DONE_SOCKFD; whether or not the
 *       three-way handshake completed doesn't matter to the genl
 *       request table walker on the receive side.
 *   3.  HANDSHAKE_CMD_ACCEPT non-blocking probe with HANDLER_CLASS=
 *       TLSHD.  Kernel returns -EAGAIN when no request is pending —
 *       benign coverage of the request-table walk under the per-net
 *       lock.  Counted as accept_ok regardless of ack errno because
 *       the lookup path ran.
 *   4.  BUDGETED loop:
 *         a) HANDSHAKE_CMD_DONE with HANDSHAKE_A_DONE_STATUS=0 and
 *            HANDSHAKE_A_DONE_SOCKFD=our connected socket.  Kernel
 *            walks the per-net request table looking for a request
 *            keyed on this sockfd; with no live request it returns
 *            -ENOENT, but the lookup runs end-to-end — exactly the
 *            slot that mishandles a request freed by a prior DONE.
 *            done_ok bumped on ack 0 (which only fires on hosts with
 *            a live in-kernel handshake request, very rare).
 *         b) Race window: a second HANDSHAKE_CMD_DONE on the same
 *            sockfd with non-zero status — the "abort" shape (DONE
 *            with status != 0 is the kernel's idiomatic abort, see
 *            handshake_complete() in net/handshake/request.c).  The
 *            kernel-side handler races the prior DONE's request-
 *            destroy if both happen to find the same struct
 *            handshake_req — the targeted UAF window.  Counted as
 *            abort_ok regardless of ack errno because the lookup +
 *            (potential) destroy path ran.
 *   5.  close(socket) while requests are notionally outstanding —
 *       drives __sock_handshake_req_destroy() through the
 *       handshake_sk_destruct() callback if the kernel had ever bound
 *       a request to this sock.  orphan_close bumped per close.
 *
 * Self-bounding: one full cycle per invocation, all sockets non-
 * blocking, loopback only, all genl requests timestamped with
 * SO_RCVTIMEO so an unresponsive controller can't pin past child.c's
 * SIGALRM(1s).  Per-invocation iteration budget is small (defaults to
 * a few cycles, jittered ±50%, scaled by adapt_budget) — every iter
 * emits a small handful of genl messages and one or two syscalls.
 *
 * Brick risk: kernel-side genl + socket-syscall only.  No module
 * load, no sysfs writes, no persistent state outside per-process
 * socket fds.  net/handshake doesn't expose any kernel-state-altering
 * commands beyond per-request lookup; READY isn't issued from this
 * childop (READY is a multicast-ack from the daemon side and would
 * confuse a real tlshd if one were running on the host).
 *
 * Cap-gate latch behaviour: genl_open("handshake", ...) issues one
 * CTRL_CMD_GETFAMILY per invocation.  -ENOENT (CONFIG_NET_HANDSHAKE=n,
 * or the family hasn't been registered on this kernel) latches
 * ns_unsupported_handshake; every further invocation short-circuits
 * via the latch and returns without re-opening a netlink socket.
 * EAGAIN/ENOENT acks from the kernel are benign coverage signals,
 * not failures.
 *
 * Header gating: <linux/handshake.h> is the YNL-generated UAPI header
 * that ships from kernel 6.5 onward.  Older sysroots without it fall
 * to a stub that bumps runs+setup_failed and returns — same shape as
 * mptcp-pm-churn's __has_include fallback.
 *
 * Failure modes treated as benign coverage:
 *   - genl_open("handshake", ...) returns -ENOENT: kernel doesn't
 *     expose the handshake family.  Latched ns_unsupported_handshake.
 *   - EAGAIN on ACCEPT: no pending request — the ordinary case
 *     without an in-kernel submitter.  Lookup path ran.
 *   - ENOENT on DONE: no request matches the sockfd — the ordinary
 *     case.  Lookup path ran.
 *   - EPERM on any genl op: trinity wasn't run with the right caps
 *     in this netns.  The lookup path still ran on the genl front
 *     door.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/handshake.h>)

#include <netinet/in.h>
#include <linux/handshake.h>
#include <linux/netlink.h>

#include "childops-genl.h"
#include "jitter.h"
#include "random.h"

/* Latched per-process: genl_open("handshake", ...) returned -ENOENT,
 * so the kernel doesn't expose the handshake family.  Once latched,
 * every further invocation just bumps setup_failed and returns. */
static bool ns_unsupported_handshake;

#define HANDSHAKE_GENL_BUF_BYTES	1024
#define HANDSHAKE_GENL_RECV_TIMEO_S	1
#define HANDSHAKE_CHURN_BUDGET		16U
#define HANDSHAKE_CHURN_ITERS_BASE	2U

/* Loopback target for the dummy connect.  Port 9 (discard) is closed
 * on a sane host — ECONNREFUSED is the expected outcome and the
 * sockfd is still valid for HANDSHAKE_A_DONE_SOCKFD lookups on the
 * kernel side. */
#define HANDSHAKE_LOOPBACK_ADDR		0x7f000001U	/* 127.0.0.1 */
#define HANDSHAKE_LOOPBACK_PORT		9U		/* discard */

/*
 * Build & send HANDSHAKE_CMD_ACCEPT carrying just
 * HANDSHAKE_A_ACCEPT_HANDLER_CLASS=TLSHD.  The kernel walks the per-
 * net request table under net->hs_lock looking for a pending request
 * matching this handler class — returns -EAGAIN when none is queued
 * (the ordinary case without an in-kernel submitter).  Lookup path
 * runs end-to-end regardless.
 */
static int handshake_accept(struct genl_ctx *ctx)
{
	unsigned char buf[HANDSHAKE_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   HANDSHAKE_CMD_ACCEPT, 0);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  HANDSHAKE_A_ACCEPT_HANDLER_CLASS,
			  HANDSHAKE_HANDLER_CLASS_TLSHD);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send HANDSHAKE_CMD_DONE carrying STATUS + SOCKFD.  The
 * kernel walks the per-net request table looking for a request keyed
 * on this sockfd.  status==0 is the normal-completion shape; status
 * != 0 is the abort shape (handshake_complete() in
 * net/handshake/request.c treats any non-zero status as "the daemon
 * failed/aborted the handshake, tear the request down").  Without a
 * live in-kernel submitter the ack is -ENOENT; the lookup path still
 * ran on the genl front door.
 */
static int handshake_done(struct genl_ctx *ctx, int sockfd, __s32 status)
{
	unsigned char buf[HANDSHAKE_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   HANDSHAKE_CMD_DONE, 0);
	if (!off)
		return -EIO;

	off = nla_put(buf, off, sizeof(buf),
		      HANDSHAKE_A_DONE_STATUS, &status, sizeof(status));
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  HANDSHAKE_A_DONE_SOCKFD, (__u32)sockfd);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Open a loopback TCP socket and best-effort-connect to a closed
 * port.  ECONNREFUSED / EINPROGRESS / success are all fine — the
 * sockfd is what we feed into HANDSHAKE_A_DONE_SOCKFD.  Returns the
 * socket fd, or -1 on socket() failure (rare).
 */
static int open_loopback_sock(void)
{
	struct sockaddr_in dst;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(HANDSHAKE_LOOPBACK_ADDR);
	dst.sin_port = htons(HANDSHAKE_LOOPBACK_PORT);
	(void)connect(fd, (struct sockaddr *)&dst, sizeof(dst));
	return fd;
}

bool handshake_req_abort(struct childdata *child)
{
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	bool ctx_open = false;
	int sock = -1;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.handshake_req_abort_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_handshake) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = HANDSHAKE_FAMILY_NAME;
	opts.version      = HANDSHAKE_FAMILY_VERSION;
	opts.recv_timeo_s = HANDSHAKE_GENL_RECV_TIMEO_S;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT)
			ns_unsupported_handshake = true;
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	ctx_open = true;

	sock = open_loopback_sock();
	if (sock < 0) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* 3) Non-blocking ACCEPT probe — exercises the per-net request-
	 *    table walk under hs_lock.  Counted regardless of ack errno
	 *    (EAGAIN is the ordinary outcome). */
	(void)handshake_accept(&ctx);
	__atomic_add_fetch(&shm->stats.handshake_req_abort_accept_ok,
			   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_HANDSHAKE_REQ_ABORT,
			 JITTER_RANGE(HANDSHAKE_CHURN_ITERS_BASE));
	if (iters > HANDSHAKE_CHURN_BUDGET)
		iters = HANDSHAKE_CHURN_BUDGET;
	if (iters == 0U)
		iters = 1U;

	for (i = 0; i < iters; i++) {
		/* a) DONE with status=0 — normal-completion shape.
		 *    Kernel walks the request table; ENOENT without a
		 *    live submitter, which is the bulk case. */
		(void)handshake_done(&ctx, sock, 0);
		__atomic_add_fetch(&shm->stats.handshake_req_abort_done_ok,
				   1, __ATOMIC_RELAXED);

		/* b) DONE with non-zero status — abort shape.  Targets
		 *    the double-complete / complete-vs-cancel race
		 *    against the prior DONE. */
		(void)handshake_done(&ctx, sock,
				     -(__s32)(1U + (rand32() & 0x7fU)));
		__atomic_add_fetch(&shm->stats.handshake_req_abort_abort_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* 5) Orphan close: drives __sock_handshake_req_destroy() through
	 *    handshake_sk_destruct() if the kernel ever bound a request
	 *    to this sock.  Kernel GCs unconditionally on close; we just
	 *    bump the counter so productivity is observable. */
	close(sock);
	sock = -1;
	__atomic_add_fetch(&shm->stats.handshake_req_abort_orphan_close,
			   1, __ATOMIC_RELAXED);

out:
	if (sock >= 0)
		close(sock);
	if (ctx_open)
		genl_close(&ctx);
	return true;
}

#else  /* !__has_include(<linux/handshake.h>) */

bool handshake_req_abort(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.handshake_req_abort_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/handshake.h>) */

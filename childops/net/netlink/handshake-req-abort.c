/*
 * handshake_req_abort - net/handshake request/abort race over kTLS
 * plumbing (kernel 6.5+ genl family for tlshd-class daemons).
 *
 * Target: net/handshake/request.c -- handshake_req_next (ACCEPT),
 * handshake_complete (DONE), handshake_req_cancel (orphan-on-close),
 * __sock_handshake_req_destroy.  Bug class: async-request-broker UAF
 * -- two daemons racing ACCEPT, two DONE messages on the same sockfd,
 * or a close() landing while DONE is mid-walk, all aim at
 * __sock_handshake_req_destroy with stale or doubly-released refs
 * (mirrors prior async netlink-broker UAF families).  Kernel side is
 * reachable only via tlshd + a socket whose owner called the in-kernel
 * tls_client_hello_*() API; flat syscall fuzzing assembles neither.
 * We drive the genl front door directly -- ACCEPT/DONE lookup walks
 * the per-net request table under net->hs_lock end-to-end even without
 * a live in-kernel submitter, exercising the doubly-completed /
 * completed-after-cancel slots.
 *
 * Per invocation: resolve the "handshake" genl family (CTRL_CMD_
 * GETFAMILY); AF_INET/SOCK_STREAM connect to a closed loopback port
 * (ECONNREFUSED fine -- we just need a sockfd for HANDSHAKE_A_DONE_
 * SOCKFD); non-blocking HANDSHAKE_CMD_ACCEPT probe with HANDLER_CLASS
 * =TLSHD (kernel returns -EAGAIN; lookup path ran); BUDGETED loop of
 * HANDSHAKE_CMD_DONE STATUS=0 followed by a second DONE with STATUS!=0
 * (the kernel's idiomatic abort) on the same sockfd -- races the
 * prior DONE's request-destroy; then close(socket) driving
 * __sock_handshake_req_destroy via handshake_sk_destruct.  READY is
 * intentionally never issued (it would confuse a real tlshd).
 *
 * Brick-safety: genl + socket-syscall only, no modules/sysfs/persistent
 * state; loopback only; sockets non-blocking; genl requests carry
 * SO_RCVTIMEO so an unresponsive controller stays inside child.c's
 * SIGALRM(1s).
 *
 * Latch: ns_unsupported_handshake fires on CTRL_CMD_GETFAMILY
 * -ENOENT (CONFIG_NET_HANDSHAKE absent).  Header-gated by
 * __has_include on <linux/handshake.h> (YNL-generated UAPI, 6.5+);
 * older sysroots fall to a stub that bumps runs+setup_failed.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/handshake.h>)

#include <netinet/in.h>
#include <linux/netlink.h>

#include "childops-genl.h"
#include "jitter.h"
#include "random.h"

#include "kernel/handshake.h"
#include "kernel/socket.h"
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

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.handshake_req_abort.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_handshake) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = HANDSHAKE_FAMILY_NAME;
	opts.version      = HANDSHAKE_FAMILY_VERSION;
	opts.recv_timeo_s = HANDSHAKE_GENL_RECV_TIMEO_S;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_handshake = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.handshake_req_abort.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	ctx_open = true;

	sock = open_loopback_sock();
	if (sock < 0) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* 3) Non-blocking ACCEPT probe — exercises the per-net request-
	 *    table walk under hs_lock.  Counted regardless of ack errno
	 *    (EAGAIN is the ordinary outcome). */
	(void)handshake_accept(&ctx);
	__atomic_add_fetch(&shm->stats.handshake_req_abort.accept_ok,
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
		__atomic_add_fetch(&shm->stats.handshake_req_abort.done_ok,
				   1, __ATOMIC_RELAXED);

		/* b) DONE with non-zero status — abort shape.  Targets
		 *    the double-complete / complete-vs-cancel race
		 *    against the prior DONE. */
		(void)handshake_done(&ctx, sock,
				     -(__s32)(1U + (rand32() & 0x7fU)));
		__atomic_add_fetch(&shm->stats.handshake_req_abort.abort_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* 5) Orphan close: drives __sock_handshake_req_destroy() through
	 *    handshake_sk_destruct() if the kernel ever bound a request
	 *    to this sock.  Kernel GCs unconditionally on close; we just
	 *    bump the counter so productivity is observable. */
	close(sock);
	sock = -1;
	__atomic_add_fetch(&shm->stats.handshake_req_abort.orphan_close,
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
	__atomic_add_fetch(&shm->stats.handshake_req_abort.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.handshake_req_abort.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/handshake.h>) */

/*
 * iouring-recipes-net -- socket / connect / accept / sendmsg / recvmsg
 * / bind / listen / shutdown recipe family for the iouring-recipes
 * catalogue.
 *
 * See childops/io_uring/recipes.c for the dispatcher and the shared
 * pool-race fault handler; see iouring-recipes-internal.h for the
 * cross-TU symbol boundary.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/io_uring.h>
#include <string.h>
#include <unistd.h>

#include "errno-classify.h"
#include "shm.h"
#include "stats.h"
#include "syscall-gate.h"
#include "trinity.h"

#include "childops/io_uring/recipes-internal.h"

#include "kernel/io_uring.h"
#include "kernel/socket.h"
/* ------------------------------------------------------------------ *
 * Recipe 4: SEND + RECV over a socketpair with linked SQEs
 *
 * Create a UNIX socketpair, link a SEND into a RECV.  IOSQE_IO_LINK
 * on the SEND means the RECV only starts when SEND completes — this
 * walks the linked-request dispatch and the UNIX socket I/O path
 * within a single submission batch.
 * ------------------------------------------------------------------ */
bool recipe_send_recv_linked(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	char buf[32];
	bool ok = false;
	int r;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, s->sock) < 0)
		goto out;

	memset(buf, 's', sizeof(buf));

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_SEND;
	sqes[0].fd        = s->sock[0];
	sqes[0].addr      = (__u64)(uintptr_t)buf;
	sqes[0].len       = sizeof(buf);
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 30;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_RECV;
	sqes[1].fd        = s->sock[1];
	sqes[1].addr      = (__u64)(uintptr_t)buf;
	sqes[1].len       = sizeof(buf);
	sqes[1].user_data = 31;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 2);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 6: SOCKET + SHUTDOWN in linked SQEs
 *
 * IORING_OP_SOCKET creates a TCP socket through the ring.  Linking a
 * SHUTDOWN on fd=-1 (placeholder — result fd not wired up at submission
 * time) exercises the linked-request setup/teardown and the SHUTDOWN
 * opcode path.
 * ------------------------------------------------------------------ */
bool recipe_socket_shutdown_linked(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_SOCKET;
	sqes[0].fd        = AF_INET;
	sqes[0].off       = SOCK_STREAM;
	sqes[0].user_data = IOUR_UD_SOCKET_LINK_SOCK;
	sqes[0].flags     = IOSQE_IO_LINK;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_SHUTDOWN;
	sqes[1].fd        = -1;
	sqes[1].len       = SHUT_RDWR;
	sqes[1].user_data = IOUR_UD_SOCKET_LINK_SHUT;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}

	iour_drain_cqes_close_fd(ctx, IOUR_UD_SOCKET_LINK_SOCK);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SENDMSG over socketpair
 * ------------------------------------------------------------------ */
bool recipe_sendmsg(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct msghdr msg;
	struct iovec iov;
	char buf[32];
	int r;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, s->sock) < 0)
		return false;

	memset(buf, 'm', sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_SENDMSG;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&msg;
	sqe.msg_flags = MSG_DONTWAIT;
	sqe.user_data = 200;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: RECVMSG over socketpair (with primer write)
 * ------------------------------------------------------------------ */
bool recipe_recvmsg(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct msghdr msg;
	struct iovec iov;
	char buf[32];
	int r;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, s->sock) < 0)
		return false;

	{
		const char primer[] = "recvmsg";
		ssize_t w __unused__ = write(s->sock[0], primer, sizeof(primer));
	}

	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_RECVMSG;
	sqe.fd        = s->sock[1];
	sqe.addr      = (__u64)(uintptr_t)&msg;
	sqe.msg_flags = MSG_DONTWAIT;
	sqe.user_data = 210;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: ACCEPT on a non-listening socketpair endpoint
 *
 * The socketpair fd isn't a listener, so ops->accept() returns
 * synchronously — the io_uring accept prep + issue dispatch still runs.
 * ------------------------------------------------------------------ */
bool recipe_accept(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int r;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, s->sock) < 0)
		return false;

	memset(&ss, 0, sizeof(ss));

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_ACCEPT;
	sqe.fd           = s->sock[0];
	sqe.addr         = (__u64)(uintptr_t)&ss;
	sqe.addr2        = (__u64)(uintptr_t)&slen;
	sqe.accept_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	sqe.user_data    = IOUR_UD_ACCEPT;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes_close_fd(ctx, IOUR_UD_ACCEPT);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: CONNECT to 127.0.0.1:1 (likely ECONNREFUSED)
 * ------------------------------------------------------------------ */
bool recipe_connect(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			    0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(1);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_CONNECT;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&sin;
	sqe.off       = sizeof(sin);
	sqe.user_data = 230;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: BIND to a fresh AF_INET ephemeral port
 *
 * The kernel reads sockaddr length from sqe->addr_len (the u16 sharing
 * the splice_fd_in union) for IORING_OP_BIND.  Port 0 → kernel auto-
 * assigns; loopback is universally available.
 * ------------------------------------------------------------------ */
#ifndef TRINITY_COMPAT_BACKFILLED_BIND
bool recipe_bind(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_BIND;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&sin;
	sqe.addr_len  = sizeof(sin);
	sqe.user_data = 240;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}
	iour_drain_cqes(ctx);
	return true;
}
#endif /* TRINITY_COMPAT_BACKFILLED_BIND */

/* ------------------------------------------------------------------ *
 * Recipe: LISTEN on a freshly-bound TCP socket
 * ------------------------------------------------------------------ */
bool recipe_listen(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s->sock[0], (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_LISTEN;
	sqe.fd        = s->sock[0];
	sqe.len       = 8;
	sqe.user_data = 250;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}
	iour_drain_cqes(ctx);
	return true;
}

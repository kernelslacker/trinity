/*
 * iouring_send_zc_churn - rotate a registered-buffer io_uring through
 * IORING_OP_SEND_ZC and IORING_OP_SENDMSG_ZC submissions while racing
 * IORING_UNREGISTER_BUFFERS and IORING_REGISTER_BUFFERS_UPDATE against
 * the in-flight notif slot.
 *
 * The io_uring zerocopy send contract pins user-visible buffers (either
 * fixed via IORING_REGISTER_BUFFERS or one-shot via the SQE) and emits
 * a per-send notification CQE once the kernel has released its hold on
 * the backing pages -- structurally similar to MSG_ZEROCOPY's
 * sk_error_queue notif but routed through the ring's own completion
 * queue and tied to an io_uring rsrc_node refcount on the registered
 * buffer table.  The bug class this childop drives is the rsrc_node
 * lifetime racing the notif:
 *
 *   - IORING_UNREGISTER_BUFFERS while a SEND_ZC notif still holds a
 *     reference to the imu_index it just allocated against (the
 *     historic UAF surface: the rsrc_node freed before the notif's
 *     io_rsrc_node_charge_node ref was decremented);
 *   - IORING_REGISTER_BUFFERS_UPDATE replacing the slot the SEND_ZC
 *     SQE just queued against (the imu_index race: the new io_mapped_ubuf
 *     installed under the same slot before the in-flight notif latched
 *     onto the old one);
 *   - the broader io_send_zc_finish family of retransmit-vs-free bugs,
 *     where an SQE's deferred notif posting collides with a follow-up
 *     SQE that recycles the same fixed-buffer slot.
 *
 * Per outer-loop iteration (BUDGETED + JITTER, 200 ms wall-clock cap):
 *
 *   1.  io_uring_setup(8, &p) with IORING_SETUP_SINGLE_ISSUER |
 *       IORING_SETUP_DEFER_TASKRUN -- the strictest submission contract,
 *       which is also the path the rsrc_node refcounting was hardened
 *       against most recently.  EINVAL on older kernels falls back to
 *       a no-flags retry so the rest of the sequence still runs.
 *   2.  mmap the SQ ring, CQ ring (or single-mmap alias), and SQE array
 *       inline (no liburing).
 *   3.  mmap 8 x 4 KiB anonymous pages and IORING_REGISTER_BUFFERS them
 *       as iov[8].  Each becomes an io_mapped_ubuf in the ring's
 *       fixed-buffer table indexed 0..7 -- the buf_index pool the
 *       SEND_ZC SQEs will reference.
 *   4.  socket(AF_INET, SOCK_STREAM); SO_RCVTIMEO=100ms; SO_SNDTIMEO=100ms;
 *       SO_ZEROCOPY=1; connect(127.0.0.1) to a one-shot accept-and-exit
 *       acceptor fork.
 *   5.  Inner SEND_ZC loop (BUDGETED 4 / floor 8 / cap 16, JITTER):
 *         a. SQE: IORING_OP_SEND_ZC referring buf_index = i % 8.  Sets
 *            IORING_RECVSEND_FIXED_BUF so the kernel resolves the buffer
 *            via the registered table (the rsrc_node ref path) rather
 *            than walking msg_iov.  msg.msg_iov picks 1 + rand() % 4
 *            iovs from the buffer pool.
 *         b. SQE: IORING_OP_SENDMSG_ZC pointing at a 1..4-iov msghdr
 *            assembled from the same buffer pool (the multi-iov variant
 *            also walks the rsrc_node table per iov).
 *   6.  RACE A: IORING_UNREGISTER_BUFFERS issued mid-flight, while a
 *       SEND_ZC notif may still reference an imu_index.  On a fixed
 *       kernel the notif's rsrc_node ref keeps the table alive past
 *       the unregister; the bug surface is the ordering window between
 *       the rsrc_node refcount drop and the notif's deferred lookup.
 *   7.  RACE B: IORING_REGISTER_BUFFERS_UPDATE replacing slot 0 with a
 *       freshly-mmap'd page.  An in-flight SEND_ZC SQE that latched
 *       onto the old io_mapped_ubuf must continue to resolve to it
 *       (refcounted), not be redirected to the new page mid-send.
 *   8.  io_uring_enter(SQ submit, min_complete = N) drives the ring
 *       through the rsrc_node release / notif posting paths and reaps
 *       both the send-completion CQEs and the deferred ZC notif CQEs.
 *   9.  munmap pages; close socket; close ring fd; reap acceptor.
 *
 * Per-process cap-gate latch: ns_unsupported_iouring_send_zc_churn fires
 * on ENOSYS / EPERM / ENOMEM / EINVAL from the very first
 * io_uring_setup() probe.  Once latched, every subsequent invocation
 * just bumps runs+setup_failed and returns.  Mirrors the latch shape in
 * msg_zerocopy_churn / tcp_ulp_swap_churn / handshake_req_abort.
 *
 * Brick-safety:
 *   - Every mutation runs on a fresh loopback TCP socket connected to a
 *     one-shot accept-and-exit fork.  Nothing host-visible.
 *   - Inner SEND_ZC loop is BUDGETED (base 4 / floor 8 / cap 16) with
 *     JITTER and a 200 ms wall-clock cap; SO_RCVTIMEO / SO_SNDTIMEO of
 *     100 ms on every fd; the io_uring_enter min_complete is bounded
 *     by what we submitted, so a stuck completion can't hang the loop.
 *   - Acceptor child is reaped via WNOHANG-poll then SIGTERM if it
 *     overstays.
 *   - The registered-buffer pool is exactly 8 x 4 KiB pages (32 KiB
 *     total), allocated and freed per iteration; no shared mappings.
 *
 * Header gate: __has_include(<linux/io_uring.h>) -- without it the
 * compile is skipped (translation unit produces no symbols, the dispatch
 * table entry stays a forward-declared NULL no-op via the dormant slot).
 * Opcode constants are read from the kernel uapi header; the ones this
 * childop names (IORING_OP_SEND_ZC, IORING_OP_SENDMSG_ZC,
 * IORING_REGISTER_BUFFERS, IORING_UNREGISTER_BUFFERS,
 * IORING_REGISTER_BUFFERS_UPDATE, IORING_SETUP_SINGLE_ISSUER,
 * IORING_SETUP_DEFER_TASKRUN, IORING_RECVSEND_FIXED_BUF) are all
 * upstream as of the 6.x line; missing-symbol fallbacks #define them to
 * the stable UAPI integer values so older toolchains still compile (the
 * runtime io_uring_setup / io_uring_register calls return EINVAL on
 * kernels that don't recognise them, and the cap-gate latches).
 */

#if __has_include(<linux/io_uring.h>)

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/io_uring.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

/* Opcodes / register-op codes / setup flags introduced over the 6.x
 * series.  All have stable upstream UAPI integer values; the fallbacks
 * are only used when the toolchain header predates them, in which case
 * the kernel will return EINVAL at runtime and the cap-gate latches. */
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER	(1U << 12)
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN	(1U << 13)
#endif
#ifndef IORING_RECVSEND_FIXED_BUF
#define IORING_RECVSEND_FIXED_BUF	(1U << 0)
#endif

/* Per-process latched gate.  io_uring_setup() returning ENOSYS / EPERM
 * (sysctl-disabled) / EINVAL (flag combo not recognised) / ENOMEM
 * (allocator pressure that won't clear) is static for this child's
 * lifetime; further attempts are pure overhead. */
static bool ns_unsupported_iouring_send_zc_churn;

#define ZC_OUTER_BASE			4U
#define ZC_OUTER_CAP			16U
#define ZC_OUTER_FLOOR			8U
#define ZC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define ZC_RCV_TIMEO_MS			100
#define ZC_SND_TIMEO_MS			100
#define ZC_RING_ENTRIES			8U
#define ZC_BUF_COUNT			8U
#define ZC_BUF_BYTES			4096U

struct ring_ctx {
	int		fd;
	void		*sq_ring;
	void		*cq_ring;	/* aliases sq_ring when SINGLE_MMAP */
	void		*sqes;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;	/* 0 when SINGLE_MMAP */
	size_t		sqes_sz;
	bool		single_mmap;

	unsigned int	sq_entries;

	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

	unsigned int	cq_off_head;
	unsigned int	cq_off_tail;
	unsigned int	cq_off_mask;
	unsigned int	cq_off_cqes;
};

static inline unsigned int ring_u32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void ring_store_u32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}

static int do_setup(struct io_uring_params *p, unsigned int entries)
{
	return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int do_register(int fd, unsigned int op, void *arg, unsigned int nr)
{
	return (int)syscall(__NR_io_uring_register, fd, op, arg, nr);
}

static int do_enter(int fd, unsigned int to_submit, unsigned int min_complete,
		    unsigned int flags)
{
	return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
			    flags, NULL, 0);
}

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static bool ring_setup(struct ring_ctx *ctx)
{
	struct io_uring_params p;
	size_t sq_sz, cq_sz, sqes_sz;
	void *sq_ring, *cq_ring, *sqes;
	int fd;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

	fd = do_setup(&p, ZC_RING_ENTRIES);
	if (fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		/* Older kernel without DEFER_TASKRUN/SINGLE_ISSUER -- retry
		 * with no flags so the SEND_ZC path still gets exercised on
		 * pre-6.1 kernels that have the opcode but not the strict
		 * submission contract. */
		memset(&p, 0, sizeof(p));
		fd = do_setup(&p, ZC_RING_ENTRIES);
	}
	if (fd < 0)
		return false;

	sq_sz   = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(unsigned int);
	cq_sz   = (size_t)p.cq_off.cqes  + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	sqes_sz = (size_t)p.sq_entries   * sizeof(struct io_uring_sqe);

	sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED) {
		close(fd);
		return false;
	}

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ring = sq_ring;
		ctx->single_mmap = true;
	} else {
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE,
			       fd, IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED) {
			munmap(sq_ring, sq_sz);
			close(fd);
			return false;
		}
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		if (!ctx->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, sq_sz);
		close(fd);
		return false;
	}

	ctx->fd          = fd;
	ctx->sq_ring     = sq_ring;
	ctx->sq_ring_sz  = sq_sz;
	ctx->cq_ring     = cq_ring;
	ctx->cq_ring_sz  = ctx->single_mmap ? 0 : cq_sz;
	ctx->sqes        = sqes;
	ctx->sqes_sz     = sqes_sz;
	ctx->sq_entries  = p.sq_entries;

	ctx->sq_off_head  = p.sq_off.head;
	ctx->sq_off_tail  = p.sq_off.tail;
	ctx->sq_off_mask  = p.sq_off.ring_mask;
	ctx->sq_off_array = p.sq_off.array;

	ctx->cq_off_head  = p.cq_off.head;
	ctx->cq_off_tail  = p.cq_off.tail;
	ctx->cq_off_mask  = p.cq_off.ring_mask;
	ctx->cq_off_cqes  = p.cq_off.cqes;

	return true;
}

static void ring_teardown(struct ring_ctx *ctx)
{
	if (ctx->sqes)
		munmap(ctx->sqes, ctx->sqes_sz);
	if (ctx->cq_ring && !ctx->single_mmap)
		munmap(ctx->cq_ring, ctx->cq_ring_sz);
	if (ctx->sq_ring)
		munmap(ctx->sq_ring, ctx->sq_ring_sz);
	if (ctx->fd >= 0)
		close(ctx->fd);
}

static unsigned int submit_one(struct ring_ctx *ctx,
			       const struct io_uring_sqe *src)
{
	unsigned int mask  = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	unsigned int head  = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	unsigned int tail  = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	unsigned int avail = ctx->sq_entries - (tail - head);
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int slot;

	if (avail == 0)
		return 0;

	slot = tail & mask;
	sqes[slot] = *src;
	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);
	sq_array[slot] = slot;

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + 1);
	return 1;
}

static unsigned int drain_cqes(struct ring_ctx *ctx)
{
	unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	unsigned int reaped = 0;
	struct io_uring_cqe *cqes;

	cqes = (struct io_uring_cqe *)((char *)ctx->cq_ring + ctx->cq_off_cqes);
	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		(void)cqes[head & mask];
		head++;
		reaped++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
	return reaped;
}

/* Fork a one-shot loopback acceptor.  Same shape as msg_zerocopy_churn's
 * helper -- intentionally inlined (different drain budget appropriate
 * for the registered-buffer payload size and the smaller ZC ring). */
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
		int s;
		unsigned char drain[4096];

		alarm(2);
		s = accept(listener, NULL, NULL);
		if (s >= 0) {
			ssize_t n;
			int loops = 32;

			while (loops-- > 0) {
				n = recv(s, drain, sizeof(drain), MSG_DONTWAIT);
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

/* Fill an SEND_ZC SQE referencing a registered buffer slot.  The kernel
 * resolves the buffer through the rsrc_node table when
 * IORING_RECVSEND_FIXED_BUF is set in ioprio (the documented carrier
 * for the fixed-buf bit on SEND_ZC). */
static void fill_send_zc(struct io_uring_sqe *s, int sock_fd,
			 void *buf, size_t len, unsigned int buf_index)
{
	memset(s, 0, sizeof(*s));
	s->opcode    = IORING_OP_SEND_ZC;
	s->fd        = sock_fd;
	s->addr      = (uint64_t)(uintptr_t)buf;
	s->len       = (unsigned int)len;
	s->ioprio    = IORING_RECVSEND_FIXED_BUF;
	s->buf_index = (uint16_t)buf_index;
	s->user_data = 0xCA110000ULL | buf_index;
}

/* Fill a SENDMSG_ZC SQE pointing at a caller-prepared msghdr.  The
 * msg_iov entries each pick from the registered-buffer pool, so the
 * kernel walks the rsrc_node table once per iov on the multi-iov path. */
static void fill_sendmsg_zc(struct io_uring_sqe *s, int sock_fd,
			    const struct msghdr *msg, unsigned int buf_index)
{
	memset(s, 0, sizeof(*s));
	s->opcode    = IORING_OP_SENDMSG_ZC;
	s->fd        = sock_fd;
	s->addr      = (uint64_t)(uintptr_t)msg;
	s->len       = 1;
	s->buf_index = (uint16_t)buf_index;
	s->user_data = 0xCB110000ULL | buf_index;
}

/* One full sequence on a freshly-created ring + loopback TCP socket. */
static void iter_one(const struct timespec *t_outer)
{
	struct ring_ctx ctx;
	struct iovec bufs[ZC_BUF_COUNT];
	void *pages[ZC_BUF_COUNT];
	void *replacement = MAP_FAILED;
	struct iovec replacement_iov;
	pid_t acceptor = -1;
	int sock_fd = -1;
	int one = 1;
	unsigned int i;
	bool ring_ok = false;
	bool bufs_registered = false;
	unsigned int submitted = 0;

	for (i = 0; i < ZC_BUF_COUNT; i++)
		pages[i] = MAP_FAILED;

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		return;

	if (!ring_setup(&ctx)) {
		if (errno == ENOSYS || errno == EPERM ||
		    errno == ENOMEM || errno == EINVAL)
			ns_unsupported_iouring_send_zc_churn = true;
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	ring_ok = true;

	for (i = 0; i < ZC_BUF_COUNT; i++) {
		pages[i] = mmap(NULL, ZC_BUF_BYTES, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
				-1, 0);
		if (pages[i] == MAP_FAILED) {
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		memset(pages[i], 0xa5 ^ (int)i, ZC_BUF_BYTES);
		bufs[i].iov_base = pages[i];
		bufs[i].iov_len  = ZC_BUF_BYTES;
	}

	if (do_register(ctx.fd, IORING_REGISTER_BUFFERS, bufs, ZC_BUF_COUNT) < 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	bufs_registered = true;
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_register_bufs_ok,
			   1, __ATOMIC_RELAXED);

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	sock_fd = open_loopback_pair(&acceptor);
	if (sock_fd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* SO_ZEROCOPY enables the kernel-side ZC path the SEND_ZC SQE
	 * targets.  EOPNOTSUPP / EPERM here latches the cap-gate -- the
	 * platform can't reach the path at all. */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) < 0) {
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
		    errno == EPERM)
			ns_unsupported_iouring_send_zc_churn = true;
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* SEND_ZC SQE referring buf_index 0..7 (rotating).  Send length is
	 * clamped to ZC_BUF_BYTES so we never trip the kernel's per-buffer
	 * bounds check on the iovec. */
	{
		struct io_uring_sqe sqe;
		unsigned int idx = (unsigned int)rand() % ZC_BUF_COUNT;
		size_t send_len = (size_t)(1 + (rand() % (int)ZC_BUF_BYTES));

		fill_send_zc(&sqe, sock_fd, pages[idx], send_len, idx);
		if (submit_one(&ctx, &sqe) == 1) {
			submitted++;
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_send_zc_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* SENDMSG_ZC variant -- 1..4 iovs from the registered pool, each
	 * iov pointing into a different buffer slot so the multi-iov walk
	 * touches multiple rsrc_node entries. */
	{
		struct io_uring_sqe sqe;
		struct msghdr msg;
		struct iovec local_iov[4];
		unsigned int n_iov = 1 + ((unsigned int)rand() % 4U);
		unsigned int j;
		unsigned int buf_index = (unsigned int)rand() % ZC_BUF_COUNT;

		if (n_iov > 4)
			n_iov = 4;
		for (j = 0; j < n_iov; j++) {
			unsigned int slot = (buf_index + j) % ZC_BUF_COUNT;
			size_t len = (size_t)(1 + (rand() % (int)ZC_BUF_BYTES));

			local_iov[j].iov_base = pages[slot];
			local_iov[j].iov_len  = len;
		}
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov    = local_iov;
		msg.msg_iovlen = n_iov;

		fill_sendmsg_zc(&sqe, sock_fd, &msg, buf_index);
		if (submit_one(&ctx, &sqe) == 1) {
			submitted++;
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_sendmsg_zc_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	/* RACE B: BUFFERS_UPDATE replacing slot 0 with a freshly-mmap'd
	 * page.  Issued before the io_uring_enter so the in-flight SQEs
	 * have already latched onto the original io_mapped_ubuf -- the
	 * update should refcount-protect the in-flight reference, not
	 * redirect it. */
	replacement = mmap(NULL, ZC_BUF_BYTES, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (replacement != MAP_FAILED) {
		struct io_uring_rsrc_update2 upd;

		memset(replacement, 0x5a, ZC_BUF_BYTES);
		replacement_iov.iov_base = replacement;
		replacement_iov.iov_len  = ZC_BUF_BYTES;

		memset(&upd, 0, sizeof(upd));
		upd.offset = 0;
		upd.data   = (uint64_t)(uintptr_t)&replacement_iov;
		upd.nr     = 1;

		if (do_register(ctx.fd, IORING_REGISTER_BUFFERS_UPDATE,
				&upd, sizeof(upd)) >= 0)
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_update_race_ok,
					   1, __ATOMIC_RELAXED);
	}

	/* Drive the ring through submission + completion.  min_complete is
	 * bounded by what we actually queued so a stuck completion can't
	 * hang the loop; the deferred ZC notifs will land on a subsequent
	 * drain pass after IORING_UNREGISTER_BUFFERS releases the rsrc_node
	 * (or, on a buggy kernel, before -- which is the surface we want). */
	{
		int r;
		unsigned int reaped;

		r = do_enter(ctx.fd, submitted, submitted,
			     IORING_ENTER_GETEVENTS);
		if (r >= 0) {
			reaped = drain_cqes(&ctx);
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_cqe_drained,
					   (unsigned long)reaped,
					   __ATOMIC_RELAXED);
		}
	}

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	/* RACE A: UNREGISTER_BUFFERS while a SEND_ZC notif may still
	 * reference an imu_index.  On a fixed kernel the notif's rsrc_node
	 * ref keeps the table alive past the unregister; the bug surface
	 * is the ordering window between the rsrc_node refcount drop and
	 * the notif's deferred lookup. */
	if (do_register(ctx.fd, IORING_UNREGISTER_BUFFERS, NULL, 0) >= 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_unregister_race_ok,
				   1, __ATOMIC_RELAXED);
		bufs_registered = false;
	}

	/* Final drain to harvest any deferred notif CQEs that landed
	 * after the unregister. */
	{
		unsigned int reaped = drain_cqes(&ctx);

		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_cqe_drained,
				   (unsigned long)reaped, __ATOMIC_RELAXED);
	}

out:
	if (bufs_registered)
		(void)do_register(ctx.fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (replacement != MAP_FAILED)
		(void)munmap(replacement, ZC_BUF_BYTES);
	for (i = 0; i < ZC_BUF_COUNT; i++) {
		if (pages[i] != MAP_FAILED)
			(void)munmap(pages[i], ZC_BUF_BYTES);
	}
	if (sock_fd >= 0)
		close(sock_fd);
	if (ring_ok)
		ring_teardown(&ctx);
	reap_acceptor(acceptor);
}

bool iouring_send_zc_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_iouring_send_zc_churn) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_IOURING_SEND_ZC_CHURN,
			       JITTER_RANGE(ZC_OUTER_BASE));
	if (outer_iters < ZC_OUTER_FLOOR)
		outer_iters = ZC_OUTER_FLOOR;
	if (outer_iters > ZC_OUTER_CAP)
		outer_iters = ZC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= ZC_WALL_CAP_NS)
			break;
		iter_one(&t_outer);
		if (ns_unsupported_iouring_send_zc_churn)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/io_uring.h>) */

#include <stdbool.h>

#include "child.h"
#include "shm.h"

bool iouring_send_zc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/io_uring.h>) */

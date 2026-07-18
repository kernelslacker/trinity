/*
 * iouring_send_zc_churn - rotate a registered-buffer io_uring through
 * IORING_OP_SEND_ZC and IORING_OP_SENDMSG_ZC submissions while racing
 * IORING_UNREGISTER_BUFFERS and IORING_REGISTER_BUFFERS_UPDATE against
 * the in-flight notif slot.
 *
 * Target: io_uring send-ZC notif path (io_send_zc_finish family) and
 * the fixed-buffer rsrc_node refcount.  Bug class: rsrc_node lifetime
 * racing the deferred notif -- UNREGISTER_BUFFERS while a SEND_ZC notif
 * still holds a ref to the imu_index (historic UAF), REGISTER_BUFFERS_
 * UPDATE replacing the slot an in-flight SQE latched onto, and the
 * broader retransmit-vs-free notif collisions on recycled fixed-buffer
 * slots.
 *
 * Per outer iteration (BUDGETED+JITTER, 200 ms wall cap):
 * io_uring_setup(8, SINGLE_ISSUER|DEFER_TASKRUN) with a no-flags
 * fallback on EINVAL; REGISTER_BUFFERS an 8 x 4 KiB anon pool as
 * iov[8]; SOCK_STREAM + SO_ZEROCOPY + SO_{RCV,SND}TIMEO=100 ms
 * connected to a one-shot accept-and-exit fork on 127.0.0.1.  Inner
 * loop (BUDGETED 4/8/16, JITTER) submits SEND_ZC / SENDMSG_ZC SQEs
 * with IORING_RECVSEND_FIXED_BUF pointing at buf_index i%8, then
 * races A: UNREGISTER_BUFFERS mid-flight; B: REGISTER_BUFFERS_UPDATE
 * replacing slot 0 with a fresh mmap.  io_uring_enter drives the
 * rsrc_node release/notif posting; reap acceptor.
 *
 * Brick-safety: loopback TCP only against a one-shot acceptor;
 * registered-buffer pool exactly 8 x 4 KiB per iter, freed on exit;
 * min_complete bounded by submitted count so a stuck CQE can't hang;
 * acceptor WNOHANG-polled then SIGTERM if it overstays.
 *
 * Latch: ns_unsupported_iouring_send_zc_churn fires on ENOSYS/EPERM/
 * ENOMEM/EINVAL from the first io_uring_setup probe (same shape as
 * msg_zerocopy_churn / tcp_ulp_swap_churn).  Header-gated by
 * __has_include on <linux/io_uring.h>; per-symbol #define fallbacks
 * at stable UAPI values for the SEND_ZC / SETUP / RECVSEND opcodes so
 * older toolchains still compile (kernel returns EINVAL, latch fires).
 */

#if __has_include(<linux/io_uring.h>)

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
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
#include "syscall-gate.h"
#include "childops-iouring.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "childops/io_uring/ring.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#ifndef __NR_io_uring_register
#define __NR_io_uring_register	427
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

static int do_register(int fd, unsigned int op, void *arg, unsigned int nr)
{
	return (int)trinity_raw_syscall(__NR_io_uring_register, fd, op, arg, nr);
}

static int do_enter(int fd, unsigned int to_submit, unsigned int min_complete,
		    unsigned int flags)
{
	return (int)trinity_raw_syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
			    flags, NULL, 0);
}

/*
 * Stand up the ring via the shared iour_ring_setup helper.  First
 * tries the strict IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN
 * submission contract; on an IOUR_TRANSIENT result (pre-6.1 kernels that
 * have SEND_ZC but reject the flags as EINVAL) falls back to a no-flags
 * retry so the SEND_ZC path still gets exercised.  Returns the
 * propagated status; on IOUR_SUPPORTED ctx is populated.
 */
static enum iour_setup_status ring_setup(struct iour_ring *ctx)
{
	struct io_uring_params p;
	enum iour_setup_status st;

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

	st = iour_ring_setup(&p, ZC_RING_ENTRIES, ctx);
	if (st == IOUR_TRANSIENT) {
		memset(&p, 0, sizeof(p));
		st = iour_ring_setup(&p, ZC_RING_ENTRIES, ctx);
	}
	return st;
}

static unsigned int submit_one(struct iour_ring *ctx,
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

static unsigned int drain_cqes(struct iour_ring *ctx)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	unsigned int reaped = 0;

	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
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

/*
 * Per-iteration scratchpad shared across the iouring_send_zc_iter_<phase>
 * helpers.  Lifetime is exactly one iter_one() invocation; avoids
 * threading a dozen out-parameters through the phase helpers.
 */
struct iouring_send_zc_iter_ctx {
	struct iour_ring ring;
	struct iovec	bufs[ZC_BUF_COUNT];
	void		*pages[ZC_BUF_COUNT];
	void		*replacement;
	struct iovec	replacement_iov;
	/* SENDMSG_ZC submission backing -- must outlive
	 * iouring_send_zc_iter_submit() because io_uring_enter() in the
	 * drive phase is what causes the kernel to copy_from_user() the
	 * msghdr and walk msg_iov.  Stack-locals would be UAF. */
	struct msghdr	sendmsg_msg;
	struct iovec	sendmsg_iov[4];
	pid_t		acceptor;
	int		sock_fd;
	unsigned int	submitted;
	bool		ring_ok;
	bool		bufs_registered;
	/* Caller's struct childdata so the iter phase helpers can
	 * attribute per-childop yield counters to child->op_type. */
	struct childdata *child;
};

/*
 * Stand up the ring, mmap the registered-buffer pool, and install it
 * via IORING_REGISTER_BUFFERS.  io_uring_setup() failing with the cap-
 * gate errnos latches ns_unsupported_iouring_send_zc_churn so subsequent
 * invocations short-circuit.  Returns 0 on success; nonzero means the
 * caller should bail to the teardown path.
 */
static int iouring_send_zc_iter_setup(struct iouring_send_zc_iter_ctx *it)
{
	unsigned int i;

	{
		enum iour_setup_status st = ring_setup(&it->ring);

		if (st != IOUR_SUPPORTED) {
			/* Latch the per-process cap-gate only on a real
			 * "kernel won't ever support io_uring" verdict.
			 * IOUR_TRANSIENT (ENOMEM / EAGAIN / EMFILE / a
			 * hostile-return overflow or out-of-range offset
			 * rejected by the helper, or an EINVAL on the
			 * no-flags retry too) skips this iteration but
			 * leaves siblings free to retry on the next
			 * dispatch.  The old code latched on EINVAL +
			 * ENOMEM too, but EINVAL on the no-flags retry
			 * means the kernel disliked something other than
			 * the strict-submission flags -- that may clear
			 * on the next attempt, and ENOMEM definitely
			 * will. */
			if (st == IOUR_UNSUPPORTED) {
				ns_unsupported_iouring_send_zc_churn = true;
				/* it->child->op_type lives in shared memory
				 * and can be scribbled by a poisoned-arena
				 * write from a sibling; bounds-check the
				 * snapshot before indexing the
				 * NR_CHILD_OP_TYPES-sized stats array, same
				 * pattern as 825305aed33d. */
				{
					const enum child_op_type op = it->child->op_type;
					if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
						__atomic_store_n(&shm->stats.childop.latch_reason[op],
								 CHILDOP_LATCH_UNSUPPORTED,
								 __ATOMIC_RELAXED);
				}
			}
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
					   1, __ATOMIC_RELAXED);
			return -1;
		}
	}
	it->ring_ok = true;

	for (i = 0; i < ZC_BUF_COUNT; i++) {
		it->pages[i] = mmap(NULL, ZC_BUF_BYTES, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
				    -1, 0);
		if (it->pages[i] == MAP_FAILED) {
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
					   1, __ATOMIC_RELAXED);
			return -1;
		}
		memset(it->pages[i], 0xa5 ^ (int)i, ZC_BUF_BYTES);
		it->bufs[i].iov_base = it->pages[i];
		it->bufs[i].iov_len  = ZC_BUF_BYTES;
	}

	if (do_register(it->ring.fd, IORING_REGISTER_BUFFERS,
			it->bufs, ZC_BUF_COUNT) < 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	it->bufs_registered = true;
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.register_bufs_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Open the loopback TCP socket pair, set the cap-gate latch on
 * SO_ZEROCOPY refusal, and stash the fd/acceptor pid in the ctx.
 * Returns 0 on success; nonzero means the caller should bail to the
 * shared teardown path.
 */
static int iouring_send_zc_iter_socket(struct iouring_send_zc_iter_ctx *it)
{
	int one = 1;

	it->sock_fd = open_loopback_pair(&it->acceptor);
	if (it->sock_fd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* SO_ZEROCOPY enables the kernel-side ZC path the SEND_ZC SQE
	 * targets.  EOPNOTSUPP / EPERM here latches the cap-gate -- the
	 * platform can't reach the path at all. */
	if (setsockopt(it->sock_fd, SOL_SOCKET, SO_ZEROCOPY,
		       &one, sizeof(one)) < 0) {
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT ||
		    errno == EPERM) {
			ns_unsupported_iouring_send_zc_churn = true;
			/* it->child->op_type lives in shared memory and
			 * can be scribbled by a poisoned-arena write from
			 * a sibling; bounds-check the snapshot before
			 * indexing the NR_CHILD_OP_TYPES-sized stats array,
			 * same pattern as 825305aed33d. */
			{
				const enum child_op_type op = it->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Submit the two ZC SQEs the iteration is built around: one
 * IORING_OP_SEND_ZC referencing a rotating buf_index in the
 * registered table, and one IORING_OP_SENDMSG_ZC with a 1..4-iov
 * msghdr drawn from the same pool.  Bumps it->submitted per SQE
 * actually queued so the io_uring_enter min_complete stays honest.
 */
static void iouring_send_zc_iter_submit(struct iouring_send_zc_iter_ctx *it)
{
	/* SEND_ZC SQE referring buf_index 0..7 (rotating).  Send length is
	 * clamped to ZC_BUF_BYTES so we never trip the kernel's per-buffer
	 * bounds check on the iovec. */
	{
		struct io_uring_sqe sqe;
		unsigned int idx = rnd_modulo_u32(ZC_BUF_COUNT);
		size_t send_len = (size_t)(1 + rnd_modulo_u32(ZC_BUF_BYTES));

		fill_send_zc(&sqe, it->sock_fd, it->pages[idx], send_len, idx);
		if (submit_one(&it->ring, &sqe) == 1) {
			it->submitted++;
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.send_zc_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* SENDMSG_ZC variant -- 1..4 iovs from the registered pool, each
	 * iov pointing into a different buffer slot so the multi-iov walk
	 * touches multiple rsrc_node entries. */
	{
		struct io_uring_sqe sqe;
		unsigned int n_iov = 1 + rnd_modulo_u32(4U);
		unsigned int j;
		unsigned int buf_index = rnd_modulo_u32(ZC_BUF_COUNT);

		if (n_iov > 4)
			n_iov = 4;
		for (j = 0; j < n_iov; j++) {
			unsigned int slot = (buf_index + j) % ZC_BUF_COUNT;
			size_t len = (size_t)(1 + rnd_modulo_u32(ZC_BUF_BYTES));

			it->sendmsg_iov[j].iov_base = it->pages[slot];
			it->sendmsg_iov[j].iov_len  = len;
		}
		memset(&it->sendmsg_msg, 0, sizeof(it->sendmsg_msg));
		it->sendmsg_msg.msg_iov    = it->sendmsg_iov;
		it->sendmsg_msg.msg_iovlen = n_iov;

		fill_sendmsg_zc(&sqe, it->sock_fd, &it->sendmsg_msg, buf_index);
		if (submit_one(&it->ring, &sqe) == 1) {
			it->submitted++;
			__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.sendmsg_zc_ok,
					   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * RACE B: IORING_REGISTER_BUFFERS_UPDATE replacing slot 0 with a
 * freshly-mmap'd page.  Issued before the io_uring_enter so any
 * in-flight SQE has already latched onto the original io_mapped_ubuf;
 * the update should refcount-protect the in-flight reference rather
 * than redirect it.  The replacement mmap is stashed in the ctx so
 * the shared teardown path can munmap it.
 */
static void iouring_send_zc_iter_race(struct iouring_send_zc_iter_ctx *it)
{
	struct io_uring_rsrc_update2 upd;

	it->replacement = mmap(NULL, ZC_BUF_BYTES, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			       -1, 0);
	if (it->replacement == MAP_FAILED)
		return;

	memset(it->replacement, 0x5a, ZC_BUF_BYTES);
	it->replacement_iov.iov_base = it->replacement;
	it->replacement_iov.iov_len  = ZC_BUF_BYTES;

	memset(&upd, 0, sizeof(upd));
	upd.offset = 0;
	upd.data   = (uint64_t)(uintptr_t)&it->replacement_iov;
	upd.nr     = 1;

	if (do_register(it->ring.fd, IORING_REGISTER_BUFFERS_UPDATE,
			&upd, sizeof(upd)) >= 0)
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.update_race_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Drive the ring through submit + completion, then run RACE A
 * (IORING_UNREGISTER_BUFFERS while a SEND_ZC notif may still hold an
 * rsrc_node ref against an imu_index) and harvest any deferred notif
 * CQEs.  min_complete is bounded by what was actually queued so a
 * stuck completion can't hang the loop.  Clears bufs_registered on
 * successful unregister so the shared teardown doesn't repeat it.
 */
static void iouring_send_zc_iter_drive(struct iouring_send_zc_iter_ctx *it,
				       const struct timespec *t_outer)
{
	int r;
	unsigned int reaped;

	r = do_enter(it->ring.fd, it->submitted, it->submitted,
		     IORING_ENTER_GETEVENTS);
	if (r >= 0) {
		reaped = drain_cqes(&it->ring);
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.cqe_drained,
				   (unsigned long)reaped, __ATOMIC_RELAXED);
	}

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		return;

	if (do_register(it->ring.fd, IORING_UNREGISTER_BUFFERS, NULL, 0) >= 0) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.unregister_race_ok,
				   1, __ATOMIC_RELAXED);
		it->bufs_registered = false;
	}

	reaped = drain_cqes(&it->ring);
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.cqe_drained,
			   (unsigned long)reaped, __ATOMIC_RELAXED);
}

/* One full sequence on a freshly-created ring + loopback TCP socket. */
static void iter_one(const struct timespec *t_outer, struct childdata *child)
{
	struct iouring_send_zc_iter_ctx it;
	unsigned int i;

	memset(&it, 0, sizeof(it));
	it.replacement = MAP_FAILED;
	it.acceptor    = -1;
	it.sock_fd     = -1;
	it.child       = child;
	for (i = 0; i < ZC_BUF_COUNT; i++)
		it.pages[i] = MAP_FAILED;

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		return;

	if (iouring_send_zc_iter_setup(&it) != 0)
		goto out;

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	if (iouring_send_zc_iter_socket(&it) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling, same
	 * pattern as 825305aed33d. */
	{
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
	}
	iouring_send_zc_iter_submit(&it);

	if ((unsigned long long)ns_since(t_outer) >= ZC_WALL_CAP_NS)
		goto out;

	iouring_send_zc_iter_race(&it);
	iouring_send_zc_iter_drive(&it, t_outer);

out:
	if (it.bufs_registered)
		(void)do_register(it.ring.fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (it.replacement != MAP_FAILED)
		(void)munmap(it.replacement, ZC_BUF_BYTES);
	for (i = 0; i < ZC_BUF_COUNT; i++) {
		if (it.pages[i] != MAP_FAILED)
			(void)munmap(it.pages[i], ZC_BUF_BYTES);
	}
	if (it.sock_fd >= 0)
		close(it.sock_fd);
	if (it.ring_ok)
		iour_ring_teardown(&it.ring);
	reap_acceptor(it.acceptor);
}

bool iouring_send_zc_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_iouring_send_zc_churn) {
		__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
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
		iter_one(&t_outer, child);
		if (ns_unsupported_iouring_send_zc_churn)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/io_uring.h>) */

#include <stdbool.h>

#include "child.h"
#include "shm.h"

#include "kernel/socket.h"
#include "kernel/unistd.h"
bool iouring_send_zc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.iouring_send_zc_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/io_uring.h>) */

/*
 * ublk_lifecycle — race UBLK_CMD_DEL_DEV against in-flight UBLK_U_IO_FETCH_REQ.
 *
 * The whole ublk uAPI surface is io_uring_cmd, hit constantly by
 * per-syscall fuzzing — but no producer ever assembles the (control fd,
 * kernel-assigned dev_id, queue chrdev, parked FETCH_REQ, racing
 * DEL_DEV) tuple required to reach the cmd-cancellation walker that
 * ublk_cancel_cmd() lives in.
 *
 * Sequence (per invocation):
 *   1. open /dev/ublk-control.  EPERM/ENOENT/ENXIO/EACCES latch the
 *      whole op off (kernel without CONFIG_BLK_DEV_UBLK, no
 *      CAP_SYS_ADMIN, or privs dropped to nobody).
 *   2. set up two private io_urings (control + IO) so the teardown
 *      order is independent and the cancellation walker sees in-flight
 *      cmds parked on a sibling ring.
 *   3. UBLK_U_CMD_ADD_DEV via IORING_OP_URING_CMD on the control fd
 *      with a minimal ublksrv_ctrl_dev_info (nr_hw_queues=1,
 *      queue_depth=4, dev_id=-1 for kernel-assigned).  Reap the CQE
 *      and read dev_id back out of the addr-pointed dev_info.
 *   4. open /dev/ublkc<dev_id> — the per-queue chrdev hosting the
 *      io_uring_cmd handler FETCH_REQ targets.  Block side ublkb<N>
 *      is not opened — it is not ready until UBLK_CMD_START_DEV, which
 *      is deliberately skipped: we want the post-ADD pre-START state
 *      where teardown still walks the io_cmd list.
 *   5. UBLK_U_IO_FETCH_REQ on the IO ring against the queue chrdev
 *      (q_id=0, tag=0).  Submit-only (min_complete=0) — the cmd parks
 *      waiting for an I/O that never arrives.
 *   6. UBLK_U_CMD_DEL_DEV on the control ring against dev_id.  The
 *      kernel-side ublk_ctrl_uring_cmd dispatch into the DEL path
 *      drives ublk_cancel_dev -> ublk_cancel_queue -> ublk_cancel_cmd
 *      across every parked UBLK_IO_*_REQ on the queue chrdev — the
 *      f7700a4415af UAF window.
 *   7. Cleanup: close queue chrdev, then both ring fds (force-cancels
 *      any leftover FETCH_REQ on the IO ring), control fd LAST.
 *      Best-effort — the race is the point.
 *
 * Self-bounding: one create/fetch/delete cycle per invocation; all
 * io_uring_enter calls are bounded; FETCH_REQ submit is non-blocking
 * (min_complete=0) so the parked cmd never wedges past SIGALRM(1s).
 *
 * Upstream commit referenced as evidence: f7700a4415af
 * ('ublk: fix UAF in ublk_cancel_cmd()').
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "childops/io_uring/ring.h"
#include "kernel/ublk.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/unistd.h"
/*
 * Locally-named struct mirrors (ublk_lc_*) so a sysroot whose
 * linux/ublk_cmd.h DOES expose ublksrv_ctrl_cmd / ublksrv_io_cmd does
 * not collide.  Kernel reads cmd_op + addr/len off the SQE; the
 * addr-pointed payload is what these mirror.  Layouts mirror
 * linux/ublk_cmd.h as of upstream 6.x.  Must stay in scope where the
 * UBLK_U_* macros from kernel/ublk.h are expanded.
 */
struct ublk_lc_ctrl_cmd {
	__u32	dev_id;
	__u16	queue_id;
	__u16	len;
	__u64	addr;
	__u64	data[1];
	__u16	dev_path_len;
	__u16	pad;
	__u32	reserved;
};

struct ublk_lc_ctrl_dev_info {
	__u16	nr_hw_queues;
	__u16	queue_depth;
	__u16	state;
	__u16	pad0;
	__u32	max_io_buf_bytes;
	__u32	dev_id;
	__s32	ublksrv_pid;
	__u32	pad1;
	__u64	flags;
	__u64	ublksrv_flags;
	__u32	owner_uid;
	__u32	owner_gid;
	__u64	reserved1;
	__u64	reserved2;
};

struct ublk_lc_io_cmd {
	__u16	q_id;
	__u16	tag;
	__s32	result;
	__u64	addr;
};

#define UBLK_LC_RING_DEPTH	8
#define UBLK_LC_IO_BUF_BYTES	(64U * 1024U)

/* Per-child latched gate.  Set on the first failure indicating ublk
 * is structurally absent and never cleared. */
static bool ns_unsupported_ublk;

static inline unsigned int rdu32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void wru32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}

static bool ring_submit(struct iour_ring *r, struct io_uring_sqe *sqe,
			unsigned int min_complete)
{
	unsigned int mask = rdu32(r->sq_ring, r->sq_off_mask);
	unsigned int head = rdu32(r->sq_ring, r->sq_off_head);
	unsigned int tail = rdu32(r->sq_ring, r->sq_off_tail);
	unsigned int *sq_array;
	unsigned int slot, flags;
	int rc;

	if (r->sq_entries - (tail - head) < 1)
		return false;

	sq_array = (unsigned int *)((char *)r->sq_ring + r->sq_off_array);
	slot = tail & mask;
	((struct io_uring_sqe *)r->sqes)[slot] = *sqe;
	sq_array[slot] = slot;
	__sync_synchronize();
	wru32(r->sq_ring, r->sq_off_tail, tail + 1);

	flags = min_complete ? IORING_ENTER_GETEVENTS : 0;
	rc = (int)trinity_raw_syscall(__NR_io_uring_enter, r->fd, 1U, min_complete,
			  flags, NULL, 0);
	return rc >= 0;
}

static void ring_drain(struct iour_ring *r)
{
	unsigned int head = rdu32(r->cq_ring, r->cq_off_head);
	unsigned int tail = rdu32(r->cq_ring, r->cq_off_tail);

	while (head != tail) {
		head++;
		tail = rdu32(r->cq_ring, r->cq_off_tail);
	}
	__sync_synchronize();
	wru32(r->cq_ring, r->cq_off_head, head);
}

/* Per-invocation state shared across the ublk_lifecycle_iter_* helpers.
 * Lives on the orchestrator's stack and is fresh per invocation.  Lifted
 * only the fields read across helper boundaries -- per-phase scratch
 * (ublksrv_ctrl_cmd payload, io_cmd payload, SQE, qpath, ublk_lc_ctrl_dev_info)
 * stays local to its phase.  @child is the caller's struct childdata so
 * the setup helper can record the per-op latch reason in
 * shm->stats.childop.latch_reason[op_type] at the same site that latches
 * the static ns_unsupported_ublk bool. */
struct ublk_lifecycle_iter_ctx {
	struct iour_ring	ctrl_ring;
	struct iour_ring	io_ring;
	int			ctrl_fd;
	int			q_fd;
	int			dev_id;
	bool			ctrl_ring_up;
	bool			io_ring_up;
	bool			fetch_in_flight;
	struct childdata	*child;
};

/* Open /dev/ublk-control and stand up both io_urings.  Splits the two
 * rings so teardown order is independent and the cancellation walker
 * sees in-flight cmds parked on a sibling ring.  Two failure modes
 * latch ns_unsupported_ublk for the rest of this child: ctrl-fd
 * EPERM/ENOENT/ENXIO/EACCES (no CONFIG_BLK_DEV_UBLK, no
 * CAP_SYS_ADMIN, or privs dropped to nobody) and ring_setup ENOSYS
 * (io_uring absent).  Returns false on any setup failure -- caller
 * jumps to teardown which honours the partial-up flags. */
static bool ublk_lifecycle_iter_setup(struct ublk_lifecycle_iter_ctx *ctx)
{
	ctx->ctrl_fd = open("/dev/ublk-control", O_RDWR | O_CLOEXEC);
	if (ctx->ctrl_fd < 0) {
		if (errno == EPERM || errno == ENOENT || errno == ENXIO ||
		    errno == EACCES) {
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern
			 * as 825305aed33d. */
			const enum child_op_type op = ctx->child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			ns_unsupported_ublk = true;
			__atomic_add_fetch(&shm->stats.ublk_lifecycle.eperm,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}

	{
		struct io_uring_params p;
		enum iour_setup_status st;

		memset(&p, 0, sizeof(p));
		st = iour_ring_setup(&p, UBLK_LC_RING_DEPTH, &ctx->ctrl_ring);
		if (st != IOUR_SUPPORTED) {
			/* Latch ns_unsupported_ublk only on a real "this
			 * kernel will never support io_uring" verdict.
			 * Transient setup failures (ENOMEM / EAGAIN /
			 * EMFILE / overflow-rejected hostile return / mmap
			 * blip) skip this invocation but leave siblings
			 * free to retry. */
			if (st == IOUR_UNSUPPORTED)
				ns_unsupported_ublk = true;
			return false;
		}
		ctx->ctrl_ring_up = true;

		memset(&p, 0, sizeof(p));
		if (iour_ring_setup(&p, UBLK_LC_RING_DEPTH,
				    &ctx->io_ring) != IOUR_SUPPORTED)
			return false;
		ctx->io_ring_up = true;
	}
	return true;
}

/* UBLK_U_CMD_ADD_DEV via IORING_OP_URING_CMD on the ctrl ring with a
 * minimal ublksrv_ctrl_dev_info (nr_hw_queues=1, queue_depth=4,
 * dev_id=-1 for kernel-assigned).  Reaps the CQE and reads dev_id back
 * out of the addr-pointed info.  Deliberately stops at ADD: START_DEV
 * is skipped so we land in the post-ADD pre-START state where teardown
 * still walks the io_cmd list.  Returns false on submit failure or if
 * the kernel-assigned dev_id came back negative -- caller jumps to
 * teardown. */
static bool ublk_lifecycle_iter_add_dev(struct ublk_lifecycle_iter_ctx *ctx)
{
	struct ublk_lc_ctrl_dev_info info;
	struct ublk_lc_ctrl_cmd cc;
	struct io_uring_sqe sqe;

	memset(&info, 0, sizeof(info));
	info.nr_hw_queues = 1;
	info.queue_depth = 4;
	info.dev_id = (__u32)-1;
	info.max_io_buf_bytes = UBLK_LC_IO_BUF_BYTES;

	memset(&cc, 0, sizeof(cc));
	cc.dev_id = (__u32)-1;
	cc.queue_id = (__u16)-1;
	cc.len = (__u16)sizeof(info);
	cc.addr = (__u64)(uintptr_t)&info;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.fd = ctx->ctrl_fd;
	sqe.cmd_op = UBLK_U_CMD_ADD_DEV;
	sqe.addr = (__u64)(uintptr_t)&cc;
	sqe.len = (__u32)sizeof(cc);
	sqe.user_data = 0xadd0;

	if (!ring_submit(&ctx->ctrl_ring, &sqe, 1))
		return false;
	ring_drain(&ctx->ctrl_ring);
	ctx->dev_id = (int)info.dev_id;
	if (ctx->dev_id < 0)
		return false;
	__atomic_add_fetch(&shm->stats.ublk_lifecycle.add_ok, 1,
			   __ATOMIC_RELAXED);
	return true;
}

/* Open /dev/ublkc<dev_id> (the per-queue chrdev hosting the
 * io_uring_cmd handler FETCH_REQ targets) and submit one FETCH_REQ
 * on the IO ring as submit-only (min_complete=0).  The cmd parks
 * waiting for an I/O that never arrives -- exactly the in-flight
 * state ublk_cancel_cmd() walks during DEL_DEV teardown.  Block side
 * ublkb<N> is deliberately not opened; START_DEV is skipped so we
 * stay in the post-ADD pre-START state.  Best-effort: queue-open
 * failure skips arming and the orchestrator still issues DEL_DEV. */
static void ublk_lifecycle_iter_arm_fetch(struct ublk_lifecycle_iter_ctx *ctx)
{
	struct ublk_lc_io_cmd ic;
	struct io_uring_sqe sqe;
	char qpath[64];

	(void)snprintf(qpath, sizeof(qpath), "/dev/ublkc%d", ctx->dev_id);
	ctx->q_fd = open(qpath, O_RDWR | O_CLOEXEC);
	if (ctx->q_fd < 0)
		return;

	memset(&ic, 0, sizeof(ic));
	ic.q_id = 0;
	ic.tag = 0;
	ic.result = -1;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.fd = ctx->q_fd;
	sqe.cmd_op = UBLK_U_IO_FETCH_REQ;
	sqe.addr = (__u64)(uintptr_t)&ic;
	sqe.len = (__u32)sizeof(ic);
	sqe.user_data = 0xfe70;

	if (ring_submit(&ctx->io_ring, &sqe, 0)) {
		ctx->fetch_in_flight = true;
		__atomic_add_fetch(&shm->stats.ublk_lifecycle.fetch_ok, 1,
				   __ATOMIC_RELAXED);
	}
}

/* UBLK_U_CMD_DEL_DEV on the ctrl ring while FETCH_REQ is parked on the
 * IO ring -- the f7700a4415af UAF window.  The kernel-side
 * ublk_ctrl_uring_cmd dispatch into the DEL path drives ublk_cancel_dev
 * -> ublk_cancel_queue -> ublk_cancel_cmd across every parked
 * UBLK_IO_*_REQ on the queue chrdev.  Best-effort: submit failure is
 * ignored, teardown still runs.  Bumps race_observed only when fetch
 * was actually in flight at submit time. */
static void ublk_lifecycle_iter_del_dev(struct ublk_lifecycle_iter_ctx *ctx)
{
	struct ublk_lc_ctrl_cmd cc;
	struct io_uring_sqe sqe;

	memset(&cc, 0, sizeof(cc));
	cc.dev_id = (__u32)ctx->dev_id;
	cc.queue_id = (__u16)-1;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.fd = ctx->ctrl_fd;
	sqe.cmd_op = UBLK_U_CMD_DEL_DEV;
	sqe.addr = (__u64)(uintptr_t)&cc;
	sqe.len = (__u32)sizeof(cc);
	sqe.user_data = 0xde10;

	if (ring_submit(&ctx->ctrl_ring, &sqe, 1)) {
		ring_drain(&ctx->ctrl_ring);
		__atomic_add_fetch(&shm->stats.ublk_lifecycle.del_ok, 1,
				   __ATOMIC_RELAXED);
		if (ctx->fetch_in_flight)
			__atomic_add_fetch(&shm->stats.ublk_lifecycle.race_observed,
					   1, __ATOMIC_RELAXED);
	}
}

/* Reverse-order release of everything ublk_lifecycle stood up: close the
 * queue chrdev first so the IO-ring teardown's force-cancel sees no fresh
 * submissions, then both rings (io before ctrl so the ctrl ring outlives
 * any sibling cmd it spawned), then the ctrl fd last.  Each step is
 * gated on the matching _up / >= 0 flag so a partial setup (e.g. ctrl_fd
 * open succeeded but ring_setup failed) tears down only what actually
 * came up. */
static void ublk_lifecycle_iter_teardown(struct ublk_lifecycle_iter_ctx *ctx)
{
	if (ctx->q_fd >= 0)
		close(ctx->q_fd);
	if (ctx->io_ring_up)
		iour_ring_teardown(&ctx->io_ring);
	if (ctx->ctrl_ring_up)
		iour_ring_teardown(&ctx->ctrl_ring);
	if (ctx->ctrl_fd >= 0)
		close(ctx->ctrl_fd);
}

bool ublk_lifecycle(struct childdata *child)
{
	struct ublk_lifecycle_iter_ctx ctx = {
		.ctrl_fd = -1,
		.q_fd    = -1,
		.dev_id  = -1,
		.child   = child,
	};

	__atomic_add_fetch(&shm->stats.ublk_lifecycle.iters, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ublk)
		return true;

	if (!ublk_lifecycle_iter_setup(&ctx))
		goto out;

	if (!ublk_lifecycle_iter_add_dev(&ctx))
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; same
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
	ublk_lifecycle_iter_arm_fetch(&ctx);
	ublk_lifecycle_iter_del_dev(&ctx);

out:
	ublk_lifecycle_iter_teardown(&ctx);
	return true;
}

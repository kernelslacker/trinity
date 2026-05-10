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
 *      CAP_SYS_ADMIN, --dropprivs in effect).
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
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/io_uring.h>

#include "child.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

/*
 * ublk uAPI shims.  Per-symbol #ifndef so a sysroot that ships only a
 * subset of the ublk_cmd.h symbols (older LTS, stripped headers) still
 * compiles.  Layouts mirror linux/ublk_cmd.h as of upstream 6.x.
 *
 * Locally-named struct mirrors (ublk_lc_*) so a sysroot whose
 * linux/ublk_cmd.h DOES expose ublksrv_ctrl_cmd / ublksrv_io_cmd does
 * not collide.  Kernel reads cmd_op + addr/len off the SQE; the
 * addr-pointed payload is what these mirror.
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

#ifndef UBLK_CMD_ADD_DEV
#define UBLK_CMD_ADD_DEV	0x04
#endif
#ifndef UBLK_CMD_DEL_DEV
#define UBLK_CMD_DEL_DEV	0x05
#endif
#ifndef UBLK_U_CMD_ADD_DEV
#define UBLK_U_CMD_ADD_DEV	_IOWR('u', UBLK_CMD_ADD_DEV, struct ublk_lc_ctrl_cmd)
#endif
#ifndef UBLK_U_CMD_DEL_DEV
#define UBLK_U_CMD_DEL_DEV	_IOWR('u', UBLK_CMD_DEL_DEV, struct ublk_lc_ctrl_cmd)
#endif
#ifndef UBLK_U_IO_FETCH_REQ
#define UBLK_U_IO_FETCH_REQ	_IOWR('u', 0x20, struct ublk_lc_io_cmd)
#endif

#define UBLK_LC_RING_DEPTH	8
#define UBLK_LC_IO_BUF_BYTES	(64U * 1024U)

/* Per-child latched gate.  Set on the first failure indicating ublk
 * is structurally absent and never cleared. */
static bool ns_unsupported_ublk;

struct ublk_lc_ring {
	int		fd;
	void		*sq_ring, *cq_ring, *sqes;
	size_t		sq_ring_sz, cq_ring_sz, sqes_sz;
	bool		single_mmap;
	unsigned int	sq_entries;
	unsigned int	sq_off_head, sq_off_tail, sq_off_mask, sq_off_array;
	unsigned int	cq_off_head, cq_off_tail, cq_off_mask, cq_off_cqes;
};

static inline unsigned int rdu32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void wru32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}

static bool ring_setup(struct ublk_lc_ring *r, unsigned int entries)
{
	struct io_uring_params p;
	void *sq, *cq, *sqes;

	memset(r, 0, sizeof(*r));
	r->fd = -1;
	memset(&p, 0, sizeof(p));

	r->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
	if (r->fd < 0)
		return false;

	r->sq_ring_sz = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(unsigned int);
	r->cq_ring_sz = (size_t)p.cq_off.cqes + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	r->sqes_sz    = (size_t)p.sq_entries * sizeof(struct io_uring_sqe);

	sq = mmap(NULL, r->sq_ring_sz, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
	if (sq == MAP_FAILED)
		goto fail_close;

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq = sq;
		r->single_mmap = true;
		r->cq_ring_sz = 0;
	} else {
		cq = mmap(NULL, r->cq_ring_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
		if (cq == MAP_FAILED) {
			munmap(sq, r->sq_ring_sz);
			goto fail_close;
		}
	}

	sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		if (!r->single_mmap)
			munmap(cq, r->cq_ring_sz);
		munmap(sq, r->sq_ring_sz);
		goto fail_close;
	}

	r->sq_ring = sq;
	r->cq_ring = cq;
	r->sqes = sqes;
	r->sq_entries = p.sq_entries;
	r->sq_off_head = p.sq_off.head;
	r->sq_off_tail = p.sq_off.tail;
	r->sq_off_mask = p.sq_off.ring_mask;
	r->sq_off_array = p.sq_off.array;
	r->cq_off_head = p.cq_off.head;
	r->cq_off_tail = p.cq_off.tail;
	r->cq_off_mask = p.cq_off.ring_mask;
	r->cq_off_cqes = p.cq_off.cqes;
	return true;

fail_close:
	close(r->fd);
	r->fd = -1;
	return false;
}

static void ring_teardown(struct ublk_lc_ring *r)
{
	if (r->sqes)
		munmap(r->sqes, r->sqes_sz);
	if (r->cq_ring && !r->single_mmap)
		munmap(r->cq_ring, r->cq_ring_sz);
	if (r->sq_ring)
		munmap(r->sq_ring, r->sq_ring_sz);
	if (r->fd >= 0)
		close(r->fd);
}

static bool ring_submit(struct ublk_lc_ring *r, struct io_uring_sqe *sqe,
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
	rc = (int)syscall(__NR_io_uring_enter, r->fd, 1U, min_complete,
			  flags, NULL, 0);
	return rc >= 0;
}

static void ring_drain(struct ublk_lc_ring *r)
{
	unsigned int mask = rdu32(r->cq_ring, r->cq_off_mask);
	unsigned int head = rdu32(r->cq_ring, r->cq_off_head);
	unsigned int tail = rdu32(r->cq_ring, r->cq_off_tail);
	struct io_uring_cqe *cqes;

	cqes = (struct io_uring_cqe *)((char *)r->cq_ring + r->cq_off_cqes);
	while (head != tail) {
		(void)cqes[head & mask];
		head++;
		tail = rdu32(r->cq_ring, r->cq_off_tail);
	}
	__sync_synchronize();
	wru32(r->cq_ring, r->cq_off_head, head);
}

bool ublk_lifecycle(struct childdata *child)
{
	struct ublk_lc_ring ctrl_ring, io_ring;
	struct ublk_lc_ctrl_cmd cc;
	struct ublk_lc_ctrl_dev_info info;
	struct ublk_lc_io_cmd ic;
	struct io_uring_sqe sqe;
	char qpath[64];
	int ctrl_fd = -1, q_fd = -1, dev_id = -1;
	bool ctrl_ring_up = false, io_ring_up = false, fetch_in_flight = false;

	(void)child;

	__atomic_add_fetch(&shm->stats.ublk_lifecycle_iters, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ublk)
		return true;

	ctrl_fd = open("/dev/ublk-control", O_RDWR | O_CLOEXEC);
	if (ctrl_fd < 0) {
		if (errno == EPERM || errno == ENOENT || errno == ENXIO ||
		    errno == EACCES) {
			ns_unsupported_ublk = true;
			__atomic_add_fetch(&shm->stats.ublk_lifecycle_eperm,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (!ring_setup(&ctrl_ring, UBLK_LC_RING_DEPTH)) {
		if (errno == ENOSYS)
			ns_unsupported_ublk = true;
		goto out;
	}
	ctrl_ring_up = true;

	if (!ring_setup(&io_ring, UBLK_LC_RING_DEPTH))
		goto out;
	io_ring_up = true;

	/* ADD_DEV: kernel allocates dev_id, writes it back into info. */
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
	sqe.fd = ctrl_fd;
	sqe.cmd_op = UBLK_U_CMD_ADD_DEV;
	sqe.addr = (__u64)(uintptr_t)&cc;
	sqe.len = (__u32)sizeof(cc);
	sqe.user_data = 0xadd0;

	if (!ring_submit(&ctrl_ring, &sqe, 1))
		goto out;
	ring_drain(&ctrl_ring);
	dev_id = (int)info.dev_id;
	if (dev_id < 0)
		goto out;
	__atomic_add_fetch(&shm->stats.ublk_lifecycle_add_ok, 1,
			   __ATOMIC_RELAXED);

	(void)snprintf(qpath, sizeof(qpath), "/dev/ublkc%d", dev_id);
	q_fd = open(qpath, O_RDWR | O_CLOEXEC);
	if (q_fd < 0)
		goto del_only;

	/* FETCH_REQ on the IO ring — submit-only.  Parks waiting for an
	 * I/O that never arrives, exactly the in-flight state
	 * ublk_cancel_cmd() walks during DEL_DEV teardown. */
	memset(&ic, 0, sizeof(ic));
	ic.q_id = 0;
	ic.tag = 0;
	ic.result = -1;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.fd = q_fd;
	sqe.cmd_op = UBLK_U_IO_FETCH_REQ;
	sqe.addr = (__u64)(uintptr_t)&ic;
	sqe.len = (__u32)sizeof(ic);
	sqe.user_data = 0xfe70;

	if (ring_submit(&io_ring, &sqe, 0)) {
		fetch_in_flight = true;
		__atomic_add_fetch(&shm->stats.ublk_lifecycle_fetch_ok, 1,
				   __ATOMIC_RELAXED);
	}

del_only:
	/* DEL_DEV on the control ring while FETCH_REQ is parked on the
	 * IO ring — the f7700a4415af UAF window. */
	memset(&cc, 0, sizeof(cc));
	cc.dev_id = (__u32)dev_id;
	cc.queue_id = (__u16)-1;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.fd = ctrl_fd;
	sqe.cmd_op = UBLK_U_CMD_DEL_DEV;
	sqe.addr = (__u64)(uintptr_t)&cc;
	sqe.len = (__u32)sizeof(cc);
	sqe.user_data = 0xde10;

	if (ring_submit(&ctrl_ring, &sqe, 1)) {
		ring_drain(&ctrl_ring);
		__atomic_add_fetch(&shm->stats.ublk_lifecycle_del_ok, 1,
				   __ATOMIC_RELAXED);
		if (fetch_in_flight)
			__atomic_add_fetch(&shm->stats.ublk_lifecycle_race_observed,
					   1, __ATOMIC_RELAXED);
	}

out:
	if (q_fd >= 0)
		close(q_fd);
	if (io_ring_up)
		ring_teardown(&io_ring);
	if (ctrl_ring_up)
		ring_teardown(&ctrl_ring);
	if (ctrl_fd >= 0)
		close(ctrl_fd);
	return true;
}

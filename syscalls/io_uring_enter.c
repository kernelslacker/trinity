/*
 *   SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit, u32, min_complete, u32, flags, const sigset_t __user *, sig, size_t, sigsz)
 */
#include <string.h>
#include <linux/io_uring.h>

#include "arch.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"

/* io_uring opcodes added in Linux v6.15 — not in older kernel headers. */
#ifndef IORING_OP_RECV_ZC
#define IORING_OP_RECV_ZC	58
#endif
#ifndef IORING_OP_EPOLL_WAIT
#define IORING_OP_EPOLL_WAIT	59
#endif
#ifndef IORING_OP_READV_FIXED
#define IORING_OP_READV_FIXED	60
#endif
#ifndef IORING_OP_WRITEV_FIXED
#define IORING_OP_WRITEV_FIXED	61
#endif
/* io_uring opcodes added in Linux v6.16 — not in older kernel headers. */
#ifndef IORING_OP_PIPE
#define IORING_OP_PIPE		62
#endif
/* io_uring opcodes added in Linux v7.0 — not in older kernel headers. */
#ifndef IORING_OP_NOP128
#define IORING_OP_NOP128	63
#define IORING_OP_URING_CMD128	64
#define TRINITY_IORING_OP_LAST	65
#else
#define TRINITY_IORING_OP_LAST	IORING_OP_LAST
#endif

#ifndef IORING_ENTER_EXT_ARG_REG
#define IORING_ENTER_EXT_ARG_REG	(1U << 6)
#endif
#ifndef IORING_ENTER_NO_IOWAIT
#define IORING_ENTER_NO_IOWAIT		(1U << 7)
#endif

static unsigned long io_uring_enter_flags[] = {
	IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAKEUP,
	IORING_ENTER_SQ_WAIT, IORING_ENTER_EXT_ARG,
	IORING_ENTER_REGISTERED_RING, IORING_ENTER_ABS_TIMER,
	IORING_ENTER_EXT_ARG_REG, IORING_ENTER_NO_IOWAIT,
};

/* io_uring SQE layout — 64 bytes. */
struct trinity_io_uring_sqe {
	unsigned char opcode;
	unsigned char flags;
	unsigned short ioprio;
	int fd;
	unsigned long long off;
	unsigned long long addr;
	unsigned int len;
	unsigned int op_flags;
	unsigned long long user_data;
	unsigned short buf_index;
	unsigned short personality;
	int splice_fd_in;
	unsigned long long addr3;
	unsigned long long __pad2;
};

/* SQE flags */
#ifndef IOSQE_FIXED_FILE
#define IOSQE_FIXED_FILE	(1U << 0)
#define IOSQE_IO_DRAIN		(1U << 1)
#define IOSQE_IO_LINK		(1U << 2)
#define IOSQE_IO_HARDLINK	(1U << 3)
#define IOSQE_ASYNC		(1U << 4)
#define IOSQE_BUFFER_SELECT	(1U << 5)
#define IOSQE_CQE_SKIP_SUCCESS	(1U << 6)
#endif
/* IORING_OP_TIMEOUT op_flags bit added in Linux v7.1 merge window. */
#ifndef IORING_TIMEOUT_IMMEDIATE_ARG
#define IORING_TIMEOUT_IMMEDIATE_ARG	(1U << 7)
#endif

static unsigned int read_ring_u32(void *ring, unsigned int offset)
{
	return *(volatile unsigned int *)((char *)ring + offset);
}

static void write_ring_u32(void *ring, unsigned int offset, unsigned int val)
{
	*(volatile unsigned int *)((char *)ring + offset) = val;
}

static void fill_sqe(struct trinity_io_uring_sqe *sqe)
{
	unsigned long addr;

	memset(sqe, 0, sizeof(*sqe));

	/* Pick an opcode: mostly valid, occasionally garbage. */
	if (ONE_IN(8))
		sqe->opcode = rand() & 0xff;
	else
		sqe->opcode = rand() % TRINITY_IORING_OP_LAST;

	/* SQE flags: random combination of valid bits, rarely garbage. */
	if (ONE_IN(10))
		sqe->flags = rand() & 0xff;
	else
		sqe->flags = rand() & 0x7f;	/* bits 0-6 are defined */

	sqe->ioprio = RAND_BOOL() ? 0 : rand() & 0xffff;
	sqe->fd = get_random_fd();
	sqe->off = RAND_BOOL() ? 0 : rand32();
	sqe->addr = RAND_BOOL() ? 0 : (unsigned long long)(unsigned long)get_address();
	sqe->len = RAND_BOOL() ? (unsigned int)(rand() % 4096) : rand32();
	sqe->user_data = rand32();

	/*
	 * sqe->addr is the per-op buffer pointer.  For read-direction
	 * opcodes (READ/READV/READ_FIXED/RECV/RECVMSG/RECV_ZC/READV_FIXED)
	 * the kernel writes into it; for write-direction opcodes it only
	 * reads.  Maintaining an opcode-to-direction table here would rot
	 * the moment a new opcode lands upstream, so just scrub
	 * unconditionally.  For write-direction ops the redirect is a
	 * no-op cost (kernel reads the same bytes from the replacement
	 * buffer); for read-direction ops it closes the same shm-overlap
	 * window the read/recv/getdents sanitisers already close.
	 *
	 * Pass the full sqe->len so the entire buffer range is checked
	 * against shared regions and a same-sized replacement is chosen.
	 * Capping at page_size left ops like IORING_OP_MADVISE,
	 * READ_FIXED/WRITE_FIXED, and SEND/RECV free to walk past the
	 * first page into shared bookkeeping (incl. the kcov mmap).
	 * page_size is still the floor when the fuzzer rolled len == 0,
	 * since some opcodes don't consult sqe->len at all.
	 */
	addr = (unsigned long) sqe->addr;
	avoid_shared_buffer(&addr, sqe->len > 0 ? sqe->len : page_size);
	sqe->addr = addr;

	/* op_flags: varies by opcode but we just fuzz it. */
	if (ONE_IN(4))
		sqe->op_flags = rand32();

	sqe->buf_index = rand() & 0xffff;
	sqe->personality = RAND_BOOL() ? 0 : rand() & 0xffff;

	if (ONE_IN(4))
		sqe->splice_fd_in = get_random_fd();
}

static void sanitise_io_uring_enter(struct syscallrecord *rec)
{
	struct io_uringobj *ring;
	unsigned int mask, head, tail, idx, to_submit;
	struct trinity_io_uring_sqe *sqes;
	unsigned int *sq_array;

	ring = get_io_uring_ring();
	if (ring == NULL || ring->sq_ring == NULL)
		return;

	/* Use the mapped ring's fd so the SQEs actually matter. */
	rec->a1 = ring->fd;

	mask = read_ring_u32(ring->sq_ring, ring->off_mask);
	head = read_ring_u32(ring->sq_ring, ring->off_head);
	tail = head;	/* start fresh from head */

	sqes = (struct trinity_io_uring_sqe *)ring->sqes;
	sq_array = (unsigned int *)((char *)ring->sq_ring + ring->off_array);

	to_submit = RAND_RANGE(1, ring->sq_entries);
	if (to_submit > 4)
		to_submit = RAND_RANGE(1, 4);	/* usually small batches */

	for (idx = 0; idx < to_submit; idx++) {
		unsigned int sqe_idx = (tail + idx) & mask;

		fill_sqe(&sqes[sqe_idx]);
		sq_array[(tail + idx) & mask] = sqe_idx;
	}

	/* Publish the new tail. */
	__sync_synchronize();
	write_ring_u32(ring->sq_ring, ring->off_tail, tail + to_submit);

	rec->a2 = to_submit;
}

struct syscallentry syscall_io_uring_enter = {
	.name = "io_uring_enter",
	.group = GROUP_IO_URING,
	.num_args = 6,
	.argtype = { [0] = ARG_FD_IO_URING, [1] = ARG_RANGE, [2] = ARG_RANGE, [3] = ARG_OP, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "to_submit", [2] = "min_complete", [3] = "flags", [4] = "sig", [5] = "sigsz" },
	.arg_params[1].range.low = 1,
	.arg_params[1].range.hi = 128,
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.arg_params[3].list = ARGLIST(io_uring_enter_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_uring_enter,
	.rettype = RET_ZERO_SUCCESS,
};

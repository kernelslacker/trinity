/*
 *   SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit, u32, min_complete, u32, flags, const sigset_t __user *, sig, size_t, sigsz)
 */
#include <string.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"

#define IORING_ENTER_GETEVENTS		(1U << 0)
#define IORING_ENTER_SQ_WAKEUP		(1U << 1)
#define IORING_ENTER_SQ_WAIT		(1U << 2)
#define IORING_ENTER_EXT_ARG		(1U << 3)
#define IORING_ENTER_REGISTERED_RING	(1U << 4)
#define IORING_ENTER_ABS_TIMER		(1U << 5)
#define IORING_ENTER_EXT_ARG_REG	(1U << 6)
#define IORING_ENTER_NO_IOWAIT		(1U << 7)

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

/* Common opcodes from linux/io_uring.h */
#ifndef IORING_OP_NOP
#define IORING_OP_NOP		0
#define IORING_OP_READV		1
#define IORING_OP_WRITEV	2
#define IORING_OP_FSYNC		3
#define IORING_OP_READ_FIXED	4
#define IORING_OP_WRITE_FIXED	5
#define IORING_OP_POLL_ADD	6
#define IORING_OP_POLL_REMOVE	7
#define IORING_OP_SYNC_FILE_RANGE 8
#define IORING_OP_SENDMSG	9
#define IORING_OP_RECVMSG	10
#define IORING_OP_TIMEOUT	11
#define IORING_OP_TIMEOUT_REMOVE 12
#define IORING_OP_ACCEPT	13
#define IORING_OP_ASYNC_CANCEL	14
#define IORING_OP_LINK_TIMEOUT	15
#define IORING_OP_CONNECT	16
#define IORING_OP_FALLOCATE	17
#define IORING_OP_OPENAT	18
#define IORING_OP_CLOSE		19
#define IORING_OP_FILES_UPDATE	20
#define IORING_OP_STATX		21
#define IORING_OP_READ		22
#define IORING_OP_WRITE		23
#define IORING_OP_FADVISE	24
#define IORING_OP_MADVISE	25
#define IORING_OP_SEND		26
#define IORING_OP_RECV		27
#define IORING_OP_OPENAT2	28
#define IORING_OP_EPOLL_CTL	29
#define IORING_OP_SPLICE	30
#define IORING_OP_PROVIDE_BUFFERS 31
#define IORING_OP_REMOVE_BUFFERS 32
#define IORING_OP_TEE		33
#define IORING_OP_SHUTDOWN	34
#define IORING_OP_RENAMEAT	35
#define IORING_OP_UNLINKAT	36
#define IORING_OP_MKDIRAT	37
#define IORING_OP_SYMLINKAT	38
#define IORING_OP_LINKAT	39
#define IORING_OP_MSG_RING	40
#define IORING_OP_FSETXATTR	41
#define IORING_OP_SETXATTR	42
#define IORING_OP_FGETXATTR	43
#define IORING_OP_GETXATTR	44
#define IORING_OP_SOCKET	45
#define IORING_OP_URING_CMD	46
#define IORING_OP_SEND_ZC	47
#define IORING_OP_SENDMSG_ZC	48
#define IORING_OP_READ_MULTISHOT 49
#define IORING_OP_WAITID	50
#define IORING_OP_FUTEX_WAIT	51
#define IORING_OP_FUTEX_WAKE	52
#define IORING_OP_FUTEX_WAITV	53
#define IORING_OP_FIXED_FD_INSTALL 54
#define IORING_OP_FTRUNCATE	55
#define IORING_OP_BIND		56
#define IORING_OP_LISTEN	57
#define IORING_OP_RECV_ZC	58
#define IORING_OP_EPOLL_WAIT	59
#define IORING_OP_READV_FIXED	60
#define IORING_OP_WRITEV_FIXED	61
#define IORING_OP_PIPE		62
#define IORING_OP_LAST		63
#endif

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
	memset(sqe, 0, sizeof(*sqe));

	/* Pick an opcode: mostly valid, occasionally garbage. */
	if (ONE_IN(8))
		sqe->opcode = rand() & 0xff;
	else
		sqe->opcode = rand() % IORING_OP_LAST;

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
	.low2range = 1,
	.hi2range = 128,
	.low3range = 1,
	.hi3range = 128,
	.arg4list = ARGLIST(io_uring_enter_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_uring_enter,
};

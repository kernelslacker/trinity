/*
 *   SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit, u32, min_complete, u32, flags, const sigset_t __user *, sig, size_t, sigsz)
 */
#include "sanitise.h"

#define IORING_ENTER_GETEVENTS		(1U << 0)
#define IORING_ENTER_SQ_WAKEUP		(1U << 1)
#define IORING_ENTER_SQ_WAIT		(1U << 2)
#define IORING_ENTER_EXT_ARG		(1U << 3)
#define IORING_ENTER_REGISTERED_RING	(1U << 4)
#define IORING_ENTER_ABS_TIMER		(1U << 5)
#define IORING_ENTER_EXT_ARG_REG	(1U << 6)

static unsigned long io_uring_enter_flags[] = {
	IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAKEUP,
	IORING_ENTER_SQ_WAIT, IORING_ENTER_EXT_ARG,
	IORING_ENTER_REGISTERED_RING, IORING_ENTER_ABS_TIMER,
	IORING_ENTER_EXT_ARG_REG,
};

struct syscallentry syscall_io_uring_enter = {
	.name = "io_uring_enter",
	.group = GROUP_IO_URING,
	.num_args = 6,
	.arg1name = "fd",
	.arg1type = ARG_FD_IO_URING,
	.arg2name = "to_submit",
	.arg2type = ARG_RANGE,
	.low2range = 1,
	.hi2range = 128,
	.arg3name = "min_complete",
	.arg3type = ARG_RANGE,
	.low3range = 1,
	.hi3range = 128,
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(io_uring_enter_flags),
	.arg5name = "sig",
	.arg5type = ARG_ADDRESS,
	.arg6name = "sigsz",
	.arg6type = ARG_LEN,
	.flags = NEED_ALARM,
};

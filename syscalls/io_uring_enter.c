/*
 *   SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit, u32, min_complete, u32, flags, const sigset_t __user *, sig, size_t, sigsz)
 */
#include "sanitise.h"

#define IORING_ENTER_GETEVENTS  (1U << 0)
#define IORING_ENTER_SQ_WAKEUP  (1U << 1)

static unsigned long io_uring_enter_flags[] = {
	IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAKEUP,
};

struct syscallentry syscall_io_uring_enter = {
	.name = "io_uring_enter",
	.num_args = 6,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "to_submit",
	.arg3name = "min_complete",
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(io_uring_enter_flags),
	.arg5name = "sig",
	.arg5type = ARG_ADDRESS,
	.arg6name = "sigsz",
};

/*
 *   SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode, void __user *, arg, unsigned int, nr_args)
 */
#include "sanitise.h"

#define IORING_REGISTER_BUFFERS         0
#define IORING_UNREGISTER_BUFFERS       1
#define IORING_REGISTER_FILES           2
#define IORING_UNREGISTER_FILES         3
#define IORING_REGISTER_EVENTFD         4
#define IORING_UNREGISTER_EVENTFD       5

static unsigned long io_uring_register_opcodes[] = {
	IORING_REGISTER_BUFFERS,
	IORING_UNREGISTER_BUFFERS,
	IORING_REGISTER_FILES,
	IORING_UNREGISTER_FILES,
	IORING_REGISTER_EVENTFD,
	IORING_UNREGISTER_EVENTFD,
};

struct syscallentry syscall_io_uring_register = {
	.name = "io_uring_register",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "opcode",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(io_uring_register_opcodes),
	.arg3name = "arg",
	.arg3type = ARG_ADDRESS,
	.arg4name = "nr_args",
};

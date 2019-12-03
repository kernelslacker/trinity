/*
 * SYSCALL_DEFINE4(rseq, struct rseq __user *, rseq, u32, rseq_len,
 *                 int, flags, u32, sig)
 */

#include "syscall.h"

enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

static unsigned long rseq_flags[] = {
	RSEQ_FLAG_UNREGISTER,
};

struct syscallentry syscall_rseq = {
	.name = "rseq,",
	.num_args = 4,

	.arg1name = "rseq",
	.arg2name = "rseq_len",
	.arg2type = ARG_LEN,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(rseq_flags),
	.arg4name = "sig",
};

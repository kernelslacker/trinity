/*
 * SYSCALL_DEFINE0(rseq_slice_yield)
 */
#include "sanitise.h"

struct syscallentry syscall_rseq_slice_yield = {
	.name = "rseq_slice_yield",
	.num_args = 0,
	.group = GROUP_PROCESS,
};

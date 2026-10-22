/*
   asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on)
 */
#include "sanitise.h"

struct syscallentry syscall_ioperm = {
	.name = "ioperm",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "from", [1] = "num", [2] = "turn_on" },
	/*
	 * ksys_ioperm() returns EINVAL unless num > 0 and
	 * from + num <= IO_BITMAP_BITS (65536).  Ranges that span the port
	 * space put draws on both sides of that bound; a raw 64-bit draw
	 * is almost always far past it.  turn_on is only tested for
	 * non-zero.
	 */
	.arg_params[0].range.low = 0, .arg_params[0].range.hi = 0xffff,
	.arg_params[1].range.low = 0, .arg_params[1].range.hi = 0x10000,
	.arg_params[2].range.low = 0, .arg_params[2].range.hi = 1,
	.flags = AVOID_SYSCALL | NEEDS_ROOT,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE2(swapon, const char __user *, specialfile, int, swap_flags
 */
#include <sys/swap.h>
#include "sanitise.h"
#include "compat.h"

struct syscallentry syscall_swapon = {
	.name = "swapon",
	.num_args = 2,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.arg2name = "swap_flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 2,
		.values = { SWAP_FLAG_PREFER, SWAP_FLAG_DISCARD },
	},
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE1(swapoff, const char __user *, specialfile)
 */
struct syscallentry syscall_swapoff = {
	.name = "swapoff",
	.num_args = 1,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.group = GROUP_VFS,
};

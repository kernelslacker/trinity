/*
 * SYSCALL_DEFINE2(swapon, const char __user *, specialfile, int, swap_flags
 */
#include <sys/swap.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long swapon_flags[] = {
	SWAP_FLAG_PREFER, SWAP_FLAG_DISCARD,
};

struct syscallentry syscall_swapon = {
	.name = "swapon",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LIST },
	.argname = { [0] = "path", [1] = "swap_flags" },
	.arg2list = ARGLIST(swapon_flags),
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};

/*
 * SYSCALL_DEFINE1(swapoff, const char __user *, specialfile)
 */
struct syscallentry syscall_swapoff = {
	.name = "swapoff",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "path" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};

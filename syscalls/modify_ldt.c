/*
 * asmlinkage int sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_modify_ldt = {
	.name = "modify_ldt",
	.num_args = 3,
	.arg1name = "func",
	.arg2name = "ptr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "bytecount",
	.arg3type = ARG_LEN,
};

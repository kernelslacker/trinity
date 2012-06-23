/*
   asmlinkage long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len)

   same as fadvise64 but with other argument order.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_arm_fadvise64_64 = {
	.name = "arm_fadvise64_64",
	.num_args = 4,
	.arg1name = "fd",
	.arg2name = "advice",
	.arg3name = "offset",
	.arg4name = "len",
};

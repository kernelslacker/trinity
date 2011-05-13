/*
   long sys_arch_prctl(int code, unsigned long addr)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_arch_prctl = {
	.name = "arch_prctl",
	.num_args = 2,
	.arg1name = "code",
	.arg2name = "addr",
};

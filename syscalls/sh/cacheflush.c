/*
 * arch/sh/kernel/sys_sh.c:
 * asmlinkage int sys_cacheflush(unsigned long addr, unsigned long len, int op);
 */

#include "trinity.h"
#include "sanitise.h"

#include <asm/cachectl.h>

struct syscall syscall_sh_cacheflush = {
	.name = "sh_cacheflush",
	.num_args = 3,
	.argname = { [0] = "addr", [1] = "len", [2] = "op" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_LIST },
	.arg3list = {
		.num = 4,
		.values = {
			CACHEFLUSH_D_INVAL,
			CACHEFLUSH_D_WB,
			CACHEFLUSH_D_PURGE,
			CACHEFLUSH_I,
		},
	},
};

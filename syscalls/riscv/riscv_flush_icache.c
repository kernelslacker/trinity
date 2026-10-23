/*
 * SYSCALL_DEFINE3(riscv_flush_icache, uintptr_t, start, uintptr_t, end,
 *		uintptr_t, flags)
 *
 * flags: SYS_RISCV_FLUSH_ICACHE_LOCAL (1) flushes only the calling hart;
 * any other bit is -EINVAL.
 */
#if defined(__riscv) && __riscv_xlen == 64

#include "sanitise.h"

static unsigned long flush_icache_flags[] = {
	0, 1,	/* SYS_RISCV_FLUSH_ICACHE_LOCAL */
};

struct syscallentry syscall_riscv_flush_icache = {
	.name = "riscv_flush_icache",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS,
		     [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "end", [2] = "flags" },
	.arg_params[2].list = ARGLIST(flush_icache_flags),
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};

#endif

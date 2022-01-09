/*
 * SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	 int, options, struct rusage __user *, ru)
 */
#include "sanitise.h"

#ifndef SYS_RISCV_FLUSH_ICACHE_LOCAL
#define SYS_RISCV_FLUSH_ICACHE_LOCAL 1UL
#endif

static unsigned long riscv_flush_icache_flags[] = {
	SYS_RISCV_FLUSH_ICACHE_LOCAL,
};

struct syscallentry syscall_riscv_flush_icache = {
	.name = "riscv_flush_icache",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "end",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(riscv_flush_icache_flags),
};

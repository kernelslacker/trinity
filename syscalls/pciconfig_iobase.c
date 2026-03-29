/*
   asmlinkage long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn);
 */
#include "sanitise.h"

#ifndef IOBASE_BRIDGE_NUMBER
#define IOBASE_BRIDGE_NUMBER	0
#define IOBASE_MEMORY		1
#define IOBASE_IO		2
#define IOBASE_ISA_IO		3
#define IOBASE_ISA_MEM		4
#endif

static unsigned long pciconfig_iobase_which[] = {
	IOBASE_BRIDGE_NUMBER, IOBASE_MEMORY, IOBASE_IO,
	IOBASE_ISA_IO, IOBASE_ISA_MEM,
};

struct syscallentry syscall_pciconfig_iobase = {
	.name = "pciconfig_iobase",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "which", [1] = "bus", [2] = "devfn" },
	.arg_params[0].list = ARGLIST(pciconfig_iobase_which),
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 255,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 255,
	.group = GROUP_PROCESS,
};

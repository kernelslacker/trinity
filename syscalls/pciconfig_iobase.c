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
	.arg1name = "which",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(pciconfig_iobase_which),
	.arg2name = "bus",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 255,
	.arg3name = "devfn",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 255,
	.group = GROUP_PROCESS,
};

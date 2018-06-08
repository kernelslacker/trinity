/*
   asmlinkage long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn);
 */
#include "sanitise.h"

struct syscallentry syscall_pciconfig_iobase = {
	.name = "pciconfig_iobase",
	.num_args = 3,
	.arg1name = "which",
	.arg2name = "bus",
	.arg3name = "devfn",
};

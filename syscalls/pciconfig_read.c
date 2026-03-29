/*
   sys_pciconfig_read (unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len,
                       void *buf)
 */
#include "sanitise.h"

struct syscallentry syscall_pciconfig_read = {
	.name = "pciconfig_read",
	.num_args = 5,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE, [3] = ARG_LEN, [4] = ARG_ADDRESS },
	.argname = { [0] = "bus", [1] = "dfn", [2] = "off", [3] = "len", [4] = "buf" },
	.low1range = 0, .hi1range = 255,
	.low2range = 0, .hi2range = 255,
	.low3range = 0, .hi3range = 4095,
	.group = GROUP_PROCESS,
};

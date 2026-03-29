/*
   sys_pciconfig_write (unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len,
                        void *buf)
 */
#include "sanitise.h"

struct syscallentry syscall_pciconfig_write = {
	.name = "pciconfig_write",
	.num_args = 5,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE, [3] = ARG_LEN, [4] = ARG_ADDRESS },
	.argname = { [0] = "bus", [1] = "dfn", [2] = "off", [3] = "len", [4] = "buf" },
	.arg_params[0].range.low = 0, .arg_params[0].range.hi = 255,
	.arg_params[1].range.low = 0, .arg_params[1].range.hi = 255,
	.arg_params[2].range.low = 0, .arg_params[2].range.hi = 4095,
	.group = GROUP_PROCESS,
};

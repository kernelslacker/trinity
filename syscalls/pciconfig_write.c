/*
   sys_pciconfig_write (unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len,
                        void *buf)
 */
#include "sanitise.h"

struct syscallentry syscall_pciconfig_write = {
	.name = "pciconfig_write",
	.num_args = 5,
	.argtype = { [3] = ARG_LEN, [4] = ARG_ADDRESS },
	.argname = { [0] = "bus", [1] = "dfn", [2] = "off", [3] = "len", [4] = "buf" },
	.group = GROUP_PROCESS,
};

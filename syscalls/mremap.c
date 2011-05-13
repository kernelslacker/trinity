/*
 * SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
	unsigned long, new_len, unsigned long, flags,
	unsigned long, new_addr)
 */

#include <linux/mman.h>

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mremap = {
	.name = "mremap",
	.num_args = 5,
	.sanitise = sanitise_mremap,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "old_len",
	.arg2type = ARG_LEN,
	.arg3name = "new_len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
        .arg4type = ARG_LIST,
        .arg4list = {
		.num = 2,
		.values = { MREMAP_MAYMOVE, MREMAP_FIXED },
        },
	.arg5name = "new_addr",
	.arg5type = ARG_ADDRESS,
};

/*
 * SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
	unsigned long, new_len, unsigned long, flags,
	unsigned long, new_addr)
 */

#include <linux/mman.h>
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "arch.h"

/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 *
 * This syscall is a bit of a nightmare to fuzz as we -EINVAL all over the place.
 * It might be more useful once we start passing around valid maps instead of just
 * trying random addresses.
 */

static void sanitise_mremap(
		unsigned long *addr,
		__unused__ unsigned long *old_len,
		unsigned long *new_len,
		unsigned long *flags,
		__unused__ unsigned long *new_addr,
		__unused__ unsigned long *a6)
{
	unsigned long mask = ~(page_size-1);

retry_addr:
	*addr &= mask;

	if (*addr == 0)
		*addr = (unsigned long) get_address();
	goto retry_addr;

	if (*flags & MREMAP_FIXED) {
		// Can't be fixed, and maymove.
		*flags &= ~MREMAP_MAYMOVE;

		*new_len &= TASK_SIZE-*new_len;
	}
}

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
	.group = GROUP_VM,
};

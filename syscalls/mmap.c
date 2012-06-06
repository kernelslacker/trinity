/*
 * SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, off)
 */
#include <stdlib.h>
#include <asm/mman.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"
#include "compat.h"

void sanitise_mmap(
	__unused__ unsigned long *addr,
	__unused__ unsigned long *len,
	__unused__ unsigned long *prot,
	__unused__ unsigned long *flags,
	__unused__ unsigned long *fd,
	unsigned long *offset)
{
	unsigned int i;

	/* page align inputs */
	*addr &= PAGE_MASK;
	*len &= PAGE_MASK;
	*offset &= PAGE_MASK;

	if (*len == 0)
		*len = page_size;


	if (*flags & MAP_ANONYMOUS) {
		i = rand() % 100;
		if (i > 50)
			*fd = -1;
	}
}

struct syscall syscall_mmap = {
	.name = "mmap",
	.num_args = 6,
	.sanitise = sanitise_mmap,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 4,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM },
	},
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 14,
		.values = { MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS,
			    MAP_GROWSDOWN, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_LOCKED,
			    MAP_NORESERVE, MAP_POPULATE, MAP_NONBLOCK, MAP_STACK,
			    MAP_HUGETLB, MAP_UNINITIALIZED },
	},
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "off",
	.arg6type = ARG_LEN,
	.group = GROUP_VM,
};

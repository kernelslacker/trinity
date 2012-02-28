/*
 * SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
	 unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
 */
#include <asm/mman.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"

static void sanitise_remap_file_pages(
		unsigned long *start,
		unsigned long *size,
		__unused__ unsigned long *a3,
		__unused__ unsigned long *a4,
		unsigned long *pgoff,
		__unused__ unsigned long *a6)
{

	*start = *start & PAGE_MASK;
	*size = *size & PAGE_MASK;


retry_size:
	if (*start + *size <= *start) {
		*size = get_interesting_32bit_value() & PAGE_MASK;
		goto retry_size;
	}

retry_pgoff:
	if (*pgoff + (*size >> PAGE_SHIFT) < *pgoff) {
		*pgoff = get_interesting_value();
		goto retry_pgoff;
	}

retry_pgoff_bits:
	if (*pgoff + (*size >> PAGE_SHIFT) >= (1UL << PTE_FILE_MAX_BITS)) {
		*pgoff = (*pgoff >> 1);
		goto retry_pgoff_bits;
	}
}

struct syscall syscall_remap_file_pages = {
	.name = "remap_file_pages",
	.sanitise = sanitise_remap_file_pages,
	.num_args = 5,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg4name = "pgoff",
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = {
		.num = 1,
		.values = { MAP_NONBLOCK },
	},
	.group = GROUP_VM,
};

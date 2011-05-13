/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <asm/mman.h>

#include "trinity.h"
#include "sanitise.h"

static void sanitise_mprotect(
		unsigned long *start,
		unsigned long *len,
		__unused__ unsigned long *prot,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	unsigned long end;
	unsigned long mask = ~(page_size-1);

	*start &= mask;

retry_end:
	end = *start + *len;
	if (*len == 0) {
		*len = rand64();
		goto retry_end;
	}

	/* End must be after start */
	if (end <= *start) {
		*len = rand64();
		goto retry_end;
	}
}

struct syscall syscall_mprotect = {
	.name = "mprotect",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 6,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM, PROT_GROWSDOWN, PROT_GROWSUP },
	},
	.sanitise = sanitise_mprotect,
};

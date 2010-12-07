#include <asm/mman.h>
#include "scrashme.h"
#include "sanitise.h"

/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */

void sanitise_mprotect(
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

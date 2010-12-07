#include <asm/mman.h>
#include "scrashme.h"
#include "sanitise.h"

/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */

void sanitise_mprotect(
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	unsigned long end;
	unsigned long mask = ~(page_size-1);
	int grows;

	*a1 &= mask;

retry_end:
	end = *a1 + *a2;
	if (*a2 == 0) {
		*a2 = rand64();
		goto retry_end;
	}

	/* End must be after start */
	if (end <= *a1) {
		*a2 = rand64();
		goto retry_end;
	}

retry_prot:
	*a3 &= ((PROT_GROWSDOWN|PROT_GROWSUP) | ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM));

	grows = *a3 & (PROT_GROWSDOWN|PROT_GROWSUP);

	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) { /* can't be both */
		*a3 &= rand64();
		goto retry_prot;
	}
}

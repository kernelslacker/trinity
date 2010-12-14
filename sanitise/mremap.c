#include <linux/mman.h>
#include <stdlib.h>
#include "scrashme.h"
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

void sanitise_mremap(
		unsigned long *addr,
		__unused__ unsigned long *old_len,
		unsigned long *new_len,
		unsigned long *flags,
		unsigned long *new_addr,
		__unused__ unsigned long *a6)
{
	unsigned long mask = ~(page_size-1);
	int i;

	*flags = rand64() & (MREMAP_FIXED | MREMAP_MAYMOVE);

	*addr &= mask;

	i=0;
	if (*flags & MREMAP_FIXED) {
		// Can't be fixed, and maymove.
		*flags &= ~MREMAP_MAYMOVE;

		*new_len &= TASK_SIZE-*new_len;
retry_addr:
		*new_addr &= mask;
		if ((*new_addr <= *addr) && (*new_addr+*new_len) > *addr) {
			*new_addr -= *addr - (rand() % 1000);
			goto retry_addr;
		}

		if ((*addr <= *new_addr) && (*addr+*old_len) > *new_addr) {
			*new_addr += *addr - (rand() % 1000);
			goto retry_addr;
		}

		/* new_addr > TASK_SIZE - new_len*/
retry_tasksize_end:
		if (*new_addr > TASK_SIZE - *new_len) {
			*new_addr >>= 1;
			i++;
			goto retry_tasksize_end;
		}
		printf("retried_tasksize_end: %d\n", i);
	}

	//TODO: Lots more checks here.
	// We already check for overlap in do_mremap()
}

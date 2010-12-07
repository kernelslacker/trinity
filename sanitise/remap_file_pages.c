#include "scrashme.h"
#include "sanitise.h"
#include "arch.h"

void sanitise_remap_file_pages(
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

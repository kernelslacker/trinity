#include "trinity.h"
#include "arch.h"

void sanitise_mmap(
	__unused__ unsigned long *a1,
	__unused__ unsigned long *a2,
	__unused__ unsigned long *a3,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	unsigned long *offset)
{
	*offset &= PAGE_MASK;
}

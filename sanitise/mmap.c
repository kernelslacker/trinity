#include "scrashme.h"
#include "arch.h"

void sanitise_mmap(
	__unused__ unsigned long *a1,
	__unused__ unsigned long *a2,
	__unused__ unsigned long *a3,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	unsigned long *a6)
{
	*a6 &= ~PAGE_MASK;
}

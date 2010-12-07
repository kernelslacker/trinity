#include "scrashme.h"

void sanitise_fanotify_mark(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	*a3 &= 0xffffffff;
}

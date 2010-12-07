#include <stdlib.h>
#include "scrashme.h"
#include "sanitise.h"

void sanitise_ioctl(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	int i;

	*a2 = rand() % 0xffff;
	i = rand() % 3;
	if (i == 1)
		*a2 |= 0x80044000;
	if (i == 2)
		*a2 |= 0xc0044000;

	*a3 = (rand() & 0xffffffff);
	i = rand() % 4;
	if (i == 1)
		*a3 &= 0xffff;
	if (i == 2)
		*a3 &= 0xffffff;
	if (i == 3)
		*a3 = get_interesting_32bit_value();

}

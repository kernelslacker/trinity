#include <stdlib.h>
#include "scrashme.h"
#include "sanitise.h"

void sanitise_ioctl(
		__unused__ unsigned long *fd,
		unsigned long *cmd,
		unsigned long *arg,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	int i;
	*cmd = 0;

	/* set up to 8 random bits to try and fake a cmd. */
	for (i=0; i < (rand() % 8); i++)
		*cmd |= 1L << (rand() % 32);

	/* the argument could mean anything, because ioctl sucks like that. */
	if (!(rand() % 3))
		*arg = get_interesting_32bit_value();
	else
		*arg = (unsigned long)page_rand;
}

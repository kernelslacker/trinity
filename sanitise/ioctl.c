#include <stdlib.h>
#include "scrashme.h"
#include "sanitise.h"

#include "ioctls.h"

void sanitise_ioctl(
		__unused__ unsigned long *fd,
		unsigned long *cmd,
		unsigned long *arg,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	int i;

	/* To begin, we choose from one of the known ioctls*/
	*cmd = ioctllist[rand() % NR_IOCTLS].request;

	/* One time in 50, mangle it. */
	if ((rand() % 50)==0) {

		/* mangle the cmd by ORing up to 4 random bits */
		for (i=0; i < (rand() % 4); i++)
			*cmd |= 1L << (rand() % 32);

		/* mangle the cmd by ANDing up to 4 random bits */
		for (i=0; i < (rand() % 4); i++)
			*cmd &= 1L << (rand() % 32);
	}

	/* the argument could mean anything, because ioctl sucks like that. */
	switch (rand() % 10) {
	case 0:	*arg = get_interesting_32bit_value();
		break;
	case 1 ... 5:
		*arg = (unsigned long)page_rand;
		break;
	case 6 ... 9:
		*arg = (unsigned long)page_rand;
		/* TODO: manufacture a random struct */
		break;
	}
}

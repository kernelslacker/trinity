#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"

/*
 * asmlinkage ssize_t sys_write(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_write(
		__unused__ unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	unsigned long newsize = *a3 & 0xffff;
	void *newbuffer;

retry:
	newbuffer = malloc(newsize);
	if (newbuffer == NULL) {
		newsize >>= 1;
		goto retry;
	}

	free(filebuffer);
	filebuffer = newbuffer;
	filebuffersize = newsize;

	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
}

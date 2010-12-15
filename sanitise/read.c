#include <stdlib.h>
#include <string.h>
#include "trinity.h"
#include "sanitise.h"

/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_read(
		__unused__ unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	unsigned long newsize = (unsigned int) *a3 >> 16;

	if (filebuffer != NULL) {
		if (filebuffersize < newsize) {
			free(filebuffer);
			filebuffersize = 0;
			filebuffer = NULL;
		}
	}

	if (filebuffer == NULL) {
retry:
		filebuffer = malloc(newsize);
		if (filebuffer == NULL) {
			newsize >>= 1;
			goto retry;
		}
		filebuffersize = newsize;
	}
	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
	memset(filebuffer, 0, newsize);
}

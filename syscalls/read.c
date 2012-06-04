/*
 * SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 */

#include <stdlib.h>
#include <string.h>
#include "trinity.h"
#include "sanitise.h"

/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
static void sanitise_read(
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

struct syscall syscall_read = {
	.name = "read",
	.num_args = 3,
	.sanitise = sanitise_read,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
};

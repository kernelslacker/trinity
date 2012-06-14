/*
 * SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 */

#include <stdlib.h>
#include <string.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
static void sanitise_read(int childno)
{
	unsigned long newsize = (unsigned int) shm->a3[childno] & 0xffffffff;

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
	shm->a2[childno] = (unsigned long) filebuffer;
	shm->a3[childno] = newsize;
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

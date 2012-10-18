/*
 * SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
 */
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

/*
 * asmlinkage ssize_t sys_write(unsigned int fd, char __user * buf, size_t count)
 */
static void sanitise_write(int childno)
{
	unsigned long newsize = shm->a3[childno] & 0xfffff;
	void *newbuffer;

retry:
	newbuffer = malloc(newsize);
	if (newbuffer == NULL) {
		newsize >>= 1;
		if (newsize == 0)
			return;		// FIXME: Need a better way to indicate "we're fucked".
		if (shm->exit_reason != STILL_RUNNING)
			return;
		goto retry;
	}

	if (filebuffer != NULL)
		free(filebuffer);
	filebuffer = newbuffer;
	filebuffersize = newsize;

	shm->a2[childno] = (unsigned long) filebuffer;
	shm->a3[childno] = newsize;
}

struct syscall syscall_write = {
	.name = "write",
	.num_args = 3,
	.sanitise = sanitise_write,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.flags = NEED_ALARM,
};

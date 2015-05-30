/* memfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "log.h"
#include "memfd.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static int memfd_create(__unused__ const char *uname, __unused__ unsigned int flag)
{
#ifdef SYS_memfd_create
	return syscall(SYS_memfd_create, uname, flag);
#else
	return -ENOSYS;
#endif
}

static int open_memfd_fds(void)
{
	unsigned int i;
	unsigned int count = 0;

	shm->memfd_fds[0] = memfd_create("memfd1", 0);
	shm->memfd_fds[1] = memfd_create("memfd2", MFD_CLOEXEC);
	shm->memfd_fds[2] = memfd_create("memfd3", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	shm->memfd_fds[3] = memfd_create("memfd4", MFD_ALLOW_SEALING);

	for (i = 0; i < MAX_MEMFD_FDS; i++) {
		if (shm->memfd_fds[i] > 0) {
			output(2, "fd[%d] = memfd\n", shm->memfd_fds[i]);
			count++;
		}
	}

	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_memfd_fd(void)
{
	return shm->memfd_fds[rand() % MAX_MEMFD_FDS];
}

const struct fd_provider memfd_fd_provider = {
	.name = "memfd",
	.enabled = TRUE,
	.open = &open_memfd_fds,
	.get = &get_rand_memfd_fd,
};

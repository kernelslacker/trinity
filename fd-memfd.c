/* memfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "memfd.h"
#include "fd.h"
#include "log.h"
#include "net.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

// FIXME: Keep all this here until glibc supports it.
#ifndef SYS_memfd_create
#ifdef __x86_64__
#define SYS_memfd_create 319
#endif
#ifdef __i386__
#define SYS_memfd_create 356
#endif
#ifdef __sparc__
#define SYS_memfd_create 348
#endif
#endif

static int memfd_create(const char *uname, unsigned int flag)
{
	return syscall(SYS_memfd_create, uname, flag);
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fd.h"
#include "shm.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "testfile.h"

static int open_testfile(unsigned int i)
{
	char *filename;
	int fd;
	int flags = 0;

	filename = zmalloc(64);
	sprintf(filename, "trinity-testfile%d", i);

	unlink(filename);

	if (rand_bool())
		flags |= O_DIRECT;

	if (rand_bool())
		flags |= O_DSYNC;

	if (rand_bool())
		flags |= O_SYNC;

	fd = open(filename, O_CREAT | flags, 0666);
	if (fd == -1)
		outputerr("Couldn't open testfile %d for writing.\n", i);
	else
		output(2, "fd[%d] = testfile%d (flags:%x)\n", fd, i, flags);	//TODO: decode flags

	free(filename);

	return fd;
}

static int open_testfile_fds(void)
{
	unsigned int i = 0;

	while (i < MAX_TESTFILE_FDS) {
		int fd;

		fd = open_testfile(i + 1);
		if (fd == -1)
			return FALSE;

		shm->testfile_fds[i] = fd;
		i++;
	}

	return TRUE;
}

static int get_rand_testfile_fd(void)
{
	return shm->testfile_fds[rand() % MAX_TESTFILE_FDS];
}

struct fd_provider testfile_fd_provider = {
	.open = &open_testfile_fds,
	.get = &get_rand_testfile_fd,
};

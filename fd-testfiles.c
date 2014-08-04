#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "fd.h"
#include "shm.h"
#include "log.h"
#include "sanitise.h"
#include "testfile.h"

static int open_testfile(unsigned int i)
{
	FILE *file;
	char *filename;

	filename = zmalloc(64);
	sprintf(filename, "trinity-testfile%d", i);

	unlink(filename);

	file = fopen(filename, "w");
	if (!file)
		outputerr("Couldn't open testfile %d for writing.\n", i);

	free(filename);

	return fileno(file);
}

static int open_testfile_fds(void)
{
	unsigned int i = 0;

	while (i < MAX_TESTFILE_FDS) {
		int fd;

		fd = open_testfile(i + 1);
		if (fd != -1) {
			shm->testfile_fds[i] = fd;
			output(2, "fd[%d] = testfile%d\n", fd, i + 1);
			i++;
		}
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

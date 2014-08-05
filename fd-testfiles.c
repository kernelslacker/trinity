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

static int open_with_fopen(char *filename, int i)
{
	FILE *file;
	int fd = -1;

	file = fopen(filename, "w");
	if (!file)
		outputerr("Couldn't fopen() testfile %d for writing.\n", i);
	else {
		fd = fileno(file);
		output(2, "fd[%d] = fopen(testfile%d)\n", fd, i);
	}
	return fd;
}

static int open_with_open(char *filename, int flags, int i)
{
	int fd;

	unlink(filename);

	fd = open(filename, O_CREAT | flags, 0666);
	if (fd == -1)
		outputerr("Couldn't open testfile %d for writing.\n", i);
	else
		output(2, "fd[%d] = open(testfile%d, flags:%x)\n", fd, i, flags);	//TODO: decode flags

	return fd;
}

static int open_testfile(unsigned int i)
{
	char *filename;
	int fd;
	int flags = 0;

	if (rand_bool())
		flags |= O_DIRECT;

	if (rand_bool())
		flags |= O_DSYNC;

	if (rand_bool())
		flags |= O_SYNC;

	filename = zmalloc(64);
	sprintf(filename, "trinity-testfile%d", i);

	if (rand_bool())
		fd = open_with_fopen(filename, i);
	else
		fd = open_with_open(filename, flags, i);

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

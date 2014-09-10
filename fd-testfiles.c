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
#include "files.h"
#include "shm.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "testfile.h"

static int open_testfile(char *filename)
{
	int fd;
	int flags = 0;

	/* file might be around from an earlier run, nuke it. */
	(void) unlink(filename);

	if (rand_bool())
		flags |= O_DIRECT;

	if (rand_bool())
		flags |= O_DSYNC;

	if (rand_bool())
		flags |= O_SYNC;

	if (rand_bool()) {
		fd = open_with_fopen(filename, O_RDWR);
		if (fd != -1)
			output(2, "fd[%d] = fopen(\"%s\", O_RDWR)\n", fd, filename);
	} else {
		fd = open(filename, O_CREAT | flags, 0666);
		if (fd != -1)
			output(2, "fd[%d] = open(\"%s\", flags:%x)\n", fd, filename, flags);	//TODO: decode flags
	}

	return fd;
}

static int open_testfile_fds(void)
{
	char *filename;
	unsigned int i = 1;
	unsigned int fails = 0;

	filename = zmalloc(64);

	while (i < MAX_TESTFILE_FDS) {
		int fd;

		sprintf(filename, "trinity-testfile%d", i);

		fd = open_testfile(filename);
		if (fd != -1) {
			shm->testfile_fds[i - 1] = fd;
			i++;
			fails = 0;
		} else {
			fails++;
			if (fails == 100) {
				output(2, "testfile creation is failing a lot. last error:%s\n", strerror(errno));
			}
		}
	}

	free(filename);
	return TRUE;
}

static int get_rand_testfile_fd(void)
{
	return shm->testfile_fds[rand() % MAX_TESTFILE_FDS];
}

const struct fd_provider testfile_fd_provider = {
	.name = "testfile",
	.enabled = TRUE,
	.open = &open_testfile_fds,
	.get = &get_rand_testfile_fd,
};

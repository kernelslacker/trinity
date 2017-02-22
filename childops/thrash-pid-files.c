/*
 * Simple child to hammer on every child pids /proc/<pid>/ files.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"	// page_size
#include "child.h"
#include "pathnames.h"
#include "pids.h"
#include "random.h"
#include "shm.h"

static void read_pid_files(pid_t pid, char *buffer)
{
	int fd;
	int ret;
	int n;
	char filename[128];

	n = sprintf(filename, "/proc/%d/status", pid);
	filename[n] = 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return;

	ret = read(fd, buffer, page_size);
	if (ret < 0) {
		close(fd);
		return;
	}

	close(fd);
}

bool thrash_pidfiles(__unused__ struct childdata *child)
{
	unsigned int i;
	char *buffer;

	buffer = zmalloc(page_size);

	for_each_child(i) {
		pid_t pid = pids[i];

		if (pid != EMPTY_PIDSLOT)
			read_pid_files(pid, buffer);

		if (shm->exit_reason != STILL_RUNNING) {
			free(buffer);
			return FALSE;
		}

		clock_gettime(CLOCK_MONOTONIC, &child->tp);
	}

	free(buffer);
	return TRUE;
}

/* Pipe FD related functions. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "fd.h"
#include "files.h"
#include "log.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static unsigned int offset = 0;

static void open_pipe_pair(unsigned int flags)
{
	int pipes[2];

	if (pipe2(pipes, flags) < 0) {
		perror("pipe fail.\n");
		return;
	}

	shm->pipe_fds[offset] = pipes[0];
	shm->pipe_fds[offset + 1] = pipes[1];

	output(2, "fd[%d] = pipe([reader] flags:%x)\n", pipes[0], flags);
	output(2, "fd[%d] = pipe([writer] flags:%x)\n", pipes[1], flags);

	offset += 2;
}


static int open_pipes(void)
{
	open_pipe_pair(0);
	open_pipe_pair(O_NONBLOCK);
	open_pipe_pair(O_CLOEXEC);
	open_pipe_pair(O_NONBLOCK | O_CLOEXEC);

	return TRUE;
}

static int get_rand_pipe_fd(void)
{
	return shm->pipe_fds[rand() % MAX_PIPE_FDS];
}

const struct fd_provider pipes_fd_provider = {
	.name = "pipes",
	.enabled = TRUE,
	.open = &open_pipes,
	.get = &get_rand_pipe_fd,
};

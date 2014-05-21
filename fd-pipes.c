/* Pipe FD related functions. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "fd.h"
#include "files.h"
#include "log.h"
#include "net.h"
#include "params.h"
#include "pids.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static int open_pipes(void)
{
	int pipes[2];
	unsigned int i;

	for (i = 0; i < MAX_PIPE_FDS; i+=2) {
		if (pipe(pipes) < 0) {
			perror("pipe fail.\n");
			return FALSE;
		}
		shm->pipe_fds[i] = pipes[0];
		shm->pipe_fds[i+1] = pipes[1];

		output(2, "fd[%d] = pipe\n", shm->pipe_fds[i]);
		output(2, "fd[%d] = pipe\n", shm->pipe_fds[i+1]);
	}
	return TRUE;
}

static int get_rand_pipe_fd(void)
{
	return shm->pipe_fds[rand() % MAX_PIPE_FDS];
}

struct fd_provider pipes_fd_provider = {
	.open = &open_pipes,
	.get = &get_rand_pipe_fd,
};

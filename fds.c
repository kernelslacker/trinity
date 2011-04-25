#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "trinity.h"

unsigned int fds[1024];
unsigned int fd_idx;

unsigned int fds_left_to_create = MAX_FDS;

static int pipes[2];

void setup_fds(void)
{
	fd_idx = 0;

	printf("Creating pipes\n");
	if (pipe(pipes) < 0) {
		perror("pipe fail.\n");
		exit(EXIT_FAILURE);
	}
	fds[0] = pipes[0];
	fds[1] = pipes[1];
	fd_idx += 2;
	fds_left_to_create-=2;
	output("fd[%d] = pipe\n", fds[0]);
	output("fd[%d] = pipe\n", fds[1]);

	open_sockets();
	open_fds("/dev");
	open_fds("/proc");
	open_fds("/sys");

	printf("done getting fds [idx:%d]\n", fd_idx);
	if (!fd_idx) {
		printf("couldn't open any files\n");
		exit(0);
	}
}


int get_random_fd(void)
{
	int i;

	i = rand() % 2;
	if (i == 0)
		return fds[rand() % fd_idx];
	if (i == 1)
		return socket_fds[rand() % socks];

	// should never get here.
	printf("oops! %s:%d\n", __FILE__, __LINE__);
	exit(EXIT_FAILURE);
}

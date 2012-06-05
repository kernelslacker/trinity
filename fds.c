#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trinity.h"
#include "shm.h"

unsigned int fd_idx = 0;

unsigned int fds_left_to_create = MAX_FDS;

void open_pipes(void)
{
	int pipes[MAX_PIPE_FDS * 2];
	unsigned int i;

	for (i = 0; i < MAX_PIPE_FDS; i+=2) {
		if (pipe(pipes) < 0) {
			perror("pipe fail.\n");
			exit(EXIT_FAILURE);
		}
		shm->pipe_fds[i] = pipes[0];
		shm->pipe_fds[i+1] = pipes[1];

		output("fd[%d] = pipe\n", shm->pipe_fds[i]);
		output("fd[%d] = pipe\n", shm->pipe_fds[i+1]);
	}
}

void setup_fds(void)
{
	open_pipes();
	open_sockets();
	open_files();
}

static int get_random_fd(void)
{
	unsigned int i;
	FILE *file;
	int fd = 0;
	int ret;

	if (do_specific_proto == TRUE)
		i = 1;
	else
		i = rand() % 3;

	switch (i) {
	case 0:
retry:		fd = shm->fds[rand() % fd_idx];

		/* avoid stdin/stdout/stderr */
		if (logging == FALSE)
			ret = fileno(stderr);

		/* get highest logfile fd if logging is enabled */
		else {
			file = shm->logfiles[shm->nr_childs-1];
			if (file == NULL) {
				printf("## WTF, logfile was null!\n");
				printf("## logfiles: ");
				for (i = 0; i < shm->nr_childs; i++)
					printf("%p ", shm->logfiles[i]);
				printf("\n");
				exit(EXIT_FAILURE);
			}
			ret = fileno(file);
			if (ret == -1) {
				printf("%s:%s: fileno failed! %s\n", __FILE__, __func__, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}


		if (fd <= ret)
			goto retry;
		break;

	case 1:
		fd = shm->socket_fds[rand() % socks];
		break;

	case 2:
		fd = shm->pipe_fds[rand() % MAX_PIPE_FDS];
		break;
	default:
		break;
	}

	return fd;
}

int get_fd(void)
{
regen:
	if (shm->fd_lifetime == 0) {
		shm->current_fd = get_random_fd();
		shm->fd_lifetime = rand() % MAX_NR_CHILDREN;
	} else
		shm->fd_lifetime--;

	if (shm->current_fd == 0) {
		shm->fd_lifetime = 0;
		goto regen;
	}

	return shm->current_fd;
}

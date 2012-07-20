#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trinity.h"
#include "shm.h"

unsigned int fd_idx = 0;

unsigned int fds_left_to_create = MAX_FDS;

static void open_pipes(void)
{
	int pipes[2];
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

static void close_pipes(void)
{
	unsigned int i;
	int fd;

	for (i = 0; i < MAX_PIPE_FDS; i+=2) {
		fd = shm->pipe_fds[i];
		shm->pipe_fds[i] = 0;
		close(fd);
		fd = shm->pipe_fds[i+1];
		shm->pipe_fds[i+1] = 0;
		close(fd);
	}
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
retry:
		if (fd_idx == 0) {
			i = find_pid_slot(getpid());
			output("[%d] wtf, no fds! Last syscall was %d\n",
				getpid(), shm->previous_syscallno[i]);
			shm->exit_reason = EXIT_NO_FDS;
			return -1;
		}

		fd = shm->fds[rand() % fd_idx];

		/* avoid stdin/stdout/stderr */
		if (logging == FALSE)
			ret = fileno(stderr);

		/* get highest logfile fd if logging is enabled */
		else {
			file = shm->logfiles[shm->max_children - 1];
			if (file == NULL) {
				printf("## WTF, logfile was null!\n");
				printf("## logfiles: ");
				for (i = 0; i < shm->max_children; i++)
					printf("%p ", shm->logfiles[i]);
				printf("\n");
				exit(EXIT_FAILURE);
			}
			ret = fileno(file);
			if (ret == -1) {
				BUG("fileno failed!");
				printf("%s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}


		if (fd <= ret)
			goto retry;
		break;

	case 1:
		fd = shm->socket_fds[rand() % nr_sockets];
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

void setup_fds(void)
{
	open_pipes();
	open_sockets();
	open_files();
}

void regenerate_fds(void)
{
	close_files();
	close_pipes();

	open_pipes();
	open_files();
}

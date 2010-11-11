#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

/* TODO:
 * socket fds
 */
static int file_user = 0;
static int pipes[2];

void setup_fds(void)
{
	char filename[]="tmp/testfileXXXXXX";

retry:
	file_user = mkstemp(filename);
	if (!file_user)
		goto retry;

	if (pipe(pipes) < 0) {
		perror("pipe fail.\n");
		exit(EXIT_FAILURE);
	}
}

void close_fds(void)
{
	(void)close(file_user);
	file_user = 0;
}


int get_random_fd(void)
{
	int i = rand();

	switch (i % 3) {
	case 0:	return pipes[0];
	case 1:	return pipes[1];
	case 2:	return file_user;
	}

	return 0;
}

int get_pipe_fd(void)
{
	if (rand() % 1)
		return pipes[0];
	else
		return pipes[1];
}

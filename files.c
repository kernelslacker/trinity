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

void setup_fds(void)
{
	char filename[]="tmp/testfileXXXXXX";

retry:
	file_user = mkstemp(filename);
	if (!file_user)
		goto retry;
}

void close_fds(void)
{
	(void)close(file_user);
	file_user = 0;
}


int get_random_fd(void)
{
	return file_user;
}


#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

/* TODO:
 * socket fds
 */
static int file_user = 0;
static int file_no_write = 0;

void setup_fds(void)
{
	if (!file_user)
		file_user = open("tmp/testfile", O_RDWR | O_TRUNC);
	if (file_user < 0) {
		perror("couldn't open testfile");
		exit(0);
	}
	if (!file_no_write)
		file_no_write = open("tmp/testfile2", O_RDONLY);
	if (file_no_write < 0) {
		perror("couldn't open testfile2");
		exit(0);
	}
}

static void close_fds(void)
{
	if (close(file_user)==-1) {
		perror("close file_user");
		exit(EXIT_FAILURE);
	}
	if (close(file_no_write)==-1) {
		perror("close file_nowrite");
		exit(EXIT_FAILURE);
	}
	file_user = 0;
	file_no_write = 0;
}


int get_random_fd()
{
	int i = rand();
	int fd = 0;

	close_fds();
	setup_fds();

	switch (i & 1) {
	case 0:	fd = file_user;
			break;
	case 1:	fd = file_no_write;
			break;
	}
	return fd;
}


#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "trinity.h"

unsigned char do_check_tainted;

int check_tainted(void)
{
	int fd;
	int ret;
	char buffer[4];

	fd = open("/proc/sys/kernel/tainted", O_RDONLY);
	if (!fd)
		return -1;
	ret = read(fd, buffer, 3);
	close(fd);
	ret = atoi(buffer);

	return ret;
}

void syscall_list()
{
	unsigned int i;

	for (i=0; i < max_nr_syscalls; i++)
		 printf("%u: %s\n", i, syscalls[i].entry->name);
}

void main_loop(void)
{
	int ret;

	shm->execcount = 1;

	while (1) {
		sigsetjmp(ret_jump, 1);

		do_syscall_from_child();

		if (syscallcount && (shm->execcount >= syscallcount))
			break;

		/* Only check taint if it was zero on startup */
		if (do_check_tainted == 0) {
			ret = check_tainted();
			if (ret != 0) {
				output("kernel became tainted! (%d)\n", ret);
				ctrlc_hit = 1;
				return;
			}
		}

		if (ctrlc_hit == 1)
			_exit(EXIT_SUCCESS);
		if (syscallcount && (shm->execcount >= syscallcount))
			_exit(EXIT_SUCCESS);
	}
}

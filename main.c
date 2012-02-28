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

void display_opmode(void)
{
	output("trinity mode: %s\n", opmodename[opmode]);

	if (opmode == MODE_ROTATE)
		output("Rotating value %lx though all registers\n", regval);

	sync_output();
}

void main_loop(void)
{
	int ret;

	for (;;) {

		if (ctrlc_hit == 1)
			return;

		switch (opmode) {
		case MODE_ROTATE:
			if (rep == max_nr_syscalls) {
				/* Pointless running > once. */
				if (rotate_mask == (1<<6)-1)
					goto done;
				rep = 0;
				rotate_mask++;
			}
			do_syscall_from_child(rep);
			break;

		case MODE_RANDOM:
			rep = rand();
			do_syscall_from_child(rep);
			break;
		}

		rep++;
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
	}
done: ;
}

void do_main_loop(void)
{
	shm->execcount = 1;

	if (opmode != MODE_RANDOM) {
		main_loop();
		return;
	}

	/* By default, MODE_RANDOM will do one syscall per child,
	 * unless -F is passed.
	 */
	if (nofork == 0) {
		main_loop();
		return;
	} else {
		/* if we opt to not fork for each syscall, we still need
		   to fork once, in case calling the syscall segfaults. */
		while (1) {
			sigsetjmp(ret_jump, 1);
			printf("forking new child.\n");
			sleep(1);
			if (fork() == 0) {
				seed_from_tod();
				mask_signals();
				main_loop();
				if (ctrlc_hit == 1)
					_exit(EXIT_SUCCESS);
				if (syscallcount && (shm->execcount >= syscallcount))
					_exit(EXIT_SUCCESS);
			}
			(void)waitpid(-1, NULL, 0);

			if (ctrlc_hit == 1)
				return;
			if (syscallcount && (shm->execcount >= syscallcount))
				return;
		}
	}
}


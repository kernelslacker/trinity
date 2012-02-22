/*
 * Functions for actually doing the system calls.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "arch.h"
#include "trinity.h"
//#include "files.h"
#include "sanitise.h"

unsigned char do_check_tainted;

static long res = 0;

static long mkcall(unsigned int call)
{
	unsigned long olda1=0, olda2=0, olda3=0, olda4=0, olda5=0, olda6=0;
	unsigned long a1=0, a2=0, a3=0, a4=0, a5=0, a6=0;
	int ret = 0;
	char string[512], *sptr=string;

	sptr += sprintf(sptr, "%lu: ", shm->execcount);

	switch (opmode) {
	case MODE_ROTATE:
		a1 = a2 = a3 = a4 = a5 = a6 = regval;
		if (!(rotate_mask & (1<<0))) a6 = rand64();
		if (!(rotate_mask & (1<<1))) a5 = rand64();
		if (!(rotate_mask & (1<<2))) a4 = rand64();
		if (!(rotate_mask & (1<<3))) a3 = rand64();
		if (!(rotate_mask & (1<<4))) a2 = rand64();
		if (!(rotate_mask & (1<<5))) a1 = rand64();
		break;

	case MODE_RANDOM:
	default:
		a1 = rand64();
		a2 = rand64();
		a3 = rand64();
		a4 = rand64();
		a5 = rand64();
		a6 = rand64();
		break;
	}
	if (call > max_nr_syscalls)
		sptr += sprintf(sptr, "%u", call);
	else
		sptr += sprintf(sptr, "%s", syscalls[call].entry->name);

	olda1=a1; olda2=a2; olda3=a3; olda4=a4; olda5=a5; olda6=a6;

	if (intelligence == 1) {
		generic_sanitise(call, &a1, &a2, &a3, &a4, &a5, &a6);
		if (syscalls[call].entry->sanitise)
			syscalls[call].entry->sanitise(&a1, &a2, &a3, &a4, &a5, &a6);
	}

#define COLOR_ARG(ARGNUM, NAME, BIT, OLDREG, REG)					\
	if (syscalls[call].entry->num_args >= ARGNUM) {					\
		if (!NAME)								\
			goto args_done;							\
		if (ARGNUM != 1)							\
			sptr += sprintf(sptr, WHITE ", ");				\
		if (NAME)								\
			sptr += sprintf(sptr, "%s=", NAME);				\
		if (opmode == MODE_ROTATE) {						\
			if (rotate_mask & (BIT))					\
				if (OLDREG == REG)					\
					sptr += sprintf(sptr, YELLOW "0x%lx" WHITE, REG);	\
				else							\
					sptr += sprintf(sptr, CYAN "0x%lx" WHITE, REG);	\
			else {								\
				if (OLDREG == REG)					\
					sptr += sprintf(sptr, WHITE);			\
				else							\
					sptr += sprintf(sptr, CYAN);			\
				if (REG > 1024)						\
					sptr += sprintf(sptr, "0x%lx" WHITE, REG);	\
				else							\
					sptr += sprintf(sptr, "%ld" WHITE, REG);	\
			}								\
		} else {								\
			if (OLDREG == REG)						\
				sptr += sprintf(sptr, WHITE);				\
			else								\
				sptr += sprintf(sptr, CYAN);				\
			if (REG > 1024)							\
				sptr += sprintf(sptr, "0x%lx" WHITE, REG);		\
			else								\
				sptr += sprintf(sptr, "%ld" WHITE, REG);		\
		}									\
		if (REG == (unsigned long)page_zeros)					\
			sptr += sprintf(sptr, "[page_zeros]");				\
		if (REG == (unsigned long)page_rand)					\
			sptr += sprintf(sptr, "[page_rand]");				\
		if (REG == (unsigned long)page_0xff)					\
			sptr += sprintf(sptr, "[page_0xff]");				\
		if (REG == (unsigned long)page_allocs)					\
			sptr += sprintf(sptr, "[page_allocs]");				\
	}

	sptr += sprintf(sptr, WHITE "(");

	COLOR_ARG(1, syscalls[call].entry->arg1name, 1<<5, olda1, a1);
	COLOR_ARG(2, syscalls[call].entry->arg2name, 1<<4, olda2, a2);
	COLOR_ARG(3, syscalls[call].entry->arg3name, 1<<3, olda3, a3);
	COLOR_ARG(4, syscalls[call].entry->arg4name, 1<<2, olda4, a4);
	COLOR_ARG(5, syscalls[call].entry->arg5name, 1<<1, olda5, a5);
	COLOR_ARG(6, syscalls[call].entry->arg6name, 1<<0, olda6, a6);
args_done:
	sptr += sprintf(sptr, WHITE ") ");

	output("%s", string);
	sptr = string;
	sync_output();

	if (dopause == 1)
		sleep(1);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = syscall(call, a1, a2, a3, a4, a5, a6);

	if (ret < 0) {
		sptr +=sprintf(sptr, RED "= %d (%s)" WHITE, ret, strerror(errno));
		shm->failures++;
	} else {
		sptr += sprintf(sptr, GREEN "= %d" WHITE, ret);
		shm->successes++;
	}
	sptr += sprintf(sptr, " [T:%ld F:%ld S:%ld]", shm->execcount, shm->failures, shm->successes);
	sptr += sprintf(sptr, "\n");

	output("%s", string);
	sptr = string;
	sync_output();

	if (quiet) {
		if (shm->execcount % 1000 == 0) {
			sptr = string;
			sptr += sprintf(sptr, "%ld\n", shm->execcount);
			printf("%s", string);
		}
	}

	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].entry->flags |= AVOID_SYSCALL;

	shm->execcount++;

	return ret;
}


static int do_syscall(int callnr)
{
	unsigned int syscallnr = callnr;
	int retrycount = 0;

	if (opmode == MODE_RANDOM)
		syscallnr = rand() / (RAND_MAX/max_nr_syscalls);

	if (do_specific_syscall != 0)
		syscallnr = specific_syscall;
	else {

		if (syscalls[syscallnr].entry->num_args == 0)
			goto skip_syscall;

		if (syscalls[syscallnr].entry->flags & AVOID_SYSCALL)
			goto skip_syscall;

		if (syscalls[syscallnr].entry->flags & NI_SYSCALL)
			goto skip_syscall;
	}

retry_same:
	(void)alarm(3);

	res = mkcall(syscallnr);

	/*  Brute force the same syscall until it succeeds */
	if ((opmode == MODE_RANDOM) && (intelligence == 1) && (bruteforce == 1)) {
		// Don't bother trying to bruteforce ni_syscall
		if (res == -ENOSYS)
			goto failed_repeat;

		if (retrycount == 100) {
			//printf("100 retries done without success. moving on\n");
			goto failed_repeat;
		}

		if (res < 0) {
			//printf ("syscall failed. Retrying\n");
			retrycount++;
			shm->retries++;
			goto retry_same;
		}
	}

failed_repeat:

skip_syscall:
	return res;
}

static void do_syscall_from_child(int cl)
{
	int ret;

	if (!shm->regenerate_fds) {
		close_files();
		open_files();

		destroy_maps();
		setup_maps();

		shm->regenerate_fds = FD_REGENERATION_POINT - 1;
	}
	shm->regenerate_fds--;


	if (nofork==1) {
		ret = do_syscall(cl);
		return;
	}

	if (fork() == 0) {
		if (!shm->regenerate_fds)
			regenerate_random_page();
		if (do_specific_syscall == 1)
			regenerate_random_page();
		ret = do_syscall(cl);
		_exit(ret);
	}
	(void)waitpid(-1, NULL, 0);
}


void display_opmode(void)
{
	output("trinity mode: %s\n", opmodename[opmode]);

	if (opmode == MODE_ROTATE)
		output("Rotating value %lx though all registers\n", regval);

	sync_output();
}


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

void syscall_list()
{
	unsigned int i;

	for (i=0; i < max_nr_syscalls; i++)
		 printf("%u: %s\n", i, syscalls[i].entry->name);
}

void check_sanity(void)
{
	//unsigned int i;
	//int ret;

	/* Sanity test. All NI_SYSCALL's should return ENOSYS. */
	/* disabled for now, breaks with 32bit calls.
	for (i=0; i<= max_nr_syscalls; i++) {
		if (syscalls[i].entry->flags & NI_SYSCALL) {
			ret = syscall(i);
			if (ret == -1) {
				if (errno != ENOSYS) {
					printf("syscall %d (%s) should be ni_syscall, but returned %d(%s) !\n",
						i, syscalls[i].entry->name, errno, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	*/
}

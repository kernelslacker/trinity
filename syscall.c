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
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "arch.h"
#include "trinity.h"
//#include "files.h"
#include "sanitise.h"

static long res = 0;

#define __syscall_return(type, res) \
do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
		errno = -(res); \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

static long call_syscall(__unused__ int num_args, unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, unsigned long a6)
{
	if (!do_32bit)
		return syscall(call, a1, a2, a3, a4, a5, a6);

	if (num_args < 6) {
		long __res;
		__asm__ volatile ("int $0x80"
		: "=a" (__res)
		: "0" (call),"b" ((long)(a1)),"c" ((long)(a2)),
		"d" ((long)(a3)), "S" ((long)(a4)),
		"D" ((long)(a5)));
		__syscall_return(long,__res);
		return __res;
	}
	/* TODO: 6 arg 32bit syscall goes here.*/

	return 0;

}


static void dump_poison(char *addr)
{
	unsigned int i, j;

	for (i = 0; i < page_size; i+=32) {
		printf("%d: ", i);
		for (j=0; j < 32; j++)
			printf("%x ", (unsigned int) addr[i+j]);
		printf("\n");
	}
	(void)fflush(stdout);
	(void)sleep(10);
	exit(EXIT_FAILURE);
}

static long mkcall(unsigned int call)
{
	unsigned long olda1=0, olda2=0, olda3=0, olda4=0, olda5=0, olda6=0;
	unsigned long a1=0, a2=0, a3=0, a4=0, a5=0, a6=0;
	int ret = 0;
	unsigned int i;

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
		printf("%u", call);
	else
		printf("%s", syscalls[call].name);

	/* If there are no inputs, we can't fuzz anything. */
	if (syscalls[call].num_args == 0) {
		syscalls[call].flags |= AVOID_SYSCALL;
		printf(" syscall has no inputs:- skipping\n");
		return 0;
	}

	olda1=a1; olda2=a2; olda3=a3; olda4=a4; olda5=a5; olda6=a6;

	if (intelligence == 1) {
		generic_sanitise(call, &a1, &a2, &a3, &a4, &a5, &a6);
		if (syscalls[call].sanitise)
			syscalls[call].sanitise(&a1, &a2, &a3, &a4, &a5, &a6);
	}

#define COLOR_ARG(ARGNUM, NAME, BIT, OLDREG, REG)			\
	if (syscalls[call].num_args >= ARGNUM) {			\
		if (ARGNUM != 1)					\
			printf(WHITE ", ");				\
		if (NAME)						\
			printf("%s=", NAME);				\
		if (opmode == MODE_ROTATE) {				\
			if (rotate_mask & (BIT))			\
				printf(YELLOW "0x%lx" WHITE, REG);	\
			else {						\
				if (OLDREG == REG)			\
					printf(WHITE "0x%lx", REG);	\
				else					\
					printf(CYAN "0x%lx" WHITE, REG); \
			}						\
		} else {						\
			if (OLDREG == REG)				\
				printf(WHITE "0x%lx", REG);		\
			else						\
				printf(CYAN "0x%lx" WHITE, REG);	\
		}							\
	}

	printf(WHITE "(");

	COLOR_ARG(1, syscalls[call].arg1name, 1<<5, olda1, a1);
	COLOR_ARG(2, syscalls[call].arg2name, 1<<4, olda2, a2);
	COLOR_ARG(3, syscalls[call].arg3name, 1<<3, olda3, a3);
	COLOR_ARG(4, syscalls[call].arg4name, 1<<2, olda4, a4);
	COLOR_ARG(5, syscalls[call].arg5name, 1<<1, olda5, a5);
	COLOR_ARG(6, syscalls[call].arg6name, 1<<0, olda6, a6);

	printf(WHITE ") ");


	writelog("%s (0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ",
		syscalls[call].name, a1, a2, a3, a4, a5, a6);


	(void)fflush(stdout);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = call_syscall(syscalls[call].num_args, call, a1, a2, a3, a4, a5, a6);

	if (ret < 0) {
		printf(RED "= %d (%s)\n" WHITE, ret, strerror(errno));
		writelog("= %d (%s)\n", ret, strerror(errno));
		shm->failures++;
	} else {
		printf(GREEN "= %d\n" WHITE, ret);
		writelog("= %d\n" , ret);
		shm->successes++;
	}
	(void)fflush(stdout);

	if (check_poison==1) {
		for (i = 0; i < page_size; i++) {
			if (userbuffer[i]!=poison) {
				printf ("Yikes! poison1 was overwritten!\n");
				dump_poison(userbuffer);
			}
		}
		for (i = page_size*2; i < page_size*3; i++) {
			if (userbuffer[i]!=poison) {
				printf ("Yikes! poison2 was overwritten!\n");
				dump_poison(userbuffer+(page_size*2));
			}
		}
		for (i = page_size*4; i < page_size*5; i++) {
			if (userbuffer[i]!=poison) {
				printf ("Yikes! poison3 was overwritten!\n");
				dump_poison(userbuffer+(page_size*4));
			}
		}
		for (i = page_size*6; i < page_size*7; i++) {
			if (userbuffer[i]!=poison) {
				printf ("Yikes! poison4 was overwritten!\n");
				dump_poison(userbuffer+(page_size*6));
			}
		}
	}

	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].flags |= AVOID_SYSCALL;

	printf("\n");
	return ret;
}


static int do_syscall(int cl)
{
	int retrycount = 0;

	printf ("%i: ", cl);

	if (opmode == MODE_RANDOM)
retry:
		cl = rand() / (RAND_MAX/max_nr_syscalls);

retry_same:
	if (syscalls[cl].flags & AVOID_SYSCALL)
		goto retry;

	(void)alarm(3);

	if (do_specific_syscall != 0)
		cl = specific_syscall;

	res = mkcall(cl);

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

	if (dopause==1)
		(void)sleep(1);

	return res;
}

static void do_syscall_from_child(int cl)
{
	int ret;

	if (nofork==1) {
		ret = do_syscall(cl);
		return;
	}

	if (fork() == 0) {
		ret = do_syscall(cl);
		//if (intelligence==1)
		//	close_fds();
		_exit(ret);
	}
	(void)waitpid(-1, NULL, 0);
}


void do_main_loop(void)
{
	unsigned int i;

	printf("trinity mode: %s\n", opmodename[opmode]);

	switch (opmode) {

	case MODE_ROTATE:
		switch (passed_type) {
		case TYPE_STRUCT:
			printf("struct mode = %s\n", structmodename[structmode]);
			if (structmode == STRUCT_CONST)
				printf("struct fill value is 0x%x\n", (int)struct_fill);
			break;
		}

		printf("Rotating value %lx though all registers\n", regval);
		break;
	}

	(void)fflush(stdout);

	/* This is our main loop. */

	for (;;) {

		if (ctrlc_hit == 1)
			return;

		switch (opmode) {
		case MODE_ROTATE:
			/* It's easier to just use all regs for now. */
			for (i=0; i<=max_nr_syscalls; i++) {
				syscalls[i].num_args = 6;
			}

			if (do_specific_syscall == 1) {
				rotate_mask++;
				if (rotate_mask == (1<<6)-1)
					goto done;
			} else {
				if (rep > max_nr_syscalls) {
					/* Pointless running > once. */
					if (rotate_mask == (1<<6)-1)
						goto done;
					rep = 0;
					rotate_mask++;
				}
			}
			do_syscall_from_child(rep);
			break;

		case MODE_CAPCHECK:
			if (rep > max_nr_syscalls)
				goto done;
			if (syscalls[rep].flags & CAPABILITY_CHECK) {
				int r;
				printf ("%i: ", rep);
				r = do_syscall(rep);
				if (r != -EPERM)
					printf ("Didn't return EPERM!\n");
			}
			break;

		case MODE_RANDOM:
			do_syscall_from_child(rep);
			break;
		}

		rep++;
		execcount++;
		if (syscallcount && (execcount >= syscallcount))
			break;

		/* regenerate the random buffer every time we make a syscall. */
		for (i=0; i<page_size; i++)
			page_rand[i]= rand();

		/* If we're passing userspace addresses, mess with alignment */
		if ((passed_type == TYPE_VALUE) &&
		    ((regval & ~0xf) == (unsigned long)page_zeros))
			regval = (unsigned long)page_zeros+(rand() & 0xf);

	}
done: ;
}

void syscall_list()
{
	unsigned int i;

	for (i=0; i<=max_nr_syscalls; i++)
		 printf("%u: %s\n", i, syscalls[i].name);
}

void check_sanity(void)
{
	//unsigned int i;
	//int ret;

	/* Sanity test. All NI_SYSCALL's should return ENOSYS. */
	/* disabled for now, breaks with 32bit calls.
	for (i=0; i<= max_nr_syscalls; i++) {
		if (syscalls[i].flags & NI_SYSCALL) {
			ret = syscall(i);
			if (ret == -1) {
				if (errno != ENOSYS) {
					printf("syscall %d (%s) should be ni_syscall, but returned %d(%s) !\n",
						i, syscalls[i].name, errno, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	*/
}

/*
 *
 * Call random system calls with random arguments.
 * Based on an original program by Kurt Garloff <garloff@suse.de>
 *
 * License: Artistic
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#ifdef __x86_64__
#include "x86-64.h"
#endif
#ifdef __i386__
#include "i386.h"
#endif
#include "scrashme.h"
#include "files.h"

static struct syscalltable *syscalls;

static long res=0;
static long specificsyscall=0;
static long regval=0;
static char *progname=NULL;
static char *structptr=NULL;
static unsigned char zeromask=0;
static unsigned char dopause=0;
static unsigned char intelligence=0;
static unsigned char do_specific_syscall=0;

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ZEROREGS 2
#define MODE_REGVAL 3
#define MODE_STRUCT 4

static char opmode = MODE_UNDEFINED;

static void sighandler(int sig)
{
	printf("%s ", strsignal (sig));
	(void)fflush(stdout);
	_exit(0);
}

static unsigned long getrand()
{
	unsigned long r;
	r = (unsigned long)rand();
	r *= (unsigned long)rand();
	return r;
}

static long mkcall(int call)
{
	unsigned long a1=0, a2=0, a3=0, a4=0, a5=0, a6=0;
	long ret = 0;
	switch (opmode) {
	case MODE_ZEROREGS:
		if (!(zeromask & (1<<0))) a6 = getrand();
		if (!(zeromask & (1<<1))) a5 = getrand();
		if (!(zeromask & (1<<2))) a4 = getrand();
		if (!(zeromask & (1<<3))) a3 = getrand();
		if (!(zeromask & (1<<4))) a2 = getrand();
		if (!(zeromask & (1<<5))) a1 = getrand();
		break;

	case MODE_REGVAL:
		a1 = a2 = a3 = a4 = a5 = a6 = regval;
		break;

	case MODE_STRUCT:
		a1 = a2 = a3 = a4 = a5 = a6 = (unsigned long) structptr;
		break;

	case MODE_RANDOM:
	default:
		a1 = getrand();
		a2 = getrand();
		a3 = getrand();
		a4 = getrand();
		a5 = getrand();
		a6 = getrand();
		break;
	}
	if (call > NR_SYSCALLS)
		printf("%d", call);
	else
		printf("%s", syscalls[call].name);

	if (intelligence == 1) {
		if (syscalls[call].sanitise) {
#if 1
			printf("\n\tSanitising options.\n\tBefore:\t");
			printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx)\n\tAfter:\t", a1, a2, a3, a4, a5, a6);
#endif
			syscalls[call].sanitise(&a1, &a2, &a3, &a4, &a5, &a6);
		}
	}
	printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4, a5, a6);

	(void)fflush(stdout);

	if (call != __NR_exit && call != __NR_pause)
		ret = syscall(call, a1, a2, a3, a4, a5);
	printf("= %ld", ret);

	if (ret < 0)
		printf(" %s\n", strerror (errno));
	else
		printf("\n");
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, "   -bN: begin at offset N.\n");
	fprintf(stderr, "   -cN: do syscall N with random inputs.\n");
	fprintf(stderr, "   -f:  pass struct filled with 0xff.\n");
	fprintf(stderr, "   -j:  pass struct filled with random junk.\n");
	fprintf(stderr, "   -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, "   -n:  pass struct filled with 0x00.\n");
	fprintf(stderr, "   -p;  pause after syscall.\n");
	fprintf(stderr, "   -r:  call random syscalls with random inputs.\n");
	fprintf(stderr, "   -sN: use N as random seed.\n");
	fprintf(stderr, "   -t:  use time of day as seed.\n");
	fprintf(stderr, "   -xN:  use value as arguments.\n");
	fprintf(stderr, "   -z:  Use all zeros as register parameters.\n");
	exit(EXIT_SUCCESS);
}


static void do_call(int cl)
{
	if (opmode == MODE_RANDOM)
retry:
		cl = rand() / (RAND_MAX/NR_SYSCALLS);

	switch (cl) {
		case __NR_exit:
		case __NR_fork:
#ifdef __i386__
		case __NR_sigsuspend:
		case __NR_sigreturn:
#endif
		case __NR_select:
		case __NR_clone:
		case __NR_rt_sigreturn:
		case __NR_exit_group:
			goto retry;
		default:
			break;
	}

	(void)alarm(2);

	if (do_specific_syscall != 0)
		cl = specificsyscall;

	res = mkcall(cl);
	if (dopause==1)
		(void)sleep(1);
}

#define STRUCTMODE_FF 1
#define STRUCTMODE_RAND 2
#define STRUCTMODE_0 3


int main (int argc, char* argv[])
{
	volatile int rep=0;
	int c=0, i;
	int seed=0;
	struct timeval t;
	volatile char randomtime=0;
	int structmode=0;

#ifdef __x86_64__
	syscalls = syscalls_x86_64;
#else
	syscalls = syscalls_i386;
#endif


	progname = argv[0];

	while ((c = getopt(argc, argv, "b:c:fijknprs:tx:z")) != -1) {
		switch (c) {
			case 'b':
				rep = strtol(optarg, NULL, 10);
				break;
			case 'c':
				do_specific_syscall = 1;
				specificsyscall = strtol(optarg, NULL, 10);
				break;

			/* Pass a ptr to a struct filled with -1 */
			case 'f':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_FF;
				structptr = malloc(4096);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, 0xff, 4096);
				break;

			/* use semi-intelligent options */
			case 'i':
				intelligence = 1;
				setup_fds();
				break;

			/* Pass a ptr to a struct filled with junk */
			case 'j':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_RAND;
				structptr = malloc(4096);
				if (!structptr)
					exit(EXIT_FAILURE);
				for (i=0; i<4096; i++)
					structptr[i]= rand();
				break;

			/* Pass in address of kernel text */
			case 'k':
				opmode = MODE_REGVAL;
				regval = KERNEL_ADDR;
				break;

			/* Pause after each syscall */
			case 'p':
				dopause =1;
				break;

			/* Pass a ptr to a struct filled with zeros */
			case 'n':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_0;
				structptr = malloc(4096);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, 0, 4096);
				break;

			/* Pass in random numbers in registers. */
			case 'r':
				opmode = MODE_RANDOM;
				break;

			/* Set seed */
			case 's':
				seed = strtol(optarg, NULL, 10);
				break;

			/* Set seed from TOD */
			case 't':
				gettimeofday(&t, 0);
				seed = t.tv_sec * t.tv_usec;
				randomtime = 1;
				break;

			/* Set registers to specific value */
			case 'x':
				regval = strtoul(optarg, NULL, 10);
				opmode = MODE_REGVAL;
				break;

			/* Wander a 0 through every register */
			case 'z':
				opmode = MODE_ZEROREGS;
				break;
		}
	}

	if (argc==1)
		usage();

	if (opmode==MODE_UNDEFINED) {
		fprintf (stderr, "Must be either random (-r), specific (-c) or zero-sweep (-z).\n");
		usage();
	}

	for (i=1; i<512; i++)  {
		struct sigaction sa;
		sigset_t ss;

		if (sigfillset(&ss) == -1) {
			perror("sigfillset");
			exit(EXIT_FAILURE);
		}
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)(sigaction(i, &sa, NULL) == -1);
	}
	(void)signal(SIGCHLD, SIG_IGN);

	srand(seed);

	chroot("tmp");

	for (;;) {
		switch (opmode) {
			case MODE_REGVAL:
				if (rep > NR_SYSCALLS)
					goto done;
				break;

			case MODE_ZEROREGS:
				if (do_specific_syscall == 1) {
					zeromask++;
					if (zeromask == (1<<6)-1)
						goto done;
				} else {
					if (rep > NR_SYSCALLS) {
						/* Pointless running > once. */
						if (zeromask == (1<<6)-1)
							goto done;
						rep = 0;
						zeromask++;
					}
				}
				break;

			case MODE_STRUCT:
				switch (structmode) {
				case STRUCTMODE_RAND:
					for (i=0; i<4096; i++)
						structptr[i]= rand();
					break;
				}
				if (rep > NR_SYSCALLS)
					goto done;
				break;
		}

		if (randomtime == 1) {
			gettimeofday(&t, 0);
			seed = t.tv_sec * t.tv_usec;
			srand(seed);
		}

		if (fork() == 0) {
			printf ("%i: ", rep);
			(void)alarm(1);
			do_call(rep);
			_exit(0);
		}
		(void)waitpid(-1, NULL, 0);
		rep++;
	}

done:
	if (structptr!=NULL)
		free(structptr);

	exit(EXIT_SUCCESS);
}


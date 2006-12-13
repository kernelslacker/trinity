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
#ifdef __powerpc__
#include "ppc.h"
#endif
#ifdef __ia64__
#include "ia64.h"
#endif
#ifdef __sparc__
#include "sparc.h"
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
static unsigned int seed=0;
static long long syscallcount=0;
static long long execcount=0;

#define STRUCT_SIZE	4096

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ZEROREGS 2
#define MODE_REGVAL 3
#define MODE_STRUCT 4
#define MODE_CAPCHECK 5

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

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = syscall(call, a1, a2, a3, a4, a5);
	printf("= %ld", ret);

	if (ret < 0)
		printf(" %s\n", strerror (errno));
	else
		printf("\n");
	(void)fflush(stdout);
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, "   -b#: begin at offset #.\n");
	fprintf(stderr, "   -c#: do syscall # with random inputs.\n");
	fprintf(stderr, "   -C:  check syscalls that call capable() return -EPERM.\n");
	fprintf(stderr, "   -f:  pass struct filled with 0xff.\n");
	fprintf(stderr, "   -j:  pass struct filled with random junk.\n");
	fprintf(stderr, "   -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, "   -N#: do # syscalls then exit.\n");
	fprintf(stderr, "   -n:  pass struct filled with 0x00.\n");
	fprintf(stderr, "   -p:  pause after syscall.\n");
	fprintf(stderr, "   -r:  call random syscalls with random inputs.\n");
	fprintf(stderr, "   -s#: use # as random seed.\n");
	fprintf(stderr, "   -x#: use value as arguments.\n");
	fprintf(stderr, "   -z:  Use all zeros as register parameters.\n");
	exit(EXIT_SUCCESS);
}


static int do_syscall(int cl)
{
	struct timeval t;

	gettimeofday(&t, 0);
	seed = t.tv_sec * t.tv_usec;
	srand(seed);

	if (opmode == MODE_RANDOM)
retry:
		cl = rand() / (RAND_MAX/NR_SYSCALLS);

	if (syscalls[cl].flags & AVOID_SYSCALL)
		goto retry;

	(void)alarm(2);

	if (do_specific_syscall != 0)
		cl = specificsyscall;

	res = mkcall(cl);
	if (dopause==1)
		(void)sleep(1);

	return res;
}


static void do_syscall_from_child(int cl)
{
	if (fork() == 0) {
		printf ("%i: ", cl);
		(void)alarm(1);

		do_syscall(cl);
		if (intelligence==1)
			close_fds();
		_exit(EXIT_SUCCESS);
	}
	(void)waitpid(-1, NULL, 0);
}

#define STRUCTMODE_FF 1
#define STRUCTMODE_RAND 2
#define STRUCTMODE_0 3


int main (int argc, char* argv[])
{
	volatile int rep=0;
	int c=0, i;
	int structmode=0;

#ifdef __x86_64__
	syscalls = syscalls_x86_64;
#elif __powerpc__
	syscalls = syscalls_ppc;
#elif __ia64__
	syscalls = syscalls_ia64;
#elif __sparc__
	syscalls = syscalls_sparc;
#else
	syscalls = syscalls_i386;
#endif


	progname = argv[0];

	while ((c = getopt(argc, argv, "b:c:CfijkN:nprs:x:z")) != -1) {
		switch (c) {
			case 'b':
				rep = strtol(optarg, NULL, 10);
				break;
			case 'c':
				do_specific_syscall = 1;
				specificsyscall = strtol(optarg, NULL, 10);
				break;

			case 'C':
				opmode = MODE_CAPCHECK;
				break;

			/* Pass a ptr to a struct filled with -1 */
			case 'f':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_FF;
				structptr = malloc(STRUCT_SIZE);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, 0xff, STRUCT_SIZE);
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
				structptr = malloc(STRUCT_SIZE);
				if (!structptr)
					exit(EXIT_FAILURE);
				for (i=0; i<STRUCT_SIZE; i++)
					structptr[i]= rand();
				break;

			/* Pass in address of kernel text */
			case 'k':
				opmode = MODE_REGVAL;
				regval = KERNEL_ADDR;
				break;

			/* Set syscall loop counter */
			case 'N':
				syscallcount = strtoll(optarg, NULL, 10);
				break;

			/* Pause after each syscall */
			case 'p':
				dopause =1;
				break;

			/* Pass a ptr to a struct filled with zeros */
			case 'n':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_0;
				structptr = malloc(STRUCT_SIZE);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, 0, STRUCT_SIZE);
				break;

			/* Pass in random numbers in registers. */
			case 'r':
				opmode = MODE_RANDOM;
				break;

			/* Set seed */
			case 's':
				seed = strtol(optarg, NULL, 10);
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
		fprintf (stderr, "Must be one of random (-r), specific (-c), capable (-C), zero-sweep (-z), fixed register value (-x), kernel address args (-k),\n");
		fprintf (stderr, "  struct with all bits filled (-f), struct with junk (-j), struct filled with zeros (-n)\n");
		usage();
	}

	seteuid(65536);
	seteuid(65536);
	(void)setgid(65536);
	seteuid(65536);

	for (i=1; i<512; i++)  {
		struct sigaction sa;
		sigset_t ss;

		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	(void)signal(SIGCHLD, SIG_IGN);

	srand(seed);

	chroot("tmp");

	for (;;) {
		switch (opmode) {
			case MODE_REGVAL:
				if (rep > NR_SYSCALLS)
					goto done;
				do_syscall_from_child(rep);
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
				do_syscall_from_child(rep);
				break;

			case MODE_STRUCT:
				if (rep > NR_SYSCALLS)
					goto done;
				switch (structmode) {
				case STRUCTMODE_RAND:
					for (i=0; i<STRUCT_SIZE; i++)
						structptr[i]= rand();
					break;
				}
				do_syscall_from_child(rep);
				break;

			case MODE_CAPCHECK:
				if (rep > NR_SYSCALLS)
					goto done;
				if (syscalls[rep].flags & CAPABILITY_CHECK) {
					int r;
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
		if (execcount >= syscallcount)
			break;
	}

done:
	if (structptr!=NULL)
		free(structptr);

	exit(EXIT_SUCCESS);
}


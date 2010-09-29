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
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
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

static int rep=0;
static long res=0;
static long specificsyscall=0;
static unsigned long regval=0;
static char *progname=NULL;
static char *structptr=NULL;
static unsigned char rotate_mask=1;
static unsigned char dopause=0;
static unsigned char intelligence=0;
static unsigned char do_specific_syscall=0;
static unsigned char check_poison = 0;
static unsigned int seed=0;
static long long syscallcount=0;
static long long execcount=0;


char poison = 0x55;

int page_size;

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ROTATE 2
#define MODE_CAPCHECK 3
static int opmode = MODE_UNDEFINED;

#define STRUCT_UNDEFINED 0
#define STRUCT_CONST 1
#define STRUCT_RAND 2
static int structmode = STRUCT_UNDEFINED;

static long struct_fill;		/* value to fill struct with if CONST */

char *opmodename[] = {
	[MODE_UNDEFINED] = "undef",
	[MODE_RANDOM] = "random",
	[MODE_ROTATE] = "rotate",
	[MODE_CAPCHECK] = "capabilities_check",
};
char *structmodename[] = {
	[STRUCT_UNDEFINED] = "unknown",
	[STRUCT_CONST] = "constant",
	[STRUCT_RAND]  = "random",
};

#define TYPE_UNDEFINED 0
#define TYPE_VALUE 1
#define TYPE_STRUCT 2
static char passed_type = TYPE_UNDEFINED;


static char *userbuffer;
char *useraddr;
void init_buffer()
{
	userbuffer = malloc(4096*3);
	memset(userbuffer, poison, 4096);
	memset(userbuffer+4096+4096, poison, 4096);

	useraddr = userbuffer+4096;
	memset(useraddr, 0, 4096);
}

static void sighandler(int sig)
{
	printf("signal: %s\n", strsignal (sig));
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
	int i, j;
	int poisoned = 0;

	switch (opmode) {
	case MODE_ROTATE:
		a1 = a2 = a3 = a4 = a5 = a6 = regval;
		if (!(rotate_mask & (1<<0))) a6 = getrand();
		if (!(rotate_mask & (1<<1))) a5 = getrand();
		if (!(rotate_mask & (1<<2))) a4 = getrand();
		if (!(rotate_mask & (1<<3))) a3 = getrand();
		if (!(rotate_mask & (1<<4))) a2 = getrand();
		if (!(rotate_mask & (1<<5))) a1 = getrand();
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

	/* If there are no inputs, we can't fuzz anything. */
	if (syscalls[call].num_args == 0) {
		syscalls[call].flags |= AVOID_SYSCALL;
		printf(" syscall has no inputs:- skipping\n");
		return 0;
	}

	if (intelligence == 1) {
		if (syscalls[call].sanitise) {
#if 1
			printf("\n\tSanitising options.\n\tBefore:\t");
			printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx)\n\tAfter:\t", a1, a2, a3, a4, a5, a6);
#endif
			syscalls[call].sanitise(&a1, &a2, &a3, &a4, &a5, &a6);
		}
	}

	if (syscalls[call].num_args == 1)
		printf("(0x%lx) ", a1);
	if (syscalls[call].num_args == 2)
		printf("(0x%lx,0x%lx) ", a1, a2);
	if (syscalls[call].num_args == 3)
		printf("(0x%lx,0x%lx,0x%lx) ", a1, a2, a3);
	if (syscalls[call].num_args == 4)
		printf("(0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4);
	if (syscalls[call].num_args == 5)
		printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4, a5);

	if (opmode == MODE_ROTATE) {
		printf("(");
		if (rotate_mask & (1<<5))
			printf("[1;33m0x%lx[0;37m, ", a1);
		else
			printf("[0;37m0x%lx[0;37m, ", a1);

		if (rotate_mask & (1<<4))
			printf("[1;33m0x%lx[0;37m, ", a2);
		else
			printf("[0;37m0x%lx[0;37m, ", a2);

		if (rotate_mask & (1<<3))
			printf("[1;33m0x%lx[0;37m, ", a3);
		else
			printf("[0;37m0x%lx[0;37m, ", a3);

		if (rotate_mask & (1<<2))
			printf("[1;33m0x%lx[0;37m, ", a4);
		else
			printf("[0;37m0x%lx[0;37m, ", a4);

		if (rotate_mask & (1<<1))
			printf("[1;33m0x%lx[0;37m, ", a5);
		else
			printf("[0;37m0x%lx[0;37m, ", a5);

		if (rotate_mask & (1<<0))
			printf("[1;33m0x%lx[0;37m", a6);
		else
			printf("[0;37m0x%lx[0;37m", a6);
		printf(")");
	} else {
		if (syscalls[call].num_args == 6)
			printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4, a5, a6);
	}

	(void)fflush(stdout);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = syscall(call, a1, a2, a3, a4, a5);

#define RED	"[1;31m"
#define GREEN	"[1;32m"
#define WHITE	"[1;37m"

	if (ret < 0)
		printf(RED " %s\n" WHITE, strerror (errno));
	else
		printf(GREEN "= %ld\n" WHITE, ret);

	(void)fflush(stdout);

	if (check_poison==1) {
		for (i = 0; i < 4096; i++) {
			if (userbuffer[i]!=poison)
				poisoned = 1;
		}
		for (i = 4096*2; i < 4096*3; i++) {
			if (userbuffer[i]!=poison)
				poisoned = 2;
		}

		if (poisoned==1) {
			printf ("Yikes! pre-buffer poison was overwritten!\n");
			for (i = 0; i < 4096; i+=32) {
				printf("%d: ", i);
				for (j=0; j < 32; j++)
					printf("%x ", userbuffer[i+j]);
				printf("\n");
			}
			(void)fflush(stdout);
			(void)sleep(10);
		}
		if (poisoned==2) {
			printf ("Yikes! post-buffer poison was overwritten!\n");
			for (i = 4096*2; i < 4096*3; i+=32) {
				printf("%i: ", i);
				for (j=0; j < 32; j++)
					printf("%x ", userbuffer[i+j]);
				printf("\n");
			}
			(void)fflush(stdout);
			(void)sleep(10);
		}
	}


	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].flags |= AVOID_SYSCALL;

	return ret;
}

static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, "   --mode=random : pass random values in registers to random syscalls\n");
	fprintf(stderr, "     -s#: use # as random seed.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   --mode=rotate : rotate value through all register combinations\n");
	fprintf(stderr, "     -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, "     -u:  pass userspace addresses as arguments.\n");
	fprintf(stderr, "     -x#: use value as register arguments.\n");
	fprintf(stderr, "     -z:  use all zeros as register parameters.\n");
	fprintf(stderr, "     -Sr: pass struct filled with random junk.\n");
	fprintf(stderr, "     -Sxx: pass struct filled with hex value xx.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   --mode=capcheck:  check syscalls that call capable() return -EPERM.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   -b#: begin at offset #.\n");
	fprintf(stderr, "   -c#: target syscall # only.\n");
	fprintf(stderr, "   -N#: do # syscalls then exit.\n");
	fprintf(stderr, "   -P:  poison buffers before calling syscall, and check afterwards.\n");
	fprintf(stderr, "   -p:  pause after syscall.\n");
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

	(void)alarm(3);

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

		do_syscall(cl);
		if (intelligence==1)
			close_fds();
		_exit(EXIT_SUCCESS);
	}
	(void)waitpid(-1, NULL, 0);
}

static void syscall_list()
{
	int i;

	for (i=0; i<=NR_SYSCALLS; i++) {
		 printf("%i: %s\n", i, syscalls[i].name);
	}
}

static void parse_args(int argc, char *argv[])
{
	int i;
	int opt;

	struct option longopts[] = {
		{ "list", optional_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "mode", required_argument, NULL, 'm' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "b:c:hikLN:m:pPs:S:ux:z", longopts, NULL)) != -1) {
		switch (opt) {
		default:
		case '\0':
			exit(EXIT_FAILURE);

		/* Get the mode we want to run */
		case 'm':
			if (!strcmp(optarg, "random"))
				opmode = MODE_RANDOM;
			if (!strcmp(optarg, "rotate"))
				opmode = MODE_ROTATE;
			if (!strcmp(optarg, "capcheck"))
				opmode = MODE_CAPCHECK;
			break;

		case 'b':
			rep = strtol(optarg, NULL, 10);
			break;

		case 'c':
			do_specific_syscall = 1;
			specificsyscall = strtol(optarg, NULL, 10);

			for (i=0; i<=NR_SYSCALLS; i++) {
				if (strcmp(optarg, syscalls[i].name) == 0) {
					printf("Found %s at %d\n", syscalls[i].name, i);
					specificsyscall = i;
					break;
				}
			}
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;

		/* use semi-intelligent options */
		case 'i':
			intelligence = 1;
			setup_fds();
			break;

		case 'L':
			syscall_list();
			exit(EXIT_SUCCESS);
			break;

		/* Pass in address of kernel text */
		case 'k':
			passed_type = TYPE_VALUE;
			regval = KERNEL_ADDR;
			break;

		/* Set syscall loop counter */
		case 'N':
			syscallcount = strtoll(optarg, NULL, 10);
			break;

		/* Pause after each syscall */
		case 'p':
			dopause = 1;
			break;

		/* Poison buffers before syscall, and check afterwards. */
		case 'P':
			check_poison = 1;
			break;

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			break;

		/* Set Struct fill mode */
		case 'S':
			switch (*optarg) {
				/* Pass a ptr to a struct filled with random junk */
			case 'r':
				structmode = STRUCT_RAND;
				structptr = malloc(page_size);
				if (!structptr)
					exit(EXIT_FAILURE);
				for (i=0; i<page_size; i++)
					structptr[i]= rand();
				break;
			case '\0':
			case ' ':
				fprintf(stderr,
					"-S requires 'r' or a hex value\n");
				exit(EXIT_FAILURE);
				break;

			/* Pass a ptr to a struct filled with the
			 * user-specified constant value. */
			default:
				structmode = STRUCT_CONST;
				if (!isxdigit(*optarg)) {
					fprintf(stderr,
					    "-S requires 'r' or a "
					    "hex value\n");
					exit(EXIT_FAILURE);
				}
				struct_fill = strtol(optarg, NULL, 16);
				structptr = malloc(page_size);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, struct_fill, page_size);
				break;
			}
			passed_type = TYPE_STRUCT;
			regval = (unsigned long) structptr;
			break;

		/* Pass in address of kernel text */
		case 'u':
			passed_type = TYPE_VALUE;
			regval = (unsigned long) useraddr;
			break;

		/* Set registers to specific value */
		case 'x':
			regval = strtoul(optarg, NULL, 0);
			passed_type = TYPE_VALUE;
			break;

		/* Wander a 0 through every register */
		case 'z':
			regval = 0;
			passed_type = TYPE_VALUE;
			break;
		}
	}

	if (opmode == MODE_UNDEFINED) {
		fprintf(stderr, "Unrecognised mode \'%s\'\n", optarg);
		fprintf(stderr, "--mode must be one of random, rotate, regval, "
			"struct, or capcheck\n\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

static void run_setup(void)
{
	int i;

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
}

static void run_mode(void)
{
	int i;

	printf("scrashme mode: %s\n", opmodename[opmode]);

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
		switch (opmode) {
		case MODE_ROTATE:
			/* It's easier to just use all regs for now. */
			for (i=0; i<=NR_SYSCALLS; i++) {
				syscalls[i].num_args = 6;
			}

			if (do_specific_syscall == 1) {
				rotate_mask++;
				if (rotate_mask == (1<<6)-1)
					goto done;
			} else {
				if (rep > NR_SYSCALLS) {
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
			if (rep > NR_SYSCALLS)
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

		/*
		 * If we're passing random structs, regenerate the
		 * buffer every time we make a syscall.
		 */
		if (passed_type == TYPE_STRUCT) {
			if (structmode == STRUCT_RAND) {
				for (i=0; i<page_size; i++) {
					structptr[i]= rand();
					break;
				}
			}
		}

		/* If we're passing userspace addresses, mess with alignment */
		if ((passed_type == TYPE_VALUE) &&
		    ((regval & ~0xf) == (unsigned long)useraddr))
			regval = (unsigned long)useraddr+(rand() & 0xf);

	}
done: ;
}

int main(int argc, char* argv[])
{
	int i;
	int ret;

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

	page_size = getpagesize();

	progname = argv[0];

	/* Sanity test. All NI_SYSCALL's should return ENOSYS. */
	for (i=0; i<=NR_SYSCALLS; i++) {
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

	if (argc==1)
		usage();


	init_buffer();

	parse_args(argc, argv);

	run_setup();

	run_mode();

	if (structptr!=NULL)
		free(structptr);

	exit(EXIT_SUCCESS);
}

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
#include <setjmp.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "arch.h"
#include "arch-syscalls.h"
#include "trinity.h"
#include "files.h"

static char *progname=NULL;
static char *structptr=NULL;
static unsigned int seed=0;
jmp_buf ret_jump;

struct syscalltable *syscalls;
struct syscalltable *syscalls32;

unsigned long long syscallcount = 0;

unsigned long regval = 0;
unsigned long specific_syscall = 0;
unsigned char ctrlc_hit = 0;
unsigned int page_size;
unsigned int rep = 0;
unsigned char rotate_mask = 1;
unsigned char dopause = 0;
unsigned char intelligence = 0;
unsigned char do_specific_syscall = 0;
unsigned char bruteforce = 0;
unsigned char nofork = 0;
unsigned char show_syscall_list = 0;
int do_32bit = 0;

unsigned int max_nr_syscalls;
static unsigned int max_nr_syscalls32;

struct shm_s *shm;

unsigned int opmode = MODE_UNDEFINED;
unsigned int structmode = STRUCT_UNDEFINED;

long struct_fill;		/* value to fill struct with if CONST */

char *opmodename[] = {
	[MODE_UNDEFINED] = "undef",
	[MODE_RANDOM] = "random",
	[MODE_ROTATE] = "rotate",
};
char *structmodename[] = {
	[STRUCT_UNDEFINED] = "unknown",
	[STRUCT_CONST] = "constant",
	[STRUCT_RAND]  = "random",
};

char passed_type = TYPE_UNDEFINED;

char *userbuffer;
char *page_zeros;
char *page_0xff;
char *page_rand;

static char *specific_optarg;

static void init_buffers()
{
	userbuffer = malloc(page_size);
	if (!userbuffer)
		exit(EXIT_FAILURE);

	page_zeros = malloc(page_size);
	if (!page_zeros)
		exit(EXIT_FAILURE);
	memset(page_zeros, 0, page_size);

	page_0xff = malloc(page_size);
	if (!page_0xff)
		exit(EXIT_FAILURE);
	memset(page_0xff, 0xff, page_size);

	page_rand = malloc(page_size);
	if (!page_rand)
		exit(EXIT_FAILURE);

	setup_maps();
}

static void sighandler(int sig)
{
	printf("signal: %s\n", strsignal (sig));
	(void)fflush(stdout);
	(void)signal(sig, sighandler);
	if (sig == SIGALRM)
		printf("Alarm clock.\n");
	_exit(0);
}


unsigned long rand64()
{
	unsigned long r;

	r = (unsigned long)rand();
	r *= (unsigned long)rand();
	return r;
}


static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, "   --mode=random : pass random values in registers to random syscalls\n");
	fprintf(stderr, "     -s#: use # as random seed.\n");
	fprintf(stderr, "     --bruteforce : Keep retrying syscalls until it succeeds (needs -i) [EXPERIMENTAL]\n");
	fprintf(stderr, "     --32bit : call 32bit entrypoint\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   --mode=rotate : rotate value through all register combinations\n");
	fprintf(stderr, "     -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, "     -u:  pass userspace addresses as arguments.\n");
	fprintf(stderr, "     -x#: use value as register arguments.\n");
	fprintf(stderr, "     -z:  use all zeros as register parameters.\n");
	fprintf(stderr, "     -Sr: pass struct filled with random junk.\n");
	fprintf(stderr, "     -Sxx: pass struct filled with hex value xx.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   -b#: begin at offset #.\n");
	fprintf(stderr, "   -c#: target syscall # only.\n");
	fprintf(stderr, "   -F:  don't fork after each syscall.\n");
	fprintf(stderr, "   -i:  pass sensible parameters where possible.\n");
	fprintf(stderr, "   -l, --logfile:  set logfile name\n");
	fprintf(stderr, "   -N#: do # syscalls then exit.\n");
	fprintf(stderr, "   -p:  pause after syscall.\n");
	exit(EXIT_SUCCESS);
}

void seed_from_tod()
{
	struct timeval t;

	gettimeofday(&t, 0);
	seed = t.tv_sec * t.tv_usec;
	srand(seed);
	output("Randomness reseeded to 0x%x\n", seed);
}


static void parse_args(int argc, char *argv[])
{
	unsigned int i;
	int opt;

	struct option longopts[] = {
		{ "list", optional_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "mode", required_argument, NULL, 'm' },
		{ "nofork", optional_argument, NULL, 'F' },
		{ "bruteforce", optional_argument, NULL, 'B' },
		{ "32bit", optional_argument, &do_32bit, 1 },
		{ "logfile", optional_argument, NULL, 'l' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "b:Bc:Fhikl:LN:m:ps:S:ux:z", longopts, NULL)) != -1) {
		switch (opt) {
		default:
		case '\0':
			return;

		/* Get the mode we want to run */
		case 'm':
			if (!strcmp(optarg, "random"))
				opmode = MODE_RANDOM;
			if (!strcmp(optarg, "rotate"))
				opmode = MODE_ROTATE;
			break;

		case 'b':
			rep = strtol(optarg, NULL, 10);
			break;

		case 'B':
			bruteforce = 1;
			break;

		case 'c':
			do_specific_syscall = 1;
			specific_syscall = strtol(optarg, NULL, 10);
			specific_optarg = optarg;
			break;

		case 'F':
			nofork = 1;
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		/* use semi-intelligent options */
		case 'i':
			intelligence = 1;
			break;

		case 'l':
			logfilename = optarg;
			break;

		case 'L':
			show_syscall_list = 1;
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

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			output("Setting random seed to %d\n", seed);
			srand(seed);
			break;

		/* Set Struct fill mode */
		case 'S':
			switch (*optarg) {
				/* Pass a ptr to a struct filled with random junk */
			case 'r':
				structmode = STRUCT_RAND;
				structptr = page_rand;
				for (i=0; i<page_size; i++)
					structptr[i]= rand();
				break;
			case '\0':
			case ' ':
				fprintf(stderr,
					"-S requires 'r' or a hex value\n");
				exit(EXIT_FAILURE);

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

		/* Pass in address of userspace addr text */
		case 'u':
			passed_type = TYPE_VALUE;
			regval = (unsigned long) page_zeros;
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

	if (show_syscall_list == 1)
		return;

	if (bruteforce == 1) {
		if (opmode != MODE_RANDOM) {
			printf("Brute-force only works in --mode=random\n");
			exit(EXIT_FAILURE);
		}
		if (intelligence != 1) {
			printf("Brute-force needs -i\n");
			exit(EXIT_FAILURE);
		}
	}

	if (opmode == MODE_UNDEFINED) {
		fprintf(stderr, "Unrecognised mode \'%s\'\n", optarg);
		fprintf(stderr, "--mode must be one of random, rotate, regval, "
			"or struct\n\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

static void ctrlc(__attribute((unused)) int sig)
{
	ctrlc_hit=1;
}

void mask_signals(void)
{
	int i;

	for (i=1; i<512; i++)  {
		struct sigaction sa;
		sigset_t ss;

		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	(void)signal(SIGWINCH, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGINT, ctrlc);
}

static void find_specific_syscall()
{
	unsigned int i;

	if (specific_syscall != 0) {
		i = specific_syscall;
		if (syscalls[i].flags &= AVOID_SYSCALL) {
			printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls[i].name);
			exit(EXIT_FAILURE);
		}
		return;
	}

	if (do_32bit == 1)
		goto force_32bit;

	for (i=0; i<=max_nr_syscalls; i++) {
		if (strcmp(specific_optarg, syscalls[i].name) == 0) {
			printf("Found %s at %u\n", syscalls[i].name, i);
			if (syscalls[i].flags &= AVOID_SYSCALL) {
				printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls[i].name);
				exit(EXIT_FAILURE);
			}
			specific_syscall = i;
			break;
		}
	}

	if (i > max_nr_syscalls) {

		if (!max_nr_syscalls32)
			goto no_sys32;

force_32bit:
		/* Try looking in the 32bit table. */
		for (i=0; i<=max_nr_syscalls32; i++) {
			if (strcmp(specific_optarg, syscalls32[i].name) == 0) {
				if (syscalls32[i].flags &= AVOID_SYSCALL) {
					printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls32[i].name);
					exit(EXIT_FAILURE);
				}
				printf("Found in the 32bit syscall table %s at %u\n", syscalls32[i].name, i);
				specific_syscall = i;
				printf("Forcing into 32bit mode.\n");
				do_32bit = 1;
				break;
			}
		}

		if (i>max_nr_syscalls32) {
no_sys32:
			printf("syscall not found :(\n");
			exit(EXIT_FAILURE);
		}
	}
}


int main(int argc, char* argv[])
{
	int shmid;
	key_t key;

	if (getuid() == 0) {
		printf("Don't run as root.\n");
		exit(EXIT_FAILURE);
	}

#ifdef __x86_64__
	syscalls32 = syscalls_i386;
	syscalls = syscalls_x86_64;
	max_nr_syscalls = NR_X86_64_SYSCALLS;
	max_nr_syscalls32 = NR_I386_SYSCALLS;
#elif __i386__
	syscalls = syscalls_i386;
	max_nr_syscalls = NR_I386_SYSCALLS;
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

	parse_args(argc, argv);
	if (argc==1)
		usage();

	if (logfilename == NULL)
		logfilename = strdup("trinity-cpu0.log");
	unlink(logfilename);
	logfile = fopen(logfilename, "a");
	if (!logfile) {
		perror("couldn't open logfile\n");
		exit(EXIT_FAILURE);
	}

	max_nr_syscalls = NR_SYSCALLS;


#ifdef __x86_64__
	if (do_32bit) {
		syscalls = syscalls_i386;
		max_nr_syscalls = NR_I386_SYSCALLS;
		printf("32bit mode. Fuzzing %d syscalls.\n", max_nr_syscalls);
	} else {
		printf("64bit mode. Fuzzing %d syscalls.\n", max_nr_syscalls);
	}
#endif

	if (do_specific_syscall == 1)
		find_specific_syscall();

	if (show_syscall_list == 1) {
		syscall_list();
		exit(EXIT_SUCCESS);
	}

	/* rotate doesn't work with nofork. */
	if (opmode == MODE_ROTATE)
		nofork = 0;

	page_size = getpagesize();

	if (!seed)
		seed_from_tod();

	key = rand64();
	if ((shmid = shmget(key, sizeof(struct shm_s), IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		exit(EXIT_FAILURE);
	}
	if ((shm = shmat(shmid, NULL, 0)) == (void *) -1) {
		perror("shmat");
		exit(EXIT_FAILURE);
	}
	shm->successes = 0;
	shm->failures = 0;

	init_buffers();

	if (intelligence == 1)
		setup_fds();

	check_sanity();

	mask_signals();

	/* just in case we're not using the test.sh harness. */
	chmod("tmp/", 0755);
	chdir("tmp/");

	sigsetjmp(ret_jump, 1);

	display_opmode();

	do_main_loop();

	if ((structptr!=NULL) && (structmode != STRUCT_RAND))
		free(structptr);

	printf("\nRan %ld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		shm->execcount, shm->retries, shm->successes, shm->failures);

	shmdt(shm);

	exit(EXIT_SUCCESS);
}

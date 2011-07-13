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
#include <sys/socket.h>

#include "arch.h"
#include "arch-syscalls.h"
#include "trinity.h"
#include "files.h"

static char *progname=NULL;
static unsigned int seed=0;
jmp_buf ret_jump;

struct syscalltable *syscalls;
struct syscalltable *syscalls32;

unsigned long long syscallcount = 0;

unsigned long regval = 0;
unsigned long specific_syscall = 0;
unsigned int specific_proto = 0;
unsigned char ctrlc_hit = 0;
unsigned int page_size;
unsigned int rep = 0;
unsigned char rotate_mask = 1;
unsigned char dopause = 0;
unsigned char intelligence = 0;
unsigned char do_specific_syscall = 0;
unsigned char do_specific_proto = 0;
unsigned char bruteforce = 0;
unsigned char nofork = 0;
unsigned char show_syscall_list = 0;
int do_32bit = 0;

unsigned int max_nr_syscalls;
static unsigned int max_nr_syscalls32;

struct shm_s *shm;

unsigned int opmode = MODE_UNDEFINED;

char *opmodename[] = {
	[MODE_UNDEFINED] = "undef",
	[MODE_RANDOM] = "random",
	[MODE_ROTATE] = "rotate",
};

char *userbuffer;
char *page_zeros;
char *page_0xff;
char *page_rand;

static char *specific_syscall_optarg;
static char *specific_proto_optarg;

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
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   -P,--proto=#: Create socket fd's using a specific protocol.\n");
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
	int opt;

	struct option longopts[] = {
		{ "list", no_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "mode", required_argument, NULL, 'm' },
		{ "nofork", no_argument, NULL, 'F' },
		{ "bruteforce", no_argument, NULL, 'B' },
		{ "32bit", no_argument, &do_32bit, 1 },
		{ "logfile", required_argument, NULL, 'l' },
		{ "proto", required_argument, NULL, 'P' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "b:Bc:Fhikl:LN:m:P:ps:ux:z", longopts, NULL)) != -1) {
		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				printf("opt:%c\n", opt);

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
			specific_syscall_optarg = optarg;
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
			regval = KERNEL_ADDR;
			break;

		/* Set syscall loop counter */
		case 'N':
			syscallcount = strtoll(optarg, NULL, 10) + 1;
			break;

		/* Pause after each syscall */
		case 'p':
			dopause = 1;
			break;

		case 'P':
			do_specific_proto = 1;
			specific_proto = strtol(optarg, NULL, 10);
			specific_proto_optarg = optarg;
			break;

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			srand(seed);
			break;

		/* Pass in address of userspace addr text */
		case 'u':
			regval = (unsigned long) page_zeros;
			break;

		/* Set registers to specific value */
		case 'x':
			regval = strtoul(optarg, NULL, 0);
			break;

		/* Wander a 0 through every register */
		case 'z':
			regval = 0;
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
		if (optarg != NULL)
			fprintf(stderr, "Unrecognised mode \'%s\'\n", optarg);
		fprintf(stderr, "--mode must be either random or rotate\n\n");
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
		if (syscalls[i].entry->flags &= AVOID_SYSCALL) {
			printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls[i].entry->name);
			exit(EXIT_FAILURE);
		}
		return;
	}

	if (do_32bit == 1)
		goto force_32bit;

	for (i = 0; i < max_nr_syscalls; i++) {
		if (strcmp(specific_syscall_optarg, syscalls[i].entry->name) == 0) {
			printf("Found %s at %u\n", syscalls[i].entry->name, i);
			if (syscalls[i].entry->flags &= AVOID_SYSCALL) {
				printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls[i].entry->name);
				exit(EXIT_FAILURE);
			}
			specific_syscall = i;
			break;
		}
	}

	if (i == max_nr_syscalls) {
		printf("couldn't find syscall. looking in 32bit table\n");
		if (!max_nr_syscalls32)
			goto no_sys32;

force_32bit:
		/* Try looking in the 32bit table. */
		for (i = 0; i < max_nr_syscalls32; i++) {
			if (strcmp(specific_syscall_optarg, syscalls32[i].entry->name) == 0) {
				if (syscalls32[i].entry->flags &= AVOID_SYSCALL) {
					printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls32[i].entry->name);
					exit(EXIT_FAILURE);
				}
				printf("Found in the 32bit syscall table %s at %u\n", syscalls32[i].entry->name, i);
				specific_syscall = i;
				printf("Forcing into 32bit mode.\n");
				do_32bit = 1;
				break;
			}
		}

		if (i == max_nr_syscalls32) {
no_sys32:
			printf("syscall not found :(\n");
			exit(EXIT_FAILURE);
		}
	}
}

struct protocol {
	char *name;
	unsigned int proto;
};

static struct protocol protocols[] = {
	{ "PF_UNSPEC",       0 },
	{ "PF_LOCAL",        1 },
	{ "PF_UNIX",         PF_LOCAL },
	{ "PF_FILE",         PF_LOCAL },
	{ "PF_INET",         2 },
	{ "PF_AX25",         3 },
	{ "PF_IPX",          4 },
	{ "PF_APPLETALK",    5 },
	{ "PF_NETROM",       6 },
	{ "PF_BRIDGE",       7 },
	{ "PF_ATMPVC",       8 },
	{ "PF_X25",          9 },
	{ "PF_INET6",        10 },
	{ "PF_ROSE",         11 },
	{ "PF_DECnet",       12 },
	{ "PF_NETBEUI",      13 },
	{ "PF_SECURITY",     14 },
	{ "PF_KEY",          15 },
	{ "PF_NETLINK",      16 },
	{ "PF_ROUTE",        PF_NETLINK },
	{ "PF_PACKET",       17 },
	{ "PF_ASH",          18 },
	{ "PF_ECONET",       19 },
	{ "PF_ATMSVC",       20 },
	{ "PF_RDS",          21 },
	{ "PF_SNA",          22 },
	{ "PF_IRDA",         23 },
	{ "PF_PPPOX",        24 },
	{ "PF_WANPIPE",      25 },
	{ "PF_LLC",          26 },
	{ "PF_CAN",          29 },
	{ "PF_TIPC",         30 },
	{ "PF_BLUETOOTH",    31 },
	{ "PF_IUCV",         32 },
	{ "PF_RXRPC",        33 },
	{ "PF_ISDN",         34 },
	{ "PF_PHONET",       35 },
	{ "PF_IEEE802154",   36 },
	{ "PF_CAIF",         37 },
	{ "PF_ALG",          38 },
};

static void find_specific_proto()
{
	unsigned int i;
	struct protocol *p = protocols;

	if (specific_proto == 0) {
		/* we were passed a string */
		for (i = 0; i < (sizeof(protocols) / sizeof(struct protocol)); i++) {
			if (strcmp(specific_proto_optarg, p[i].name) == 0) {
				specific_proto = p[i].proto;
				break;
			}
		}
	} else {
		/* we were passed a numeric arg. */
		for (i = 0; i < PROTO_MAX; i++) {
			if (specific_proto == p[i].proto)
				break;
		}
	}

	if (i > PF_MAX) {
		printf("Protocol unknown. Pass a numeric value [0-%d] or one of ", PF_MAX);
		for (i = 0; i < (sizeof(protocols) / sizeof(struct protocol)); i++)
			printf("%s ", p[i].name);
		printf("\n");

		exit(EXIT_FAILURE);
	}

	printf("Using protocol %s (%u) for all sockets\n", p[i].name, p[i].proto);
	return;
}


int main(int argc, char* argv[])
{
	int shmid, ret;
	unsigned int i;
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

	if (do_specific_proto == 1)
		find_specific_proto();

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
	else
		output("Setting random seed to 0x%x\n", seed);

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
	shm->regenerate_fds = FD_REGENERATION_POINT - 1;

	init_buffers();

	if (intelligence == 1)
		setup_fds();

	check_sanity();

	mask_signals();

	/* just in case we're not using the test.sh harness. */
	chmod("tmp/", 0755);
	ret = chdir("tmp/");
	if (!ret) {
		/* nothing right now */
	}

	sigsetjmp(ret_jump, 1);

	display_opmode();

	do_main_loop();

	printf("\nRan %ld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		shm->execcount - 1, shm->retries, shm->successes, shm->failures);

	shmdt(shm);

	destroy_maps();

	for (i = 0; i < socks; i++)
		close(socket_fds[i]);

	fclose(logfile);

	exit(EXIT_SUCCESS);
}

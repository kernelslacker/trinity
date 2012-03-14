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

unsigned long long syscallcount = 0;

unsigned char debug = 0;

unsigned long regval = 0;
unsigned long specific_syscall = 0;
unsigned int specific_proto = 0;
unsigned int page_size;
unsigned char dopause = 0;
unsigned char do_specific_syscall = 0;
unsigned char do_specific_proto = 0;
unsigned long syscalls_per_child = DEFAULT_SYSCALLS_PER_CHILD;
unsigned char show_syscall_list = 0;
unsigned char quiet = 0;
static unsigned char dangerous = 0;
unsigned char logging = 1;

static unsigned char desired_group = GROUP_NONE;

unsigned int max_nr_syscalls;

struct shm_s *shm;

char *page_zeros;
char *page_0xff;
char *page_rand;
char *page_allocs;

static char *specific_syscall_optarg;
static char *specific_proto_optarg;

static void init_buffers()
{
	unsigned int i;

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
	memset(page_rand, 0x55, page_size);	/* overwritten below */

	page_allocs = malloc(page_size);
	if (!page_allocs)
		exit(EXIT_FAILURE);
	memset(page_allocs, 0xff, page_size);

	for (i = 0; i < (page_size / sizeof(unsigned long *)); i++)
		page_allocs[i] = (unsigned long) malloc(page_size);

	setup_maps();

	// regenerate_random_page may end up using maps, so has to be last.
	regenerate_random_page();
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
	fprintf(stderr, " --list: list all syscalls known on this architecture.\n");
	fprintf(stderr, " --quiet: less output.\n");
	fprintf(stderr, " --childcalls,-F: number of syscalls to do in child.\n");
	fprintf(stderr, " --logging,-l: (off=disable logging).\n");
	fprintf(stderr, " --proto,-P: specify specific network protocol for sockets.\n");
	fprintf(stderr, " --group: only run syscalls from a certain group (So far just 'vm').\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " -c#: target syscall # only.\n");
	fprintf(stderr, " -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, " -N#: do # syscalls then exit.\n");
	fprintf(stderr, " -p:  pause after syscall.\n");
	fprintf(stderr, " -s#: use # as random seed.\n");
	fprintf(stderr, " -u:  pass userspace addresses as arguments.\n");
	fprintf(stderr, " -x#: use value as register arguments.\n");
	fprintf(stderr, " -z:  use all zeros as register parameters.\n");
	exit(EXIT_SUCCESS);
}

void seed_from_tod()
{
	struct timeval t;

	gettimeofday(&t, 0);
	seed = t.tv_sec * t.tv_usec;
	srand(seed);
	output("[%d] Random seed: %u (0x%x)\n", getpid(), seed, seed);
}


static void parse_args(int argc, char *argv[])
{
	int opt;

	struct option longopts[] = {
		{ "list", no_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "childcalls", required_argument, NULL, 'F' },
		{ "logging", required_argument, NULL, 'l' },
		{ "proto", required_argument, NULL, 'P' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "dangerous", no_argument, NULL, 'd' },
		{ "group", required_argument, NULL, 'g' },
		{ "debug", no_argument, NULL, 'D' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "c:dDF:g:hkl:LN:m:P:pqs:Sux:z", longopts, NULL)) != -1) {
		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				printf("opt:%c\n", opt);
			return;

		case '\0':
			return;

		case 'c':
			do_specific_syscall = 1;
			specific_syscall = strtol(optarg, NULL, 10);
			specific_syscall_optarg = optarg;
			break;

		case 'd':
			dangerous = 1;
			break;

		case 'D':
			debug = 1;
			break;

		case 'F':
			syscalls_per_child = strtol(optarg, NULL, 10);
			printf("doing %ld syscalls per child\n", syscalls_per_child);
			break;

		case 'g':
			if (!strcmp(optarg, "vm"))
				desired_group = GROUP_VM;
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'l':
			if (!strcmp(optarg, "off"))
				logging = 0;
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

		case 'q':
			quiet = 1;
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

		/* Pass zeros in registers */
		case 'z':
			regval = 0;
			break;
		}
	}

	if (show_syscall_list == 1)
		return;
}


static void sighandler(int sig)
{
	if (debug == 1) {
		printf("[%d] signal: %s\n", getpid(), strsignal(sig));
		(void)fflush(stdout);
	}
	(void)signal(sig, sighandler);
	_exit(0);
}

static void mask_signals(void)
{
	struct sigaction sa;
	sigset_t ss;

	(void)sigfillset(&ss);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sighandler;
	sa.sa_mask = ss;
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGFPE, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	(void)sigaction(SIGILL, &sa, NULL);
}

static void find_specific_syscall()
{
	unsigned int i;

	if (isdigit(*specific_syscall_optarg)) {
		i = specific_syscall;
		if (syscalls[i].entry->flags &= AVOID_SYSCALL) {
			printf("%s is marked AVOID_SYSCALL (probably for good reason)\n", syscalls[i].entry->name);
			exit(EXIT_FAILURE);
		}
		return;
	}

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
		printf("syscall not found :(\n");
		exit(EXIT_FAILURE);
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

int create_shm()
{
	int shmid;
	key_t key;
	struct shmid_ds shmid_ds;

	key = rand64();
	if ((shmid = shmget(key, sizeof(struct shm_s), IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		return -1;
	}
	if ((shm = shmat(shmid, NULL, 0)) == (void *) -1) {
		perror("shmat");
		return -1;
	}
	shmctl(key, IPC_RMID, &shmid_ds);

	shm->successes = 0;
	shm->failures = 0;
	shm->regenerate = REGENERATION_POINT - 1;

	shm->nr_childs = sysconf(_SC_NPROCESSORS_ONLN);
	if (shm->nr_childs > MAX_NR_CHILDREN) {
		printf("Increase MAX_NR_CHILDREN!\n");
		exit(EXIT_FAILURE);
	}
	memset(shm->pids, -1, sizeof(shm->pids));
	return 0;
}


int main(int argc, char* argv[])
{
	int ret;
	unsigned int i;

	printf("Trinity v" __stringify(VERSION) "  Dave Jones <davej@redhat.com> 2012\n");

#ifdef __x86_64__
	syscalls = syscalls_x86_64;
	max_nr_syscalls = NR_X86_64_SYSCALLS;
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

	if (getuid() == 0) {
		if (dangerous == 1) {
			printf("DANGER: RUNNING AS ROOT.\n");
			printf("Unless you are running in a virtual machine, this could cause serious problems such as overwriting CMOS\n");
			printf("or similar which could potentially make this machine unbootable without a firmware reset.\n\n");
			printf("ctrl-c now unless you really know what you are doing.\n");
			for (i = 10; i > 0; i--) {
				printf("Continuing in %d seconds.\r", i);
				(void)fflush(stdout);
				sleep(1);
			}
		} else {
			printf("Don't run as root (or pass --dangerous if you know what you are doing).\n");
			exit(EXIT_FAILURE);
		}
	}

	if (create_shm())
		exit(EXIT_FAILURE);

	if (logging != 0)
		open_logfiles(shm->nr_childs);

	max_nr_syscalls = NR_SYSCALLS;
	for (i = 0; i < max_nr_syscalls; i++)
		syscalls[i].entry->number = i;

	if (desired_group == GROUP_VM) {
		struct syscalltable *newsyscalls;
		int count = 0, j = 0;

		for (i = 0; i < max_nr_syscalls; i++) {
			if (syscalls[i].entry->group == GROUP_VM)
				count++;
		}

		newsyscalls = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls == NULL)
			exit(EXIT_FAILURE);

		for (i = 0; i < max_nr_syscalls; i++) {
			if (syscalls[i].entry->group == GROUP_VM)
				newsyscalls[j++].entry = syscalls[i].entry;
		}

		max_nr_syscalls = count;
		syscalls = newsyscalls;
	}


	if (!do_specific_syscall)
		output("Fuzzing %d syscalls.\n", max_nr_syscalls);

	if (do_specific_syscall == 1)
		find_specific_syscall();

	if (do_specific_proto == 1)
		find_specific_proto();

	if (show_syscall_list == 1) {
		syscall_list();
		exit(EXIT_SUCCESS);
	}

	page_size = getpagesize();

	if (!seed)
		seed_from_tod();
	else
		output("Random seed: %u (0x%x)\n", seed, seed);


	init_buffers();

	mask_signals();

	setup_fds();

	if (check_tainted() != 0) {
		output("Kernel was tainted on startup. Will keep running if trinity causes an oops.\n");
		do_check_tainted = 1;
	}

	/* just in case we're not using the test.sh harness. */
	chmod("tmp/", 0755);
	ret = chdir("tmp/");
	if (!ret) {
		/* nothing right now */
	}

	main_loop();

	printf("\nRan %ld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		shm->execcount - 1, shm->retries, shm->successes, shm->failures);

	shmdt(shm);

	destroy_maps();

	for (i = 0; i < socks; i++)
		close(socket_fds[i]);

	if (logging != 0)
		close_logfiles();

	exit(EXIT_SUCCESS);
}

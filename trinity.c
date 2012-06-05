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
#include <malloc.h>
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
#include "shm.h"
#include "syscall.h"

pid_t parentpid;
static char *progname=NULL;
static unsigned int seed=0;
jmp_buf ret_jump;

struct syscalltable *syscalls;
struct syscalltable *syscalls_32bit;
struct syscalltable *syscalls_64bit;

unsigned long long syscallcount = 0;

unsigned char debug = 0;

static unsigned char do_specific_syscall = FALSE;
static unsigned char do_exclude_syscall = FALSE;

unsigned int specific_proto = 0;
unsigned int page_size;
unsigned char dopause = 0;
unsigned char do_specific_proto = 0;
unsigned char show_syscall_list = 0;
unsigned char quiet = 0;
unsigned char monochrome = 0;
static unsigned char dangerous = 0;
unsigned char logging = 1;
unsigned char extrafork = 0;

static unsigned char desired_group = GROUP_NONE;

unsigned int max_nr_syscalls;
unsigned int max_nr_32bit_syscalls;
unsigned int max_nr_64bit_syscalls;

unsigned char biarch = FALSE;

struct shm_s *shm;

char *page_zeros;
char *page_0xff;
char *page_rand;
char *page_allocs;

static char *specific_proto_optarg;

char *victim_path;

static void init_buffers()
{
	unsigned int i;

	page_zeros = memalign(page_size, page_size * 2);
	if (!page_zeros)
		exit(EXIT_FAILURE);
	memset(page_zeros, 0, page_size);
	output("page_zeros @ %p\n", page_zeros);

	page_0xff = memalign(page_size, page_size * 2);
	if (!page_0xff)
		exit(EXIT_FAILURE);
	memset(page_0xff, 0xff, page_size);
	output("page_0xff @ %p\n", page_0xff);

	page_rand = memalign(page_size, page_size * 2);
	if (!page_rand)
		exit(EXIT_FAILURE);
	memset(page_rand, 0x55, page_size);	/* overwritten below */
	output("page_rand @ %p\n", page_rand);

	page_allocs = memalign(page_size, page_size * 2);
	if (!page_allocs)
		exit(EXIT_FAILURE);
	memset(page_allocs, 0xff, page_size);
	output("page_allocs @ %p\n", page_allocs);

	for (i = 0; i < (page_size / sizeof(unsigned long *)); i++)
		page_allocs[i] = (unsigned long) malloc(page_size);

	setup_maps();

	// regenerate_random_page may end up using maps, so has to be last.
	regenerate_random_page();
}


unsigned long rand64()
{
	unsigned long r = 0;

	switch (rand() % 3) {
	case 0:
		r = (unsigned long)rand() & rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= (unsigned long)rand() & rand();
#endif
		break;

	case 1:
		r = (unsigned long)rand() | rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= (unsigned long)rand() | rand();
#endif
		break;

	case 2:
		r = (unsigned long)rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= (unsigned long)rand();
#endif
		break;

	default:
		break;
	}
	return r;
}


void seed_from_tod()
{
	struct timeval t;

	gettimeofday(&t, 0);
	seed = t.tv_sec * t.tv_usec;
	srand(seed);
	output("\n\n[%d] Random seed: %u (0x%x)\n", getpid(), seed, seed);
}

static int parse_victim_path(char *opt)
{
	struct stat statbuf;
	int status;

	status = stat(opt, &statbuf);
	if (status == -1) {
		printf("stat failed\n");
		return -1;
	}

	if (!(S_ISDIR(statbuf.st_mode))) {
		printf("Victim path not a directory\n");
		return -1;
	}

	victim_path = strdup(opt);

	return 0;
}

static int search_syscall_table(struct syscalltable *table, unsigned int nr_syscalls, char *arg)
{
	unsigned int i;

	/* search by name */
	for (i = 0; i < nr_syscalls; i++) {
		if (strcmp(arg, table[i].entry->name) == 0) {
			//printf("Found %s at %u\n", table[i].entry->name, i);
			return i;
		}
	}

	return -1;
}

static int validate_specific_syscall(struct syscalltable *table, int call)
{
	if (call != -1) {
		if (table[call].entry->flags & AVOID_SYSCALL) {
			printf("%s is marked as AVOID. Skipping\n", table[call].entry->name);
			return FALSE;
		}

		if (table[call].entry->flags & NI_SYSCALL) {
			printf("%s is NI_SYSCALL. Skipping\n", table[call].entry->name);
			return FALSE;
		}
		if (table[call].entry->num_args == 0) {
			printf("%s has no arguments. Skipping\n", table[call].entry->name);
			return FALSE;
		}
	}
	return TRUE;
}

static void mark_all_syscalls_active(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++)
			syscalls_32bit[i].entry->flags |= ACTIVE;
		for (i = 0; i < max_nr_64bit_syscalls; i++)
			syscalls_64bit[i].entry->flags |= ACTIVE;
	} else {
		for (i = 0; i < max_nr_syscalls; i++)
			syscalls[i].entry->flags |= ACTIVE;
	}
}


static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, " --exclude,-x: don't call a specific syscall\n");
	fprintf(stderr, " --group,-g: only run syscalls from a certain group (So far just 'vm').\n");
	fprintf(stderr, " --list,-L: list all syscalls known on this architecture.\n");
	fprintf(stderr, " --logging,-l: (off=disable logging).\n");
	fprintf(stderr, " --monochrome,-m: don't output ANSI codes\n");
	fprintf(stderr, " --proto,-P: specify specific network protocol for sockets.\n");
	fprintf(stderr, " --quiet,-q: less output.\n");
	fprintf(stderr, " --victims,-V: path to victim files.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " -c#: target specific syscall (takes syscall name as parameter).\n");
	fprintf(stderr, " -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, " -N#: do # syscalls then exit.\n");
	fprintf(stderr, " -p:  pause after syscall.\n");
	fprintf(stderr, " -s#: use # as random seed.\n");
	exit(EXIT_SUCCESS);
}

static void toggle_syscall(char *arg, unsigned char state)
{
	int specific_syscall32 = 0;
	int specific_syscall64 = 0;
	int ret;

	if (biarch == TRUE)
		specific_syscall64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, arg);
	else
		specific_syscall64 = -1;

	/* If we found a 64bit syscall, validate it. */
	if (specific_syscall64 != -1) {
		ret = validate_specific_syscall(syscalls_64bit, specific_syscall64);
		if (ret == FALSE)
			exit(EXIT_FAILURE);
		if (state == TRUE) {
			printf("[%d] Marking 64-bit syscall %d (%s) as enabled\n", getpid(), specific_syscall64, arg);
			syscalls_64bit[specific_syscall64].entry->flags |= ACTIVE;
		} else {
			printf("[%d] Marking 64-bit syscall %d (%s) as disabled\n", getpid(), specific_syscall64, arg);
			syscalls_64bit[specific_syscall64].entry->flags &= ~ACTIVE;
		}
	}

	/* Search for and validate 32bit */
	specific_syscall32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, arg);
	if (specific_syscall32 != -1) {
		ret = validate_specific_syscall(syscalls_32bit, specific_syscall32);
		if (ret == FALSE)
			exit(EXIT_FAILURE);
		if (state == TRUE) {
			printf("[%d] Marking 32-bit syscall %d (%s) as enabled\n", getpid(), specific_syscall32, arg);
			syscalls_32bit[specific_syscall32].entry->flags |= ACTIVE;
		} else {
			printf("[%d] Marking 32-bit syscall %d (%s) as disabled\n", getpid(), specific_syscall32, arg);
			syscalls_32bit[specific_syscall32].entry->flags &= ~ACTIVE;
		}
	}

	if ((specific_syscall64 == -1) && (specific_syscall32 == -1)) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}
}

void dump_syscall_status(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++) {
			printf("32bit %s : ", syscalls_32bit[i].entry->name);
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
		for (i = 0; i < max_nr_64bit_syscalls; i++) {
			printf("64bit %s : ", syscalls_64bit[i].entry->name);
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
	} else {
		for (i = 0; i < max_nr_syscalls; i++) {
			printf("%s : ", syscalls[i].entry->name);
			if (syscalls[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
	}
}


static void parse_args(int argc, char *argv[])
{
	int opt;

	struct option longopts[] = {
		{ "dangerous", no_argument, NULL, 'd' },
		{ "debug", no_argument, NULL, 'D' },
		{ "exclude", required_argument, NULL, 'x' },
		{ "group", required_argument, NULL, 'g' },
		{ "help", no_argument, NULL, 'h' },
		{ "list", no_argument, NULL, 'L' },
		{ "logging", required_argument, NULL, 'l' },
		{ "monochrome", no_argument, NULL, 'M' },
		{ "proto", required_argument, NULL, 'P' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "victims", required_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "c:dDfg:hl:LN:mP:pqs:SV:x:", longopts, NULL)) != -1) {
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
			/* syscalls are all disabled at this point. enable the syscall we care about. */
			do_specific_syscall = TRUE;
			toggle_syscall(optarg, TRUE);
			printf("Enabling syscall %s\n", optarg);
			break;

		case 'd':
			dangerous = 1;
			break;

		case 'D':
			debug = 1;
			break;

		case 'f':
			extrafork = 1;
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

		case 'm':
			monochrome = TRUE;
			break;

		/* Set number of syscalls to do */
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

		case 'V':
			if (parse_victim_path(optarg) < 0) {
				printf("oops\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'x':
			/* First time we see a '-x', set all syscalls to enabled, then selectively disable. */
			if (do_exclude_syscall == FALSE)
				mark_all_syscalls_active();

			do_exclude_syscall = TRUE;
			toggle_syscall(optarg, FALSE);

			printf("Disabling syscall %s\n", optarg);
		}
	}

	if (show_syscall_list == 1)
		return;
}

static void sighandler(__unused__ int sig)
{
/*	if (sig == SIGALRM) {
		(void)signal(sig, sighandler);
		siglongjmp(ret_jump, 1);
	}
*/
	_exit(EXIT_SUCCESS);
}

static void mask_signals(void)
{
	struct sigaction sa;
	sigset_t ss;
	unsigned int i;

	for (i = 1; i < 512; i++) {
		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	(void)signal(SIGCHLD, SIG_DFL);
	(void)signal(SIGFPE, SIG_IGN);
	if (debug == TRUE)
		(void)signal(SIGSEGV, SIG_DFL);
}

int create_shm()
{
	int shmid;
	key_t key;
	struct shmid_ds shmid_ds;

	key = IPC_PRIVATE;
	if ((shmid = shmget(key, sizeof(struct shm_s), IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		return -1;
	}
	if ((shm = shmat(shmid, NULL, 0)) == (void *) -1) {
		perror("shmat");
		return -1;
	}
	shmctl(key, IPC_RMID, &shmid_ds);

	memset(shm, 0, sizeof(struct shm_s));

	shm->execcount = 1;
	shm->regenerate = REGENERATION_POINT - 1;

	shm->nr_childs = sysconf(_SC_NPROCESSORS_ONLN);
	if (shm->nr_childs > MAX_NR_CHILDREN) {
		printf("Increase MAX_NR_CHILDREN!\n");
		exit(EXIT_FAILURE);
	}
	memset(shm->pids, -1, sizeof(shm->pids));
	return 0;
}


void setup_syscall_tables(void)
{
	unsigned int i;

#if defined(__x86_64__)
	syscalls_64bit = syscalls_x86_64;
	syscalls_32bit = syscalls_i386;
	max_nr_64bit_syscalls = NR_X86_64_SYSCALLS;
	max_nr_32bit_syscalls = NR_I386_SYSCALLS;
	biarch = TRUE;
#elif defined(__i386__)
	syscalls = syscalls_i386;
	max_nr_syscalls = NR_I386_SYSCALLS;
#elif defined(__powerpc__)
	syscalls = syscalls_ppc;
#elif defined(__ia64__)
	syscalls = syscalls_ia64;
#elif defined(__sparc__)
	syscalls = syscalls_sparc;
#else
	syscalls = syscalls_i386;
#endif

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++)
			syscalls_32bit[i].entry->number = i;

		for (i = 0; i < max_nr_64bit_syscalls; i++)
			syscalls_64bit[i].entry->number = i;
	} else {
		for (i = 0; i < max_nr_syscalls; i++)
			syscalls[i].entry->number = i;
	}
}

int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;
	unsigned int i;

	printf("Trinity v" __stringify(VERSION) "  Dave Jones <davej@redhat.com> 2012\n");

	progname = argv[0];
	parentpid = getpid();

	setup_syscall_tables();

	parse_args(argc, argv);

	/* If we didn't pass -c or -x, mark all syscalls active. */
	if ((do_specific_syscall == FALSE) && (do_exclude_syscall == FALSE))
		mark_all_syscalls_active();

	if (debug == TRUE)
		dump_syscall_status();

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

	if (show_syscall_list == TRUE) {
		syscall_list();
		goto cleanup_shm;
	}

	if (logging != 0)
		open_logfiles();

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

	if (!do_specific_syscall) {
		if (biarch == TRUE)
			output("Fuzzing %d 32-bit syscalls & %d 64-bit syscalls.\n",
				max_nr_32bit_syscalls, max_nr_64bit_syscalls);
		else
			output("Fuzzing %d syscalls.\n", max_nr_syscalls);
	}

	if (do_specific_proto == 1)
		find_specific_proto(specific_proto_optarg);

	page_size = getpagesize();

	if (!seed)
		seed_from_tod();
	else
		output("[%d] Random seed: %u (0x%x)\n", getpid(), seed, seed);


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

	wait_for_watchdog_to_exit();

	printf("\nRan %ld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		shm->execcount - 1, shm->retries, shm->successes, shm->failures);

	ret = EXIT_SUCCESS;


	destroy_maps();

	for (i = 0; i < socks; i++)
		close(shm->socket_fds[i]);

	if (logging != 0)
		close_logfiles();

cleanup_shm:

	shmdt(shm);

	exit(ret);
}

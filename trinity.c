#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <setjmp.h>
#include <malloc.h>
#include <syslog.h>
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
#include "trinity.h"
#include "files.h"
#include "shm.h"
#include "syscall.h"

char *progname = NULL;
unsigned int seed = 0;
jmp_buf ret_jump;

unsigned int page_size;

unsigned char biarch = FALSE;

struct shm_s *shm;

char *page_zeros;
char *page_0xff;
char *page_rand;
char *page_allocs;


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

void set_seed(unsigned int pidslot)
{
	struct timeval t;

	if (user_set_seed == TRUE)
		output("[%d] Using user passed random seed: %u (0x%x)\n", getpid(), seed, seed);
	else {
		gettimeofday(&t, 0);
		seed = t.tv_sec * t.tv_usec;

		output("[%d:%d] Random seed from time of day: %u (0x%x)\n", pidslot, getpid(), seed, seed);
	}

	/* Mix in the pidslot so that all children get different randomness.
	 * we can't use the actual pid or anything else 'random' because otherwise reproducing
	 * seeds with -s would be much harder to replicate.
	 *
	 * This still isn't perfect: When we -s right now, we set all children to the same seed.
	 *  This sucks if the bug we're trying to reproduce was caused by interaction between threads.
	 */
	srand(seed << pidslot);

	if (do_syslog == FALSE)
		return;

	fprintf(stderr, "Randomness reseeded to 0x%x\n", seed);
	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Randomness reseeded to 0x%x\n", seed);
	closelog();
}

static void sighandler(__unused__ int sig)
{
	switch(sig) {
	case SIGALRM:
		/* if we blocked in read() or similar, we want to avoid doing it again. */
		shm->fd_lifetime = 0;

		(void)signal(sig, sighandler);
		siglongjmp(ret_jump, 1);
		break;

	case SIGINT:
		shm->exit_reason = EXIT_SIGINT;
		break;

	default:
		_exit(EXIT_SUCCESS);
	}
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
	(void)signal(SIGXCPU, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGWINCH, SIG_IGN);
	if (debug == TRUE)
		(void)signal(SIGSEGV, SIG_DFL);
}

static int create_shm()
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
	shm->regenerate = 0;

	shm->nr_childs = sysconf(_SC_NPROCESSORS_ONLN);
	if (shm->nr_childs > MAX_NR_CHILDREN) {
		printf("Increase MAX_NR_CHILDREN!\n");
		exit(EXIT_FAILURE);
	}
	memset(shm->pids, -1, sizeof(shm->pids));

	shm->parentpid = getpid();
	return 0;
}


int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;
	unsigned int i;

	printf("Trinity v" __stringify(VERSION) "  Dave Jones <davej@redhat.com> 2012\n");

	progname = argv[0];

	setup_syscall_tables();

	parse_args(argc, argv);

	/* If we didn't pass -c or -x, mark all syscalls active. */
	if ((do_specific_syscall == FALSE) && (do_exclude_syscall == FALSE))
		mark_all_syscalls_active();

	if (getuid() == 0) {
		if (dangerous == TRUE) {
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

	if (desired_group != GROUP_NONE) {
		ret = setup_syscall_group(desired_group);
		if (ret == FALSE) {
			ret = EXIT_FAILURE;
			goto cleanup_shm;
		}
	}

	if (show_syscall_list == TRUE) {
		dump_syscall_tables();
		goto cleanup_shm;
	}

	if (validate_syscall_tables() == FALSE) {
		printf("No syscalls were enabled!\n");
		printf("Use 32bit:%d 64bit:%d\n", use_32bit, use_64bit);
		goto cleanup_shm;
	}

	sanity_check_tables();

	if (logging == TRUE)
		open_logfiles();


	if (do_specific_syscall == FALSE) {
		if (biarch == TRUE)
			output("Fuzzing %d 32-bit syscalls & %d 64-bit syscalls.\n",
				max_nr_32bit_syscalls, max_nr_64bit_syscalls);
		else
			output("Fuzzing %d syscalls.\n", max_nr_syscalls);
	}

	if (do_specific_proto == TRUE)
		find_specific_proto(specific_proto_optarg);

	page_size = getpagesize();

	init_buffers();

	mask_signals();

	setup_fds();

	if (check_tainted() != 0) {
		output("Kernel was tainted on startup. Will keep running if trinity causes an oops.\n");
		do_check_tainted = TRUE;
	}

	/* just in case we're not using the test.sh harness. */
	chmod("tmp/", 0755);
	ret = chdir("tmp/");
	if (!ret) {
		/* nothing right now */
	}

	if (shm->exit_reason != STILL_RUNNING)
		goto cleanup_fds;

	init_watchdog();

	do_main_loop();

	printf("\nRan %ld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		shm->execcount - 1, shm->retries, shm->successes, shm->failures);

	ret = EXIT_SUCCESS;

cleanup_fds:

	for (i = 0; i < nr_sockets; i++)
		close(shm->socket_fds[i]);

	destroy_maps();

	if (logging == TRUE)
		close_logfiles();

cleanup_shm:

	shmdt(shm);

	exit(ret);
}

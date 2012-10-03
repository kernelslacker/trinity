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
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "arch.h"
#include "trinity.h"
#include "files.h"
#include "shm.h"
#include "syscall.h"

char *progname = NULL;
jmp_buf ret_jump;

unsigned int page_size;

struct shm_s *shm;

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
	/* we want default behaviour for child process signals */
	(void)signal(SIGCHLD, SIG_DFL);

	/* ignore signals we don't care about */
	(void)signal(SIGFPE, SIG_IGN);
	(void)signal(SIGXCPU, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGWINCH, SIG_IGN);

	/* Ignore the RT signals. */
	for (i = SIGRTMIN; i <= (unsigned int) SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

	/* If we are in debug mode, we want segfaults and core dumps */
	if (debug == TRUE)
		(void)signal(SIGSEGV, SIG_DFL);
}

static int create_shm()
{
	shm = alloc_shared(sizeof(struct shm_s));
	if (shm == NULL) {
		perror("mmap");
		return -1;
	}

	memset(shm, 0, sizeof(struct shm_s));

	shm->execcount = 1;
	shm->regenerate = 0;

	if (user_specified_children != 0)
		shm->max_children = user_specified_children;
	else
		shm->max_children = sysconf(_SC_NPROCESSORS_ONLN);

	if (shm->max_children > MAX_NR_CHILDREN) {
		printf("Increase MAX_NR_CHILDREN!\n");
		exit(EXIT_FAILURE);
	}
	memset(shm->pids, EMPTY_PIDSLOT, sizeof(shm->pids));

	shm->parentpid = getpid();

	shm->seed = init_seed(seed);

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
			output(0, "Fuzzing %d 32-bit syscalls & %d 64-bit syscalls.\n",
				max_nr_32bit_syscalls, max_nr_64bit_syscalls);
		else
			output(0, "Fuzzing %d syscalls.\n", max_nr_syscalls);
	}

	if (do_specific_proto == TRUE)
		find_specific_proto(specific_proto_optarg);

	page_size = getpagesize();

	init_buffers();

	mask_signals();

	setup_fds();

	if (check_tainted() != 0) {
		output(0, "Kernel was tainted on startup. Will keep running if trinity causes an oops.\n");
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

	printf("\nRan %ld syscalls. Successes: %ld  Failures: %ld\n",
		shm->execcount - 1, shm->successes, shm->failures);

	ret = EXIT_SUCCESS;

cleanup_fds:

	for (i = 0; i < nr_sockets; i++) {
		struct linger ling;

		ling.l_onoff = FALSE;	/* linger active */
		setsockopt(shm->socket_fds[i], SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
		shutdown(shm->socket_fds[i], SHUT_RDWR);
		close(shm->socket_fds[i]);
	}

	destroy_maps();

	if (logging == TRUE)
		close_logfiles();

cleanup_shm:

	if (shm != NULL)
		munmap(shm, sizeof(struct shm_s));

	exit(ret);
}

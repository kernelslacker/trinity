#include <stdlib.h>
#include <signal.h>

#include "shm.h"

jmp_buf ret_jump;

static void ctrlc_handler(__unused__ int sig)
{
	shm->exit_reason = EXIT_SIGINT;
}

static void sighandler(int sig)
{
	switch (sig) {
	case SIGALRM:
		/* if we blocked in read() or similar, we want to avoid doing it again. */
		shm->fd_lifetime = 0;

		(void)signal(sig, sighandler);
		siglongjmp(ret_jump, 1);
		break;

	default:
		_exit(EXIT_SUCCESS);
	}
}

void mask_signals_child(void)
{
	struct sigaction sa;
	sigset_t ss;
	int i;

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
	(void)signal(SIGIO, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);

	/* Ignore the RT signals. */
	for (i = SIGRTMIN; i <= SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

	/* If we are in debug mode, we want segfaults and core dumps */
	if (debug == TRUE)
		(void)signal(SIGSEGV, SIG_DFL);

	/* trap ctrl-c */
	(void)signal(SIGINT, ctrlc_handler);
}


void setup_main_signals(void)
{
	/* we want default behaviour for child process signals */
	(void)signal(SIGFPE, SIG_DFL);
	(void)signal(SIGCHLD, SIG_DFL);

	(void)signal(SIGINT, ctrlc_handler);
}

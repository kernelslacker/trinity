#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "child.h"
#include "trinity.h"	// __unused__
#include "pids.h"
#include "signals.h"
#include "shm.h"

sigjmp_buf ret_jump;

static void ctrlc_handler(__unused__ int sig)
{
	panic(EXIT_SIGINT);
}

static void sighandler(int sig)
{
	switch (sig) {
	case SIGALRM:
		/* Re-arm the alarm. */
		alarm(1);
		(void)signal(sig, sighandler);

		/* Jump back, maybe we'll make progress. */
		siglongjmp(ret_jump, sig);
		break;

	default:
		_exit(EXIT_SUCCESS);
	}
}

static void sigxcpu_handler(__unused__ int sig)
{
	struct childdata *child = this_child();

	child->xcpu_count++;

	siglongjmp(ret_jump, 1);
}

/*
 * Handler for signals that should only be fatal if they come from the
 * kernel (real fault), not from a child process sending us garbage via
 * kill/tkill/tgkill.  If si_code > 0, the kernel generated the signal
 * (e.g. SEGV_MAPERR).  If si_code <= 0 (SI_USER, SI_TKILL, SI_QUEUE),
 * another process sent it — ignore.
 */
static void main_fault_handler(int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0) {
		/* Real fault — restore default and re-raise to get a core dump */
		signal(sig, SIG_DFL);
		raise(sig);
	}
	/* Sent by a child process — ignore */
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

	/* Count SIGXCPUs */
	(void)signal(SIGXCPU, sigxcpu_handler);

	/* ignore signals we don't care about */
	(void)signal(SIGFPE, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGWINCH, SIG_IGN);
	(void)signal(SIGIO, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGXFSZ, SIG_IGN);

	/* Ignore the RT signals. */
	for (i = SIGRTMIN; i <= SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

	/* If we are in debug mode, we want segfaults and core dumps */
	if (shm->debug == true) {
		(void)signal(SIGABRT, SIG_DFL);
		(void)signal(SIGSEGV, SIG_DFL);
	}

	/* trap ctrl-c */
	(void)signal(SIGINT, ctrlc_handler);
}


void setup_main_signals(void)
{
	struct sigaction sa;

	(void)signal(SIGCHLD, SIG_DFL);

	/*
	 * Ignore signals that children can send us via kill/tkill/tgkill.
	 * Without this, the fuzzer randomly terminates when a child happens
	 * to send a fatal signal to the parent PID.
	 */
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGUSR1, SIG_IGN);
	(void)signal(SIGUSR2, SIG_IGN);
	(void)signal(SIGALRM, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGVTALRM, SIG_IGN);
	(void)signal(SIGPROF, SIG_IGN);
	(void)signal(SIGXFSZ, SIG_IGN);
	(void)signal(SIGXCPU, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);

	/*
	 * Use SA_SIGINFO for fault/core-dump signals so we can distinguish
	 * real faults (si_code > 0, from kernel) from signals sent by child
	 * processes fuzzing kill/tkill/tgkill (si_code <= 0).
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = main_fault_handler;
	(void)sigaction(SIGABRT, &sa, NULL);
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	(void)sigaction(SIGILL, &sa, NULL);
	(void)sigaction(SIGFPE, &sa, NULL);
	(void)sigaction(SIGQUIT, &sa, NULL);
	(void)sigaction(SIGTRAP, &sa, NULL);
	(void)sigaction(SIGSYS, &sa, NULL);

	(void)signal(SIGINT, ctrlc_handler);
}

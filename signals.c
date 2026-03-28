#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "trinity.h"	// __unused__
#include "signals.h"
#include "shm.h"

sigjmp_buf ret_jump;

volatile sig_atomic_t xcpu_pending;
volatile sig_atomic_t ctrlc_pending;

static void ctrlc_handler(__unused__ int sig)
{
	ctrlc_pending = 1;
}

/*
 * SA_SIGINFO version: only honor SIGINT from the terminal (kernel) or
 * ourselves.  Children fuzzing kill/tkill/tgkill can send us SIGINT —
 * treat it the same as the other spoofable signals and ignore it.
 */
static void sigint_handler(__unused__ int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0 || info->si_pid == getpid())
		panic(EXIT_SIGINT);
	/* Sent by a child process — ignore */
}

static void sighandler(int sig)
{
	switch (sig) {
	case SIGALRM:
		/* Jump back, maybe we'll make progress.
		 * Don't re-arm the alarm here — do_syscall() will arm a
		 * fresh one for the next NEED_ALARM syscall.  Re-arming
		 * here just creates a stale 1-second timer that can fire
		 * while we hold rec->lock in handle_sigreturn. */
		siglongjmp(ret_jump, sig);
		break;

	default:
		_exit(EXIT_SUCCESS);
	}
}

static void sigxcpu_handler(__unused__ int sig)
{
	xcpu_pending = 1;
	/* Don't siglongjmp here.  The signal interrupts the syscall
	 * (SIGXCPU is installed without SA_RESTART), and the child
	 * main loop checks xcpu_pending on the next iteration.
	 * Longjmping from here risked orphaning locks held at the
	 * time of the signal. */
}

/*
 * Handler for signals that should only be fatal if they come from the
 * kernel (real fault), not from a child process sending us garbage via
 * kill/tkill/tgkill.
 *
 * si_code > 0:  kernel generated (e.g. SEGV_MAPERR) — always fatal
 * si_code <= 0: sent by a process (SI_USER, SI_TKILL, SI_QUEUE)
 *   - from ourselves (abort(), raise()): fatal — it's a real crash
 *   - from a child process: ignore — it's fuzzer noise
 */
static void main_fault_handler(int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0 || info->si_pid == getpid()) {
		/* Real fault or self-sent (e.g. glibc abort) — die properly */
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

	for (i = 1; i < _NSIG; i++) {
		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	/* we want default behaviour for child process signals */
	(void)signal(SIGCHLD, SIG_DFL);

	/* Count SIGXCPUs.  Install without SA_RESTART so the signal
	 * interrupts blocking syscalls and control returns to the
	 * child main loop where xcpu_pending is checked. */
	{
		struct sigaction xcpu_sa;
		sigemptyset(&xcpu_sa.sa_mask);
		xcpu_sa.sa_flags = 0;
		xcpu_sa.sa_handler = sigxcpu_handler;
		(void)sigaction(SIGXCPU, &xcpu_sa, NULL);
	}

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
	(void)signal(SIGIO, SIG_IGN);

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

	/* SIGINT: use SA_SIGINFO so we can ignore child-sent SIGINTs.
	 * Real ctrl-c from the terminal has si_code > 0 (SI_KERNEL). */
	sa.sa_sigaction = sigint_handler;
	(void)sigaction(SIGINT, &sa, NULL);
}

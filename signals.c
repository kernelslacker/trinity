#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#ifdef USE_BACKTRACE
#include <execinfo.h>
#endif

#include "trinity.h"	// __unused__
#include "signals.h"
#include "shm.h"
#include "pids.h"

volatile sig_atomic_t sigalrm_pending;
volatile sig_atomic_t xcpu_pending;
volatile sig_atomic_t ctrlc_pending;

/*
 * SA_SIGINFO version: only honor SIGINT from the terminal (kernel) or
 * ourselves.  Children fuzzing kill/tkill/tgkill can send us SIGINT —
 * treat it the same as the other spoofable signals and ignore it.
 *
 * Used by both parent and children.  The parent calls panic() directly;
 * children set ctrlc_pending and let the main loop exit cleanly.
 */
static void sigint_handler(__unused__ int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0 || info->si_pid == getpid()) {
		if (getpid() == mainpid)
			panic(EXIT_SIGINT);
		else
			ctrlc_pending = 1;
	}
	/* Sent by a child process — ignore */
}

static void sighandler(int sig)
{
	/* Every signal except SIGALRM, SIGXCPU, and those handled
	 * separately (SIGINT, SIGCHLD, etc.) exits the child. */
	(void)sig;
	_exit(EXIT_SUCCESS);
}

static void sigalrm_handler(__unused__ int sig)
{
	sigalrm_pending = 1;
	/* Don't siglongjmp here.  SIGALRM is installed without
	 * SA_RESTART, so the signal interrupts the blocking syscall
	 * (it returns EINTR/ERESTARTNOHAND) and control returns to
	 * the child main loop where sigalrm_pending is checked.
	 *
	 * The old code called siglongjmp() from here, which could
	 * permanently leak glibc's allocator lock if the child was
	 * inside malloc/free at signal delivery time, causing
	 * deadlock or heap corruption on the next allocation. */
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
		/* Real fault or self-sent (e.g. glibc abort) — dump a
		 * backtrace and siginfo to stderr first so we have a handle
		 * on the crash even when no coredump lands (ulimit -c 0 or a
		 * restrictive core_pattern), then die properly. */
#ifdef USE_BACKTRACE
		void *frames[64];
		int nframes = backtrace(frames, 64);
		backtrace_symbols_fd(frames, nframes, STDERR_FILENO);
#endif
		psiginfo(info, "trinity main: fatal signal");
		signal(sig, SIG_DFL);
		raise(sig);
	}
	/* Sent by a child process — ignore */
}

void mask_signals_child(void)
{
	struct sigaction sa;
	sigset_t ss, oldss;
	int i;

	/* Block all signals while we install handlers.  Without this,
	 * a signal arriving between the catch-all sighandler install
	 * and the proper handler install would silently _exit(SUCCESS),
	 * masking the real cause of the child's death. */
	sigfillset(&ss);
	sigprocmask(SIG_BLOCK, &ss, &oldss);

	for (i = 1; i < _NSIG; i++) {
		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	/* we want default behaviour for child process signals */
	(void)signal(SIGCHLD, SIG_DFL);

	/* SIGALRM: set a flag and let the interrupted syscall return
	 * EINTR.  Installed without SA_RESTART so blocking syscalls
	 * are interrupted rather than silently restarted. */
	{
		struct sigaction alrm_sa;
		sigemptyset(&alrm_sa.sa_mask);
		alrm_sa.sa_flags = 0;
		alrm_sa.sa_handler = sigalrm_handler;
		(void)sigaction(SIGALRM, &alrm_sa, NULL);
	}

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

	/* trap ctrl-c — use SA_SIGINFO so we can ignore child-sent SIGINTs,
	 * same as the parent handler. Without this, children fuzzing
	 * rt_tgsigqueueinfo/kill with SIGINT cause phantom ctrl-c exits. */
	{
		struct sigaction int_sa;
		sigemptyset(&int_sa.sa_mask);
		int_sa.sa_flags = SA_SIGINFO;
		int_sa.sa_sigaction = sigint_handler;
		(void)sigaction(SIGINT, &int_sa, NULL);
	}

	/* All handlers installed — unblock signals. */
	sigprocmask(SIG_SETMASK, &oldss, NULL);
}


void setup_main_signals(void)
{
	struct sigaction sa;
	int i;

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

	/* Ignore RT signals — children fuzzing rt_sigqueueinfo,
	 * pidfd_send_signal, timer_create/settime with sigev_signo in
	 * [SIGRTMIN..SIGRTMAX], etc. can deliver any RT signal to us.
	 * Default kernel action for an unhandled RT signal is termination,
	 * which silently exits trinity ("Real-time signal N" printed by
	 * glibc).  Mirror the same loop the children use in mask_signals_child. */
	for (i = SIGRTMIN; i <= SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

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

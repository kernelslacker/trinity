/*
 * Self-check for parent_stop_reason() (include/signals.h): which
 * SIGINT/SIGTERM deliveries stop the parent.  An operator outside the
 * children's uid must get a clean stop; anything a fuzzing child can
 * send must not.  Covers root and non-root runs (init_uids() leaves
 * nobody_uid 0 in the latter), the overflowuid a child in an unmapped
 * user namespace arrives as, and a failure shutdown keeping its reason.
 * Also checks that a child ignores SIGINT, which fault signals the
 * parent takes for real, and that every signal the F_SETSIG sanitiser
 * may route a SIGIO to is one the parent ignores.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "signals.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils.h"		/* waitpid_eintr */

#ifndef SYS_SECCOMP
#define SYS_SECCOMP	1
#endif

struct uid_setup {
	uid_t orig, nobody, overflow;
};

static const struct uid_setup root_run = { 0, 65534, 65534 };
static const struct uid_setup root_run_nobody99 = { 0, 99, 65534 };
static const struct uid_setup user_run = { 1000, 0, 65534 };

struct stop_case {
	const char *what;
	const struct uid_setup *run;
	int sig;
	int code;
	uid_t sender;
	enum exit_reasons cur;
	enum exit_reasons want;
};

/*
 * F_SETOWN to the parent plus F_SETSIG(SIGINT) on an O_ASYNC fd makes
 * the kernel send SIGINT with a POLL_* si_code.  Its siginfo carries
 * si_band where a sender's si_pid/si_uid would be, so si_uid names no
 * sender; uid 0 is the one an operator would have.
 */
#define POLL_SIGINT_CASE(poll_code) \
	{ "user run: F_SETSIG SIGINT, " #poll_code, &user_run, \
	  SIGINT, poll_code, 0, STILL_RUNNING, STILL_RUNNING }

static const struct stop_case cases[] = {
	{ "root run: root kill -TERM", &root_run,
	  SIGTERM, SI_USER, 0, STILL_RUNNING, EXIT_USER_REQUEST },
	{ "root run: root kill -INT", &root_run,
	  SIGINT, SI_USER, 0, STILL_RUNNING, EXIT_USER_REQUEST },
	{ "root run: a nobody child", &root_run,
	  SIGTERM, SI_USER, 65534, STILL_RUNNING, STILL_RUNNING },
	{ "root run: child uid 99", &root_run_nobody99,
	  SIGTERM, SI_USER, 99, STILL_RUNNING, STILL_RUNNING },
	{ "root run: overflowuid", &root_run_nobody99,
	  SIGTERM, SI_USER, 65534, STILL_RUNNING, STILL_RUNNING },
	{ "root run: root via tgkill", &root_run,
	  SIGTERM, SI_TKILL, 0, STILL_RUNNING, STILL_RUNNING },
	{ "root run: SI_QUEUE claiming root", &root_run,
	  SIGTERM, SI_QUEUE, 0, STILL_RUNNING, STILL_RUNNING },
	{ "user run: own uid, child or operator", &user_run,
	  SIGTERM, SI_USER, 1000, STILL_RUNNING, STILL_RUNNING },
	{ "user run: root kill -TERM", &user_run,
	  SIGTERM, SI_USER, 0, STILL_RUNNING, EXIT_USER_REQUEST },
	{ "user run: another uid with CAP_KILL", &user_run,
	  SIGTERM, SI_USER, 1001, STILL_RUNNING, EXIT_USER_REQUEST },
	{ "user run: child in unmapped userns", &user_run,
	  SIGTERM, SI_USER, 65534, STILL_RUNNING, STILL_RUNNING },
	{ "user run: terminal ctrl-c", &user_run,
	  SIGINT, SI_KERNEL, 0, STILL_RUNNING, EXIT_SIGINT },
	{ "root run: terminal ctrl-c", &root_run,
	  SIGINT, SI_KERNEL, 0, STILL_RUNNING, EXIT_SIGINT },
	POLL_SIGINT_CASE(POLL_IN),
	POLL_SIGINT_CASE(POLL_OUT),
	POLL_SIGINT_CASE(POLL_MSG),
	POLL_SIGINT_CASE(POLL_ERR),
	POLL_SIGINT_CASE(POLL_PRI),
	POLL_SIGINT_CASE(POLL_HUP),
	{ "root run: F_SETSIG SIGINT, POLL_IN", &root_run,
	  SIGINT, POLL_IN, 0, STILL_RUNNING, STILL_RUNNING },
	{ "user run: kernel-generated SIGTERM", &user_run,
	  SIGTERM, SI_KERNEL, 0, STILL_RUNNING, STILL_RUNNING },
	{ "operator stop during a taint shutdown", &root_run,
	  SIGTERM, SI_USER, 0, EXIT_KERNEL_TAINTED, STILL_RUNNING },
	{ "ctrl-c during a fork-failure shutdown", &root_run,
	  SIGINT, SI_KERNEL, 0, EXIT_FORK_FAILURE, STILL_RUNNING },
	{ "operator stop at an epoch boundary", &root_run,
	  SIGTERM, SI_USER, 0, EXIT_EPOCH_DONE, EXIT_USER_REQUEST },
	{ "operator stop after a ctrl-c", &user_run,
	  SIGTERM, SI_USER, 0, EXIT_SIGINT, EXIT_USER_REQUEST },
};

/*
 * A child ignores SIGINT.  Its session has no terminal, so what reaches
 * it is a spoof: rt_sigqueueinfo() to itself may carry SI_KERNEL, and a
 * pty it holds as its terminal raises the real thing.  A handler that
 * took one for a ctrl-c would end the whole run.  mask_signals_child()
 * rewrites every disposition, so ask it in a task of its own.
 */
static void child_sigint_check(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("child SIGINT: fork failed");
	if (pid == 0) {
		struct sigaction sa;

		mask_signals_child();
		_exit(sigaction(SIGINT, NULL, &sa) == 0 &&
		      sa.sa_handler == SIG_IGN ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	if (waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
		BUG("child SIGINT: not ignored");
}

#define SELF	4242
#define OTHER	4243

struct fault_case {
	const char *what;
	int sig;
	int code;
	pid_t pid;
	bool real;
};

/*
 * A child can aim F_SETOWN and F_SETSIG at the parent.  The siginfo the
 * kernel then builds has si_band where a sender's si_pid would be, and
 * si_band is the poll mask (0x41 for POLL_IN, which reads as pid 65), so
 * SELF stands for a parent whose pid is one of those values.  It also
 * stands for what rt_sigqueueinfo() lets a child write into si_pid under
 * any negative code but SI_TKILL.
 */
#define POLL_FAULT_CASE(signo, name, poll_code) \
	{ name " from F_SETSIG, " #poll_code, signo, poll_code, SELF, false }
#define POLL_FAULT_CASES(signo) \
	POLL_FAULT_CASE(signo, #signo, POLL_IN), \
	POLL_FAULT_CASE(signo, #signo, POLL_OUT), \
	POLL_FAULT_CASE(signo, #signo, POLL_MSG), \
	POLL_FAULT_CASE(signo, #signo, POLL_ERR), \
	POLL_FAULT_CASE(signo, #signo, POLL_PRI), \
	POLL_FAULT_CASE(signo, #signo, POLL_HUP)
#define SIGIO_FAULT_CASE(signo) \
	{ #signo " from F_SETSIG, SI_SIGIO", signo, SI_SIGIO, SELF, false }

static const struct fault_case fault_cases[] = {
	{ "SIGSEGV, SEGV_MAPERR", SIGSEGV, SEGV_MAPERR, 0, true },
	{ "SIGBUS, BUS_ADRERR", SIGBUS, BUS_ADRERR, 0, true },
	{ "SIGILL, ILL_ILLOPC", SIGILL, ILL_ILLOPC, 0, true },
	{ "SIGFPE, FPE_INTDIV", SIGFPE, FPE_INTDIV, 0, true },
	{ "SIGTRAP, TRAP_BRKPT", SIGTRAP, TRAP_BRKPT, 0, true },
	{ "SIGSYS, SYS_SECCOMP", SIGSYS, SYS_SECCOMP, 0, true },
	{ "SIGSEGV forced by the kernel", SIGSEGV, SI_KERNEL, 0, true },
	{ "SIGQUIT from the terminal", SIGQUIT, SI_KERNEL, 0, true },
	{ "SIGABRT from abort()", SIGABRT, SI_TKILL, SELF, true },
	{ "SIGABRT from kill(getpid())", SIGABRT, SI_USER, SELF, true },
	{ "SIGSEGV from raise()", SIGSEGV, SI_TKILL, SELF, true },
	{ "SIGABRT, SI_QUEUE with the parent's pid", SIGABRT, SI_QUEUE, SELF, false },
	{ "SIGQUIT, SI_QUEUE with the parent's pid", SIGQUIT, SI_QUEUE, SELF, false },
	{ "SIGABRT, SI_MESGQ with the parent's pid", SIGABRT, SI_MESGQ, SELF, false },
	{ "SIGABRT, SI_ASYNCIO with the parent's pid", SIGABRT, SI_ASYNCIO, SELF, false },
	{ "SIGABRT from a child's tgkill", SIGABRT, SI_TKILL, OTHER, false },
	{ "SIGQUIT from a child's kill", SIGQUIT, SI_USER, OTHER, false },
	{ "SIGSEGV from a child's sigqueue", SIGSEGV, SI_QUEUE, OTHER, false },
	POLL_FAULT_CASES(SIGQUIT),
	POLL_FAULT_CASES(SIGABRT),
	SIGIO_FAULT_CASE(SIGSEGV),
	SIGIO_FAULT_CASE(SIGBUS),
	SIGIO_FAULT_CASE(SIGILL),
	SIGIO_FAULT_CASE(SIGFPE),
	SIGIO_FAULT_CASE(SIGTRAP),
	SIGIO_FAULT_CASE(SIGSYS),
	{ "SIGSEGV from F_SETSIG, another pid's band", SIGSEGV, SI_SIGIO, OTHER, false },
	{ "SIGABRT from a timer whose id is our pid", SIGABRT, SI_TIMER, SELF, false },
};

static void fault_signal_check(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fault_cases); i++) {
		const struct fault_case *c = &fault_cases[i];
		siginfo_t si;

		memset(&si, 0, sizeof(si));
		si.si_signo = c->sig;
		si.si_code = c->code;
		si.si_pid = c->pid;
		if (fault_signal_is_real(c->sig, &si, SELF) != c->real) {
			fprintf(stderr, "%s: the parent takes it for %s\n",
				c->what, c->real ? "noise" : "a fault");
			BUG("fault_signal_is_real: wrong verdict");
		}
	}
}

/*
 * parent_ignores_sigio_as() lets the F_SETSIG sanitiser route a SIGIO to
 * every signal it allows, because the parent ignores that signal.  What
 * the parent ignores is up to setup_main_signals(), so ask it, in a task
 * of its own because it rewrites every disposition.
 */
static void sigio_routing_check(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("sigio routing: fork failed");
	if (pid == 0) {
		struct sigaction sa;
		int sig;

		setup_main_signals();
		for (sig = 1; sig <= 64; sig++) {
			if (!parent_ignores_sigio_as(sig))
				continue;
			if (sigaction(sig, NULL, &sa) == 0 &&
			    (sa.sa_handler == SIG_IGN ||
			     (sa.sa_handler == SIG_DFL &&
			      (sig == SIGCHLD || sig == SIGCONT ||
			       sig == SIGURG || sig == SIGWINCH))))
				continue;
			fprintf(stderr, "sigio routing: the parent does not ignore signal %d\n", sig);
			_exit(EXIT_FAILURE);
		}
		_exit(EXIT_SUCCESS);
	}
	if (waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
		BUG("sigio routing: wrong verdict");
}

void parent_stop_self_check(void);
void parent_stop_self_check(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct stop_case *c = &cases[i];
		enum exit_reasons got;
		siginfo_t si;

		orig_uid = c->run->orig;
		nobody_uid = c->run->nobody;
		overflowuid = c->run->overflow;

		memset(&si, 0, sizeof(si));
		si.si_signo = c->sig;
		si.si_code = c->code;
		si.si_uid = c->sender;

		got = parent_stop_reason(c->sig, &si, c->cur);
		if (got != c->want) {
			fprintf(stderr, "%s: got %s, want %s\n", c->what,
				decode_exit(got), decode_exit(c->want));
			BUG("parent_stop_reason: wrong verdict");
		}
	}

	fault_signal_check();
	sigio_routing_check();
	child_sigint_check();
}

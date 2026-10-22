/*
 * Self-check for parent_stop_reason() (include/signals.h): which
 * SIGINT/SIGTERM deliveries stop the parent.  An operator outside the
 * children's uid must get a clean stop; anything a fuzzing child can
 * send must not.  Covers root and non-root runs (init_uids() leaves
 * nobody_uid 0 in the latter), the overflowuid a child in an unmapped
 * user namespace arrives as, and a failure shutdown keeping its reason.
 * Also checks that a child ignores SIGINT.
 */

#include <signal.h>
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

/* mask_signals_child() installs these for the fault signals.  Nothing
 * here raises one; end the task rather than return into a fault. */
void child_fault_handler(int sig, siginfo_t *info, void *ctx);
void writer_trap_handler(int sig, siginfo_t *info, void *ctx);

void child_fault_handler(int sig, siginfo_t *info, void *ctx)
{
	(void)sig; (void)info; (void)ctx;
	_exit(EXIT_FAILURE);
}

void writer_trap_handler(int sig, siginfo_t *info, void *ctx)
{
	(void)sig; (void)info; (void)ctx;
	_exit(EXIT_FAILURE);
}

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

	child_sigint_check();
}

/*
 * Self-check for extrafork_reap() (dispatch/extrafork-reap.c): what ends
 * do_extrafork() once its throwaway grandchild has had its time.  Each
 * fixture forks a bare child in a state a fuzzed grandchild can be in
 * and checks who is left alive, reaped or signalled afterwards.  The
 * poll budget is cut to ~100ms so the timeout fixtures stay quick.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "syscall-internal.h"
#include "utils.h"		/* waitpid_eintr */

#define POLLS	100

static void exit_now(void)
{
}

static void idle(void)
{
	for (;;)
		pause();
}

static pid_t spawn(void (*body)(void))
{
	pid_t pid = fork();

	if (pid < 0)
		BUG("extrafork_reap: fork failed");
	if (pid == 0) {
		/* Don't outlive the test binary if a fixture aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		body();
		_exit(0);
	}
	return pid;
}

/* After extrafork_reap() the child must be gone: reaped by it, or killed
 * by it and left a zombie for us.  Give a slow exit a second; a child
 * that is still alive then is killed here so nothing outlives the test. */
static void expect_killed(pid_t pid, const char *why)
{
	int i;

	for (i = 0; i < 1000; i++) {
		int status;
		pid_t w = waitpid_eintr(pid, &status, WNOHANG);

		if (w == 0) {
			usleep(1000);
			continue;
		}
		if (w == pid ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
			     : errno == ECHILD)
			return;
		BUG(why);
	}
	kill(pid, SIGKILL);
	(void)waitpid_eintr(pid, NULL, 0);
	BUG(why);
}

static void selftest_exited(void)
{
	pid_t pid = spawn(exit_now);

	extrafork_reap(pid, POLLS);

	if (waitpid_eintr(pid, NULL, WNOHANG) != -1 || errno != ECHILD)
		BUG("extrafork_reap: an exited grandchild was not reaped");
}

static void selftest_running_at_timeout(void)
{
	pid_t pid = spawn(idle);

	extrafork_reap(pid, POLLS);
	expect_killed(pid, "extrafork_reap: a grandchild still running at the timeout survived");
}

void extrafork_reap_self_check(void);
void extrafork_reap_self_check(void)
{
	selftest_exited();
	selftest_running_at_timeout();
}

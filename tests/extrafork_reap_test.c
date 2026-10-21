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
#include <sys/ptrace.h>
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

static void stop_then_idle(void)
{
	raise(SIGSTOP);
	idle();
}

static void trace_stop_then_idle(void)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	raise(SIGSTOP);
	idle();
}

static void probe_traceme(void)
{
	_exit(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : 1);
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

/* Nothing reports a group-stop to a waiter that did not ask for one, so
 * the wait runs out and the timeout kill takes the grandchild. */
static void selftest_stopped(void)
{
	pid_t pid = spawn(stop_then_idle);

	extrafork_reap(pid, POLLS);
	expect_killed(pid, "extrafork_reap: a stopped grandchild was abandoned");
}

/* Same for a continue report: the grandchild is running, not gone. */
static void selftest_continued(void)
{
	pid_t pid = spawn(stop_then_idle);
	int status;

	/* The kernel holds the continue report until a waiter asks for it. */
	if (waitpid_eintr(pid, &status, WUNTRACED) != pid || !WIFSTOPPED(status))
		BUG("extrafork_reap: cannot stop the test child");
	kill(pid, SIGCONT);

	extrafork_reap(pid, POLLS);
	expect_killed(pid, "extrafork_reap: a continued grandchild was abandoned");
}

/* A ptrace-stop is reported to the tracer whatever the wait flags are.
 * Skipped where PTRACE_TRACEME is refused (Yama ptrace_scope 3, seccomp). */
static void selftest_ptrace_stopped(void)
{
	pid_t pid = spawn(probe_traceme);
	int status;

	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("extrafork_reap: cannot reap the PTRACE_TRACEME probe");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("(PTRACE_TRACEME refused, skipping the traced stop) ");
		return;
	}

	pid = spawn(trace_stop_then_idle);
	extrafork_reap(pid, POLLS);
	expect_killed(pid, "extrafork_reap: a ptrace-stopped grandchild was abandoned");
}

/* ECHILD means the grandchild is no longer an unreaped child of ours: a
 * SIGCHLD that is ignored or has SA_NOCLDWAIT makes the kernel reap it
 * at exit, and its pid can be reissued.  Stand in for that with a live
 * pid that is not the caller's child; it must not be signalled. */
static void selftest_not_our_child(void)
{
	pid_t victim = spawn(idle);
	pid_t other = fork();
	int i;

	if (other < 0)
		BUG("extrafork_reap: fork failed");
	if (other == 0) {
		extrafork_reap(victim, POLLS);
		_exit(0);
	}
	if (waitpid_eintr(other, NULL, 0) != other)
		BUG("extrafork_reap: cannot reap the test process");

	/* A wrong SIGKILL is already queued; give the victim time to die. */
	for (i = 0; i < 100; i++) {
		if (waitpid_eintr(victim, NULL, WNOHANG) != 0)
			BUG("extrafork_reap: signalled a pid that is not its child");
		usleep(1000);
	}
	kill(victim, SIGKILL);
	(void)waitpid_eintr(victim, NULL, 0);
}

void extrafork_reap_self_check(void);
void extrafork_reap_self_check(void)
{
	selftest_exited();
	selftest_running_at_timeout();
	selftest_stopped();
	selftest_continued();
	selftest_ptrace_stopped();
	selftest_not_our_child();
}

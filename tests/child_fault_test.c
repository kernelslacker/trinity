/*
 * Self-check for child_fault_handler() (health/signals-fault-handler.c):
 * which fault signals a child takes for its own.  Each case forks a task
 * with mask_signals_child()'s handlers, delivers one signal to it for
 * real, and reads the verdict off its exit status and stderr.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "pids.h"		/* cached_pid */
#include "signals.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils.h"		/* waitpid_eintr */

#define SURVIVED	42	/* the task got past the signal */
#define NOT_SENT	43	/* the task could not send the signal */

enum verdict {
	IGNORED,	/* the handler returned and the task carried on */
	DROPPED,	/* a signal the task fuzzed at itself: a quiet exit */
	LOGGED,		/* taken for a fault: a crash report, then exit */
};

static const char *const verdict_name[] = {
	[IGNORED] = "ignored",
	[DROPPED] = "dropped",
	[LOGGED] = "logged",
};

#define SIBLING		0x1	/* a sibling sends it, else the task itself */
#define NAMES_SELF	0x2	/* si_pid names the task, else the sender */
#define IN_SYSCALL	0x4	/* the task is inside do_syscall() */

/*
 * SI_USER is kill() and SI_TKILL is tgkill(), which stamp the sender's
 * pid themselves; every other code is queued with rt_sigqueueinfo(),
 * which lets the sender write any si_pid.  A positive code can only be
 * queued at the sender itself, which is how a kernel fault looks.
 */
struct child_case {
	const char *what;
	int sig;
	int code;
	unsigned int flags;
	enum verdict want;
};

static const struct child_case cases[] = {
	/* What a sibling's fuzzing can queue at a child.  Naming the
	 * receiver in si_pid must not make it the receiver's own. */
	{ "SIGSEGV, SI_QUEUE naming the task",
	  SIGSEGV, SI_QUEUE, SIBLING | NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGBUS, SI_MESGQ naming the task",
	  SIGBUS, SI_MESGQ, SIBLING | NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGILL, SI_ASYNCIO naming the task",
	  SIGILL, SI_ASYNCIO, SIBLING | NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGABRT, SI_TIMER with the task's pid as its id",
	  SIGABRT, SI_TIMER, SIBLING | NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGSEGV, F_SETSIG band naming the task",
	  SIGSEGV, SI_SIGIO, SIBLING | NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGSEGV, SI_QUEUE naming the task, outside do_syscall",
	  SIGSEGV, SI_QUEUE, SIBLING | NAMES_SELF, IGNORED },
	{ "SIGSEGV, SI_QUEUE naming the sender",
	  SIGSEGV, SI_QUEUE, SIBLING | IN_SYSCALL, IGNORED },
	{ "SIGBUS from a sibling's kill",
	  SIGBUS, SI_USER, SIBLING | IN_SYSCALL, IGNORED },
	{ "SIGABRT from a sibling's tgkill",
	  SIGABRT, SI_TKILL, SIBLING | IN_SYSCALL, IGNORED },

	/* The task's own fuzzing: kill(getpid()) and raise() in a syscall
	 * end the task quietly, the same outside one is abort() and a
	 * crash. */
	{ "SIGSEGV from kill(getpid()) in do_syscall",
	  SIGSEGV, SI_USER, NAMES_SELF | IN_SYSCALL, DROPPED },
	{ "SIGBUS from raise() in do_syscall",
	  SIGBUS, SI_TKILL, NAMES_SELF | IN_SYSCALL, DROPPED },
	{ "SIGABRT from abort()",
	  SIGABRT, SI_TKILL, NAMES_SELF, LOGGED },
	{ "SIGILL from kill(getpid()) outside do_syscall",
	  SIGILL, SI_USER, NAMES_SELF, LOGGED },

	/* A signal the task queues at itself has a si_pid of its own
	 * choosing, as a sibling's does.  And F_SETSIG gives SIGABRT, which
	 * has no signal specific si_codes, a positive POLL_* code. */
	{ "SIGSEGV, SI_QUEUE the task queued at itself",
	  SIGSEGV, SI_QUEUE, NAMES_SELF | IN_SYSCALL, IGNORED },
	{ "SIGABRT from F_SETSIG, POLL_IN",
	  SIGABRT, POLL_IN, 0, IGNORED },

	/* What the kernel reports for a fault stays one, in do_syscall
	 * or not. */
	{ "SIGSEGV, SEGV_MAPERR in do_syscall",
	  SIGSEGV, SEGV_MAPERR, IN_SYSCALL, LOGGED },
	{ "SIGBUS, BUS_ADRERR",
	  SIGBUS, BUS_ADRERR, 0, LOGGED },
	{ "SIGILL, ILL_ILLOPC",
	  SIGILL, ILL_ILLOPC, 0, LOGGED },
	{ "SIGSEGV forced by the kernel",
	  SIGSEGV, SI_KERNEL, 0, LOGGED },
};

static int deliver(pid_t target, int sig, int code, pid_t named)
{
	siginfo_t si;

	if (code == SI_USER)
		return kill(target, sig);
	if (code == SI_TKILL)
		return syscall(SYS_tgkill, target, target, sig);

	memset(&si, 0, sizeof(si));
	si.si_signo = sig;
	si.si_code = code;
	si.si_pid = named;
	si.si_uid = getuid();
	return syscall(SYS_rt_sigqueueinfo, target, sig, &si);
}

/* The signal comes from the task itself, or from the test while the task
 * sleeps in read().  It interrupts the read, there being no SA_RESTART,
 * so the handler has run when read() returns.  The byte the test writes
 * afterwards is for a signal that came before the read began: without it
 * the read would sleep on. */
static void task(const struct child_case *c, int ready, int go, int err)
{
	pid_t named = (c->flags & NAMES_SELF) ? getpid() : getppid();
	sigset_t set;
	char b;

	/* Don't outlive the test binary if a case aborts. */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	dup2(err, STDERR_FILENO);
	mask_signals_child();
	/* mask_signals_child() puts back the mask it found, and a signal
	 * the test harness blocked would only sit pending. */
	sigemptyset(&set);
	sigaddset(&set, c->sig);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	cached_pid = getpid();
	in_do_syscall = (c->flags & IN_SYSCALL) != 0;

	if (c->flags & SIBLING) {
		if (write(ready, "r", 1) != 1)
			_exit(NOT_SENT);
		if (read(go, &b, 1) < 0 && errno != EINTR)
			_exit(NOT_SENT);
	} else if (deliver(getpid(), c->sig, c->code, named) != 0) {
		_exit(NOT_SENT);
	}
	_exit(SURVIVED);
}

static enum verdict run_case(const struct child_case *c)
{
	int ready[2], go[2], err[2], status;
	char log[8192];
	size_t used = 0;
	ssize_t n;
	pid_t pid;

	if (pipe(ready) != 0 || pipe(go) != 0 || pipe(err) != 0)
		BUG("child fault: pipe failed");
	pid = fork();
	if (pid < 0)
		BUG("child fault: fork failed");
	if (pid == 0)
		task(c, ready[1], go[0], err[1]);

	close(ready[1]);
	close(err[1]);

	/* The alarm turns a task that never answers into a failure, not a
	 * hang. */
	alarm(10);
	if (c->flags & SIBLING) {
		char b;

		/* The signal can end the task before this write, so the
		 * test keeps go[0] open: with no reader it would be SIGPIPE. */
		if (read(ready[0], &b, 1) != 1 ||
		    deliver(pid, c->sig, c->code,
			    (c->flags & NAMES_SELF) ? pid : getpid()) != 0 ||
		    write(go[1], "g", 1) != 1) {
			fprintf(stderr, "%s: not sent\n", c->what);
			BUG("child fault: no signal sent");
		}
	}
	while (used < sizeof(log) - 1 &&
	       (n = read(err[0], log + used, sizeof(log) - 1 - used)) != 0) {
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			break;
		used += n;
	}
	log[used] = '\0';
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("child fault: waitpid failed");
	alarm(0);
	close(ready[0]);
	close(go[0]);
	close(go[1]);
	close(err[0]);

	if (WIFEXITED(status) && WEXITSTATUS(status) == SURVIVED)
		return IGNORED;
	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS)
		return strstr(log, "BUGLOG-COMPLETE") ? LOGGED : DROPPED;
	fprintf(stderr, "%s: task status %#x\n", c->what, status);
	BUG("child fault: the task did not end as the handler would end it");
}

void child_fault_self_check(void);
void child_fault_self_check(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct child_case *c = &cases[i];
		enum verdict got = run_case(c);

		if (got != c->want) {
			fprintf(stderr, "%s: got %s, want %s\n", c->what,
				verdict_name[got], verdict_name[c->want]);
			BUG("child_fault_handler: wrong verdict");
		}
	}
}

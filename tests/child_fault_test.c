/*
 * Self-check for the handlers a child takes fault signals with:
 * child_fault_handler() and writer_trap_handler()
 * (health/signals-fault-handler.c) and the guards around a walk of a
 * mapping in mm/fault-read.c and mm/fault-write.c.  Each case forks a
 * task, delivers one signal to it for real, and reads the verdict off
 * its exit status and stderr.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "maps.h"
#include "pids.h"		/* cached_pid */
#include "random.h"		/* generate_random_page */
#include "shm.h"
#include "signals.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils.h"		/* waitpid_eintr */

/* The si_code of a perf event's sigtrap; older libc headers lack it. */
#ifndef TRAP_PERF
#define TRAP_PERF	6
#endif

#define SURVIVED	42	/* the task got past the signal */
#define NOT_SENT	43	/* the task could not send the signal */

enum verdict {
	IGNORED,	/* the handler returned and the task carried on */
	DROPPED,	/* a signal the task fuzzed at itself: a quiet exit */
	LOGGED,		/* taken for a fault: a crash report, then exit */
	PINNED,		/* taken for the writer-watch trap: its report, then exit */
};

static const char *const verdict_name[] = {
	[IGNORED] = "ignored",
	[DROPPED] = "dropped",
	[LOGGED] = "logged",
	[PINNED] = "pinned",
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

	/* The writer-watch breakpoint's SIGTRAP is the kernel's, with
	 * TRAP_PERF, and ends the task with a report of the writer.  What
	 * a sibling or F_SETSIG can send is not that.  The handler has no
	 * quiet drop, so the task's own kill() is reported like a trap. */
	{ "SIGTRAP, TRAP_PERF from the writer-watch breakpoint",
	  SIGTRAP, TRAP_PERF, 0, PINNED },
	{ "SIGTRAP from kill(getpid())",
	  SIGTRAP, SI_USER, NAMES_SELF, PINNED },
	{ "SIGTRAP from a sibling's kill",
	  SIGTRAP, SI_USER, SIBLING, IGNORED },
	{ "SIGTRAP from a sibling's tgkill",
	  SIGTRAP, SI_TKILL, SIBLING, IGNORED },
	{ "SIGTRAP, SI_QUEUE naming the task",
	  SIGTRAP, SI_QUEUE, SIBLING | NAMES_SELF, IGNORED },
	{ "SIGTRAP, F_SETSIG band naming the task",
	  SIGTRAP, SI_SIGIO, SIBLING | NAMES_SELF, IGNORED },
	{ "SIGTRAP, SI_QUEUE the task queued at itself",
	  SIGTRAP, SI_QUEUE, NAMES_SELF, IGNORED },
};

/* @word is what the siginfo holds first: si_pid for a code that has a
 * sender, si_addr for a positive one, which is a fault's. */
static int deliver(pid_t target, int sig, int code, unsigned long word)
{
	siginfo_t si;

	if (code == SI_USER)
		return kill(target, sig);
	if (code == SI_TKILL)
		return syscall(SYS_tgkill, target, target, sig);

	memset(&si, 0, sizeof(si));
	si.si_signo = sig;
	si.si_code = code;
	if (code > 0) {
		si.si_addr = (void *)word;
	} else {
		si.si_pid = word;
		si.si_uid = getuid();
	}
	return syscall(SYS_rt_sigqueueinfo, target, sig, &si);
}

/* Setup the tasks share.  Don't outlive the test binary if a case
 * aborts.  Unblock @sig: mask_signals_child() puts back the mask it
 * found, and a signal the harness blocked would only sit pending.  And
 * set the pid mypid() reports. */
static void task_init(int sig)
{
	sigset_t set;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	sigemptyset(&set);
	sigaddset(&set, sig);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	cached_pid = getpid();
}

/* The signal comes from the task itself, or from the test while the task
 * sleeps in read().  It interrupts the read, there being no SA_RESTART,
 * so the handler has run when read() returns.  The byte the test writes
 * afterwards is for a signal that came before the read began: without it
 * the read would sleep on. */
static void task(const struct child_case *c, int ready, int go, int err)
{
	pid_t named = (c->flags & NAMES_SELF) ? getpid() : getppid();
	char b;

	dup2(err, STDERR_FILENO);
	mask_signals_child();
	task_init(c->sig);
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
	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
		if (strstr(log, "WRITER-PINNED"))
			return PINNED;
		return strstr(log, "BUGLOG-COMPLETE") ? LOGGED : DROPPED;
	}
	fprintf(stderr, "%s: task status %#x\n", c->what, status);
	BUG("child fault: the task did not end as the handler would end it");
}

/*
 * The walkers guard a walk of a mapping against the SIGBUS or SIGSEGV a
 * sibling's munmap or hole punch causes.  A fault inside the walked
 * range abandons the walk, a signal the task sent itself goes on to
 * trinity's handler, and the rest is ignored.  Both walkers call
 * log_mprotect_failure() from inside the walk when an mprotect() fails,
 * which one on an unaligned page does, so that is where a case lands its
 * signal.  Trinity's handler is a recorder here: the verdict is what the
 * walker decided, not what child_fault_handler() makes of what it is
 * handed.
 */
enum walk_verdict {
	WALK_IGNORED,	/* the handler returned and the walk finished */
	WALK_PASSED,	/* handed on to trinity's own handler */
	WALK_ABORTED,	/* a fault in the walked range: the walk was dropped */
};

static const char *const walk_verdict_name[] = {
	[WALK_IGNORED] = "ignored",
	[WALK_PASSED] = "passed on",
	[WALK_ABORTED] = "aborted the walk",
};

#define IN_RANGE	0x8	/* a fault's si_addr is in the walked range */
#define WALK_EXIT	50	/* exit status of WALK_IGNORED, then up */

struct walk_case {
	const char *what;
	int sig;
	int code;
	unsigned int flags;
	enum walk_verdict want;
};

static const struct walk_case walk_cases[] = {
	/* What the walkers are there for, and what is not theirs. */
	{ "BUS_ADRERR inside the walked range",
	  SIGBUS, BUS_ADRERR, IN_RANGE, WALK_ABORTED },
	{ "SEGV_MAPERR inside the walked range",
	  SIGSEGV, SEGV_MAPERR, IN_RANGE, WALK_ABORTED },
	{ "BUS_ADRERR outside the walked range",
	  SIGBUS, BUS_ADRERR, 0, WALK_PASSED },
	{ "SIGSEGV forced by the kernel",
	  SIGSEGV, SI_KERNEL, 0, WALK_PASSED },
	{ "SIGSEGV from kill(getpid())",
	  SIGSEGV, SI_USER, NAMES_SELF, WALK_PASSED },
	{ "SIGBUS from raise()",
	  SIGBUS, SI_TKILL, NAMES_SELF, WALK_PASSED },

	/* What a sibling can queue at the task: naming it in si_pid must
	 * not make the signal the task's own. */
	{ "SIGSEGV, SI_QUEUE naming the task",
	  SIGSEGV, SI_QUEUE, NAMES_SELF, WALK_IGNORED },
	{ "SIGBUS, SI_MESGQ naming the task",
	  SIGBUS, SI_MESGQ, NAMES_SELF, WALK_IGNORED },
	{ "SIGSEGV, SI_ASYNCIO naming the task",
	  SIGSEGV, SI_ASYNCIO, NAMES_SELF, WALK_IGNORED },
	{ "SIGBUS, F_SETSIG band naming the task",
	  SIGBUS, SI_SIGIO, NAMES_SELF, WALK_IGNORED },
	{ "SIGSEGV, SI_TIMER with the task's pid as its id",
	  SIGSEGV, SI_TIMER, NAMES_SELF, WALK_IGNORED },
	{ "SIGBUS, SI_QUEUE naming another process",
	  SIGBUS, SI_QUEUE, 0, WALK_IGNORED },
};

static const struct {
	const char *name;
	void (*walk)(struct map *map);
} walkers[] = {
	{ "random_map_readfn", random_map_readfn },
	{ "random_map_writefn", random_map_writefn },
};

static const struct walk_case *walk_armed;
static volatile sig_atomic_t passed_on;

/* Where the armed case lands its signal, once. */
void log_mprotect_failure(void *addr, size_t len, int prot, void *caller,
			  int err)
{
	const struct walk_case *c = walk_armed;
	unsigned long word;

	(void)len; (void)prot; (void)caller; (void)err;
	if (c == NULL)
		return;
	walk_armed = NULL;
	if (c->code > 0)
		word = (c->flags & IN_RANGE) ? (unsigned long)addr : 0;
	else
		word = (c->flags & NAMES_SELF) ? getpid() : getppid();
	if (deliver(getpid(), c->sig, c->code, word) != 0)
		_exit(NOT_SENT);
}

/* Only dirty_first_page() calls it, once an mprotect() has worked, which
 * one on an unaligned page does not. */
void generate_random_page(char *page)
{
	(void)page;
}

static void recorder(int sig, siginfo_t *info, void *ctx)
{
	(void)sig; (void)info; (void)ctx;
	passed_on = 1;
}

static void walk_task(const struct walk_case *c, void (*walk)(struct map *map))
{
	size_t len = 2 * (size_t)sysconf(_SC_PAGESIZE);
	unsigned long aborted = shm->stats.diag.read_walk_aborted +
				shm->stats.diag.write_walk_aborted;
	struct sigaction sa;
	struct map map;
	char *region;

	task_init(c->sig);
	/* Trinity's own handler, as a walker finds it on its first call. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = recorder;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		_exit(NOT_SENT);
	memset(&map, 0, sizeof(map));
	/* Not page aligned, so the walk's mprotect() fails.  The read that
	 * follows stays inside the two pages mapped here, and the write is
	 * skipped. */
	map.ptr = region + 1;
	map.size = page_size;
	map.type = INITIAL_ANON;
	map.fd = -1;

	walk_armed = c;
	walk(&map);
	if (walk_armed != NULL)
		_exit(NOT_SENT);
	if (aborted != shm->stats.diag.read_walk_aborted +
		       shm->stats.diag.write_walk_aborted)
		_exit(WALK_EXIT + WALK_ABORTED);
	_exit(WALK_EXIT + (passed_on ? WALK_PASSED : WALK_IGNORED));
}

static enum walk_verdict run_walk(const struct walk_case *c,
				  void (*walk)(struct map *map))
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		BUG("guarded walk: fork failed");
	if (pid == 0)
		walk_task(c, walk);

	alarm(10);
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("guarded walk: waitpid failed");
	alarm(0);

	if (!WIFEXITED(status) || WEXITSTATUS(status) < WALK_EXIT ||
	    WEXITSTATUS(status) > WALK_EXIT + WALK_ABORTED) {
		fprintf(stderr, "%s: task status %#x\n", c->what, status);
		BUG("guarded walk: the task did not end as a walk would");
	}
	return WEXITSTATUS(status) - WALK_EXIT;
}

static void walk_check(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(walkers); i++) {
		for (j = 0; j < ARRAY_SIZE(walk_cases); j++) {
			const struct walk_case *c = &walk_cases[j];
			enum walk_verdict got = run_walk(c, walkers[i].walk);

			if (got != c->want) {
				fprintf(stderr, "%s, %s: got %s, want %s\n",
					walkers[i].name, c->what,
					walk_verdict_name[got],
					walk_verdict_name[c->want]);
				BUG("guarded walk: wrong verdict");
			}
		}
	}
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
	walk_check();
}

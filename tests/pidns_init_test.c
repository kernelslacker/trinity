/*
 * Self-check for the idle init of a child's new pid namespace
 * (child/child-pidns-init.c).  Each fixture runs in a helper that
 * unshares a user and a pid namespace, standing in for a sandboxed
 * child, starts the init and checks that the namespace stays usable,
 * that the init keeps out of the child's way, its fuzzed waits included,
 * and that pidns_init_lost() notices when it is gone.  Skipped where
 * unprivileged user namespaces are not available.
 */

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arg_coupling.h"	/* validate_arg_coupling */
#include "child-internal.h"	/* start_pidns_init, pidns_init_pid, pidns_init_lost */
#include "debug.h"		/* BUG */
#include "pidstat-probe.h"	/* pidstat_read, pidstat_parse */
#include "syscall.h"
#include "utils.h"		/* ARRAY_SIZE, waitpid_eintr */

/* How a helper exits when it cannot unshare the namespaces. */
#define NO_USERNS	77

/* Run @body in a helper inside the namespaces; false if there are none. */
static bool run_in_pidns(void (*body)(void))
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("pidns_init: fork failed");
	if (pid == 0) {
		/* Don't outlive the test binary if a fixture aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0)
			_exit(NO_USERNS);
		body();
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("pidns_init: cannot reap the helper");
	if (WIFEXITED(status) && WEXITSTATUS(status) == NO_USERNS)
		return false;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		BUG("pidns_init: a check failed in the namespace helper");
	return true;
}

/* Fork a process into the namespace and reap it; false if the fork fails. */
static bool fork_and_reap(void)
{
	pid_t pid = fork();

	if (pid < 0)
		return false;
	if (pid == 0)
		_exit(0);
	if (waitpid_eintr(pid, NULL, 0) != pid)
		BUG("pidns_init: cannot reap a process forked into the namespace");
	return true;
}

/* The init sleeps in poll() once it has dropped the handlers it inherited. */
static void wait_until_asleep(pid_t init)
{
	char buf[512];
	int i;

	for (i = 0; i < 1000; i++) {
		if (pidstat_read(init, buf, sizeof(buf)) == PIDSTAT_OK &&
		    pidstat_parse(buf).state == 'S')
			return;
		usleep(1000);
	}
	BUG("pidns_init: the init never went to sleep");
}

/* Without an init, the first process forked after the unshare would be
 * pid 1, and the namespace would die with it. */
static void fork_after_reap(void)
{
	if (start_pidns_init() < 0)
		BUG("pidns_init: the init did not start");
	if (!fork_and_reap())
		BUG("pidns_init: cannot fork into the namespace");
	if (!fork_and_reap())
		BUG(errno == ENOMEM ?
		    "pidns_init: the namespace died with its first process (ENOMEM)" :
		    "pidns_init: a second fork into the namespace failed");
}

/* A wait for any child, or for any in the caller's process group, finds
 * no child at all; one for any child that asks for __WALL finds the init
 * still running. */
static void hidden_from_wildcard_waits(void)
{
	siginfo_t si;

	if (start_pidns_init() < 0)
		BUG("pidns_init: the init did not start");
	if (waitpid_eintr(-1, NULL, WNOHANG) != -1 || errno != ECHILD)
		BUG("pidns_init: a wait for any child saw the init");
	if (waitid(P_ALL, 0, &si, WEXITED | WNOHANG) != -1 || errno != ECHILD)
		BUG("pidns_init: waitid(P_ALL) saw the init");
	if (waitpid_eintr(0, NULL, WNOHANG | __WALL) != -1 || errno != ECHILD)
		BUG("pidns_init: a __WALL wait for the caller's group saw the init");
	if (waitpid_eintr(-1, NULL, WNOHANG | __WALL) != 0)
		BUG("pidns_init: a __WALL wait did not find the init running");
}

/* A wait for any child that asks for __WALL or __WCLONE still finds the
 * init, and would block on it until the alarm.  validate_arg_coupling()
 * has to make just those waits WNOHANG while the init runs, and the call
 * then has to come straight back. */
static void wildcard_waits_do_not_block(void)
{
	struct syscallentry wait4_entry = { .name = "wait4", .num_args = 4,
					    .is_wait4_family = true };
	struct syscallentry waitid_entry = { .name = "waitid", .num_args = 5,
					     .is_waitid = true };
	static const struct {
		bool is_waitid;
		int id;
		unsigned int options;
		bool nohang;
	} cases[] = {
		{ true,  P_ALL,  WEXITED | __WALL,   true },
		{ true,  P_ALL,  WEXITED | __WCLONE, true },
		{ true,  P_ALL,  WEXITED,            false },
		{ true,  P_PGID, WEXITED | __WALL,   false },
		{ true,  P_PID,  WEXITED | __WALL,   false },
		{ false, -1,     __WALL,             true },
		{ false, -1,     __WCLONE,           true },
		{ false, -1,     0,                  false },
		{ false, 0,      __WALL,             false },
		{ false, -2,     __WALL,             false },
	};
	static struct syscallrecord rec;
	unsigned long *options;
	unsigned int i;
	siginfo_t si;

	if (start_pidns_init() < 0)
		BUG("pidns_init: the init did not start");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = cases[i].is_waitid ? &waitid_entry : &wait4_entry;
		rec.a1 = (unsigned long)(long) cases[i].id;
		options = cases[i].is_waitid ? &rec.a4 : &rec.a3;
		*options = cases[i].options;
		if (validate_arg_coupling(&rec) != 0)
			BUG("pidns_init: the coupling validator refused a wait");
		if (((*options & WNOHANG) != 0) != cases[i].nohang)
			BUG(cases[i].nohang ?
			    "pidns_init: a wait that finds the init was left to block" :
			    "pidns_init: a wait that cannot find the init was made WNOHANG");
		if (!cases[i].nohang)
			continue;
		/* SIGALRM ends this helper if the call waits on the init. */
		alarm(2);
		if (cases[i].is_waitid ? waitid(P_ALL, 0, &si, (int) *options) != 0 :
				      wait4(-1, NULL, (int) *options, NULL) != 0)
			BUG("pidns_init: a WNOHANG wait with only the init running did not return 0");
		alarm(0);
	}

	/* Without an init there is nothing to keep a wait off. */
	pidns_init_pid = 0;
	memset(&rec, 0, sizeof(rec));
	rec.entry = &waitid_entry;
	rec.a1 = P_ALL;
	rec.a4 = WEXITED | __WALL;
	(void)validate_arg_coupling(&rec);
	if (rec.a4 & WNOHANG)
		BUG("pidns_init: a wait was made WNOHANG in a child without an init");
}

static void exit_on_signal(int sig)
{
	(void)sig;
	_exit(1);
}

/* The init inherits the child's handlers, which would end it here; the
 * signals a fuzzed kill() sends must not. */
static void survives_fuzzed_signals(void)
{
	const int sigs[] = { SIGHUP, SIGTERM, SIGUSR1, SIGUSR2, SIGALRM, SIGRTMIN };
	struct sigaction sa = { .sa_handler = exit_on_signal };
	unsigned int i;
	pid_t init;

	for (i = 0; i < ARRAY_SIZE(sigs); i++)
		sigaction(sigs[i], &sa, NULL);
	init = start_pidns_init();
	if (init < 0)
		BUG("pidns_init: the init did not start");
	wait_until_asleep(init);

	for (i = 0; i < ARRAY_SIZE(sigs); i++)
		kill(init, sigs[i]);
	for (i = 0; i < 100; i++) {
		if (waitpid_eintr(init, NULL, WNOHANG | __WALL) != 0)
			BUG("pidns_init: a signal ended the init");
		usleep(1000);
	}
	if (!fork_and_reap())
		BUG("pidns_init: cannot fork into the namespace after the signals");
}

/* The init must not outlive the child that started it, here one ended by
 * SIGKILL as the parent ends a stuck child.  Its pidfd turns readable once
 * it exits, whoever reaps it. */
static void dies_with_child(void)
{
	struct pollfd pfd = { .events = POLLIN };
	pid_t helper, init = -1;
	int report[2];
	int status;

	if (pipe(report) != 0)
		BUG("pidns_init: pipe failed");
	helper = fork();
	if (helper < 0)
		BUG("pidns_init: fork failed");
	if (helper == 0) {
		close(report[0]);
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0)
			_exit(NO_USERNS);
		init = start_pidns_init();
		if (write(report[1], &init, sizeof(init)) != (ssize_t)sizeof(init))
			_exit(1);
		for (;;)
			pause();
	}
	close(report[1]);
	if (read(report[0], &init, sizeof(init)) != (ssize_t)sizeof(init)) {
		if (waitpid_eintr(helper, &status, 0) != helper)
			BUG("pidns_init: cannot reap the helper");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != NO_USERNS)
			BUG("pidns_init: the helper did not report its init");
		printf("(no user namespace for the parent-death check, skipping) ");
		close(report[0]);
		return;
	}
	close(report[0]);
	if (init < 0)
		BUG("pidns_init: the init did not start");

#ifdef __NR_pidfd_open
	pfd.fd = (int)syscall(__NR_pidfd_open, init, 0);
#else
	pfd.fd = -1;
#endif
	kill(helper, SIGKILL);
	if (waitpid_eintr(helper, NULL, 0) != helper)
		BUG("pidns_init: cannot reap the helper");
	if (pfd.fd < 0) {
		printf("(no pidfd_open, skipping the parent-death check) ");
		kill(init, SIGKILL);
		return;
	}
	if (poll(&pfd, 1, 5000) != 1) {
		kill(init, SIGKILL);
		BUG("pidns_init: the init outlived the child that started it");
	}
	close(pfd.fd);
}

/* SIGKILL from outside the namespace still ends the init, and the
 * namespace with it; pidns_init_lost() has to say so. */
static void lost_once_killed(void)
{
	pid_t init = start_pidns_init();
	int i;

	if (init < 0)
		BUG("pidns_init: the init did not start");
	if (pidns_init_lost())
		BUG("pidns_init: a running init was reported lost");
	kill(init, SIGKILL);
	for (i = 0; i < 1000 && !pidns_init_lost(); i++)
		usleep(1000);
	if (i == 1000)
		BUG("pidns_init: a killed init was not reported lost");
	if (fork_and_reap() || errno != ENOMEM)
		BUG("pidns_init: the namespace outlived its init");
}

/* An init that cannot be started leaves the child on its own, as before
 * there was one: a fresh child would only fail the same way.  RLIMIT_NPROC
 * at 0 stops the clone, every retry included, for anyone but root. */
static void degraded_without_start(void)
{
	const struct rlimit none = { 0, 0 };

	if (setrlimit(RLIMIT_NPROC, &none) != 0)
		BUG("pidns_init: cannot lower RLIMIT_NPROC");
	if (start_pidns_init() >= 0)
		BUG("pidns_init: an init started past RLIMIT_NPROC");
	if (pidns_init_pid != 0 || pidns_init_lost())
		BUG("pidns_init: a child whose init never started was sent to recycle");
}

void pidns_init_self_check(void);
void pidns_init_self_check(void)
{
	if (!run_in_pidns(fork_after_reap)) {
		printf("(no unprivileged user namespaces, skipping) ");
		return;
	}
	run_in_pidns(hidden_from_wildcard_waits);
	run_in_pidns(wildcard_waits_do_not_block);
	run_in_pidns(survives_fuzzed_signals);
	dies_with_child();
	run_in_pidns(lost_once_killed);
	if (geteuid() == 0)
		printf("(root ignores RLIMIT_NPROC, skipping the failed start) ");
	else
		run_in_pidns(degraded_without_start);
}

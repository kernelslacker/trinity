/*
 * The idle init of a pid namespace a child unshared.  The child's first
 * fork after unshare(CLONE_NEWPID) becomes pid 1 there, and once pid 1
 * exits every later fork into the namespace fails with ENOMEM
 * (zap_pid_ns_processes() clears PIDNS_ADDING, which alloc_pid() checks).
 * This process holds pid 1 for the child's lifetime and does nothing else.
 */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child-internal.h"
#include "utils.h"	/* waitpid_eintr */

/* Set once the init of the namespace the child forks into has died */
static bool pidns_lost;

/*
 * The init's whole life.  The handlers it inherited are the child's and
 * must not run here, so every signal goes back to SIG_DFL: the kernel
 * then drops whatever is sent to a namespace init (SIGNAL_UNKILLABLE),
 * except SIGKILL and SIGSTOP sent from outside the namespace.  With
 * SIGCHLD ignored the kernel reaps anything reparented to us, at its
 * exit or, if it is already a zombie, when it is reparented, so there
 * is no wait loop to run.
 */
static void pidns_init(int parent_pidfd)
{
	struct pollfd pfd = { .fd = parent_pidfd, .events = POLLIN };
	nfds_t nfds = parent_pidfd >= 0 ? 1 : 0;
	char name[] = "trinity-nsinit";
	sigset_t none;
	int sig;

	for (sig = 1; sig < _NSIG; sig++)
		(void)signal(sig, SIG_DFL);
	(void)signal(SIGCHLD, SIG_IGN);
	sigemptyset(&none);
	(void)sigprocmask(SIG_SETMASK, &none, NULL);

	(void)prctl(PR_SET_NAME, (unsigned long)name);

	/*
	 * Die with the child.  getppid() cannot confirm the child is still
	 * there: the child is outside our namespace, so it reads 0 here
	 * whether or not the child has gone.  The child's pidfd turns
	 * readable once it exits, which also catches a child that died
	 * before PDEATHSIG was armed.  Without a pidfd, or should poll()
	 * fail for good, sleep until PDEATHSIG comes.
	 */
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	while (poll(&pfd, nfds, -1) <= 0) {
		if (errno != EINTR)
			nfds = 0;
	}
}

/* clone() attempts before going without an init: EAGAIN or ENOMEM can be
 * a passing pids or RLIMIT_NPROC squeeze, or an injected fault. */
#define PIDNS_INIT_TRIES	4

pid_t pidns_init_pid;

/*
 * Fork the init of the pid namespace the caller unshared, and return its
 * pid, or -1 if it could not be started; pidns_init_pid follows suit.
 * Without an init the child runs on as it did before there was one: its
 * first fork becomes pid 1, and the namespace dies with it.
 *
 * No exit signal makes a wait pass over the init unless it asks for
 * __WALL or __WCLONE (eligible_child()), and its own process group keeps
 * it out of a wait for the caller's group; validate_arg_coupling() makes
 * the waits left, those for any child with __WALL or __WCLONE, WNOHANG.
 * clone() takes its arguments in a different order on some architectures,
 * but every one of them is zero here.
 */
pid_t start_pidns_init(void)
{
	unsigned int tries = 0;
	int pidfd = -1;
	pid_t pid;

#ifdef __NR_pidfd_open
	pidfd = (int)syscall(__NR_pidfd_open, getpid(), 0);
#endif
	for (;;) {
		pid = (pid_t)syscall(__NR_clone, 0UL, 0UL, 0UL, 0UL, 0UL);
		if (pid >= 0 || ++tries == PIDNS_INIT_TRIES ||
		    (errno != EAGAIN && errno != ENOMEM))
			break;
		usleep(1000);
	}
	if (pid == 0) {
		pidns_init(pidfd);
		/* Not _exit(): a noreturn call has ASAN unpoison a stack it
		 * holds no bounds for in a task forked behind libc's back
		 * (see spawn_child()). */
		syscall(SYS_exit_group, 0);
		__builtin_unreachable();
	}
	if (pidfd >= 0)
		close(pidfd);
	if (pid <= 0)
		return -1;
	(void)setpgid(pid, pid);
	pidns_init_pid = pid;
	return pid;
}

/*
 * True once the init of the namespace the child forks into has died:
 * every fork from then on fails, and a dead namespace is worse than
 * none, so the child should make way for a fresh one.  A child that never
 * got an init runs on without one.  The init has no exit signal, hence
 * __WALL.  Every answer but "still running" counts as gone, a ptrace-stop
 * included: only a fuzzed ptrace() of the init brings one, and recycling
 * the child for it costs nothing.
 */
bool pidns_init_lost(void)
{
	if (pidns_init_pid > 0 &&
	    waitpid_eintr(pidns_init_pid, NULL, WNOHANG | __WALL) != 0) {
		pidns_init_pid = 0;
		pidns_lost = true;
	}
	return pidns_lost;
}

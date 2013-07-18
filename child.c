/*
 * Each process that gets forked runs this code.
 */

#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/prctl.h>

#include "child.h"
#include "syscall.h"
#include "log.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "pids.h"
#include "params.h"	// for 'debug'

static struct rlimit oldrlimit;

static void disable_coredumps(void)
{
	struct rlimit limit;

	if (debug == TRUE) {
		(void)signal(SIGSEGV, SIG_DFL);
		return;
	}

	getrlimit(RLIMIT_CORE, &oldrlimit);

	limit.rlim_cur = 0;
	limit.rlim_max = oldrlimit.rlim_max;
	if (setrlimit(RLIMIT_CORE, &limit) != 0)
		perror( "setrlimit(RLIMIT_CORE)" );
}

static void reenable_coredumps(void)
{
	if (debug == TRUE)
		return;

	prctl(PR_SET_DUMPABLE, TRUE);

	if (setrlimit(RLIMIT_CORE, &oldrlimit) != 0) {
		printf("[%d] Error restoring rlimits to cur:%d max:%d (%s)\n",
			getpid(),
			(unsigned int) oldrlimit.rlim_cur,
			(unsigned int) oldrlimit.rlim_max,
			strerror(errno));
	}
}
static void set_make_it_fail(void)
{
	int fd;
	const char *buf = "1";

	/* If we failed last time, don't bother trying in future. */
	if (shm->do_make_it_fail == TRUE)
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1)
		return;

	if (write(fd, buf, 1) == -1) {
		if (errno != EPERM)
			printf("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
		else
			shm->do_make_it_fail = TRUE;
	}
	close(fd);
}

/*
 * We call this occasionally to set some FPU state, in the hopes that we
 * might tickle some weird FPU/scheduler related bugs
 */
static void use_fpu(void)
{
	double x = 0;
	asm volatile("":"+m" (x));
	x += 1;
	asm volatile("":"+m" (x));
}

void init_child(int childno)
{
	cpu_set_t set;
	pid_t pid = getpid();

	set_seed(childno);

	disable_coredumps();

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(childno, &set);
		sched_setaffinity(pid, sizeof(set), &set);
	}

	shm->child_syscall_count[childno] = 0;

	set_make_it_fail();

	if (rand() % 100 < 50)
		use_fpu();
}

void check_parent_pid(void)
{
	pid_t pid;
	unsigned int i;
	static unsigned int parent_check_time = 10;

	parent_check_time--;
	if (parent_check_time != 0)
		return;

	parent_check_time = 10;

	if (getppid() == mainpid)
		return;

	pid = getpid();

	//FIXME: Add locking so only one child does this output.
	output(0, BUGTXT "CHILD (pid:%d) GOT REPARENTED! "
		"parent pid:%d. Watchdog pid:%d\n",
		pid, mainpid, watchdog_pid);
	output(0, BUGTXT "Last syscalls:\n");

	for (i = 0; i < MAX_NR_CHILDREN; i++) {
		// Skip over 'boring' entries.
		if ((shm->pids[i] == -1) &&
		    (shm->previous_syscallno[i] == 0) &&
		    (shm->child_syscall_count[i] == 0))
			continue;

		output(0, "[%d]  pid:%d call:%s callno:%d\n",
			i, shm->pids[i],
			print_syscall_name(shm->previous_syscallno[i], shm->do32bit[i]),	// FIXME: need previous do32bit
			shm->child_syscall_count[i]);
	}
	shm->exit_reason = EXIT_REPARENT_PROBLEM;
	exit(EXIT_FAILURE);
	//TODO: Emergency logging.
}

int child_process(int childno)
{
	int ret;

	ret = do_random_syscalls(childno);

	reenable_coredumps();

	return ret;
}

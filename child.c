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

#include "trinity.h"
#include "syscall.h"
#include "shm.h"

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
		printf("Error restoring rlimits to cur:%d max:%d (%s)\n",
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

void init_child(void)
{
	int i;

	i = find_pid_slot(getpid());
	shm->child_syscall_count[i] = 0;

	set_make_it_fail();
	if (rand() % 100 < 50)
		use_fpu();
}

int child_process(void)
{
	cpu_set_t set;
	pid_t pid = getpid();
	int ret;
	unsigned int syscallnr;
	unsigned int childno = find_pid_slot(pid);
	unsigned int i;

	disable_coredumps();

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(childno, &set);
		sched_setaffinity(getpid(), sizeof(set), &set);
	}

	init_child();

	sigsetjmp(ret_jump, 1);

	ret = 0;

	while (shm->exit_reason == STILL_RUNNING) {

		if (getppid() != shm->parentpid) {
			//FIXME: Add locking so only one child does this output.
			output(0, BUGTXT "CHILD (pid:%d) GOT REPARENTED! "
				"parent pid:%d. Watchdog pid:%d\n",
				getpid(),
				shm->parentpid, shm->watchdog_pid);
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

		while (shm->regenerating == TRUE)
			sleep(1);

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (shm->seed != shm->seeds[childno])
			set_seed(childno);

		if (biarch == TRUE) {

			if ((use_64bit == TRUE) && (use_32bit == TRUE)) {
				/*
				 * 10% possibility of a 32bit syscall
				 */
				shm->do32bit[childno] = FALSE;
//				if (rand() % 100 < 10)
//					shm->do32bit[childno] = TRUE;
			}

			if (validate_syscall_table_32() == FALSE)
				use_32bit = FALSE;

			if (validate_syscall_table_64() == FALSE)
				use_64bit = FALSE;

			if (shm->do32bit[childno] == FALSE) {
				syscalls = syscalls_64bit;
				max_nr_syscalls = max_nr_64bit_syscalls;
			} else {
				syscalls = syscalls_32bit;
				max_nr_syscalls = max_nr_32bit_syscalls;
			}
		}

		if (no_syscalls_enabled() == TRUE) {
			output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
			shm->exit_reason = EXIT_NO_SYSCALLS_ENABLED;
		}

retry:
		if (shm->exit_reason != STILL_RUNNING)
			goto out;

		syscallnr = rand() % max_nr_syscalls;

		if (syscalls[syscallnr].entry->num_args == 0)
			goto retry;

		if (!(syscalls[syscallnr].entry->flags & ACTIVE))
			goto retry;

		if (syscalls[syscallnr].entry->flags & AVOID_SYSCALL)
			goto retry;

		if (syscalls[syscallnr].entry->flags & NI_SYSCALL)
			goto retry;

		/* if we get here, syscallnr is finally valid */

		shm->syscallno[childno] = syscallnr;

		if (syscalls_todo) {
			if (shm->total_syscalls_done >= syscalls_todo) {
				output(0, "[%d] shm->total_syscalls_done (%d) >= syscalls_todo (%d)\n", getpid(), shm->total_syscalls_done,syscalls_todo);
				shm->exit_reason = EXIT_REACHED_COUNT;
			}

			if (shm->total_syscalls_done == syscalls_todo)
				printf("[%d] Reached maximum syscall count %ld\n", pid, shm->total_syscalls_done);
		}

		ret = mkcall(childno);
	}


out:
	reenable_coredumps();

	return ret;
}

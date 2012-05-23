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

#include "trinity.h"
#include "syscall.h"
#include "shm.h"

static struct rlimit oldrlimit;

static void disable_coredumps()
{
	struct rlimit limit;

	if (debug == TRUE) {
		(void)signal(SIGSEGV, SIG_DFL);
		return;
	}

	getrlimit(RLIMIT_CORE, &oldrlimit);

	limit.rlim_cur = 0;
	limit.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &limit) != 0) {
		perror( "setrlimit(RLIMIT_CORE)" );
		exit(EXIT_FAILURE);
	}
}

static void reenable_coredumps()
{
	struct rlimit limit;

	if (debug == TRUE)
		return;

	getrlimit(RLIMIT_CORE, &limit);
	limit.rlim_cur = oldrlimit.rlim_cur;

	if (setrlimit(RLIMIT_CORE, &limit) != 0) {
		printf("Error restoring rlimits to cur:%d max:%d (%s)\n",
			(unsigned int) limit.rlim_cur,
			(unsigned int) limit.rlim_max,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
}
static void set_make_it_fail()
{
	static char failed = 0;
	int fd;
	const char *buf = "1";

	/* If we failed last time, don't bother trying in future. */
	if (failed == 1)
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1)
		return;

	if (write(fd, buf, 1) == -1) {
		if (errno != EPERM)
			printf("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
		else
			failed = 1;
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
	shm->total_syscalls[i] = 0;

	set_make_it_fail();
	if (rand() % 100 < 50)
		use_fpu();
}

int child_process(void)
{
	cpu_set_t set;
	pid_t pid = getpid();
	int ret = 0;
	unsigned int syscallnr;
	unsigned int cpu;

	seed_from_tod();

	disable_coredumps();

	for (cpu = 0; cpu < shm->nr_childs; cpu++) {
		if (shm->pids[cpu] == pid)
			break;
	}

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		sched_setaffinity(getpid(), sizeof(set), &set);
		output("bound child %d to cpu %d\n", pid, cpu);
	}
	if (extrafork == FALSE)
		init_child();

	while (shm->exit_now == FALSE) {

		if (biarch == TRUE) {
			/*
			 * 10% possibility of a 32bit syscall
			 */
			shm->do32bit = FALSE;
//			if (rand() % 100 < 10)
//				shm->do32bit = TRUE;

			if (shm->do32bit == FALSE) {
				syscalls = syscalls_64bit;
				max_nr_syscalls = max_nr_64bit_syscalls;
			} else {
				syscalls = syscalls_32bit;
				max_nr_syscalls = max_nr_32bit_syscalls;
			}
		}

		if (do_specific_syscall == TRUE) {
			/* If we asked for a 32bit only syscall, force 32bit mode. */
			if (specific_syscall64 == -1) {
				shm->do32bit = TRUE;
				syscalls = syscalls_32bit;
				max_nr_syscalls = max_nr_32bit_syscalls;
			}

			if (shm->do32bit == TRUE)
				syscallnr = specific_syscall32;
			else
				syscallnr = specific_syscall64;
		} else {
retry:
			/* We're doing something random. */
			syscallnr = rand() % max_nr_syscalls;

			if (syscalls[syscallnr].entry->num_args == 0)
				goto retry;

			if (syscalls[syscallnr].entry->flags & AVOID_SYSCALL)
				goto retry;

			if (syscalls[syscallnr].entry->flags & NI_SYSCALL)
				goto retry;
		}

		if (syscallcount) {
			if (shm->execcount >= syscallcount) {
				shm->exit_now = TRUE;
				printf("[%d] Reached maximum syscall count %ld\n", getpid(), shm->execcount);
			}
		}

		ret = mkcall(syscallnr);
	}

	reenable_coredumps();

	/* Let the watchdog process die before the children. */
	while (shm->watchdog_pid != 0) {
		printf("Waiting for watchdog at %d to die\n", shm->watchdog_pid);
		sleep(1);
	}

	return ret;
}

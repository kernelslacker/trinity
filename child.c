/*
 * Each process that gets forked runs this code.
 */

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

#include "trinity.h"
#include "syscall.h"
#include "shm.h"

static void set_make_it_fail()
{
	int fd;
	const char *buf = "1";

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1)
		return;

	if (write(fd, buf, 1) == -1)
		printf("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));

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
	unsigned int left_to_do = syscalls_per_child;

	seed_from_tod();

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

	while (left_to_do > 0) {

		if (biarch == TRUE) {
			/*
			 * 10% possibility of a 32bit syscall
			 */
			shm->do32bit = FALSE;
//			if (rand() % 100 < 10)
//				shm->do32bit = TRUE;



			// FIXME: if we passed -c, we call the wrong syscall in 32bit mode.
			// For now, force it to be 64bit always in that case.
			if (do_specific_syscall == 1)
				shm->do32bit = FALSE;


			if (shm->do32bit == FALSE) {
				syscalls = syscalls_64bit;
				max_nr_syscalls = max_nr_64bit_syscalls;
			} else {
				syscalls = syscalls_32bit;
				max_nr_syscalls = max_nr_32bit_syscalls;
			}
		}

		syscallnr = rand() % max_nr_syscalls;

		if (do_specific_syscall != 0)
			syscallnr = specific_syscall;
		else {

			if (syscalls[syscallnr].entry->num_args == 0)
				goto skip_syscall;

			if (syscalls[syscallnr].entry->flags & AVOID_SYSCALL)
				goto skip_syscall;

			if (syscalls[syscallnr].entry->flags & NI_SYSCALL)
				goto skip_syscall;
		}

		ret = mkcall(syscallnr);

skip_syscall:
		left_to_do--;
	}

	return ret;
}

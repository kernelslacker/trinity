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

#include "arch.h"
#include "child.h"
#include "list.h"
#include "log.h"
#include "maps.h"
#include "params.h"	// for 'debug'
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "utils.h"	// zmalloc

static void disable_coredumps(void)
{
	struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };

	if (debug == TRUE) {
		(void)signal(SIGABRT, SIG_DFL);
		(void)signal(SIGSEGV, SIG_DFL);
		return;
	}

	if (setrlimit(RLIMIT_CORE, &limit) != 0)
		perror( "setrlimit(RLIMIT_CORE)" );

	prctl(PR_SET_DUMPABLE, FALSE);
}

static void enable_coredumps(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	if (debug == TRUE)
		return;

	prctl(PR_SET_DUMPABLE, TRUE);

	(void) setrlimit(RLIMIT_CORE, &limit);
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
			outputerr("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
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

int this_child = 0;

static void setup_page_maps(void)
{
	unsigned long *page;
	unsigned int i;

	page = (void *) page_maps;

	for (i = 0; i < page_size / sizeof(unsigned long); i++) {
		struct map *map;

		map = get_map();
		page[i] = (unsigned long) map->ptr;
	}
}

static void oom_score_adj(int adj)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_score_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%d", adj);
	fclose(fp);
}

void init_child(int childno)
{
	cpu_set_t set;
	pid_t pid = getpid();
	char childname[17];

	this_child = childno;

	set_seed(childno);

	shm->kill_count[childno] = 0;

	shm->num_mappings[childno] = 0;
	shm->mappings[childno] = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&shm->mappings[childno]->list);

	setup_page_maps();

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(childno, &set);
		sched_setaffinity(pid, sizeof(set), &set);
	}

	shm->child_syscall_count[childno] = 0;

	memset(childname, 0, sizeof(childname));
	sprintf(childname, "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);

	oom_score_adj(500);

	/* Wait for parent to set our pidslot */
	while (shm->pids[childno] != getpid()) {
		int ret = 0;

		/* Make sure parent is actually alive to wait for us. */
		ret = pid_alive(shm->mainpid);
		if (ret != 0) {
			shm->exit_reason = EXIT_SHM_CORRUPTION;
			outputerr(BUGTXT "parent (%d) went away!\n", shm->mainpid);
			sleep(20000);
		}
	}

	/* Wait for all the children to start up. */
	while (shm->ready == FALSE)
		sleep(1);

	set_make_it_fail();

	if (rand() % 100 < 50)
		use_fpu();

	mask_signals_child();

	disable_coredumps();
}

static void check_parent_pid(void)
{
	pid_t pid;
	unsigned int i;
	static unsigned int parent_check_time = 10;

	parent_check_time--;
	if (parent_check_time != 0)
		return;

	parent_check_time = 10;

	if (getppid() == shm->mainpid)
		return;

	pid = getpid();

	//FIXME: Add locking so only one child does this output.
	output(0, BUGTXT "CHILD (pid:%d) GOT REPARENTED! "
		"parent pid:%d. Watchdog pid:%d\n",
		pid, shm->mainpid, watchdog_pid);
	output(0, BUGTXT "Last syscalls:\n");

	for_each_pidslot(i) {
		// Skip over 'boring' entries.
		if ((shm->pids[i] == EMPTY_PIDSLOT) &&
		    (shm->previous[i].nr == 0) &&
		    (shm->child_syscall_count[i] == 0))
			continue;

		output(0, "[%d]  pid:%d call:%s callno:%d\n",
			i, shm->pids[i],
			print_syscall_name(shm->previous[i].nr, shm->previous[i].do32bit),
			shm->child_syscall_count[i]);
	}
	shm->exit_reason = EXIT_REPARENT_PROBLEM;
	exit(EXIT_FAILURE);
	//TODO: Emergency logging.
}

struct child_funcs {
	const char *name;
	bool (*func)(int childno);
	unsigned char likelyhood;
};

static const struct child_funcs child_ops[] = {
	{ .name = "rand_syscalls", .func = child_random_syscalls, .likelyhood = 100 },
};


// FIXME: when we have different child ops, we're going to need to redo the progress detector.
static unsigned int handle_sigreturn(int childno)
{
	static unsigned int count = 0;
	static unsigned int last = -1;

	output(2, "<timed out>\n");     /* Flush out the previous syscall output. */

	/* Check if we're making any progress at all. */
	if (shm->child_syscall_count[childno] == last) {
		count++;
		//output(1, "no progress for %d tries.\n", count);
	} else {
		count = 0;
		last = shm->child_syscall_count[childno];
	}
	if (count == 3) {
		output(1, "no progress for 3 tries, exiting child.\n");
		return 0;
	}

	if (shm->kill_count[childno] > 0) {
		output(1, "[%d] Missed a kill signal, exiting\n", getpid());
		return 0;
	}

	if (sigwas != SIGALRM)
		output(1, "[%d] Back from signal handler! (sig was %s)\n", getpid(), strsignal(sigwas));

	return 1;
}

void child_process(int childno)
{
	int ret;
	const char *lastop = NULL;

	ret = sigsetjmp(ret_jump, 1);
	if (ret != 0) {
		if (handle_sigreturn(childno) == 0)
			return;	// Exit the child, things are getting too weird.
	}

	while (shm->exit_reason == STILL_RUNNING) {
		unsigned int i;

		check_parent_pid();

		while (shm->regenerating == TRUE)
			sleep(1);

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (shm->seed != shm->seeds[childno])
			set_seed(childno);

		/* Choose operations for this iteration. */
		i = rand() % ARRAY_SIZE(child_ops);

		if (rand() % 100 <= child_ops[i].likelyhood) {
			if (lastop != child_ops[i].name) {
				output(0, "Chose %s.\n", child_ops[i].name);
				lastop = child_ops[i].name;
			}

			ret = child_ops[i].func(childno);
			if (ret == FAIL)
				return;
		}
	}

	enable_coredumps();
}

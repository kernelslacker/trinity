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

void check_parent_pid(void)
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
	int type;
	const char *name;
	int (*func)(int childno);
};

static const struct child_funcs child_functions[] = {
	{ .type = CHILD_RANDOM_SYSCALLS, .name = "rand_syscalls", .func = child_random_syscalls },
#ifdef DEBUG_MULTI
	{ .type = CHILD_OPEN_ALL_FILES, .name = "read_all_files", .func = child_read_all_files },
#endif
};

int child_process(int childno)
{
	int ret;
	unsigned int i;

	i = rand() % ARRAY_SIZE(child_functions);

#ifdef DEBUG_MULTI
	output(0, "Chose %s.\n", child_functions[i].name);
#endif

	shm->child_type[childno] = child_functions[i].type;
	ret = child_functions[i].func(childno);

	enable_coredumps();

	return ret;
}

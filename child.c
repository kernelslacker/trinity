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

struct childdata *this_child = NULL;

struct child_funcs {
	const char *name;
	bool (*func)(void);
	unsigned char likelyhood;
};

static const struct child_funcs child_ops[] = {
	{ .name = "rand_syscalls", .func = child_random_syscalls, .likelyhood = 100 },
};

/*
 * Provide temporary immunity from the watchdog.
 * This is useful if we're going to do something that might take
 * longer than the time the watchdog is prepared to wait, especially if
 * we're doing something critical, like handling a lock, or dumping a log.
 */
void set_dontkillme(pid_t pid, bool state)
{
	int childno;

	childno = find_childno(pid);
	if (childno == CHILD_NOT_FOUND)		/* possible, we might be the watchdog for example */
		return;
	shm->children[childno]->dontkillme = state;
}

/*
 * For the child processes, we don't want core dumps (unless we're running with -D)
 * This is because it's not uncommon for us to get segfaults etc when we're doing
 * syscalls with garbage for arguments.
 */
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

/*
 * We reenable core dumps when we're about to exit a child.
 * TODO: Maybe narrow the disable/enable pair to just around do_syscall ?
 */
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

/*
 * Enable the kernels fault-injection code for our child process.
 * (Assumes you've set everything else up by hand).
 */
static void set_make_it_fail(void)
{
	int fd;
	const char *buf = "1";

	/* If we failed last time, it's probably because we don't
	 * have fault-injection enabled, so don't bother trying in future.
	 */
	if (shm->dont_make_it_fail == TRUE)
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1) {
		shm->dont_make_it_fail = TRUE;
		return;
	}

	if (write(fd, buf, 1) == -1) {
		if (errno != EPERM)
			outputerr("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
		shm->dont_make_it_fail = TRUE;
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

/*
 * Tweak the oom_score_adj setting for our child so that there's a higher
 * chance that the oom-killer kills our processes rather than something
 * more important.
 */
static void oom_score_adj(int adj)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_score_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%d", adj);
	fclose(fp);
}

/*
 * Reset a log file contents.
 * If we successfully exited and respawned, we don't care about what
 * happened last time.
 */
static void truncate_log(void)
{
	int fd;

	this_child->logdirty = FALSE;

	if (logging == FALSE)
		return;

	fd = fileno(this_child->logfile);
	if (ftruncate(fd, 0) == 0)
		lseek(fd, 0, SEEK_SET);
}

/*
 * Wipe out any state left from a previous child running in this slot.
 * Right now the logfile entry is the only persistent thing across instances.
 */
static void reinit_child(struct childdata *child)
{
	memset(&child->syscall, 0, sizeof(struct syscallrecord));
	memset(&child->previous, 0, sizeof(struct syscallrecord));

	child->num_mappings = 0;
	child->seed = 0;
	child->kill_count = 0;
	child->dontkillme = FALSE;
}

/*
 * Called from the fork_children loop in the main process.
 */
void init_child(int childno)
{
	struct childdata *child = shm->children[childno];
	cpu_set_t set;
	pid_t pid = getpid();
	char childname[17];

	/* Wait for parent to set our childno */
	while (child->pid != pid) {
		int ret = 0;

		/* Make sure parent is actually alive to wait for us. */
		ret = pid_alive(shm->mainpid);
		if (ret != 0) {
			panic(EXIT_SHM_CORRUPTION);
			outputerr("BUG!: parent (%d) went away!\n", shm->mainpid);
			sleep(20000);
		}
	}

	this_child = child;

	child->num = childno;

	reinit_child(child);

	truncate_log();

	set_seed(this_child);

	child->mappings = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&child->mappings->list);

	generate_random_page(page_rand);

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(childno, &set);
		sched_setaffinity(pid, sizeof(set), &set);
	}

	memset(childname, 0, sizeof(childname));
	sprintf(childname, "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);

	oom_score_adj(500);

	/* Wait for all the children to start up. */
	while (shm->ready == FALSE)
		sleep(1);

	set_make_it_fail();

	if (rand() % 100 < 50)
		use_fpu();

	mask_signals_child();

	disable_coredumps();
}

/*
 * Sanity check to make sure that the main process is still around
 * to wait for us.
 */
static void check_parent_pid(void)
{
	struct childdata *child;
	pid_t pid;
	unsigned int i;

	if (getppid() == shm->mainpid)
		return;

	pid = getpid();

	lock(&shm->buglock);

	if (shm->exit_reason == EXIT_REPARENT_PROBLEM)
		goto out;

	output(0, "BUG!: CHILD (pid:%d) GOT REPARENTED! "
		"parent pid:%d. Watchdog pid:%d\n",
		pid, shm->mainpid, watchdog_pid);
	output(0, "BUG!: Last syscalls:\n");

	//TODO: replace all this with calls to postmortem()
	for_each_child(i) {
		child = shm->children[i];

		// Skip over 'boring' entries.
		if (child->pid == EMPTY_PIDSLOT)
			continue;

		output(0, "[%d]  pid:%d call:%s callno:%d\n",
			i, child->pid,
			print_syscall_name(child->previous.nr, child->previous.do32bit),
			child->syscall.op_nr);
	}
	panic(EXIT_REPARENT_PROBLEM);

out:
	unlock(&shm->buglock);
	exit(EXIT_FAILURE);
}

/*
 * Here we call various functions that perform checks/changes that
 * we don't want to happen on every iteration of the child loop.
 */
static void periodic_work(void)
{
	static unsigned int periodic_counter = 0;

	periodic_counter++;
	if (periodic_counter < 10)
		return;

	/* Every ten iterations. */
	if (!(periodic_counter % 10))
		check_parent_pid();

	/* Every hundred iterations. */
	if (!(periodic_counter % 100))
		generate_random_page(page_rand);

	if (periodic_counter == 100)
		periodic_counter = 0;
}

/*
 * We jump here on return from a signal. We do all the stuff here that we
 * otherwise couldn't do in a signal handler.
 *
 * FIXME: when we have different child ops, we're going to need to redo the progress detector.
 */
static bool handle_sigreturn(void)
{
	struct syscallrecord *rec;
	static unsigned int count = 0;
	static unsigned int last = 0;

	rec = &this_child->syscall;

	/* If we held a lock before the signal happened, drop it. */
	bust_lock(&rec->lock);

	/* Check if we're blocked because we were stuck on an fd. */
	if (check_if_fd(rec) == TRUE) {
		/* avoid doing it again from other threads. */
		shm->fd_lifetime = 0;

		/* TODO: Somehow mark the fd in the parent not to be used again too. */
	}

	output(2, "<timed out>\n");     /* Flush out the previous syscall output. */

	/* Check if we're making any progress at all. */
	if (rec->op_nr == last) {
		count++;
		//output(1, "no progress for %d tries.\n", count);
	} else {
		count = 0;
		last = rec->op_nr;
	}
	if (count == 10) {
		output(1, "no progress for 10 tries, exiting child.\n");
		return FALSE;
	}

	if (this_child->kill_count > 0) {
		output(1, "[%d] Missed a kill signal, exiting\n", getpid());
		return FALSE;
	}

	if (sigwas != SIGALRM)
		output(1, "[%d] Back from signal handler! (sig was %s)\n", getpid(), strsignal(sigwas));

	return TRUE;
}

/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 * We also re-enter it from the signal handler code if something happened.
 */
void child_process(void)
{
	const char *lastop = NULL;
	int ret;

	ret = sigsetjmp(ret_jump, 1);
	if (ret != 0) {
		if (handle_sigreturn() == FALSE)
			return;	// Exit the child, things are getting too weird.
	}

	while (shm->exit_reason == STILL_RUNNING) {
		unsigned int i;

		periodic_work();

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (shm->seed != this_child->seed)
			set_seed(this_child);

		/* Choose operations for this iteration. */
		i = rand() % ARRAY_SIZE(child_ops);

		if (rand() % 100 <= child_ops[i].likelyhood) {
			if (lastop != child_ops[i].name) {
				//output(0, "Chose %s.\n", child_ops[i].name);
				lastop = child_ops[i].name;
			}

			ret = child_ops[i].func();
			if (ret == FAIL)
				return;
		}
	}

	enable_coredumps();

	/* If we're exiting because we tainted, wait here for it to be done. */
	while (shm->postmortem_in_progress == TRUE) {
		/* Make sure the main process & watchdog are still around. */
		if (pid_alive(shm->mainpid) == -1)
			return;

		if (pid_alive(watchdog_pid) == -1)
			return;

		usleep(1);
	}
}

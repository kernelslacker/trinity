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
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "uid.h"
#include "utils.h"	// zmalloc

/*
 * Provide temporary immunity from the reaper
 * This is useful if we're going to do something that might take
 * longer than the time the reaper is prepared to wait, especially if
 * we're doing something critical, like handling a lock, or dumping a log.
 */
void set_dontkillme(struct childdata *child, bool state)
{
	if (child == NULL)	/* possible, we might be the mainpid */
		return;
	child->dontkillme = state;

	/* bump the progress indicator */
	clock_gettime(CLOCK_MONOTONIC, &child->tp);
}

/*
 * For the child processes, we don't want core dumps (unless we're running with -D)
 * This is because it's not uncommon for us to get segfaults etc when we're doing
 * syscalls with garbage for arguments.
 */
static void disable_coredumps(void)
{
	struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };

	if (shm->debug == TRUE) {
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

	if (shm->debug == TRUE)
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
 * Wipe out any state left from a previous child running in this slot.
 */
void clean_childdata(struct childdata *child)
{
	memset(&child->syscall, 0, sizeof(struct syscallrecord));
	child->logdirty = FALSE;
	child->seed = 0;
	child->kill_count = 0;
	child->dontkillme = FALSE;
	child->xcpu_count = 0;
	child->op_nr = 0;
	child->dropped_privs = FALSE;
	clock_gettime(CLOCK_MONOTONIC, &child->tp);
}

static void bind_child_to_cpu(struct childdata *child)
{
	cpu_set_t set;
	unsigned int cpudest;
	pid_t pid = pids[child->num];

	if (no_bind_to_cpu == TRUE)
		return;

	if (sched_getaffinity(pid, sizeof(set), &set) != 0)
		return;

	if (child->num > num_online_cpus)
		cpudest = child->num % num_online_cpus;
	else
		cpudest = child->num;

	CPU_ZERO(&set);
	CPU_SET(cpudest, &set);
	sched_setaffinity(pid, sizeof(set), &set);
}

/*
 * Called from the fork_children loop in the main process.
 */
static void init_child(struct childdata *child, int childno)
{
	pid_t pid = getpid();
	char childname[17];
	unsigned int i;

	for_each_child(i) {
		if (child->num != i)
			mprotect(shm->children[i], sizeof(struct childdata), PROT_READ);
	}

	mprotect(pids, max_children * sizeof(int), PROT_READ);

	/* Wait for parent to set our childno */
	while (pids[childno] != pid) {
		/* Make sure parent is actually alive to wait for us. */
		if (pid_alive(mainpid) == FALSE) {
			panic(EXIT_SHM_CORRUPTION);
			outputerr("BUG!: parent (%d) went away!\n", mainpid);
			sleep(20000);
		}
	}

	set_seed(child);

	init_object_lists(OBJ_LOCAL);

	init_child_mappings();

	dirty_random_mapping();

	if (RAND_BOOL())
		bind_child_to_cpu(child);

	memset(childname, 0, sizeof(childname));
	sprintf(childname, "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);

	oom_score_adj(500);

	/* Wait for all the children to start up. */
	while (shm->ready == FALSE)
		sleep(1);

	set_make_it_fail();

	if (RAND_BOOL())
		use_fpu();

	mask_signals_child();

	disable_coredumps();

	if (RAND_BOOL()) {
		unshare(CLONE_NEWNS);
		unshare(CLONE_NEWIPC);
		unshare(CLONE_IO);
		unshare(CLONE_NEWNET);
	}

/*
	if (shm->unshare_perm_err == FALSE) {
		if (RAND_BOOL()) {
			int ret = unshare(CLONE_NEWUSER);
			if (ret != 0)
				output(0, "couldn't unshare: %s\n", strerror(errno));
			if (ret == -EPERM)
				shm->unshare_perm_err = TRUE;
		}
	}
*/
	if (orig_uid == 0)
		child->dropped_privs = FALSE;
}

/*
 * Sanity check to make sure that the main process is still around
 * to wait for us.
 */
static void check_parent_pid(void)
{
	pid_t pid, ppid;

	ppid = getppid();
	if (ppid == mainpid)
		return;

	pid = getpid();

	/* TODO: it'd be neat to do stuff inside pidns's, but right now
	 * we shit ourselves when we exit and get reparented to pid 1
	 */
	if (pid == ppid) {
		debugf("pid became ppid! exiting child.\n");
		_exit(EXIT_FAILURE);
	}

	if (ppid < 2) {
		debugf("ppid == %d. pidns? exiting child.\n", ppid);
		_exit(EXIT_FAILURE);;
	}

	lock(&shm->buglock);

	if (shm->exit_reason == EXIT_REPARENT_PROBLEM)
		goto out;

	output(0, "BUG!: CHILD (pid:%d) GOT REPARENTED! "
		"main pid:%d. ppid=%d\n",
		pid, mainpid, ppid);

	if (pid_alive(mainpid) == FALSE)
		output(0, "main pid %d is dead.\n", mainpid);

	panic(EXIT_REPARENT_PROBLEM);

out:
	unlock(&shm->buglock);
	_exit(EXIT_FAILURE);
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

	/* Every 100 iterations. */
//	if (!(periodic_counter % 100))
//		dirty_random_mapping();

	if (periodic_counter == 1000)
		periodic_counter = 0;
}

/*
 * We jump here on return from a signal. We do all the stuff here that we
 * otherwise couldn't do in a signal handler.
 *
 * FIXME: when we have different child ops, we're going to need to redo the progress detector.
 */
static bool handle_sigreturn(int sigwas)
{
	struct childdata *child = this_child();
	struct syscallrecord *rec;
	static unsigned int count = 0;
	static unsigned int last = 0;

	rec = &child->syscall;

	/* If we held a lock before the signal happened, drop it. */
	bust_lock(&rec->lock);

	/* Check if we're blocked because we were stuck on an fd. */
	lock(&rec->lock);
	if (check_if_fd(child, rec) == TRUE) {
		/* avoid doing it again from other threads. */
		shm->fd_lifetime = 0;

		/* TODO: Somehow mark the fd in the parent not to be used again too. */
	}
	unlock(&rec->lock);

	/* Check if we're making any progress at all. */
	if (child->op_nr == last) {
		count++;
		//output(1, "no progress for %d tries.\n", count);
	} else {
		count = 0;
		last = child->op_nr;
	}
	if (count == 10) {
		output(1, "no progress for 10 tries, exiting child.\n");
		return FALSE;
	}

	if (child->kill_count > 0) {
		output(1, "[%d] Missed a kill signal, exiting\n", getpid());
		return FALSE;
	}

	if (sigwas == SIGHUP)
		return FALSE;

	if (sigwas != SIGALRM)
		output(1, "[%d] Back from signal handler! (sig was %s)\n", getpid(), strsignal(sigwas));
	else {
		child->op_nr++;
	}
	return TRUE;
}


/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 * We also re-enter it from the signal handler code if something happened.
 */
#define NEW_OP_COUNT 100000

void child_process(struct childdata *child, int childno)
{
	int ret;

	init_child(child, childno);

	ret = sigsetjmp(ret_jump, 1);
	if (ret != 0) {
		if (child->xcpu_count == 100) {
			debugf("Child %d [%d] got 100 XCPUs. Exiting child.\n", child->num, pids[child->num]);
			goto out;
		}

		if (handle_sigreturn(ret) == FALSE)
			goto out;	// Exit the child, things are getting too weird.
	}

	while (shm->exit_reason == STILL_RUNNING) {
		/* If the parent reseeded, we should reflect the latest seed too. */
		if (shm->seed != child->seed) {
			//output(0, "child %d reseeded to %x\n", child->num, child->seed);
			set_seed(child);
		}

		periodic_work();

		/* timestamp, and do the syscall */
		clock_gettime(CLOCK_MONOTONIC, &child->tp);

		ret = random_syscall(child);

		child->op_nr++;

		if (ret == FAIL)
			goto out;

		if (syscalls_todo) {
			if (shm->stats.op_count >= syscalls_todo) {
				shm->exit_reason = EXIT_REACHED_COUNT;
				goto out;
			}
		}
	}

	enable_coredumps();

	/* If we're exiting because we tainted, wait here for it to be done. */
	while (shm->postmortem_in_progress == TRUE) {
		/* Make sure the main process is still around. */
		if (pid_alive(mainpid) == FALSE)
			goto out;

		usleep(1);
	}

out:
	shutdown_child_logging(child);

	debugf("child %d %d exiting.\n", childno, getpid());
}

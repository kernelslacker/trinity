#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <time.h>

#include "child.h"
#include "debug.h"
#include "fd-event.h"
#include "kcov.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"

static void handle_child(int childno, pid_t childpid, int childstatus);
static void replace_child(int childno);

/* Parent-local array of /proc/<pid>/stat file handles, indexed by childno.
 * Kept out of shared memory so children's stray writes can't corrupt them. */
static FILE **pidstatfiles;

/*
 * Parent-local tracking of slots whose former occupant is in the kernel
 * as an unkillable D-state task.  We have already cleared the pid slot
 * (via reap_child), but the kernel may still wake the task to finish its
 * syscall and let it write back into our shared childdata.  If we hand
 * the slot to a freshly-forked replacement child before the kernel has
 * fully torn the zombie down, those late writes corrupt fields the new
 * child owns (local_op_count, tp, fd_event_ring head/tail, etc.).
 *
 * Two observed corruption cases trace back to exactly this race:
 *   1. local_op_count appearing with bit 58 set ("Ran 288230376159883121
 *      syscalls"), which is the new child's small counter ORed with a
 *      stale write from the post-reap zombie.
 *   2. fd_event_ring contents containing a non-canonical pointer
 *      0x9c000000890000 that segfaulted fd_event_drain — a half-written
 *      ring index from a ghost producer that no longer existed by the
 *      time the parent looked.
 *
 * zombie_pids[childno] holds the pid we are still waiting on, or
 * EMPTY_PIDSLOT if the slot is not in zombie-pending state.
 * zombie_since[childno] is the CLOCK_MONOTONIC second at which we
 * registered the zombie, used to bound the wait.
 */
static pid_t *zombie_pids;
static time_t *zombie_since;

/* If the kernel still hasn't released a zombie task after this long,
 * something is badly wrong (likely a kernel bug worth investigating).
 * We log loudly and reuse the slot anyway, accepting a possible
 * one-shot corruption in exchange for not stalling fuzzing forever. */
#define ZOMBIE_REAP_TIMEOUT_SEC 300

static unsigned long hiscore = 0;

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * also check the pids for sanity.
 */
static int shm_is_corrupt(void)
{
	unsigned int i;

	unsigned long current_previous_op_count = __atomic_load_n(&shm->stats.previous_op_count, __ATOMIC_RELAXED);
	unsigned long current_op_count = __atomic_load_n(&shm->stats.op_count, __ATOMIC_RELAXED);

	if (current_op_count < current_previous_op_count) {
		output(0, "Execcount went backwards! (old:%lu new:%lu):\n",
			current_previous_op_count, current_op_count);
		panic(EXIT_SHM_CORRUPTION);
		return true;
	}
	__atomic_store_n(&shm->stats.previous_op_count, current_op_count, __ATOMIC_RELAXED);

	for_each_child(i) {
		struct childdata *child;
		pid_t pid;

		if (children == NULL)
			return true;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (child == NULL)
			continue;
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == false) {
			static bool once = false;

			if (once != false)
				return true;

			output(0, "Sanity check failed! Found pid %d at pidslot %u!\n", pid, i);

			dump_childnos();

			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING)
				panic(EXIT_PID_OUT_OF_RANGE);
			dump_childdata(child);
			once = true;
			return true;
		}
	}

	return false;
}

/*
 * reap_child: Remove all references to a running child.
 *
 * This can get called from two possible places.
 * 1. From reap_dead_kids if it finds reference to a pid that no longer exists.
 * 2. From handle_child() if it gets a SIGBUS or SIGSTOP from the child,
 *    or if it dies from natural causes.
 */
void reap_child(struct childdata *child, int childno)
{
	pid_t pid;

	if (child == NULL)
		return;
	/* Don't reap a child again */
	pid = __atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE);
	if (pid == EMPTY_PIDSLOT)
		return;
	child->tp = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	bust_lock(&child->syscall.lock);

	/* Flush any unbatched per-child syscall count into the shared total
	 * so it isn't lost when the child slot is recycled. */
	{
		unsigned long local = __atomic_load_n(&child->local_op_count,
						      __ATOMIC_RELAXED);
		if (local > 0) {
			__atomic_add_fetch(&shm->stats.op_count, local,
					   __ATOMIC_RELAXED);
			__atomic_store_n(&child->local_op_count, 0,
					 __ATOMIC_RELAXED);
		}
	}

	unsigned int cur;
	do {
		cur = __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED);
		if (cur == 0)
			break;
	} while (!__atomic_compare_exchange_n(&shm->running_childs, &cur, cur - 1,
					       0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	__atomic_store_n(&pids[childno], EMPTY_PIDSLOT, __ATOMIC_RELEASE);

	/* Catch the SIGKILL'd-child case where inode_spewer_cleanup()
	 * never ran in the child.  No-op when the dir doesn't exist. */
	inode_spewer_reap(pid);
}

/* Make sure there's no dead kids lying around.
 * We need to do this in case the oom killer has been killing them,
 * otherwise we end up stuck with no child processes.
 */
static void reap_dead_kids(void)
{
	unsigned int i;
	unsigned int reaped = 0;

	if (children == NULL)
		return;

	for_each_child(i) {
		pid_t pid, wpid;
		int childstatus;

		pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == false)
			continue;

		if (pid_alive(pid) == false) {
			if (errno == ESRCH) {
				/* pid_alive treats zombies as not-alive so check_lock
				 * can release locks held by dying children.  A zombie
				 * still has an exit status to harvest — try waitpid
				 * first so we route through handle_child like a normal
				 * exit, instead of silently dropping the status and
				 * leaking the zombie task struct. */
				wpid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
				if (wpid > 0) {
					handle_child(i, wpid, childstatus);
					continue;
				}
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				reap_child(children[i], i);
				reaped++;
			} else {
				output(0, "problem checking on pid %u (%d:%s)\n", pid, errno, strerror(errno));
			}
			continue;
		}

		wpid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		handle_child(i, wpid, childstatus);

		if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
			return;
	}

	if (reaped != 0)
		output(0, "Reaped %d dead children\n", reaped);
}

static void kill_all_kids(void)
{
	unsigned int i;
	int children_seen = 0;

	__atomic_store_n(&shm->spawn_no_more, true, __ATOMIC_RELEASE);

	reap_dead_kids();

	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
		return;

	/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
	for_each_child(i) {
		pid_t pid;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == false)
			continue;

		if (pid_alive(pid) == true) {
			kill_pid(pid);
			children_seen++;
		} else {
			/* check we don't have anything stale in the pidlist */
			if (errno == ESRCH)
				reap_child(children[i], i);
		}
	}

	if (children_seen == 0)
		__atomic_store_n(&shm->running_childs, 0, __ATOMIC_RELAXED);

	/* Check that no dead children hold locks.  Bound the loop: a child
	 * stuck in D-state can hold a lock indefinitely; after 10 iterations
	 * force-bust any remaining locks so we don't spin forever. */
	for (i = 0; check_all_locks() == true && i < 10; i++)
		reap_dead_kids();
	if (check_all_locks() == true) {
		for_each_child(i)
			bust_lock(&children[i]->syscall.lock);
		bust_lock(&shm->syscalltable_lock);
		bust_lock(&shm->objlock);
	}
}


/* if the first arg was an fd, find out which one it was.
 * Call with syscallrecord lock held. */
bool check_if_fd(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int fd;

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL)
		return false;

	if (!is_typed_fdarg(entry->argtype[0])) {
		switch (entry->argtype[0]) {
		case ARG_FD:
		case ARG_SOCKETINFO:
			break;
		default:
			return false;
		}
	}

	/* in the SOCKETINFO case, post syscall, a1 is actually the fd,
	 * not the socketinfo.  In ARG_FD a1=fd.
	 */
	fd = rec->a1;

	/* if it's out of range, it's not going to be valid. */
	if (fd > max_files_rlimit.rlim_cur)
		return false;

	return true;
}

/*
 * This is only ever used by the main process, so we cache the FILE ptr
 * for each child there, to save having to constantly reopen it.
 */
static FILE * open_child_pidstat(pid_t target)
{
	FILE *fp;
	char filename[80];

	snprintf(filename, sizeof(filename), "/proc/%d/stat", target);

	fp = fopen(filename, "r");

	return fp;
}

static char get_pid_state(int childno)
{
	size_t n = 0;
	char *line = NULL;
	pid_t pid;
	char state = '?';
	char procname[100];
	FILE *fp;

	if (getpid() != mainpid)
		BUG("get_pid_state can only be called from main!\n");

	fp = pidstatfiles[childno];
	if (fp == NULL)
		return '?';

	fseek(fp, 0L, SEEK_SET);
	fflush(fp);

	if (getline(&line, &n, fp) != -1)
		sscanf(line, "%d %99s %c", &pid, procname, &state);

	free(line);
	return state;
}

static void dump_pid_stack(int pid)
{
	FILE *fp;
	char filename[80];

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return;

	size_t n = 0;
	char *line = NULL;

	while (!(feof(fp))) {
		if (getline(&line, &n, fp) != -1) {
			output(0, "pid %d stack: %s", pid, line);
		} else {
			if (errno != EAGAIN)
				output(0, "Error reading /proc/%d/stack :%s\n", pid, strerror(errno));
			free(line);
			fclose(fp);
			return;
		}
	}
	free(line);
	output(0, "------------------------------------------------\n");

	fclose(fp);
}

static void dump_pid_syscall(int pid)
{
	FILE *fp;
	char filename[80];
	char buf[256];

	snprintf(filename, sizeof(filename), "/proc/%d/syscall", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return;

	if (fgets(buf, sizeof(buf), fp) != NULL)
		output(0, "pid %d syscall: %s", pid, buf);

	fclose(fp);
}

static void stuck_syscall_info(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	unsigned int callno;
	char fdstr[20];
	pid_t pid;
	bool do32;
	char state;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	if (shm->debug == false)
		return;

	rec = &child->syscall;

	if (trylock(&rec->lock) == false)
		return;

	do32 = rec->do32bit;
	callno = rec->nr;

	memset(fdstr, 0, sizeof(fdstr));

	state = rec->state;

	/* we can only be 'stuck' if we're still doing the syscall. */
	if (state == BEFORE) {
		if (check_if_fd(rec) == true) {
			snprintf(fdstr, sizeof(fdstr), "(fd = %u)", (unsigned int) rec->a1);
			child->fd_lifetime = 0;
			/* Remove the bad fd from the object pool so it
			 * won't be handed out again. */
			remove_object_by_fd((int) rec->a1);
		}
	}

	unlock(&rec->lock);

	output(0, "child %d (pid %u. state:%d) Stuck in syscall %d:%s%s%s.\n",
		childno, pid, state, callno,
		print_syscall_name(callno, do32),
		do32 ? " (32bit)" : "",
		fdstr);
	if (state >= BEFORE)
		dump_pid_stack(pid);
}

/*
 * Move a slot into zombie-pending state.  The child is unkillable
 * (D-state) and we have given up trying to make it die, but the kernel
 * still owns the task struct and may run it again.  Clear the slot so
 * stats stay sensible, but do NOT spawn a replacement: we have to wait
 * until waitpid confirms the kernel released the task, otherwise the
 * zombie's last writes will land in the replacement child's childdata.
 */
static void register_zombie_slot(int childno, pid_t pid)
{
	struct timespec now;
	pid_t wpid;

	/* Fast path: it's not uncommon for the kernel to release a
	 * transient D-state task between our kill loop giving up and
	 * us reaching this function.  A non-blocking waitpid here
	 * tells us if the task is already gone — if so, skip the whole
	 * deferral machinery and just reap+replace immediately and
	 * silently.  Saves the unkillable-log + stack/syscall dump +
	 * zombie_pids[] bookkeeping that would otherwise fire and then
	 * unwind on the very next process_zombie_pending() pass. */
	wpid = waitpid(pid, NULL, WNOHANG);
	if (wpid == pid || (wpid == -1 && errno == ECHILD)) {
		if (pidstatfiles[childno]) {
			fclose(pidstatfiles[childno]);
			pidstatfiles[childno] = NULL;
		}
		reap_child(children[childno], childno);
		replace_child(childno);
		__atomic_add_fetch(&shm->stats.zombies_reaped, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	output(0, "child %d (pid %u) unkillable, deferring slot reuse "
		"until kernel releases the D-state task.\n",
		childno, pid);
	dump_pid_stack(pid);
	dump_pid_syscall(pid);

	if (pidstatfiles[childno]) {
		fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
	}

	reap_child(children[childno], childno);

	clock_gettime(CLOCK_MONOTONIC, &now);
	zombie_pids[childno] = pid;
	zombie_since[childno] = now.tv_sec;
	__atomic_add_fetch(&shm->stats.zombie_slots_pending, 1, __ATOMIC_RELAXED);
}

/*
 * Walk the zombie-pending slots and try to retire each one.
 * waitpid(WNOHANG) returns the pid once the kernel has fully torn down
 * the task — at that point no further writes to the slot are possible
 * and we can safely spawn a replacement.  If the wait times out
 * (ZOMBIE_REAP_TIMEOUT_SEC), log loudly and reuse the slot anyway:
 * indefinite throughput loss is worse than one possible corruption.
 */
static void process_zombie_pending(void)
{
	struct timespec now;
	unsigned int i;

	if (zombie_pids == NULL)
		return;

	if (__atomic_load_n(&shm->stats.zombie_slots_pending,
			    __ATOMIC_RELAXED) == 0)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	for_each_child(i) {
		pid_t pid = zombie_pids[i];
		pid_t wpid;
		bool retire = false;
		bool timed_out = false;

		if (pid == EMPTY_PIDSLOT)
			continue;

		wpid = waitpid(pid, NULL, WNOHANG);
		if (wpid == pid) {
			retire = true;
		} else if (wpid == -1 && errno == ECHILD) {
			/* Kernel has no record of this pid as our child
			 * — it's gone (already reaped or never existed in
			 * a way we can wait on).  Safe to reuse the slot. */
			retire = true;
		} else if ((now.tv_sec - zombie_since[i]) >= ZOMBIE_REAP_TIMEOUT_SEC) {
			retire = true;
			timed_out = true;
		}

		if (!retire)
			continue;

		if (timed_out) {
			output(0, "child %d zombie (pid %u) still pending after "
				"%d seconds — forcing slot reuse. Kernel may be "
				"buggy; investigate the D-state task manually.\n",
				i, pid, ZOMBIE_REAP_TIMEOUT_SEC);
			__atomic_add_fetch(&shm->stats.zombies_timed_out, 1,
					   __ATOMIC_RELAXED);
		} else {
			long elapsed = (long)(now.tv_sec - zombie_since[i]);
			/* Only report when the kernel actually held the
			 * zombie around long enough to be operationally
			 * interesting.  Sub-second hold times are normal
			 * when the D-state was transient and the kernel
			 * reaped between our kill loop giving up and the
			 * next process_zombie_pending() pass — silent
			 * stats counter is enough. */
			if (elapsed >= 1)
				output(0, "child %d zombie (pid %u) finally "
					"released by kernel after %ld seconds; "
					"reusing slot.\n", i, pid, elapsed);
			__atomic_add_fetch(&shm->stats.zombies_reaped, 1,
					   __ATOMIC_RELAXED);
		}

		zombie_pids[i] = EMPTY_PIDSLOT;
		zombie_since[i] = 0;
		__atomic_sub_fetch(&shm->stats.zombie_slots_pending, 1,
				   __ATOMIC_RELAXED);

		replace_child(i);
	}
}

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static bool is_child_making_progress(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	struct timespec tp;
	time_t diff, old, now;
	pid_t pid;
	char state;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	if (pid == EMPTY_PIDSLOT)
		return true;
	// bail if we've not done a syscall yet, we probably just haven't
	// been scheduled due to other pids hogging the cpu
	rec = &child->syscall;
	if (trylock(&rec->lock) == false)
		return true;

	if (rec->state < BEFORE) {
		unlock(&rec->lock);
		return true;
	}
	unlock(&rec->lock);

	old = child->tp.tv_sec;

	/* haven't done anything yet. */
	if (old == 0)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	now = tp.tv_sec;

	if (old > now)
		diff = old - now;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return true;

	/* After too many kill attempts, the child is truly stuck (D state,
	 * frozen cgroup, etc).  Hand the slot to the zombie-pending list:
	 * we will reuse it once waitpid confirms the kernel released the
	 * task.  Reusing immediately would let the still-alive D-state task
	 * write into the replacement child's childdata as soon as it wakes.
	 *
	 * This check must come before the D-state early return below,
	 * otherwise unkillable D-state children never get reaped. */
	if (child->kill_count >= 10) {
		register_zombie_slot(childno, pid);
		return true;
	}

	/* if we're blocked in uninteruptible sleep, SIGKILL won't help.
	 * Still increment kill_count so we eventually reap the slot. */
	state = get_pid_state(childno);
	if (state == 'D') {
		child->kill_count++;
		return false;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff >= 30) {
		stuck_syscall_info(child, childno);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				childno, pid);
		child->kill_count++;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return false;

	debugf("sending another SIGKILL to child %u (pid:%u). [kill count:%u] [diff:%lu]\n",
		childno, pid, child->kill_count, diff);
	child->kill_count++;
	kill_pid(pid);

	return false;
}

/*
 * If we call this, all children are stalled. Randomly kill a few.
 */
static void stall_genocide(void)
{
	unsigned int killed = 0;
	unsigned int i;

	for_each_child(i) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (RAND_BOOL()) {
			if (pid_alive(pid) == true) {
				kill_pid(pid);
				killed++;
			}
		}
		if (killed == (max_children / 4))
			break;
	}
}

static bool spawn_child(int childno)
{
	struct childdata *child;
	int pid = 0;
	int nr_fds;

	if (children == NULL)
		return false;

	child = children[childno];

	/* a new child means a new seed, or the new child
	 * will do the same syscalls as the one in the child it's replacing.
	 * (special case startup, or we reseed unnecessarily)
	 */
	if (__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))
		reseed();

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	nr_fds = get_num_fds();
	if ((max_files_rlimit.rlim_cur - nr_fds) < 3) {
		outputerr("current number of fd: %d, please consider ulimit -n xxx to increase fd limition\n", nr_fds);
		panic(EXIT_NO_FDS);
		return false;
	}

	fflush(stdout);
	pid = fork();

	if (pid == 0) {
		child_process(child, childno);
		_exit(EXIT_SUCCESS);
	} else {
		if (pid == -1) {
			debugf("Couldn't fork a new child in pidslot %d. errno:%s\n",
					childno, strerror(errno));
			return false;
		}
	}

	/* Child won't get out of init_child until we write the pid */
	__atomic_store_n(&pids[childno], pid, __ATOMIC_RELEASE);
	if (pidstatfiles[childno]) {
		fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
	}
	pidstatfiles[childno] = open_child_pidstat(pid);
	__atomic_add_fetch(&shm->running_childs, 1, __ATOMIC_RELAXED);

	debugf("Created child %d (pid:%d) [total:%u/%u]\n",
		childno, pid,
		__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED),
		max_children);
	return true;
}

static void replace_child(int childno)
{
	unsigned int retries = 0;

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		return;

	while (spawn_child(childno) == false) {
		if (++retries >= 10) {
			outputerr("Failed to replace child %d after %u fork attempts, giving up.\n",
				childno, retries);
			return;
		}
		usleep(retries * 10000);
	}
}

/* Generate children*/
static void fork_children(void)
{
	while (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) < max_children) {
		int childno;

		if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
			return;

		/* Find a space for it in the pid map */
		childno = find_childno(EMPTY_PIDSLOT);
		if (childno == CHILD_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_childnos();
			exit(EXIT_LOST_CHILD);
		}

		if (spawn_child(childno) == false) {
			outputerr("Couldn't fork initial children!\n");
			panic(EXIT_FORK_FAILURE);
			exit(EXIT_FORK_FAILURE);
		}

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			return;
	}
	__atomic_store_n(&shm->ready, true, __ATOMIC_RELEASE);
}

static void handle_childsig(int childno, int childstatus, bool stop)
{
	int __sig;
	pid_t pid = __atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE);

	if (children == NULL)
		return;

	if (stop == true)
		__sig = WSTOPSIG(childstatus);
	else
		__sig = WTERMSIG(childstatus);

	switch (__sig) {
	case SIGSTOP:
		if (stop != true)
			return;
		debugf("Sending PTRACE_DETACH (and then KILL)\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		kill_pid(pid);
		/* Reap the killed child to avoid leaving a zombie — once
		 * reap_child() clears the pid slot nobody will waitpid() it. */
		waitpid(pid, NULL, WNOHANG);
		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
		reap_child(children[childno], childno);
		replace_child(childno);
		return;

	case SIGALRM:
		debugf("got a alarm signal from child %d (pid %d)\n", childno, pid);
		reap_child(children[childno], childno);
		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
		replace_child(childno);
		return;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
	case SIGILL:
		if (stop == true)
			debugf("Child %d (pid %d) was stopped by %s\n",
					childno, pid, strsignal(WSTOPSIG(childstatus)));
		else {
			debugf("got a signal from child %d (pid %d) (%s)\n",
					childno, pid, strsignal(WTERMSIG(childstatus)));
		}
		reap_child(children[childno], childno);
		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;

		replace_child(childno);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d).\n", pid, __sig);
		} else if (stop == true) {
			debugf("Child %d was stopped by unhandled signal (%s).\n", pid, strsignal(WSTOPSIG(childstatus)));
		} else {
			debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
		}

		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
		if (stop == false) {
			reap_child(children[childno], childno);
			replace_child(childno);
		}
		return;
	}
}

static void handle_child(int childno, pid_t childpid, int childstatus)
{
	switch (childpid) {
	case 0:
		break;

	case -1:
		break;

	default:
		if (children == NULL)
			break;

		if (WIFEXITED(childstatus)) {
			struct childdata *child = children[childno];

			debugf("Child %d (pid:%u) exited after %ld operations.\n",
				childno, childpid, child->op_nr);
			reap_child(children[childno], childno);
			if (pidstatfiles[childno] != NULL)
				fclose(pidstatfiles[childno]);
			pidstatfiles[childno] = NULL;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			handle_childsig(childno, childstatus, false);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childno, childstatus, true);
		} else if (WIFCONTINUED(childstatus)) {
			break;
		}
	}
}

static void handle_children(void)
{
	unsigned int i;
	int collected = 0;

	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
		return;

	if (children == NULL)
		return;

	for_each_child(i) {
		int childstatus;
		pid_t pid;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);

		if (pid == EMPTY_PIDSLOT)
			continue;

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid > 0)
			collected++;
		handle_child(i, pid, childstatus);
	}

	/* If nothing happened, sleep briefly to avoid busy-looping. */
	if (collected == 0)
		usleep(25000);
}

static unsigned int stall_count;

static void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		if (is_child_making_progress(child, i) == false)
			stall_count++;

		if (child->op_nr > hiscore)
			hiscore = child->op_nr;
	}

	if (stall_count == __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED))
		stall_genocide();
}

unsigned long sum_local_op_counts(void)
{
	unsigned long sum = 0;
	unsigned int i;

	if (children == NULL)
		return 0;

	for_each_child(i) {
		struct childdata *child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		unsigned long count;

		if (child == NULL)
			continue;

		count = __atomic_load_n(&child->local_op_count, __ATOMIC_RELAXED);
		/* The child flushes and zeroes local_op_count once it hits
		 * LOCAL_OP_FLUSH_BATCH, so a higher value can only come from
		 * a stray write — most likely a former occupant of this slot
		 * that the kernel woke up after we reaped it.  Cap the value
		 * we report, zero it so we don't keep tripping on the same
		 * corruption, and log a stat for the operator. */
		if (count >= LOCAL_OP_FLUSH_BATCH) {
			output(0, "child %u local_op_count corrupted (0x%lx), "
				"capping. Possible stray write into recycled slot.\n",
				i, count);
			__atomic_store_n(&child->local_op_count, 0, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.local_op_count_corrupted, 1,
					   __ATOMIC_RELAXED);
			count = LOCAL_OP_FLUSH_BATCH;
		}
		sum += count;
	}
	return sum;
}

static void print_stats(void)
{
	unsigned long op_count = __atomic_load_n(&shm->stats.op_count, __ATOMIC_RELAXED) +
				 sum_local_op_counts();

	if (op_count > 1) {
		static unsigned long lastcount = 0;
		static struct timespec last_tp = { 0 };

		if (op_count - lastcount > 10000) {
			struct timespec now;
			unsigned long rate = 0;
			char stalltxt[32] = "";

			clock_gettime(CLOCK_MONOTONIC, &now);
			if (last_tp.tv_sec > 0) {
				double elapsed = (now.tv_sec - last_tp.tv_sec) +
					(now.tv_nsec - last_tp.tv_nsec) / 1e9;
				if (elapsed > 0.01)
					rate = (unsigned long)((op_count - lastcount) / elapsed);
			}
			last_tp = now;

			if (stall_count > 0 && stall_count < 10000)
				snprintf(stalltxt, sizeof(stalltxt), " STALLED:%u", stall_count);

			if (kcov_shm != NULL) {
				static unsigned long last_edges = 0;
				unsigned long edges = kcov_shm->edges_found;
				long delta = edges - last_edges;

				output(0, "%ld iterations. [F:%ld S:%ld HI:%ld%s] %lu/sec  KCOV: [%lu edges, %+ld]\n",
					op_count,
					__atomic_load_n(&shm->stats.failures, __ATOMIC_RELAXED),
					__atomic_load_n(&shm->stats.successes, __ATOMIC_RELAXED),
					hiscore,
					stall_count ? stalltxt : "",
					rate,
					edges, last_edges > 0 ? delta : 0);
				last_edges = edges;
			} else {
				output(0, "%ld iterations. [F:%ld S:%ld HI:%ld%s] %lu/sec\n",
					op_count,
					__atomic_load_n(&shm->stats.failures, __ATOMIC_RELAXED),
					__atomic_load_n(&shm->stats.successes, __ATOMIC_RELAXED),
					hiscore,
					stall_count ? stalltxt : "",
					rate);
			}
			lastcount = op_count;
		}
	}
}

static bool handled_taint = false;

static void taint_check(void)
{
	if (handled_taint == true)
		return;

	if (is_tainted() == true) {
		tainted_postmortem();
		handled_taint = true;
	}
}

void main_loop(void)
{
	struct timespec epoch_start;
	unsigned int i;

	pidstatfiles = zmalloc(max_children * sizeof(FILE *));
	zombie_pids = zmalloc(max_children * sizeof(pid_t));
	zombie_since = zmalloc(max_children * sizeof(time_t));
	for_each_child(i)
		zombie_pids[i] = EMPTY_PIDSLOT;

	if (epoch_timeout)
		clock_gettime(CLOCK_MONOTONIC, &epoch_start);

	fork_children();

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {

		handle_children();

		/* Drain fd events from all children's ring buffers.
		 * This processes dup/close events that children couldn't
		 * apply directly (COW heap prevents global pool mutation). */
		fd_event_drain_all();

		taint_check();

		if (shm_is_corrupt() == true)
			goto corrupt;

		while (check_all_locks() == true) {
			reap_dead_kids();
			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_REACHED_COUNT)
				kill_all_kids();
		}

		if (syscalls_todo && (__atomic_load_n(&shm->stats.op_count, __ATOMIC_RELAXED) >= syscalls_todo)) {
			output(0, "Reached limit %lu. Telling children to exit.\n", syscalls_todo);
			panic(EXIT_REACHED_COUNT);
		}

		if (epoch_iterations && (__atomic_load_n(&shm->stats.op_count, __ATOMIC_RELAXED) >= epoch_iterations)) {
			output(0, "Epoch iteration limit %lu reached.\n", epoch_iterations);
			panic(EXIT_EPOCH_DONE);
		}

		if (epoch_timeout) {
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if ((unsigned int)(now.tv_sec - epoch_start.tv_sec) >= epoch_timeout) {
				output(0, "Epoch timeout %u seconds reached.\n", epoch_timeout);
				panic(EXIT_EPOCH_DONE);
			}
		}

		check_children_progressing();

		process_zombie_pending();

		print_stats();

		/* This should never happen, but just to catch corner cases, like if
		 * fork() failed when we tried to replace a child.
		 */
		if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) < max_children)
			fork_children();
	}

	/* if the pid map is corrupt, we can't trust that we'll
	 * ever successfully finish pidmap_empty, so skip it */
	if ((__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_LOST_CHILD) ||
	    (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_SHM_CORRUPTION))
		goto dont_wait;

	handle_children();

	/* Are there still children running ? */
	while (pidmap_empty() == false) {
		static unsigned int last = 0;
		static unsigned int shutdown_attempts = 0;

		if (++shutdown_attempts > 10) {
			output(0, "Gave up waiting for children after %u attempts.\n",
				shutdown_attempts);
			panic(EXIT_TIMED_OUT);
			break;
		}

		if (last != __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED)) {
			last = __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED);

			output(0, "exit_reason=%d, but %u children still running.\n",
				__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED),
				__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED));
		}

		/* Wait for all the children to exit. */
		while (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) > 0) {
			taint_check();

			handle_children();
			kill_all_kids();
			/* Give children a chance to exit before retrying. */
			sleep(1);
		}
		reap_dead_kids();
	}

corrupt:
	kill_all_kids();

dont_wait:
	output(0, "Bailing main loop because %s.\n",
		decode_exit(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED)));
}


/*
 * Reset shared state between epochs.  Coverage data (kcov bitmap,
 * cmp_hints, minicorpus, edgepair) is deliberately preserved so
 * that coverage accumulates across epoch boundaries.
 */
void reset_epoch_state(void)
{
	unsigned int i;

	__atomic_store_n(&shm->exit_reason, STILL_RUNNING, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->spawn_no_more, false, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->ready, false, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->running_childs, 0, __ATOMIC_RELAXED);

	shm->stats.op_count = 0;
	shm->stats.previous_op_count = 0;

	for_each_child(i) {
		__atomic_store_n(&pids[i], EMPTY_PIDSLOT, __ATOMIC_RELAXED);
		clean_childdata(children[i]);
		fd_event_ring_init(children[i]->fd_event_ring);
	}

	reseed();
}

/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	__atomic_store_n(&shm->spawn_no_more, true, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->exit_reason, reason, __ATOMIC_RELAXED);
}

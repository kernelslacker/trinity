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
#include "cmp_hints.h"
#include "debug.h"
#include "edgepair_ring.h"
#include "fd-event.h"
#include "healer.h"
#include "healer_ring.h"
#include "kcov.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "random.h"
#include "self_cgroup.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
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
 * child owns (tp, fd_event_ring head/tail, etc.).
 *
 * One observed corruption case traces back to exactly this race:
 * fd_event_ring contents containing a non-canonical pointer
 * 0x9c000000890000 that segfaulted fd_event_drain — a half-written
 * ring index from a ghost producer that no longer existed by the time
 * the parent looked.
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

/*
 * Detect a fork-die-respawn busy-loop: when something corrupts shm such
 * that freshly-spawned children trip a startup check (e.g.
 * EXIT_SHM_CORRUPTION at child.c:613 or EXIT_REPARENT_PROBLEM at
 * child.c:795) and exit within milliseconds of being forked, the parent
 * enters a perpetual reap-replace cycle.  The existing
 * consecutive_fork_failures cap in fork_children() only counts
 * spawn_child() returning false (fork() itself failing); it does NOT
 * trigger when fork SUCCEEDS but the child dies fast on startup.
 *
 * Track the spawn time of each slot, then maintain a small ring of
 * recent reap outcomes.  When the ring fills with WIFEXITED-with-non-
 * SUCCESS reaps that all happened within FAST_DIE_LIFETIME_THRESHOLD_S
 * of their fork, bail loudly instead of busy-looping forever.  Signal
 * deaths (SIGSEGV in the fuzz target, SIGABRT, etc.) are normal during
 * fuzzing and are explicitly excluded from the bail trigger via the
 * exit_status > 0 gate (signal deaths are encoded as negative below).
 */
#define FAST_DIE_RING_SIZE 16
#define FAST_DIE_LIFETIME_THRESHOLD_S 2

struct reap_record {
	time_t reaped_at;
	time_t lifetime;	/* reaped_at - spawn_times[childno] */
	int    exit_status;	/* WEXITSTATUS, or -WTERMSIG for signal deaths */
	int    childno;
};

static time_t *spawn_times;
static struct reap_record reap_ring[FAST_DIE_RING_SIZE];
static unsigned int reap_ring_head;
static unsigned int reap_ring_count;

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

	/* Both op_count and previous_op_count are now parent-private (live
	 * in the stats_aggregate, not in shm).  A wild kernel write through
	 * a child syscall arg cannot reach either field, so this regression
	 * check no longer fires for that scribble class.  Kept as defence
	 * in depth: it still trips on a parent-side bug that decrements
	 * op_count or on a stale read of either field, both of which would
	 * be real corruption signals. */
	unsigned long current_previous_op_count = parent_stats.previous_op_count;
	unsigned long current_op_count = parent_stats.op_count;

	if (current_op_count < current_previous_op_count) {
		output(0, "Execcount went backwards! (old:%lu new:%lu):\n",
			current_previous_op_count, current_op_count);
		dump_pids_page_state();
		panic(EXIT_SHM_CORRUPTION);
		return true;
	}
	parent_stats.previous_op_count = current_op_count;

	/* Mirror page integrity check: republish-time we wrote
	 * parent_stats.op_count into shm_published->fleet_op_count and then
	 * mprotected the page PROT_READ.  A read-back here that disagrees
	 * with the canonical aggregate means somebody found a write window
	 * (a freeze gap, or somehow a wild write succeeded against the
	 * mprotected page).  Log + bump rather than panic -- the canonical
	 * value is still trustworthy. */
	if (shm_published != NULL &&
	    shm_published->fleet_op_count != current_op_count) {
		output(0, "shm_published mirror: fleet_op_count=%lu, "
			  "aggregate=%lu (mirror scribbled?)\n",
			  shm_published->fleet_op_count, current_op_count);
		parent_stats.shm_published_corrupt++;
	}

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
			dump_pids_page_state();

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
	force_bust_lock(&child->syscall.lock);

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
	unsigned int drained;

	if (children == NULL)
		return;

	/* First pass: drain every reapable child via wait4(-1).
	 *
	 * SIGCHLD is edge-triggered: when N children die between handler
	 * invocations the kernel still queues only one signal, so a reap
	 * path that reaps one zombie at a time falls behind any time more
	 * than one child dies in the same tick.  The previous per-slot
	 * waitpid() walk was also vulnerable to drift between pids[] and
	 * kernel reality (stale slot, racy spawn) — a zombie whose slot
	 * had already been cleared by some other path stayed unreaped
	 * indefinitely because no slot pointed at it.
	 *
	 * Under a crash storm (e.g. a post_handler_corrupt_ptr scribble
	 * round killing children faster than we replace them) that drift
	 * has been observed to leave 22 <defunct> children parked while
	 * only one slot was actually fuzzing — net throughput ~1/16th of
	 * nominal, KCOV edge growth flatlined.
	 *
	 * wait4(-1) reaps whatever the kernel has, regardless of our
	 * bookkeeping.  Loop with WNOHANG until it returns 0 (nothing more
	 * pending) or -1 (ECHILD, no children at all — defensive; should
	 * not happen while main is fuzzing).  Bound to a sanity cap so a
	 * pathological case can't spin here forever. */
	for (drained = 0; drained < 64; drained++) {
		pid_t wpid;
		int childstatus;
		int childno;

		wpid = wait4(-1, &childstatus, WNOHANG | WUNTRACED | WCONTINUED, NULL);
		if (wpid <= 0)
			break;

		childno = find_childno(wpid);
		if (childno != CHILD_NOT_FOUND) {
			handle_child(childno, wpid, childstatus);
		} else {
			/* Reaped a pid we no longer track — its slot was
			 * already cleared by some earlier path but the
			 * kernel hadn't released the task struct yet.
			 * Nothing more to do; kernel side is now clean. */
			output(1, "reap_dead_kids: reaped untracked pid %d (status 0x%x)\n",
				wpid, childstatus);
		}
		reaped++;
	}

	/* Second pass: catch slots whose pid is gone but our bookkeeping
	 * never noticed — e.g. the wait4 drain above reaped a slotted pid
	 * via the untracked path, or the child died without routing
	 * through our normal exit accounting.  Without this the slot
	 * stays occupied forever and the spawn path can't refill it. */
	for_each_child(i) {
		pid_t pid;

		pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);
		if (pid == EMPTY_PIDSLOT)
			continue;
		if (pid_is_valid(pid) == false)
			continue;

		if (kill(pid, 0) != 0 && errno == ESRCH) {
			output(0, "pid %u has disappeared. Reaping.\n", pid);
			reap_child(children[i], i);
			reaped++;
		}
	}

	if (reaped != 0)
		output(1, "Reaped %d dead children\n", reaped);
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
			force_bust_lock(&children[i]->syscall.lock);
		force_bust_lock(&shm->syscalltable_lock);
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

	if (shm->debug == false)
		return;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

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
			struct childdata *child =
				__atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
			bool from_bug = (child != NULL &&
				__atomic_load_n(&child->hit_bug, __ATOMIC_ACQUIRE));

			if (from_bug) {
				output(0, "child %d zombie (pid %u) still pending "
					"after %d seconds — child hit __BUG() "
					"(\"%s\" at %s:%u) and exited; kernel is "
					"finishing the SIGKILL teardown. Not a "
					"kernel bug.\n",
					i, pid, ZOMBIE_REAP_TIMEOUT_SEC,
					child->bug_text ? child->bug_text : "?",
					child->bug_func ? child->bug_func : "?",
					child->bug_lineno);
			} else {
				output(0, "child %d zombie (pid %u) still pending "
					"after %d seconds — forcing slot reuse. "
					"Possible causes: a D-state task in the "
					"kernel finishing a cancelled syscall, or "
					"a real kernel bug holding the task table "
					"entry.\n",
					i, pid, ZOMBIE_REAP_TIMEOUT_SEC);
			}
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
 * Pick a slot for a freshly-forked child.  A slot is only usable when
 * BOTH the live-pid slot and the zombie-pending slot are empty: a
 * pids[i] == EMPTY_PIDSLOT alone does not mean the kernel has finished
 * tearing down the previous occupant.  If the previous occupant is
 * still in the kernel as a D-state task, handing the slot to a new
 * child lets the dying task's late writes corrupt the new child's
 * childdata (same race shape documented at the top of this file).
 *
 * Returns CHILD_NOT_FOUND when no slot is available; the caller
 * decides whether that means "pid map exhausted" (fatal) or "all empty
 * slots are zombie-pending" (transient, retry once
 * process_zombie_pending() has run).
 */
static int find_free_childno(void)
{
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) != EMPTY_PIDSLOT)
			continue;
		if (zombie_pids[i] != EMPTY_PIDSLOT)
			continue;
		return i;
	}
	return CHILD_NOT_FOUND;
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

	/* Uninterruptible sleep: SIGKILL cannot preempt a D-state task,
	 * but queueing it ensures the kernel delivers it the moment the
	 * task wakes from D and the syscall returns to the signal-check
	 * path.  Without this, kill_count saturates at 10 purely from
	 * passive D-state observations and register_zombie_slot fires
	 * for a task that has never had a SIGKILL pending — letting it
	 * resume execution (and write into childdata) the moment the
	 * kernel finally schedules it.  Pair every kill_count++ with an
	 * actual queued kill so the >= 10 threshold means "we tried." */
	state = get_pid_state(childno);
	if (state == 'D') {
		kill_pid(pid);
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

	/* Wipe any stale spawn timestamp so a slot that fails to spawn
	 * doesn't leave a misleading lifetime in the next reap record. */
	if (spawn_times != NULL)
		spawn_times[childno] = 0;

	/* a new child means a new seed, or the new child
	 * will do the same syscalls as the one in the child it's replacing.
	 * (special case startup, or we reseed unnecessarily)
	 */
	if (__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))
		reseed();

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	/* If this slot is reserved for a dedicated alt op (the first
	 * --alt-op-children=N slots), stamp the assigned op_type now so
	 * the freshly-spawned child reads it out of shared memory before
	 * its dispatch loop runs.  No-op when --alt-op-children is 0. */
	assign_dedicated_alt_op(child, childno);

	nr_fds = get_num_fds();
	if ((max_files_rlimit.rlim_cur - nr_fds) < 3) {
		outputerr("current number of fd: %d, please consider ulimit -n xxx to increase fd limition\n", nr_fds);
		panic(EXIT_NO_FDS);
		return false;
	}

	/* Phase 2 self-cgroup back-pressure: when memory.high is being
	 * crossed, the parent ramps fork_throttle_us up so we slow the
	 * spawn rate ahead of the kernel-side throttle.  Zero in the
	 * common no-pressure path. */
	if (fork_throttle_us > 0)
		usleep(fork_throttle_us);

	fflush(stdout);
	pid = self_cgroup_fork_into_workload();

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
	if (spawn_times != NULL)
		spawn_times[childno] = time(NULL);
	if (pidstatfiles[childno]) {
		fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
	}
	pidstatfiles[childno] = open_child_pidstat(pid);
	unsigned int running = __atomic_add_fetch(&shm->running_childs, 1, __ATOMIC_RELAXED);

	debugf("Created child %d (pid:%d) [total:%u/%u]\n",
		childno, pid,
		running,
		max_children);
	return true;
}

static void replace_child(int childno)
{
	unsigned int retries = 0;

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		return;

	/* Don't replace if the fleet has been halted (e.g. a __BUG fired
	 * in some child and we're now keeping the survivors quiescent so
	 * an operator can gdb-attach for inspection).  The slot stays
	 * empty rather than respawning into a known-corrupt environment. */
	if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
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

/* Dump /proc/self/status so a stuck-fork bail report shows the parent's
 * thread/process accounting (Threads:, FDSize:, etc.) at the moment we
 * gave up.  Useful for triaging whether the kernel-side resource we ran
 * out of was process slots, pid_max, or something else. */
static void dump_proc_self_status(void)
{
	FILE *fp;
	char *line = NULL;
	size_t n = 0;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL)
		return;

	while (getline(&line, &n, fp) != -1)
		outputerr("/proc/self/status: %s", line);

	free(line);
	fclose(fp);
}

/* Generate children*/
static void fork_children(void)
{
	/* Bound the outer respawn loop.  The inner spawn_child retry
	 * already caps per-slot attempts at 10, but if every slot keeps
	 * failing (e.g. the process table is full of orphans the parent
	 * cannot reap) the outer while loop will iterate forever, growing
	 * a silent wedge with no exit, no watchdog fire, and no operator
	 * visibility beyond strace.  Track consecutive failed spawn_child
	 * calls and bail once we cross the threshold; with the 10-100ms
	 * inner backoff this caps the stuck window at roughly a minute. */
	unsigned int consecutive_fork_failures = 0;
	const unsigned int max_consecutive_fork_failures = 1000;

	while (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) < max_children) {
		int childno;

		if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
			return;

		/* Find a space for it in the pid map.  A slot is only
		 * usable when both the live-pid and zombie-pending slots
		 * are empty — see find_free_childno() and the
		 * zombie_pids[] comment at the top of this file. */
		childno = find_free_childno();
		if (childno == CHILD_NOT_FOUND) {
			/* Distinguish a genuinely-full pid map (a fatal
			 * bookkeeping bug) from "every empty slot is in
			 * zombie-pending state" (transient — a future
			 * process_zombie_pending() pass will retire them
			 * and main_loop will call us again). */
			if (find_childno(EMPTY_PIDSLOT) == CHILD_NOT_FOUND) {
				outputerr("## Pid map was full!\n");
				dump_childnos();
				exit(EXIT_LOST_CHILD);
			}
			return;
		}

		{
			unsigned int retries = 0;

			while (spawn_child(childno) == false) {
				consecutive_fork_failures++;
				if (consecutive_fork_failures >= max_consecutive_fork_failures) {
					outputerr("main: fork stuck - %u consecutive spawn failures; bailing (process table likely exhausted)\n",
						consecutive_fork_failures);
					dump_proc_self_status();
					panic(EXIT_FORK_FAILURE);
					return;
				}
				if (++retries >= 10) {
					outputerr("Failed to fork initial child for slot %d after %u attempts, skipping slot.\n",
						childno, retries);
					break;
				}
				usleep(retries * 10000);
			}
			if (retries >= 10)
				continue;
			consecutive_fork_failures = 0;
		}

		/* Per-spawn visibility under -v.  Today only the final
		 * "all children running" state is observable; if a fork
		 * silently no-ops or stalls partway through populating the
		 * pidmap there's no way to tell which slot we got stuck
		 * on.  spawn_child has already published the pid into
		 * pids[childno] by this point. */
		output(1, "forked child %u/%u (pid %d)\n",
			__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED),
			max_children,
			__atomic_load_n(&pids[childno], __ATOMIC_RELAXED));

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
		/* Route through register_zombie_slot rather than reaping the
		 * slot unconditionally.  A bare waitpid(WNOHANG) here often
		 * returns 0 because the kernel hasn't finished tearing down
		 * the SIGKILL'd task; clearing pids[childno] in that window
		 * lets the next slot occupant inherit the dying task's late
		 * writes into childdata (same race shape documented at the
		 * top of this file).  register_zombie_slot's fast path reaps
		 * + replaces immediately when the kernel has already released
		 * the task, and its slow path defers replacement until
		 * process_zombie_pending() observes the zombie gone. */
		register_zombie_slot(childno, pid);
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

static void bail_fast_die_loop(void)
{
	unsigned int i;

	outputerr("FAST-DIE LOOP DETECTED: %u consecutive child reaps with lifetime < %ds and non-SUCCESS exit status. Parent is in a fork-die-respawn busy-loop. Dumping ring...\n",
		FAST_DIE_RING_SIZE, FAST_DIE_LIFETIME_THRESHOLD_S);

	for (i = 0; i < FAST_DIE_RING_SIZE; i++) {
		struct reap_record *r = &reap_ring[i];

		if (r->exit_status > 0 && r->exit_status < NUM_EXIT_REASONS)
			outputerr("  ring[%u]: childno=%d lifetime=%lds exit_status=%d (%s)\n",
				i, r->childno, (long)r->lifetime, r->exit_status,
				decode_exit((enum exit_reasons)r->exit_status));
		else
			outputerr("  ring[%u]: childno=%d lifetime=%lds exit_status=%d\n",
				i, r->childno, (long)r->lifetime, r->exit_status);
	}

	dump_proc_self_status();

	if (shm != NULL) {
		outputerr("shm->exit_reason=%d running_childs=%u buglock.state=0x%lx\n",
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED),
			__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED),
			__atomic_load_n(&shm->buglock.state, __ATOMIC_RELAXED));
		if (pids != NULL) {
			unsigned int j;

			for_each_child(j)
				outputerr("  pids[%u]=%d\n", j,
					__atomic_load_n(&pids[j], __ATOMIC_RELAXED));
			dump_pids_page_state();
		}
	}

	panic(EXIT_SHM_CORRUPTION);
}

static void record_reap(int childno, int childstatus)
{
	struct reap_record *r;
	time_t now = time(NULL);
	time_t lifetime;
	int exit_status;
	unsigned int i;

	if (spawn_times == NULL)
		return;

	if (spawn_times[childno] != 0)
		lifetime = now - spawn_times[childno];
	else
		lifetime = 0;

	if (WIFEXITED(childstatus))
		exit_status = WEXITSTATUS(childstatus);
	else if (WIFSIGNALED(childstatus))
		exit_status = -WTERMSIG(childstatus);
	else
		return;

	r = &reap_ring[reap_ring_head];
	r->reaped_at = now;
	r->lifetime = lifetime;
	r->exit_status = exit_status;
	r->childno = childno;

	reap_ring_head = (reap_ring_head + 1) % FAST_DIE_RING_SIZE;
	if (reap_ring_count < FAST_DIE_RING_SIZE)
		reap_ring_count++;

	if (reap_ring_count < FAST_DIE_RING_SIZE)
		return;

	/* Bail only when EVERY entry is a fast WIFEXITED with non-SUCCESS
	 * status.  Signal-deaths are negative, EXIT_SUCCESS is 0 — both
	 * fail the > 0 gate so a single benign reap clears the bail. */
	for (i = 0; i < FAST_DIE_RING_SIZE; i++) {
		if (reap_ring[i].lifetime >= FAST_DIE_LIFETIME_THRESHOLD_S)
			return;
		if (reap_ring[i].exit_status <= 0)
			return;
	}

	bail_fast_die_loop();
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
			record_reap(childno, childstatus);
			reap_child(children[childno], childno);
			if (pidstatfiles[childno] != NULL)
				fclose(pidstatfiles[childno]);
			pidstatfiles[childno] = NULL;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			record_reap(childno, childstatus);
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

static void print_stats(void)
{
	unsigned long op_count = parent_stats.op_count;

	if (quiet)
		return;

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
				static unsigned long last_cmp_records = 0;
				unsigned long edges = kcov_shm->edges_found;
				unsigned long cmp_records = kcov_shm->cmp_records_collected;
				long delta = edges - last_edges;
				long cmp_delta = cmp_records - last_cmp_records;

				/* cmp_records surfaced alongside edges so cmp-hints
				 * health is visible in out.log without --show-stats.
				 * A run that prints "cmp-hints: snapshot skipped, no
				 * pool changes" for its entire length should also show
				 * cmp_records=0 here, distinguishing "KCOV_TRACE_CMP
				 * produced no records" from "kcov_enable_cmp silently
				 * flipped cmp_capable=false for every child". */
				output(0, "%ld iterations. [HI:%ld%s] %lu/sec  KCOV: [%lu edges, %+ld]  KCOV CMP: [%lu cmp_records, %+ld]\n",
					op_count,
					hiscore,
					stall_count ? stalltxt : "",
					rate,
					edges, last_edges > 0 ? delta : 0,
					cmp_records, last_cmp_records > 0 ? cmp_delta : 0);
				last_edges = edges;
				last_cmp_records = cmp_records;
			} else {
				output(0, "%ld iterations. [HI:%ld%s] %lu/sec\n",
					op_count,
					hiscore,
					stall_count ? stalltxt : "",
					rate);
			}

			/* Per-pool live ratio.  When the explorer pool is empty
			 * (e.g. -C N where N/8 rounds to zero, common with ASAN
			 * configs), drop the explorer half of the line but still
			 * report bandit activity so edge-discovery visibility
			 * isn't lost. */
			static unsigned long last_bandit_edges = 0;
			unsigned long b_cur = __atomic_load_n(
				&shm->stats.bandit_pool_edges_discovered,
				__ATOMIC_RELAXED);
			unsigned long b_delta = b_cur - last_bandit_edges;

			if (explorer_children > 0) {
				static unsigned long last_explorer_edges = 0;
				unsigned long e_cur = __atomic_load_n(
					&shm->stats.explorer_pool_edges_discovered,
					__ATOMIC_RELAXED);
				unsigned long total = e_cur + b_cur;
				unsigned long e_delta = e_cur - last_explorer_edges;
				unsigned int e_share_pct = total > 0 ?
					(unsigned int)(e_cur * 100UL / total) : 0;
				unsigned int b_share_pct = 100U - e_share_pct;

				output(0, "explorer: %u/%u children, %lu edges (%u%%/+%lu)  bandit: %u/%u, %lu edges (%u%%/+%lu)\n",
					explorer_children, max_children,
					e_cur, e_share_pct, e_delta,
					max_children - explorer_children, max_children,
					b_cur, b_share_pct, b_delta);
				last_explorer_edges = e_cur;
			} else {
				output(0, "bandit: %u/%u children, %lu edges (+%lu)\n",
					max_children, max_children,
					b_cur, b_delta);
			}
			last_bandit_edges = b_cur;

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

	output(1, "phase: entering main_loop\n");

	pidstatfiles = zmalloc(max_children * sizeof(FILE *));
	zombie_pids = zmalloc(max_children * sizeof(pid_t));
	zombie_since = zmalloc(max_children * sizeof(time_t));
	spawn_times = zmalloc(max_children * sizeof(time_t));
	for_each_child(i)
		zombie_pids[i] = EMPTY_PIDSLOT;

	if (epoch_timeout)
		clock_gettime(CLOCK_MONOTONIC, &epoch_start);

	init_altop_dispatch();
	log_alt_op_config();

	output(1, "phase: fork_children\n");
	fork_children();

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {

		handle_children();

		/* Drain fd events from all children's ring buffers.
		 * This processes dup/close events that children couldn't
		 * apply directly (COW heap prevents global pool mutation). */
		fd_event_drain_all();

		/* Drain stats deltas from all children's rings into the
		 * parent-private aggregate.  Republishes the mirror page
		 * inside its own thaw/refreeze bracket. */
		stats_ring_drain_all();

		/* Drain HEALER observation events from all children's rings
		 * into the parent-private healer_aggregate.  Republishes the
		 * dirty rows of the relation and pair mirror pages inside
		 * its own thaw/refreeze bracket. */
		healer_ring_drain_all();

		/* Drain edgepair observation events from all children's rings
		 * into the parent-private edgepair_aggregate.  Republishes
		 * the mirror page inside its own thaw/refreeze bracket. */
		edgepair_ring_drain_all();

		taint_check();

		self_cgroup_events_check();

		if (shm_is_corrupt() == true)
			goto corrupt;

		while (check_all_locks() == true) {
			reap_dead_kids();
			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_REACHED_COUNT)
				kill_all_kids();
		}

		unsigned long op = parent_stats.op_count;

		if (syscalls_todo && (op >= syscalls_todo)) {
			output(0, "Reached limit %lu. Telling children to exit.\n", syscalls_todo);
			panic(EXIT_REACHED_COUNT);
		}

		if (epoch_iterations && (op >= epoch_iterations)) {
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

		corrupt_ptr_spike_check();

		defense_counters_periodic_dump();

		top_syscalls_periodic_dump();

		vma_count_periodic_dump();

		kcov_plateau_check();

		kcov_bitmap_maybe_snapshot();

		cmp_hints_maybe_snapshot();

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
	{
		enum exit_reasons reason =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		switch (reason) {
		case EXIT_UID_CHANGED: {
			uid_t bad = __atomic_load_n(&shm->uid_at_exit,
						    __ATOMIC_ACQUIRE);
			output(0, "Bailing main loop because UID changed (was %u, now %u).\n",
				orig_uid, bad);
			break;
		}
		default:
			output(0, "Bailing main loop because %s.\n",
				decode_exit(reason));
			break;
		}
	}
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

	parent_stats.op_count = 0;
	parent_stats.previous_op_count = 0;

	if (shm_published != NULL)
		shm_published->fleet_op_count = 0;
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

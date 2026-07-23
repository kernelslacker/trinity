#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include "child.h"
#include "childops-util.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "kmsg-monitor.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "syscall_record.h"
#include "sysv-msg.h"
#include "sysv-sem.h"
#include "sysv-shm.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"
#include "reap-internal.h"

#include "kernel/fcntl.h"
static void handle_child(int childno, pid_t childpid, int childstatus);

/* Parent-local array of /proc/<pid>/stat file descriptors, indexed by
 * childno.  Kept out of shared memory so children's stray writes can't
 * corrupt them.  -1 means no open fd for that slot. */
int *pidstatfiles;

time_t *spawn_times;

/*
 * reap_child: Remove all references to a running child.
 *
 * This can get called from two possible places.
 * 1. From reap_dead_kids if it finds reference to a pid that no longer exists.
 * 2. From handle_child() if it gets a SIGBUS or SIGSTOP from the child,
 *    or if it dies from natural causes.
 */
void reap_child(struct childdata *child, int childno, bool child_dead)
{
	pid_t pid;

	if (child == NULL)
		return;
	/* Don't reap a child again */
	pid = __atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE);
	if (pid == EMPTY_PIDSLOT)
		return;
	/* SHADOW-ONLY wedge accounting close-out.  If this child was
	 * latched as wedged by is_child_making_progress(), add the
	 * wall-clock interval the slot was unreusable into BOTH
	 * syscall_wedge.total_us[wedge_nr] and
	 * childop_wedge_total_us[wedge_op_type] before the slot is
	 * recycled.  ONE duration definition feeds both arrays: the
	 * elapsed from child->tp (last child-side progress, captured into
	 * wedge_start_tp at latch time) up to the reap-time read of
	 * CLOCK_MONOTONIC -- the full window the slot was unreusable, not
	 * just the post-detection tail.  CLOCK_MONOTONIC start and end so
	 * an NTP step can't regress the elapsed; the (end <= start) clamp
	 * leaves elapsed_us at 0 if a torn read of the two-long start
	 * timestamp samples a future-looking start, so the unsigned
	 * subtraction can never wrap to a huge bogus duration (the
	 * monotonic-clock rule).  The childop index is range-checked
	 * against NR_CHILD_OP_TYPES to defuse an out-of-range op_type
	 * read (the latch already clamps to CHILD_OP_SYSCALL on capture,
	 * this is belt-and-braces against any future field reuse).
	 * Clear the latch so a reap that races a half-published wedge
	 * cannot double-account on a subsequent path (clean_childdata
	 * clears it again for the next occupant; clearing here is the
	 * conservative belt-and-braces). */
	if (child->wedge_accounted &&
	    child->wedge_nr < MAX_NR_SYSCALL) {
		struct timespec now;
		unsigned long long elapsed_us = 0;
		unsigned int wop;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > child->wedge_start_tp.tv_sec ||
		    (now.tv_sec == child->wedge_start_tp.tv_sec &&
		     now.tv_nsec >= child->wedge_start_tp.tv_nsec)) {
			long long sec = (long long)now.tv_sec -
					(long long)child->wedge_start_tp.tv_sec;
			long long nsec = (long long)now.tv_nsec -
					 (long long)child->wedge_start_tp.tv_nsec;
			elapsed_us = (unsigned long long)(sec * 1000000LL +
							  nsec / 1000LL);
		}
		/* Gate the per-syscall total_us close-out on
		 * CHILD_OP_SYSCALL for the same reason as the count bump
		 * above: wedge_nr is only meaningful for syscall childops.
		 * The per-childop total_us close-out stays unconditional
		 * (range-checked wop is the authoritative axis). */
		if (child->wedge_op_type == CHILD_OP_SYSCALL) {
			__atomic_add_fetch(&shm->stats.syscall_wedge.total_us[child->wedge_nr],
					   elapsed_us, __ATOMIC_RELAXED);
		}

		wop = (unsigned int)child->wedge_op_type;
		if (wop < NR_CHILD_OP_TYPES) {
			__atomic_add_fetch(&shm->stats.childop.wedge_total_us[wop],
					   elapsed_us, __ATOMIC_RELAXED);
		}
		child->wedge_accounted = false;
	}

	child->tp = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	child->kill_in_flight = false;
	force_bust_lock(&child->syscall.lock);

	unsigned int cur;
	do {
		cur = __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED);
		if (cur == 0)
			break;
	} while (!__atomic_compare_exchange_n(&shm->running_childs, &cur, cur - 1,
					       0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	__atomic_store_n(&pids[childno], EMPTY_PIDSLOT, __ATOMIC_RELEASE);

	/* Drop the per-child pre-crash ring's backing pages now that the
	 * child is fully gone and any forensic dump has already run via
	 * dump_childdata / pre_crash_ring_dump.  Forensic semantics are
	 * preserved: reap runs strictly after the child has been waited on,
	 * and head is reset to 0 so the dumper sees an empty ring until
	 * the slot's next occupant publishes its first entry. */
	pre_crash_ring_reset(&child->pre_crash);

	/* Drop the slot's bug-backtrace snapshot too.  The ~520 B struct
	 * fits inside one page, so no MADV_DONTNEED is needed; zeroing
	 * .count is sufficient -- any frame addresses left in frames[]
	 * are unreachable once count=0.  bug_dumped is cleared in
	 * clean_childdata alongside hit_bug for the fresh occupant. */
	__atomic_store_n(&child->bug_backtrace.count, 0, __ATOMIC_RELAXED);

	/* Surface any stamped beacon BEFORE the .written edge-trigger is
	 * zeroed below.  The bottom-of-main-loop poll runs after
	 * handle_children() has already reaped fast-dying children, so a
	 * child that re-faults inside the in-handler symboliser (the exact
	 * silent-death class the beacon was added for) loses the race and
	 * its forensic is dropped.  Dumping here closes that window; the
	 * fault_beacon_dumped cmpxchg gate in dump_child_fault_beacon makes
	 * the call idempotent against the bottom poll and any other future
	 * caller, so this is safe even if both paths see the beacon. */
	dump_child_fault_beacon(child);

	/* Same treatment for the signal-time fault beacon: zero the
	 * .written edge-trigger so a fresh occupant of this slot doesn't
	 * inherit the previous occupant's signal-death context and
	 * fault_beacon_dumped is cleared in clean_childdata for the new
	 * child.  Any si_addr / fault_ip / fault_sp left in the beacon
	 * are unreachable once .written=0. */
	__atomic_store_n(&child->fault_beacon.written, 0U,
			 __ATOMIC_RELAXED);

	/* Catch the SIGKILL'd-child case where inode_spewer_cleanup()
	 * never ran in the child.  No-op when the dir doesn't exist. */
	inode_spewer_reap(pid);

	/* Same for fuzzed SysV shm segments: a SIGKILL'd/OOM'd child never ran
	 * its OBJ_LOCAL RMID destructor, so RMID them here from the id ring
	 * mirrored into childdata.  Bounds the ~10GB orphaned-shmem OOM.  Gated
	 * on child_dead: the deferred-D-state reap (register_zombie_slot) calls
	 * us on a child that is still alive and could resume and register more
	 * ids, which would race this drain -- that caller passes false and
	 * process_zombie_pending() drains the ring once waitpid confirms death. */
	if (child_dead)
		reap_child_sysv_shm(child);

	/* Same shape for fuzzed SysV message queues: a SIGKILL'd/OOM'd child
	 * skips its OBJ_LOCAL RMID destructor and every queue it created
	 * orphans.  Left unbounded these fill the MSGMNI slot table (~32000)
	 * and all subsequent msgget calls return ENOSPC -- coverage dies.
	 * Same child_dead gating as the shm ring above: the deferred D-state
	 * path passes false and process_zombie_pending() drains after waitpid. */
	if (child_dead)
		reap_child_sysv_msg(child);

	/* Same shape for fuzzed SysV semaphore sets: a SIGKILL'd/OOM'd child
	 * skips its OBJ_LOCAL RMID destructor and every set it created
	 * orphans.  Left unbounded these fill the SEMMNI slot table (~32000)
	 * and all subsequent semget calls return ENOSPC -- coverage dies.
	 * Same child_dead gating as the shm/msg rings above: the deferred
	 * D-state path passes false and process_zombie_pending() drains
	 * after waitpid. */
	if (child_dead)
		reap_child_sysv_sem(child);
}

/* Make sure there's no dead kids lying around.
 * We need to do this in case the oom killer has been killing them,
 * otherwise we end up stuck with no child processes.
 */
void reap_dead_kids(void)
{
	unsigned int i;
	unsigned int reaped = 0;
	unsigned int drained;

	if (children == NULL)
		return;

	/* First pass: drain every reapable child via waitpid(-1).
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
	 * waitpid(-1) reaps whatever the kernel has, regardless of our
	 * bookkeeping.  Loop with WNOHANG until it returns 0 (nothing more
	 * pending) or -1 (ECHILD, no children at all — defensive; should
	 * not happen while main is fuzzing).  Bound to a sanity cap so a
	 * pathological case can't spin here forever. */
	for (drained = 0; drained < 64; drained++) {
		pid_t wpid;
		int childstatus;
		int childno;

		wpid = waitpid_eintr(-1, &childstatus, WNOHANG | WUNTRACED | WCONTINUED);
		if (wpid <= 0)
			break;

		childno = find_childno(wpid);
		if (childno != CHILD_NOT_FOUND) {
			handle_child(childno, wpid, childstatus);
		} else {
			/* Reaped a pid we no longer track — its slot was
			 * already cleared by some earlier path but the
			 * kernel hadn't released the task struct yet, OR
			 * the pid belongs to the kmsg-monitor helper which
			 * lives outside the fuzz-child pids[] machinery.
			 * Nothing more to do for the fuzz side; kernel side
			 * is now clean.  Notify the kmsg monitor so it can
			 * clear its cached pid if this was the helper —
			 * otherwise a later stop() would signal a recycled
			 * pid. */
			output(1, "reap_dead_kids: reaped untracked pid %d (status 0x%x)\n",
				wpid, childstatus);
			kmsg_monitor_note_reaped(wpid, childstatus);
		}
		reaped++;
	}

	/* Second pass: catch slots whose pid is gone but our bookkeeping
	 * never noticed — e.g. the waitpid drain above reaped a slotted pid
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

		if (kill(pid, 0) != 0) {
			if (errno == ESRCH) {
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				if (pidstatfiles[i] >= 0) {
					close(pidstatfiles[i]);
					pidstatfiles[i] = -1;
				}
				reap_child(children[i], i, true);
				reaped++;
			} else if (errno == EPERM) {
				/* Child dropped privileges (setresuid/capset/etc.)
				 * and we can no longer signal it.  It is still alive;
				 * just log so the privilege-drop is visible. */
				output(1, "pid %u dropped privileges (kill probe EPERM).\n", pid);
			}
		}
	}

	if (reaped != 0)
		output(1, "Reaped %d dead children\n", reaped);
}

void kill_all_kids(void)
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
			if (errno == ESRCH) {
				if (pidstatfiles[i] >= 0) {
					close(pidstatfiles[i]);
					pidstatfiles[i] = -1;
				}
				reap_child(children[i], i, true);
			}
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

/*
 * This is only ever used by the main process, so we cache the fd for
 * each child there, to save having to constantly reopen it.
 */
int open_child_pidstat(pid_t target)
{
	char filename[80];

	snprintf(filename, sizeof(filename), "/proc/%d/stat", target);

	return open(filename, O_RDONLY | O_CLOEXEC);
}

char get_pid_state(int childno)
{
	char buf[256];
	char state = '?';
	char *p;
	int fd;
	ssize_t n;

	if (mypid() != mainpid)
		BUG("get_pid_state can only be called from main!\n");

	fd = pidstatfiles[childno];
	if (fd < 0)
		return '?';

	/* The /proc/<pid>/stat line is "pid (comm) state ...".  comm may
	 * itself contain spaces or ')' (a task can rename itself via
	 * prctl(PR_SET_NAME)), so a field-based parse on whitespace will
	 * read the wrong byte.  comm is the only field wrapped in parens,
	 * so the LAST ')' in the line reliably terminates it and the
	 * state char sits two bytes after it.  pread keeps this poll
	 * allocation-free; the parent reap loop hits it once per child
	 * per cycle. */
	n = pread(fd, buf, sizeof(buf) - 1, 0);
	if (n <= 0)
		return '?';
	buf[n] = '\0';

	p = strrchr(buf, ')');
	if (p != NULL && (p - buf) + 2 < n)
		state = p[2];
	return state;
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
		register_zombie_slot(childno, pid);
		return;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
	case SIGILL:
		if (stop == true) {
			/* ptrace-STOPPED, not dead.  The slot is still live; if
			 * we register it as a zombie, the slot's childdata is
			 * freed and replace_child() is gated for up to 300s
			 * until process_zombie_pending() decides the pid is
			 * gone -- except the pid never goes, because the task
			 * is just stopped.  Mirror the default branch: log,
			 * release the pidstat fd, and let the next ptrace event
			 * (continue / kill / real death) drive the slot. */
			debugf("Child %d (pid %d) was stopped by %s\n",
					childno, pid, strsignal(WSTOPSIG(childstatus)));
			if (pidstatfiles[childno] >= 0)
				close(pidstatfiles[childno]);
			pidstatfiles[childno] = -1;
			return;
		}
		debugf("got a signal from child %d (pid %d) (%s)\n",
				childno, pid, strsignal(WTERMSIG(childstatus)));
		register_zombie_slot(childno, pid);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d).\n", pid, __sig);
		} else if (stop == true) {
			debugf("Child %d was stopped by unhandled signal (%s).\n", pid, strsignal(WSTOPSIG(childstatus)));
		} else {
			debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
		}

		if (stop == false) {
			register_zombie_slot(childno, pid);
		} else {
			if (pidstatfiles[childno] >= 0)
				close(pidstatfiles[childno]);
			pidstatfiles[childno] = -1;
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
			record_reap(childno, childstatus);
			reap_child(children[childno], childno, true);
			if (pidstatfiles[childno] >= 0)
				close(pidstatfiles[childno]);
			pidstatfiles[childno] = -1;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			int sig = WTERMSIG(childstatus);

			/* Feed canary attribution.  Only SIGSEGV/SIGBUS/SIGILL/
			 * SIGABRT count as canary-relevant crashes; the queue
			 * filters them internally.  Reads child->op_type out of
			 * the shared childdata slot, which the child stamped on
			 * its last iteration via the dedicated-alt-op stamp path
			 * (assign_dedicated_alt_op) -- the parent is the sole
			 * reader and is consulting it post-mortem, so no
			 * coherence work is needed. */
			canary_queue_on_crash(childno, sig);
			record_reap(childno, childstatus);
			handle_childsig(childno, childstatus, false);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childno, childstatus, true);
		} else if (WIFCONTINUED(childstatus)) {
			break;
		}
	}
}

void handle_children(void)
{
	unsigned int i;
	int collected = 0;

	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
		return;

	if (children == NULL)
		return;

	for_each_child(i) {
		int childstatus = 0;
		pid_t pid;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);

		if (pid == EMPTY_PIDSLOT)
			continue;

		pid = waitpid_eintr(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid > 0)
			collected++;
		handle_child(i, pid, childstatus);
	}

	/* If nothing happened, sleep briefly to avoid busy-looping. */
	if (collected == 0)
		usleep(25000);
}

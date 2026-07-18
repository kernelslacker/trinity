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

#include "kernel/fcntl.h"
static void handle_child(int childno, pid_t childpid, int childstatus);

/* Parent-local array of /proc/<pid>/stat file descriptors, indexed by
 * childno.  Kept out of shared memory so children's stray writes can't
 * corrupt them.  -1 means no open fd for that slot. */
int *pidstatfiles;

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
pid_t *zombie_pids;
time_t *zombie_since;

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
	time_t reaped_at;	/* CLOCK_REALTIME seconds, for log-attribution
				 * only -- do NOT subtract from to compute a
				 * duration. */
	time_t lifetime;	/* CLOCK_MONOTONIC seconds between spawn and
				 * reap of this slot; the fast-die classifier
				 * reads this. */
	int    exit_status;	/* WEXITSTATUS, or -WTERMSIG for signal deaths */
	int    childno;
};

time_t *spawn_times;
static struct reap_record reap_ring[FAST_DIE_RING_SIZE];
static unsigned int reap_ring_head;
static unsigned int reap_ring_count;

/*
 * Running count of fast-die entries currently in the ring -- an
 * entry is fast-die when lifetime < FAST_DIE_LIFETIME_THRESHOLD_S
 * AND exit_status > 0.  Updated incrementally in record_reap()
 * (add on insert, subtract on overwrite of an old fast-die slot)
 * so the per-reap bail check is a single comparison instead of a
 * full ring walk on every reap.
 */
static unsigned int reap_ring_fast_die_count;

static bool reap_entry_is_fast_die(const struct reap_record *r)
{
	/*
	 * Always-exempt reasons (any mode) -- these are legitimate clean
	 * exits that a racing child can propagate via the locks.c spin-
	 * bailout _exit(shm->exit_reason).  Cascading them into the
	 * fast-die ring trips a spurious EXIT_SHM_CORRUPTION panic:
	 *   - EXIT_MAIN_DISAPPEARED:    child.c PDEATHSIG race; the parent
	 *     is gone, this is a clean shutdown not corruption.
	 *   - EXIT_NO_SYSCALLS_ENABLED: pickers.c saw no_syscalls_enabled()
	 *     == true (active set self-disabled via ENOSYS depletion or
	 *     VALIDATE_FAIL_THRESHOLD).  Exempt unconditionally: a legit
	 *     depletion cascades 16 lock-spin-bailout children through the
	 *     ring inside the corruption window, which would falsely trip
	 *     EXIT_SHM_CORRUPTION.  One clean bail is enough; let the
	 *     deeper trigger (why depletion fired) be diagnosed separately.
	 */
	if (r->exit_status == EXIT_MAIN_DISAPPEARED ||
	    r->exit_status == EXIT_NO_SYSCALLS_ENABLED)
		return false;

	/*
	 * Targeted-mode-only exempt reasons (-c/-r/-g).  In targeted mode
	 * these are the run finishing on its own terms, not corruption;
	 * in default fuzz mode they should not fire at all, and if they
	 * do a fast-die cluster still signals something wrong.
	 *   - EXIT_REACHED_COUNT: requested op count reached.
	 *   - EXIT_EPOCH_DONE:    epoch budget consumed.
	 *   - EXIT_SIGINT:        ^C from terminal -- parent panics
	 *     EXIT_SIGINT in sigint_handler; child main loop panics
	 *     EXIT_SIGINT on ctrlc_pending.  Spin-bailout then propagates
	 *     EXIT_SIGINT to any racing child.
	 *   - EXIT_USER_REQUEST:  operator-driven shutdown path; no
	 *     current caller, retained so future operator exits routed
	 *     through shm->exit_reason are exempted the same way.
	 */
	if ((r->exit_status == EXIT_REACHED_COUNT ||
	     r->exit_status == EXIT_EPOCH_DONE ||
	     r->exit_status == EXIT_SIGINT ||
	     r->exit_status == EXIT_USER_REQUEST) &&
	    (do_specific_syscall || random_selection ||
	     desired_group != GROUP_NONE))
		return false;

	return r->lifetime < FAST_DIE_LIFETIME_THRESHOLD_S &&
	       r->exit_status > 0;
}

unsigned long hiscore = 0;

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * also check the pids for sanity.
 */
int shm_is_corrupt(void)
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

	/* Mirror page integrity check: stats_publish_locked() in the
	 * parent's drain wrote parent_stats.op_count into
	 * shm_published->fleet_op_count, and each child has the page
	 * mprotected PROT_READ in its own address space via the
	 * stats_published_freeze() called from init_child().  A read-back
	 * here that disagrees with the canonical aggregate means somebody
	 * found a write window (a freeze gap before the per-child mprotect
	 * lands, or somehow a wild write succeeded against the read-only
	 * mapping in a child).  Log + bump rather than panic -- the
	 * canonical value is still trustworthy. */
	if (shm_published != NULL) {
		unsigned long mirror =
			__atomic_load_n(&shm_published->fleet_op_count,
					__ATOMIC_RELAXED);
		if (mirror != current_op_count) {
			output(0, "shm_published mirror: fleet_op_count=%lu, "
				  "aggregate=%lu (mirror scribbled?)\n",
				  mirror, current_op_count);
			parent_stats.shm_published_corrupt++;
		}
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
	 * syscall_wedge_total_us[wedge_nr] and
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
			__atomic_add_fetch(&shm->stats.syscall_wedge_total_us[child->wedge_nr],
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

/*
 * Bounded /proc/<pid>/wchan reader used by the D-state diagnostic
 * snapshot.  open(O_RDONLY) + single read into a stack buffer + close
 * keeps the reap loop allocation-free and bounded against a wedged
 * task: wchan is at most a kernel symbol name (a few dozen bytes) so a
 * 256 B scratch space is generous and the read returns whatever was
 * ready without blocking on the task's state.  Silent on any open or
 * read error -- the snapshot caller treats missing wchan as an omitted
 * line, not a failure to investigate further.
 */
static ssize_t read_pid_wchan(int pid, char *buf, size_t bufsz)
{
	char filename[80];
	int fd;
	ssize_t n;

	if (bufsz == 0)
		return 0;
	buf[0] = '\0';

	snprintf(filename, sizeof(filename), "/proc/%d/wchan", pid);

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n <= 0) {
		buf[0] = '\0';
		return 0;
	}
	buf[n] = '\0';
	/* wchan typically omits a trailing newline but be defensive. */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return n;
}

static void dump_pid_wchan(int pid)
{
	char buf[256];

	if (read_pid_wchan(pid, buf, sizeof(buf)) <= 0)
		return;
	output(0, "pid %d wchan: %s\n", pid, buf);
}

/*
 * Bounded /proc/<pid>/stack reader.  Distinct from the existing
 * dump_pid_stack() (which uses fopen/getline and allocates per call)
 * because the D-state diagnostic path runs unconditionally -- not
 * gated on shm->debug -- and must stay quiet about permission failures
 * (most production kernels reject /proc/<pid>/stack reads without
 * CAP_SYS_ADMIN, returning EACCES; some configs hide it entirely with
 * ENOENT).  Silent on any open/read failure.
 */
static void dump_pid_stack_bounded(int pid)
{
	char filename[80];
	char buf[2048];
	int fd;
	ssize_t n;
	char *p, *eol;

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	for (p = buf; *p != '\0'; p = eol + 1) {
		eol = strchr(p, '\n');
		if (eol == NULL) {
			if (*p != '\0')
				output(0, "pid %d stack: %s\n", pid, p);
			break;
		}
		*eol = '\0';
		if (*p != '\0')
			output(0, "pid %d stack: %s\n", pid, p);
	}
}

/*
 * Bounded /proc/<pid>/fdinfo/ reader.  fdinfo is a directory of
 * per-fd files, so a wedged child with many open descriptors could
 * stream unbounded text into the watchdog snapshot, and individual
 * entries (eventpoll, in particular) can dump every watched fd.
 * Cap both the number of entries walked and the bytes read per
 * entry; truncate the rest silently rather than chase the long
 * tail.  Uses getdents64 directly to stay allocation-free on the
 * reap/watchdog path (opendir/readdir would malloc), and a single
 * O_RDONLY read per fdinfo file to match the wchan/stack helpers.
 * Silent on any open/read failure -- the snapshot treats missing
 * fdinfo as an omitted line, not a failure to investigate further.
 */
#define DSTATE_FDINFO_MAX_ENTRIES 64
#define DSTATE_FDINFO_MAX_BYTES   512

static void dump_pid_fdinfo_bounded(int pid)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char dirpath[80];
	char filename[96];
	char dirbuf[4096];
	char buf[DSTATE_FDINFO_MAX_BYTES];
	int dirfd, fd;
	long nread, pos;
	unsigned int seen = 0;
	ssize_t n;
	char *p, *eol;

	snprintf(dirpath, sizeof(dirpath), "/proc/%d/fdinfo", pid);

	dirfd = open(dirpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return;

	while (seen < DSTATE_FDINFO_MAX_ENTRIES &&
	       (nread = syscall(SYS_getdents64, dirfd, dirbuf,
				sizeof(dirbuf))) > 0) {
		for (pos = 0; pos < nread &&
		     seen < DSTATE_FDINFO_MAX_ENTRIES; ) {
			struct linux_dirent64 *de =
				(struct linux_dirent64 *)(dirbuf + pos);
			const char *name = de->d_name;

			pos += de->d_reclen;

			/* Skip "." / ".." and any non-numeric entry. */
			if (name[0] < '0' || name[0] > '9')
				continue;

			snprintf(filename, sizeof(filename),
				 "/proc/%d/fdinfo/%s", pid, name);
			fd = open(filename, O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				continue;
			n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (n <= 0)
				continue;
			buf[n] = '\0';
			seen++;

			for (p = buf; *p != '\0'; p = eol + 1) {
				eol = strchr(p, '\n');
				if (eol == NULL) {
					if (*p != '\0')
						output(0, "pid %d fdinfo[%s]: %s\n",
						       pid, name, p);
					break;
				}
				*eol = '\0';
				if (*p != '\0')
					output(0, "pid %d fdinfo[%s]: %s\n",
					       pid, name, p);
			}
		}
	}

	close(dirfd);
}

struct dstate_fd_print_ctx {
	char buf[128];
	int off;
	unsigned int n;
};

static void dstate_print_fd_arg(int fd, void *vctx)
{
	struct dstate_fd_print_ctx *c = vctx;
	int written;

	if (c->off >= (int)sizeof(c->buf))
		return;
	written = snprintf(c->buf + c->off, sizeof(c->buf) - c->off,
			   "%s%d", c->n ? "," : "", fd);
	if (written < 0)
		return;
	c->off += written;
	c->n++;
}

/*
 * Targeted fd-topology line for the epoll/select syscall families.
 * These dominated a recent unkillable-D-state survey (14 of 25 wedged
 * children were in epoll_ctl alone); a generic "fd args" dump is opaque
 * for these because the syscall's semantics make different aN slots
 * mean very different things (epfd vs target_fd vs maxevents vs nfds).
 * Returns true if it handled the syscall, false otherwise so the
 * generic fd-args fallback can fire.
 */
static bool dump_dstate_epoll_select_topology(const char *name,
					      const unsigned long *args)
{
	if (strcmp(name, "epoll_ctl") == 0) {
		output(0, "  fd topology: epfd=%ld op=%ld target_fd=%ld\n",
			(long)args[0], (long)args[1], (long)args[2]);
		return true;
	}
	if (strcmp(name, "epoll_wait") == 0 ||
	    strcmp(name, "epoll_pwait") == 0 ||
	    strcmp(name, "epoll_pwait2") == 0) {
		output(0, "  fd topology: epfd=%ld maxevents=%ld\n",
			(long)args[0], (long)args[2]);
		return true;
	}
	if (strcmp(name, "select") == 0 ||
	    strcmp(name, "pselect6") == 0) {
		output(0, "  fd topology: nfds=%ld\n", (long)args[0]);
		return true;
	}
	return false;
}

/*
 * "STUCK CHILD:" loud diagnostic.  One prominent greppable line
 * summarising a wedged child (pid/childno/op/wedge duration/state
 * char/wchan) plus the kernel stack from /proc/<pid>/stack when the
 * kernel exposes it to us.  Falls back to just the wchan when the stack
 * file is empty or hidden (unprivileged reader, EACCES/ENOENT/EPERM on
 * most production kernels without CAP_SYS_ADMIN).
 *
 * Distinct tag from the existing "watchdog: kill ..." (syscall-side
 * state int) and "D-state diag ..." (multi-line fd topology / fdinfo
 * spew) lines: this is the single "which pid, where, how long"
 * summary that operators grep to attribute wedged tasks.
 *
 * Runs on the parent's reap/watchdog path, before the SIGKILL, so the
 * task's /proc state still reflects the wedge.  Every read tolerates
 * the pid having exited (open/read failure -> "?" / omitted stack) so
 * the reap loop cannot be crashed by whatever state the wedged task is
 * in.  Caller gates on the per-child dstate_diag_dumped latch so this
 * fires once per stuck child, not every watchdog tick.
 */
static void scream_stuck_child(struct childdata *child, int childno,
			       pid_t pid, time_t wedge_seconds)
{
	char wchan[128];
	char stackbuf[2048];
	char filename[80];
	ssize_t stack_n = 0;
	const char *opname;
	char state;
	int fd;
	int open_errno = 0;
	int read_errno = 0;

	state = get_pid_state(childno);

	if (read_pid_wchan(pid, wchan, sizeof(wchan)) <= 0)
		snprintf(wchan, sizeof(wchan), "?");

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);
	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		stack_n = read(fd, stackbuf, sizeof(stackbuf) - 1);
		if (stack_n < 0) {
			/* Latch read's errno before close(2), which can
			 * clobber it on failure. */
			read_errno = errno;
			stack_n = 0;
		}
		close(fd);
	} else {
		open_errno = errno;
	}
	stackbuf[stack_n] = '\0';

	if (child->op_type == CHILD_OP_SYSCALL) {
		struct syscallrecord *rec = &child->syscall;
		struct syscallentry *entry;
		unsigned int callno;
		bool do32;
		bool got;

		SREC_SNAPSHOT(rec, {
			do32 = rec->do32bit;
			callno = rec->nr;
		}, got);
		if (got) {
			entry = get_syscall_entry(callno, do32);
			opname = (entry != NULL) ? entry->name : "?";
		} else {
			opname = "?";
		}
	} else {
		opname = alt_op_name(child->op_type);
	}

	if (stack_n > 0) {
		output(0,
		       "STUCK CHILD: pid=%d childno=%d op=%s wedged %lds state=%c wchan=%s\nkernel stack:\n%s%s",
		       pid, childno, opname, (long)wedge_seconds, state, wchan,
		       stackbuf,
		       stackbuf[stack_n - 1] == '\n' ? "" : "\n");
	} else {
		/* Distinguish open-gate (EPERM: ptrace_may_access on a
		 * non-dumpable child; EACCES: CAP_SYS_ADMIN missing;
		 * ENOENT: pid exited) from read-gate from a successful
		 * empty unwind (no errno captured). */
		char errtag[48] = "";

		if (open_errno) {
			const char *n = strerrorname_np(open_errno);
			snprintf(errtag, sizeof(errtag), ": open=%s",
				 n ? n : "?");
		} else if (read_errno) {
			const char *n = strerrorname_np(read_errno);
			snprintf(errtag, sizeof(errtag), ": read=%s",
				 n ? n : "?");
		}
		output(0,
		       "STUCK CHILD: pid=%d childno=%d op=%s wedged %lds state=%c wchan=%s (kernel stack unavailable%s)\n",
		       pid, childno, opname, (long)wedge_seconds, state, wchan,
		       errtag);
	}
}

/*
 * One-shot D-state diagnostic snapshot.  Fires at the first watchdog
 * detection of TASK_UNINTERRUPTIBLE for a child and prints a richer
 * forensic than the bare "watchdog: kill ..." line:
 *
 *   - child op (when the wedged child is running a non-syscall childop,
 *     so the dispatch context is recoverable).
 *   - the targeted fd-topology line for the epoll/select families that
 *     dominate the observed unkillable population, or the generic
 *     fd-bearing arg values for every other syscall.
 *   - /proc/<pid>/wchan: the kernel sleep address/symbol.
 *   - /proc/<pid>/stack: the kernel call stack (silently omitted when
 *     the kernel hides it from unprivileged readers).
 *   - /proc/<pid>/fdinfo/: per-fd state (pos/flags + driver-specific
 *     bits like eventpoll/inotify watches) for the wedged task's open
 *     descriptors, capped at DSTATE_FDINFO_MAX_ENTRIES entries and
 *     DSTATE_FDINFO_MAX_BYTES per entry so a fd-heavy child cannot
 *     stream unbounded text into the snapshot.
 *
 * Runs on the parent's reap/watchdog path.  All /proc reads go through
 * the bounded helpers above so a wedged task cannot stall the reap
 * loop: open(O_RDONLY) + single read into a stack buffer + close, no
 * heap allocation, no looped reads.  The caller is responsible for
 * gating this on the per-child dstate_diag_dumped latch so the snapshot
 * fires once per stuck child rather than every watchdog tick.
 */
static void dump_dstate_diagnostics(struct childdata *child, int childno,
				    pid_t pid)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry = NULL;
	unsigned long args[6] = { 0 };
	unsigned int callno;
	bool do32;
	bool got;
	enum syscallstate state;
	const char *name;

	SREC_SNAPSHOT(rec, {
		do32 = rec->do32bit;
		callno = rec->nr;
		state = __atomic_load_n(&rec->state, __ATOMIC_RELAXED);
		args[0] = rec->a1;
		args[1] = rec->a2;
		args[2] = rec->a3;
		args[3] = rec->a4;
		args[4] = rec->a5;
		args[5] = rec->a6;
	}, got);

	output(0, "  D-state diag: child %d pid %u\n", childno, pid);

	if (child->op_type != CHILD_OP_SYSCALL)
		output(0, "  child op: %s\n", alt_op_name(child->op_type));

	if (got) {
		entry = get_syscall_entry(callno, do32);
		name = (entry != NULL) ? entry->name : NULL;

		/* The watchdog kill line printed by stuck_syscall_info()
		 * already names the syscall; only emit fd-topology / fd-args
		 * here, since those are what the kill line omits. */
		if (name != NULL) {
			if (!dump_dstate_epoll_select_topology(name, args) &&
			    state == BEFORE) {
				struct dstate_fd_print_ctx fdctx = { .off = 0, .n = 0 };

				for_each_fd_arg(entry, args,
						dstate_print_fd_arg, &fdctx);
				if (fdctx.n > 0)
					output(0, "  fd args (%s): %s\n",
						name, fdctx.buf);
			}
		}
	} else {
		output(0, "  syscall arg snapshot unavailable (writer churn)\n");
	}

	dump_pid_wchan(pid);
	dump_pid_stack_bounded(pid);
	dump_pid_fdinfo_bounded(pid);
}

/*
 * Global budget for the verbose dump_dstate_diagnostics() snapshot.
 * Bounds two axes so a run that wedges thousands of distinct children
 * (each already gated to one snapshot by child->dstate_diag_dumped)
 * cannot produce unbounded aggregate output:
 *
 *   - DSTATE_DIAG_RUN_BUDGET caps the total number of verbose dumps
 *     printed across the whole run.
 *   - DSTATE_DIAG_PER_SIG_MAX caps how many samples a single
 *     (op_type, syscall nr, wchan-string) signature may burn from the
 *     budget, so one hot wedge pattern cannot consume the entire budget
 *     and starve rarer signatures.
 *
 * State is a plain file-static -- the reap/watchdog path runs
 * single-threaded in the parent, so no atomic/lock is needed and
 * nothing lives in shm.  The signature table is fixed-size (no alloc);
 * on collision or table-full we linear-probe within the table and, if
 * still no slot, fall through to the run-budget gate only.
 *
 * The one-line "STUCK CHILD:" summary is *not* budgeted -- it is one
 * greppable line per stuck child and is the always-on operator signal.
 * The omitted-count is surfaced two ways: an inline notice the first
 * time the run budget is exhausted, and a final "D-state diag summary"
 * line printed by log_main_loop_exit() at shutdown.
 */
#define DSTATE_DIAG_RUN_BUDGET  256
#define DSTATE_DIAG_PER_SIG_MAX 8
#define DSTATE_DIAG_SIG_SLOTS   128

struct dstate_diag_sig {
	uint32_t hash;		/* zero means slot unused */
	uint16_t count;		/* verbose dumps printed for this signature */
};

static struct dstate_diag_sig dstate_diag_sigs[DSTATE_DIAG_SIG_SLOTS];
static unsigned int dstate_diag_printed;
static unsigned int dstate_diag_omitted;
static unsigned int dstate_diag_sig_used;
static bool dstate_diag_notice_emitted;

static uint32_t dstate_diag_hash(int op_type, unsigned int callno,
				 const char *wchan)
{
	/* FNV-1a over (op_type, callno, wchan bytes).  Force nonzero so
	 * hash==0 can mark an empty slot without a separate valid bit. */
	uint32_t h = 2166136261u;

	h ^= (uint32_t)op_type;
	h *= 16777619u;
	h ^= callno;
	h *= 16777619u;
	while (*wchan) {
		h ^= (unsigned char)*wchan++;
		h *= 16777619u;
	}
	return h ? h : 1;
}

static void dstate_diag_note_budget_exhausted(void)
{
	if (dstate_diag_notice_emitted)
		return;
	output(0,
	       "D-state diag: run budget %u reached -- further verbose"
	       " snapshots suppressed (STUCK CHILD summaries continue)\n",
	       DSTATE_DIAG_RUN_BUDGET);
	dstate_diag_notice_emitted = true;
}

/*
 * Decide whether to emit a verbose D-state diagnostic snapshot for this
 * (child, wchan).  Returns true if the caller should print, false if
 * either the per-signature cap or the run budget is exhausted.  Also
 * bumps the internal counters that log_main_loop_exit() reads via
 * dstate_diag_get_counts().
 */
static bool dstate_diag_budget_take(struct childdata *child,
				    const char *wchan)
{
	unsigned int callno = 0;
	uint32_t h;
	unsigned int slot;
	unsigned int i;

	if (child->op_type == CHILD_OP_SYSCALL) {
		struct syscallrecord *rec = &child->syscall;
		bool got;

		SREC_SNAPSHOT(rec, {
			callno = rec->nr;
		}, got);
		if (!got)
			callno = ~0u;
	}

	h = dstate_diag_hash(child->op_type, callno, wchan);
	slot = h % DSTATE_DIAG_SIG_SLOTS;

	for (i = 0; i < DSTATE_DIAG_SIG_SLOTS; i++) {
		struct dstate_diag_sig *s =
			&dstate_diag_sigs[(slot + i) % DSTATE_DIAG_SIG_SLOTS];

		if (s->hash == 0) {
			if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
				dstate_diag_omitted++;
				dstate_diag_note_budget_exhausted();
				return false;
			}
			s->hash = h;
			s->count = 1;
			dstate_diag_sig_used++;
			dstate_diag_printed++;
			return true;
		}
		if (s->hash == h) {
			if (s->count >= DSTATE_DIAG_PER_SIG_MAX) {
				dstate_diag_omitted++;
				return false;
			}
			if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
				dstate_diag_omitted++;
				dstate_diag_note_budget_exhausted();
				return false;
			}
			s->count++;
			dstate_diag_printed++;
			return true;
		}
	}

	/* Table full -- fall through to the run-budget gate only. */
	if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
		dstate_diag_omitted++;
		dstate_diag_note_budget_exhausted();
		return false;
	}
	dstate_diag_printed++;
	return true;
}

void dstate_diag_get_counts(unsigned int *printed, unsigned int *omitted,
			    unsigned int *sigs)
{
	*printed = dstate_diag_printed;
	*omitted = dstate_diag_omitted;
	*sigs = dstate_diag_sig_used;
}

struct stuck_evict_ctx {
	int fds[6];
	unsigned int n;
};

static void stuck_evict_fd(int fd, void *ctx)
{
	struct stuck_evict_ctx *c = ctx;

	if (c->n < ARRAY_SIZE(c->fds))
		c->fds[c->n++] = fd;

	/* Remove the bad fd from the object pool so it won't be handed
	 * out again. */
	remove_object_by_fd(fd);
}

static void stuck_syscall_info(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	struct syscallentry *entry = NULL;
	struct stuck_evict_ctx ctx = { .n = 0 };
	unsigned long args[6] = { 0 };
	unsigned int callno;
	char fdstr[80];
	pid_t pid;
	bool do32;
	enum syscallstate state;
	bool got;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	rec = &child->syscall;

	/* Lockless snapshot via the sequence counter.  Writers bracket
	 * coherent mutations with srec_publish_begin/end (no rec->lock
	 * involved post-strengthen); the SREC_SNAPSHOT spin pattern
	 * gives this parent-side diagnostic a coherent multi-field view
	 * without contending with the child's writer path under fleet
	 * conditions where many children wedge simultaneously. */
	SREC_SNAPSHOT(rec, {
		do32 = rec->do32bit;
		callno = rec->nr;
		state = __atomic_load_n(&rec->state, __ATOMIC_RELAXED);
		args[0] = rec->a1;
		args[1] = rec->a2;
		args[2] = rec->a3;
		args[3] = rec->a4;
		args[4] = rec->a5;
		args[5] = rec->a6;
	}, got);

	if (!got) {
		output(0, "  (snapshot give-up: writer churn)\n");
		return;
	}

	/* The name lookup is a pure table index and is meaningful in
	 * any state -- without it AFTER-state kills print cmd:? and we
	 * lose all visibility into which syscall's post-handler path
	 * stuck the child. */
	entry = get_syscall_entry(callno, do32);

	/* Always-on kill diag: the caller is about to SIGKILL this child,
	 * and without this line non-debug runs just see a child vanish.
	 * The expensive fd walk and /proc stack dump below stay gated. */
	outputerr("watchdog: kill pid:%d childno:%d nr:%u cmd:%s state:%d\n",
		  pid, childno, callno,
		  entry ? entry->name : "?", state);

	{
		/* Structured one-liner that mirrors the kill line's
		 * key:value shape and carries the fields the bare line
		 * omits: the killed child's kcov dedup generation, a
		 * boolean recording whether the stuck op was a
		 * currently-promoted canary, and the kernel wchan when
		 * /proc still exposes it.  Post-run analysis of
		 * unkillable / D-state populations grep this line to
		 * attribute wedged tasks to a (op, kcov-generation,
		 * canary-state, wchan) tuple rather than only the
		 * syscall name from the kill line above.  This does NOT
		 * change any kill/evict decision -- it is purely a
		 * record-shape extension. */
		char wbuf[128];
		const char *opname;
		bool promoted;
		bool is_syscall;

		is_syscall = (child->op_type == CHILD_OP_SYSCALL);
		if (is_syscall)
			opname = entry ? entry->name : "?";
		else
			opname = alt_op_name(child->op_type);

		promoted = canary_op_is_promoted(child->op_type);

		if (read_pid_wchan(pid, wbuf, sizeof(wbuf)) > 0)
			outputerr("watchdog: record pid:%d nr:%u op:%s"
				  " fd_gen:%" PRIu64 " canary_promoted:%d"
				  " wchan:%s\n",
				  pid, callno, opname,
				  child->kcov.current_generation,
				  promoted ? 1 : 0, wbuf);
		else
			outputerr("watchdog: record pid:%d nr:%u op:%s"
				  " fd_gen:%" PRIu64 " canary_promoted:%d\n",
				  pid, callno, opname,
				  child->kcov.current_generation,
				  promoted ? 1 : 0);
	}

	if (shm->debug == false)
		return;

	fdstr[0] = '\0';

	if (state == BEFORE && entry != NULL) {
		/* Same gate as the child-side watchdog in __do_syscall():
		 * fd_arg_mask plus the ARG_SOCKETINFO-in-slot-0 mirror.
		 * Outside that gate the syscall has no fd-bearing args at
		 * all, so leave fdstr empty rather than print "(no fds)"
		 * for every stuck non-fd syscall. */
		uint8_t gate = entry->fd_arg_mask;
		if (entry->argtype[0] == ARG_SOCKETINFO)
			gate |= 0x01;

		if (gate != 0) {
			for_each_fd_arg(entry, args, stuck_evict_fd, &ctx);

			if (ctx.n == 0) {
				snprintf(fdstr, sizeof(fdstr), "(no fds)");
			} else if (ctx.n == 1) {
				snprintf(fdstr, sizeof(fdstr), "(fd = %d)",
					 ctx.fds[0]);
				child->fd_lifetime = 0;
			} else {
				int off = snprintf(fdstr, sizeof(fdstr),
						   "(fds = ");
				unsigned int i;

				for (i = 0; i < ctx.n && off < (int)sizeof(fdstr); i++)
					off += snprintf(fdstr + off,
							sizeof(fdstr) - off,
							"%s%d", i ? "," : "",
							ctx.fds[i]);
				if (off < (int)sizeof(fdstr))
					snprintf(fdstr + off,
						 sizeof(fdstr) - off, ")");
				child->fd_lifetime = 0;
			}
		}
	}

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

	/*
	 * Catch the silent-leak shape directly: re-registering an
	 * already-zombie slot would overwrite zombie_pids[childno] and
	 * leave the prior pid waiting on a waitpid() nobody runs any
	 * more, while zombie_slots_pending double-counts.  The slot
	 * stays parked in zombie-pending state forever and the kernel's
	 * task struct is never released.  pids[childno] is cleared by
	 * reap_child() before we get here, so no fresh signal/death
	 * event can target the slot until process_zombie_pending()
	 * clears zombie_pids[childno] -- a non-empty value at entry is
	 * a state-machine violation, not a legitimate race.
	 */
	BUG_ON(zombie_pids[childno] != EMPTY_PIDSLOT);

	/* Fast path: it's not uncommon for the kernel to release a
	 * transient D-state task between our kill loop giving up and
	 * us reaching this function.  A non-blocking waitpid here
	 * tells us if the task is already gone — if so, skip the whole
	 * deferral machinery and just reap+replace immediately and
	 * silently.  Saves the unkillable-log + stack/syscall dump +
	 * zombie_pids[] bookkeeping that would otherwise fire and then
	 * unwind on the very next process_zombie_pending() pass. */
	wpid = waitpid_eintr(pid, NULL, WNOHANG);
	if (wpid == pid || (wpid == -1 && errno == ECHILD)) {
		if (pidstatfiles[childno] >= 0) {
			close(pidstatfiles[childno]);
			pidstatfiles[childno] = -1;
		}
		reap_child(children[childno], childno, true);
		replace_child(childno);
		__atomic_add_fetch(&shm->stats.zombies_reaped, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	{
		struct syscallrecord *rec = &children[childno]->syscall;
		struct syscallentry *entry;
		unsigned int nr = rec->nr;
		bool do32 = rec->do32bit;
		const char *name;

		entry = get_syscall_entry(nr, do32);
		name = (entry != NULL) ? entry->name : "?";

		output(0, "child %d (pid %u) unkillable in nr=%u (%s)%s, "
			"deferring slot reuse until kernel releases the "
			"D-state task.\n",
			childno, pid, nr, name, do32 ? " (32bit)" : "");
	}

	/* /proc/$pid/stack and /proc/$pid/syscall reads can block for up
	 * to ~12s waiting on the kernel when the task is wedged in D-state.
	 * The parent main loop is single-threaded, so a stall here halves
	 * the fleet iter rate for the rest of the 10k-iter window.  Gate
	 * these diagnostics on shm->debug, matching stuck_syscall_info().
	 */
	if (shm->debug == true) {
		dump_pid_stack(pid);
		dump_pid_syscall(pid);
	}

	if (pidstatfiles[childno] >= 0) {
		close(pidstatfiles[childno]);
		pidstatfiles[childno] = -1;
	}

	/* Child still alive here (D-state / stopped / signaled-but-running):
	 * the WNOHANG waitpid above returned 0.  Pass child_dead=false so the
	 * shm-ring drain is deferred to process_zombie_pending(); everything
	 * else reap_child() does is safe to run against the frozen slot now. */
	reap_child(children[childno], childno, false);

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
void process_zombie_pending(void)
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

		wpid = waitpid_eintr(pid, NULL, WNOHANG);
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

		/* Deferred child is now confirmed gone (waitpid above, or the
		 * long-stuck timeout).  reap_child() at the deferral point ran
		 * with child_dead=false, so drain its fuzzed shm ring here --
		 * before replace_child() recycles the slot and clean_childdata()
		 * zeroes the count. */
		reap_child_sysv_shm(children[i]);
		reap_child_sysv_msg(children[i]);
		reap_child_sysv_sem(children[i]);

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
int find_free_childno(void)
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
	if (__atomic_load_n(&rec->state, __ATOMIC_RELAXED) < BEFORE)
		return true;

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
	if (__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED) >= 10) {
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

	/* First-detection-only forensic for ANY 30s-stalled child, D or
	 * interruptible.  The epoll/ep_item_poll wedge holder blocks in
	 * interruptible sleep on the polled fd's waitqueue, not 'D', so
	 * gating this on 'D' alone skipped exactly the task whose
	 * fd-topology names the blocking fd.  A task with zero progress for
	 * 30s is parked in its wait, so /proc/<pid>/stack is stable either
	 * way.  Read-only + latched, so no change to the kill logic. */
	if (!child->dstate_diag_dumped) {
		char wchan[128];

		scream_stuck_child(child, childno, pid, diff);
		/* Gate the verbose snapshot behind the global budget.  wchan
		 * is re-read here (scream_stuck_child does its own read) so
		 * dstate_diag_budget_take can key its per-signature cap on
		 * the real sleep symbol; on read failure the signature keys
		 * on "?" and shares a slot with other unreadable-wchan
		 * wedges, which is the intended aggregation. */
		if (read_pid_wchan(pid, wchan, sizeof(wchan)) <= 0)
			snprintf(wchan, sizeof(wchan), "?");
		if (dstate_diag_budget_take(child, wchan))
			dump_dstate_diagnostics(child, childno, pid);
		child->dstate_diag_dumped = true;
	}

	/* SHADOW-ONLY wedge accounting -- both the per-syscall pair (see
	 * comment on shm->stats.syscall_wedge_count[] in include/stats.h)
	 * and the per-childop pair (see childop_wedge_count[] in the same
	 * header).  Latched via wedge_accounted so a child that stays
	 * wedged across many watchdog ticks counts as one event on both
	 * axes.  Snapshot the syscall nr and arch via SREC_SNAPSHOT (the
	 * same lockless seq-counter primitive the dstate_diag /
	 * stuck_syscall_info paths use); a snapshot give-up under writer
	 * churn skips the bump for this child but leaves the latch unset
	 * so a subsequent tick can retry.  The bump itself is gated on
	 * state >= BEFORE: a child wedged before it has published its
	 * first syscall record has no nr to attribute the time to, and
	 * counting it against nr=0 would alias every such wedge to
	 * whatever sits at index 0 of the syscall table.
	 *
	 * wedge_start_tp is seeded from child->tp -- the child's
	 * last-progress timestamp, written by the child each loop
	 * iteration and the same field the diff>=30s check above samples.
	 * Anchoring the start at last-progress rather than at the
	 * detection moment means the accumulated wedged duration covers
	 * the FULL window the slot was unreusable (the watchdog's 30 s
	 * grace period included), so the per-syscall and per-childop
	 * top-N renders share one consistent, operator-meaningful
	 * duration definition.  child->tp is CLOCK_MONOTONIC at the
	 * child's write site so the reap-time clamp (now > start) covers
	 * any torn read of the two-long timespec without depending on
	 * wall-clock monotonicity.  The early `if (old == 0)` return above
	 * has already pinned child->tp.tv_sec > 0 at this point, so the
	 * seeded start is never the zero sentinel.
	 *
	 * op_type is captured from childdata at latch time so the
	 * per-childop close-out in reap_child() attributes the wedge to
	 * the childop that was running when the stall began, even if the
	 * slot is later (post-reap) reused by a different childop -- the
	 * latch and the post-fork clean_childdata() are sequenced on the
	 * parent.  Pairs with the reap_child() close-out that adds
	 * (now - wedge_start_tp) to BOTH
	 * syscall_wedge_total_us[wedge_nr] and
	 * childop_wedge_total_us[wedge_op_type]. */
	if (!child->wedge_accounted) {
		struct syscallrecord *wrec = &child->syscall;
		unsigned int wnr;
		bool wdo32;
		enum syscallstate wstate;
		bool wgot;

		SREC_SNAPSHOT(wrec, {
			wdo32 = wrec->do32bit;
			wnr = wrec->nr;
			wstate = __atomic_load_n(&wrec->state, __ATOMIC_RELAXED);
		}, wgot);

		if (wgot && wstate >= BEFORE && wnr < MAX_NR_SYSCALL) {
			enum child_op_type wop = child->op_type;

			if ((unsigned int)wop >= NR_CHILD_OP_TYPES)
				wop = CHILD_OP_SYSCALL;

			child->wedge_nr = wnr;
			child->wedge_do32 = wdo32;
			child->wedge_op_type = wop;
			child->wedge_start_tp = child->tp;
			child->wedge_accounted = true;
			/* Gate the per-syscall axis on CHILD_OP_SYSCALL: for
			 * non-syscall childops child->syscall.nr is stale
			 * (childops issue syscalls directly without updating
			 * child->syscall), so wnr would poison the per-syscall
			 * counter with childop-wedge noise.  The per-childop
			 * axis is authoritative for those. */
			if (wop == CHILD_OP_SYSCALL)
				__atomic_add_fetch(&shm->stats.syscall_wedge_count[wnr],
						   1UL, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.wedge_count[wop],
					   1UL, __ATOMIC_RELAXED);
		}
	}

	if (state == 'D') {
		if (!child->kill_in_flight)
			stuck_syscall_info(child, childno);
		kill_pid(pid);
		__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
		child->kill_in_flight = true;
		return false;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff >= 30) {
		if (!child->kill_in_flight)
			stuck_syscall_info(child, childno);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				childno, pid);
		__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
		child->kill_in_flight = true;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return false;

	debugf("sending another SIGKILL to child %u (pid:%u). [kill count:%u] [diff:%lu]\n",
		childno, pid,
		__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED), diff);
	__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
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

		if ((rnd_u32() & 1U)) {
			if (pid_alive(pid) == true) {
				kill_pid(pid);
				killed++;
			}
		}
		if (killed == (max_children / 4))
			break;
	}
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
	time_t now_mono = (time_t)(mono_ns() / 1000000000ULL);
	time_t lifetime;
	int exit_status;

	if (spawn_times == NULL)
		return;

	/* spawn_times[] and now_mono are both CLOCK_MONOTONIC seconds,
	 * so a wall-clock NTP step between spawn and reap can no longer
	 * drive the computed lifetime negative and trip a spurious
	 * fast-die classification (which would fill the ring and panic
	 * EXIT_SHM_CORRUPTION on what is really just a clock skew).
	 * Saturating subtraction stays as belt-and-braces: if a slot's
	 * spawn stamp was ever missed, the fallback lifetime is 0. */
	if (spawn_times[childno] != 0 && now_mono >= spawn_times[childno])
		lifetime = now_mono - spawn_times[childno];
	else
		lifetime = 0;

	if (WIFEXITED(childstatus))
		exit_status = WEXITSTATUS(childstatus);
	else if (WIFSIGNALED(childstatus))
		exit_status = -WTERMSIG(childstatus);
	else
		return;

	r = &reap_ring[reap_ring_head];

	/* When the ring is full, the slot we are about to overwrite
	 * carries a previous reap; if it was fast-die, drop it from the
	 * running count before we stamp the new entry on top. */
	if (reap_ring_count == FAST_DIE_RING_SIZE &&
	    reap_entry_is_fast_die(r))
		reap_ring_fast_die_count--;

	r->reaped_at = time(NULL);
	r->lifetime = lifetime;
	r->exit_status = exit_status;
	r->childno = childno;

	if (reap_entry_is_fast_die(r))
		reap_ring_fast_die_count++;

	reap_ring_head = (reap_ring_head + 1) % FAST_DIE_RING_SIZE;
	if (reap_ring_count < FAST_DIE_RING_SIZE)
		reap_ring_count++;

	if (reap_ring_count < FAST_DIE_RING_SIZE)
		return;

	/* Bail only when EVERY entry is fast-die.  Signal-deaths are
	 * negative, EXIT_SUCCESS is 0 -- both fail reap_entry_is_fast_die,
	 * so a single benign reap drops the running count below the
	 * threshold and clears the bail. */
	if (reap_ring_fast_die_count == FAST_DIE_RING_SIZE)
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

unsigned int stall_count;

void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		unsigned long op_nr;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		if (is_child_making_progress(child, i) == false)
			stall_count++;

		op_nr = __atomic_load_n(&child->op_nr, __ATOMIC_RELAXED);
		if (op_nr > hiscore)
			hiscore = op_nr;
	}

	if (stall_count == __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED))
		stall_genocide();
}

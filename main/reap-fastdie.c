#include <stdbool.h>
#include <sys/wait.h>
#include <time.h>

#include "params.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"
#include "reap-internal.h"

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

void record_reap(int childno, int childstatus)
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

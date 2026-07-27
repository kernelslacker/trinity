/*
 * Syscall activation / deactivation helpers.
 *
 * Carved out of tables/tables.c: this file owns the cost-pool-aware
 * activate_syscall_in_table() / deactivate_syscall_in_table() pair,
 * plus the pool-partition invariant assertion and the lock-taking /
 * lock-free deactivation wrappers the pickers and auto-disable path
 * call into.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "uid.h"
#include "utils.h"

/*
 * Authoritative cost-pool classification for a table index.  Reads the
 * read-only EXPENSIVE bitmap that select_syscall_tables() built once at
 * init from the syscallentry->flags & EXPENSIVE flag; the bitmap is
 * never modified at runtime, so this is safe from concurrent scribbles
 * onto the shared syscallentry copy.
 *
 * NEVER infer the pool from a live-mutable counter or from the current
 * contents of the pool arrays -- the bitmap is the single source of
 * truth for "which pool this syscall belongs in", and every activate /
 * deactivate site must consult it directly so a torn pool array can be
 * detected by the partition-completeness assertion, not silently
 * ratified by a self-consistency read.
 */
static bool cost_pool_of(unsigned int calln, bool do32)
{
	return syscall_is_expensive(calln, do32);
}

/*
 * Partition-completeness assertion.  With the flat active_syscalls[]
 * and the pool arrays maintained in lock-step, the pool counts must
 * exactly cover the flat count at every stable point.  Any drift means
 * an activate / deactivate site desynchronised the two views, which is
 * a bug the later O(1) cost-selector phases MUST NOT see -- so panic
 * loudly at development time rather than let the pools rot into
 * unusable state.
 */
static void assert_pool_partition(unsigned int nr_active,
				  unsigned int nr_active_cheap,
				  unsigned int nr_active_exp)
{
	if (nr_active_cheap + nr_active_exp != nr_active) {
		output(0, "[tables] pool-partition drift: flat=%u cheap=%u exp=%u (sum=%u)\n",
		       nr_active, nr_active_cheap, nr_active_exp,
		       nr_active_cheap + nr_active_exp);
		exit(EXIT_FAILURE);
	}
}

void activate_syscall_in_table(unsigned int calln, unsigned int *nr_active,
			       const struct syscalltable *table,
			       int *active_syscall, bool do32,
			       int *active_cheap, unsigned int *nr_active_cheap,
			       int *active_expensive, unsigned int *nr_active_exp)
{
	struct syscallentry *entry = table[calln].entry;
	int *pool;
	unsigned int *nr_pool;

	/*
	 * Gate ineligible entries out of active_syscalls[] at construction
	 * so the flat array is authoritative.  AVOID_SYSCALL / NI_SYSCALL
	 * would otherwise sit in the active prefix and get filtered only at
	 * pick-time by validate_specific_syscall_silent(), keeping validate
	 * on the O(1) picker hot path.  NEEDS_ROOT is dropped here for the
	 * same reason on non-root runs.  All activation paths (mark_all_
	 * syscalls_active_*, setup_syscall_group_*, toggle_syscall_n,
	 * enable_random_syscalls_*) funnel through this function, so a
	 * single skip covers every mode.
	 */
	if (entry->flags & (AVOID_SYSCALL | NI_SYSCALL))
		return;

	if ((entry->flags & NEEDS_ROOT) && orig_uid != 0)
		return;

	//Check if the call is activated already, and activate it only if needed
	if (syscall_rt(entry)->active_number == 0) {
		//Sanity check
		if ((*nr_active + 1) > MAX_NR_SYSCALL) {
			output(0, "[tables] MAX_NR_SYSCALL needs to be increased. More syscalls than active table can fit.\n");
			exit(EXIT_FAILURE);
		}

		//save the call no
		active_syscall[*nr_active] = calln + 1;
		(*nr_active) += 1;
		syscall_rt(entry)->active_number = *nr_active;

		/*
		 * Cost-pool routing: mirror the flat-array append into the
		 * cheap or expensive pool, taking the pool from the
		 * authoritative EXPENSIVE bitmap (never inferred).  Same
		 * val = calln + 1 encoding, and pool_number is the pool's
		 * back-index (1 + slot) so deactivate can swap-with-last
		 * in O(1) just like the flat side.
		 */
		if (cost_pool_of(calln, do32)) {
			pool = active_expensive;
			nr_pool = nr_active_exp;
		} else {
			pool = active_cheap;
			nr_pool = nr_active_cheap;
		}
		pool[*nr_pool] = calln + 1;
		(*nr_pool) += 1;
		syscall_rt(entry)->pool_number = *nr_pool;
	}

	assert_pool_partition(*nr_active, *nr_active_cheap, *nr_active_exp);
}

void deactivate_syscall_in_table(unsigned int calln, unsigned int *nr_active,
				 const struct syscalltable *table,
				 int *active_syscall, bool do32,
				 int *active_cheap, unsigned int *nr_active_cheap,
				 int *active_expensive, unsigned int *nr_active_exp)
{
	struct syscallentry *entry;
	int *pool;
	unsigned int *nr_pool;

	entry = table[calln].entry;

	//Check if the call is activated already, and deactivate it only if needed
	if ((syscall_rt(entry)->active_number != 0) && (*nr_active > 0)) {
		unsigned int idx = syscall_rt(entry)->active_number - 1;
		unsigned int last = *nr_active - 1;

		// Swap with the last active entry to avoid O(N) memmove.
		if (idx != last) {
			active_syscall[idx] = active_syscall[last];
			syscall_rt(table[active_syscall[idx] - 1].entry)->active_number = idx + 1;
		}
		active_syscall[last] = 0;
		(*nr_active) -= 1;
		syscall_rt(entry)->active_number = 0;

		/*
		 * Cost-pool mirror: same swap-with-last shape, but the
		 * displaced neighbour's pool_number gets rewritten instead
		 * of its active_number.  Pool selection is taken from the
		 * authoritative bitmap for THIS entry -- not from a lookup
		 * on the neighbour, and not by scanning either pool for
		 * calln.  pool_number must have been set at activate time,
		 * so nr_pool > 0 whenever active_number != 0; the guard on
		 * *nr_pool below is defence-in-depth.
		 */
		if (syscall_rt(entry)->pool_number != 0) {
			if (cost_pool_of(calln, do32)) {
				pool = active_expensive;
				nr_pool = nr_active_exp;
			} else {
				pool = active_cheap;
				nr_pool = nr_active_cheap;
			}
			if (*nr_pool > 0) {
				unsigned int pidx = syscall_rt(entry)->pool_number - 1;
				unsigned int plast = *nr_pool - 1;

				if (pidx != plast) {
					pool[pidx] = pool[plast];
					syscall_rt(table[pool[pidx] - 1].entry)->pool_number = pidx + 1;
				}
				pool[plast] = 0;
				(*nr_pool) -= 1;
			}
			syscall_rt(entry)->pool_number = 0;
		}
	}

	assert_pool_partition(*nr_active, *nr_active_cheap, *nr_active_exp);
}

/*
 * Remove a syscall from the active table.  Caller must already hold
 * shm->syscalltable_lock; the swap-with-last update mutates the shared
 * active_syscall[] array and syscall_rt(entry)->active_number atomically with the
 * *nr_active counter, and those three fields must be consistent for
 * concurrent pickers.
 */
void deactivate_syscall_nolock(unsigned int call, bool do32bit)
{
	if (biarch == false) {
		deactivate_syscall_uniarch(call);
	} else {
		if (do32bit == true)
			deactivate_syscall32(call);
		else
			deactivate_syscall64(call);
	}
}

/*
 * Lock-taking wrapper for picker-side deactivations.  Pickers run
 * concurrently across children and previously mutated the active table
 * with no serialisation, which could leave duplicate active entries,
 * stale entries, a wrong active_number, or a drifted nr_active count
 * when two children deactivated overlapping slots.  The active_number
 * recheck under the lock mirrors deactivate_enosys() in syscall.c and
 * absorbs a concurrent removal by a sibling.
 */
void deactivate_syscall_locked(unsigned int call, bool do32bit)
{
	struct syscallentry *entry;

	lock(&shm->syscalltable_lock);

	entry = get_syscall_entry(call, do32bit);
	if (entry == NULL)
		goto already_done;

	/* Another child may have raced us and already removed this slot. */
	if (syscall_rt(entry)->active_number == 0)
		goto already_done;

	deactivate_syscall_nolock(call, do32bit);
already_done:
	unlock(&shm->syscalltable_lock);
}

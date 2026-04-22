/*
 * Call a single random syscall with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "edgepair.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

static int *active_syscalls;

static bool choose_syscall_table(unsigned int *nr_syscalls_out)
{
	bool do32 = false;

	if (biarch == false) {
		active_syscalls = shm->active_syscalls;
	} else {

		/* First, check that we have syscalls enabled in either table. */
		if (validate_syscall_table_64() == false) {
			use_64bit = false;
			/* If no 64bit syscalls enabled, force 32bit. */
			do32 = true;
		}

		if (validate_syscall_table_32() == false)
			use_32bit = false;

		/* If both tables enabled, pick randomly. */
		if ((use_64bit == true) && (use_32bit == true)) {
			/* 10% possibility of a 32bit syscall */
			if (ONE_IN(10))
				do32 = true;
		}

		if (do32 == false) {
			syscalls = syscalls_64bit;
			active_syscalls = shm->active_syscalls64;
			*nr_syscalls_out = max_nr_64bit_syscalls;
		} else {
			syscalls = syscalls_32bit;
			active_syscalls = shm->active_syscalls32;
			*nr_syscalls_out = max_nr_32bit_syscalls;
		}
	}
	return do32;
}

/*
 * Check if a syscall entry belongs to the target group.
 * Used by group biasing to filter candidates.
 */
static bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group)
{
	struct syscallentry *entry;

	entry = get_syscall_entry(nr, do32);
	if (entry == NULL)
		return false;

	return entry->group == target_group;
}

static bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int group_attempts = 0;
	unsigned int kcov_attempts = 0;
	unsigned int edgepair_attempts = 0;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Bail if we have spent too many iterations failing to pick a
	 * usable syscall.  Without this cap, a sparse active_syscalls
	 * table or a table dominated by EXPENSIVE syscalls (kept at
	 * 1-in-1000) can wedge the child in a tight retry loop. */
	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr exceeded retry budget\n", getpid());
		return FAIL;
	}

	/* Ok, we're doing another syscall, let's pick one. */
	do32 = choose_syscall_table(&nr_syscalls);
	if (biarch == false)
		nr_syscalls = max_nr_syscalls;
	syscallnr = rand() % nr_syscalls;

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	val = active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		deactivate_syscall(syscallnr, do32);
		goto retry;
	}

	entry = get_syscall_entry(syscallnr, do32);
	if (entry->flags & EXPENSIVE) {
		if (!ONE_IN(1000))
			goto retry;
	}

	/*
	 * Group biasing: when enabled and we have a previous group context,
	 * bias selection toward syscalls in the same group.
	 *
	 * 70% of the time: prefer same group as last call
	 * 25% of the time: accept any syscall (no bias)
	 *  5% of the time: accept any syscall (exploration)
	 *
	 * If we can't find a same-group syscall after 20 attempts,
	 * fall through and accept whatever we picked.
	 */
	if (group_bias && child->last_group != GROUP_NONE) {
		unsigned int dice = rand() % 100;

		if (dice < 70) {
			/* Try to pick from same group */
			if (!syscall_in_group(syscallnr, do32, child->last_group)) {
				group_attempts++;
				if (group_attempts < 20)
					goto retry;
				/* Gave up, accept this one. */
			}
		}
		/* dice >= 70: accept any syscall */
	}

	/* Coverage-guided cold avoidance: if this syscall has stopped
	 * finding new edges, skip it with a probability that grows the
	 * staler it gets — a syscall stuck for one threshold-window gets
	 * the same 50% baseline as before, but one stuck for ten gets
	 * skipped 90% of the time. */
	{
		unsigned int skip_pct = kcov_syscall_cold_skip_pct(syscallnr);

		if (skip_pct > 0 && (unsigned int)(rand() % 100) < skip_pct) {
			kcov_attempts++;
			if (kcov_attempts < 20)
				goto retry;
		}
	}

	/* Edge-pair sequence biasing: if we have a previous syscall,
	 * prefer pairs that have produced new edges before.
	 * Skip cold pairs (haven't found new edges recently) 50% of
	 * the time.  Boost productive pairs by accepting them
	 * immediately when we'd otherwise retry. */
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV) {
		if (edgepair_is_cold(child->last_syscall_nr, syscallnr) &&
		    RAND_BOOL()) {
			edgepair_attempts++;
			if (edgepair_attempts < 20)
				goto retry;
		}
	}

	/* critical section for shm updates. */
	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	return true;
}

/*
 * Probability (in percent) that, when a substitute retval is offered by
 * the sequence-chain executor, one randomly-chosen arg slot is overwritten
 * with it.  Exposed here (rather than in sequence.c) because the substitution
 * itself happens between argument generation and dispatch, which lives in
 * this file.  Tunable independently of the chain length distribution.
 */
#define CHAIN_SUBST_PCT 30

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval)
{
	struct syscallrecord *rec;
	struct syscallentry *entry;
	int ret = false;
	bool do_cmp;

	rec = &child->syscall;

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	memset(rec->postbuffer, 0, POSTBUFFER_LEN);

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	if (have_substitute &&
	    (unsigned int)(rand() % 100) < CHAIN_SUBST_PCT) {
		entry = syscalls[rec->nr].entry;
		if (entry != NULL && entry->num_args > 0) {
			unsigned int slot = 1 +
				(unsigned int)(rand() % entry->num_args);

			switch (slot) {
			case 1: rec->a1 = substitute_retval; break;
			case 2: rec->a2 = substitute_retval; break;
			case 3: rec->a3 = substitute_retval; break;
			case 4: rec->a4 = substitute_retval; break;
			case 5: rec->a5 = substitute_retval; break;
			case 6: rec->a6 = substitute_retval; break;
			}
			if (minicorpus_shm != NULL)
				__atomic_fetch_add(&minicorpus_shm->chain_substitution_count,
						   1, __ATOMIC_RELAXED);
		}
	}

	output_syscall_prefix(rec);

	/* Every CMP_MODE_RATIO-th syscall, run in CMP mode to collect
	 * comparison operand hints instead of PC coverage.
	 * Every KCOV_REMOTE_RATIO-th non-CMP syscall, use KCOV_REMOTE_ENABLE
	 * to also collect coverage from softirqs/threaded-irqs/kthreads. */
	do_cmp = child->kcov.active && ONE_IN(CMP_MODE_RATIO);
	child->kcov.cmp_mode = do_cmp;
	child->kcov.remote_mode = !do_cmp && child->kcov.remote_capable &&
				  ONE_IN(KCOV_REMOTE_RATIO);

	do_syscall(rec, &child->kcov, child);

	if (do_cmp) {
		cmp_hints_collect(child->kcov.trace_buf, rec->nr);
		/* cmp-mode runs don't produce a found_new signal, so the
		 * mutator-attribution stash from generate_syscall_args has
		 * no coverage event to bind to.  Drop it instead of letting
		 * it leak into the next non-cmp syscall's commit. */
		minicorpus_mut_attrib_clear();
	} else {
		bool new_edges = kcov_collect(&child->kcov, rec->nr);

		/* Record the (prev, curr) syscall pair for sequence coverage. */
		if (child->last_syscall_nr != EDGEPAIR_NO_PREV)
			edgepair_record(child->last_syscall_nr, rec->nr, new_edges);

		/* Credit each mutator case picked during this call's
		 * arg generation, with wins iff this call found new edges. */
		minicorpus_mut_attrib_commit(new_edges);

		/* Save args that discovered new coverage, but only for
		 * syscalls without sanitise (which may stash pointers). */
		if (new_edges) {
			struct syscallentry *save_entry = get_syscall_entry(rec->nr, rec->do32bit);

			if (save_entry != NULL && save_entry->sanitise == NULL)
				minicorpus_save(rec);
		}
	}

	output_syscall_postfix(rec);

	handle_syscall_ret(rec);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry != NULL) {
		/* FD leak tracking: count successful fd-creating and
		 * fd-closing syscalls per child for leak diagnosis. */
		if (rec->retval != -1UL) {
			if (entry->rettype == RET_FD) {
				child->fd_created++;
				if (entry->group < NR_GROUPS)
					child->fd_created_by_group[entry->group]++;
				/* Track returned fd for preferential reuse in arg generation. */
				if ((int)rec->retval > 2)
					child_fd_ring_push(&child->live_fds, (int)rec->retval);
			}
			if (strcmp(entry->name, "close") == 0)
				child->fd_closed++;
		}

		/* Track the group for biasing. */
		if (group_bias)
			child->last_group = entry->group;

		/* Track syscall number for edge-pair sequence coverage. */
		child->last_syscall_nr = rec->nr;
	}

	ret = true;

	return ret;
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0);
}

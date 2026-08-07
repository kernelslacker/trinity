/*
 * dispatch-wrappers.c -- public entry points into the dispatch cluster.
 *
 * The four public entry points declared in include/child.h:
 *
 *   random_syscall_step()       -- pick NR + generate args + dispatch
 *   random_syscall()            -- trivial wrapper: random_syscall_step
 *                                  with no substitute and NULL out-params
 *   random_syscall_step_biased()-- dispatch a chain-executor-supplied NR
 *                                  with fresh args (skips set_syscall_nr)
 *   replay_syscall_step()       -- replay a saved chain step through the
 *                                  mutator engine, then dispatch
 *
 * All four converge on dispatch_step() (dispatch-step.c), which runs
 * do_syscall() and all post-call bookkeeping.  The wrappers differ only
 * in how rec->nr / rec->do32bit / rec->a1..a6 are populated before the
 * call.  Bias and replay paths both set child->strategy_at_pick = -1
 * so their novelty is not misattributed to the current bandit arm.
 */

#include <string.h>

#include "arch.h"
#include "child.h"
#include "minicorpus.h"
#include "random-syscall-internal.h"
#include "sanitise.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	bool ok;

	/* Untraced dispatch-shape denominator.  Bump attempts BEFORE
	 * set_syscall_nr() so a picker-declined NR (deactivated,
	 * missing capability, biased-consumer reject) still counts as
	 * an attempt -- the completion counter at the tail then
	 * surfaces the attempt/completion gap. */
	__atomic_add_fetch(&shm->stats.syscall_dispatch.random_syscall_attempts,
			   1, __ATOMIC_RELAXED);

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	rec->postbuffer[0] = '\0';

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	entry = get_syscall_entry(rec->nr, rec->do32bit);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	ok = dispatch_step(child, entry, found_new, new_cmp_out,
			   new_transition_out);

	/* dispatch_step returning here normally means do_syscall() ran
	 * (regardless of the syscall's own success/failure); count as one
	 * completed random-syscall dispatch.  A pre-dispatch bail
	 * (set_syscall_nr FAIL above) leaves this counter untouched, so
	 * the attempts vs completions delta is the pre-dispatch reject
	 * rate.  Gate on !rec->validator_rejected: a seal failure inside
	 * do_syscall() sets that flag and returns early before the kernel
	 * is entered -- handle_syscall_ret() still ran the arg drain, but
	 * the kernel was never reached.  Counting it as a completion would
	 * inflate the throughput metric and mask the failure signal that
	 * seal_fail_ops already captures. */
	if (!rec->validator_rejected)
		__atomic_add_fetch(
			&shm->stats.syscall_dispatch.random_syscall_completions,
			1, __ATOMIC_RELAXED);

	return ok;
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL, NULL, NULL);
}

/*
 * Fresh-args dispatch for a pre-picked syscall NR.  The chain executor
 * calls this when --chain-resource-typing=live has classified the
 * previous step as a resource producer and wants to steer the next
 * link to a random consumer of the same kind.  Skips set_syscall_nr()
 * (and its strategy attribution) exactly the way replay_syscall_step
 * does: any PC / CMP / transition novelty the biased step produces
 * gets credited to no arm, so the bandit reward signal is not
 * contaminated by an external NR override.
 *
 * Returns FAIL when the biased NR is no longer callable in this run
 * (out of range, no entry, sanitise, deactivated / AVOID / lost cap);
 * the chain executor then falls back to a plain random_syscall_step
 * for the same slot so the iteration still does useful work.
 */
bool random_syscall_step_biased(struct childdata *child,
				unsigned int bias_nr, bool bias_do32,
				bool have_substitute,
				unsigned long substitute_retval,
				bool *found_new,
				unsigned long *new_transition_out,
				unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (bias_nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(bias_nr, bias_do32);
	if (entry == NULL)
		return FAIL;

	/* Same sanitise gate replay_syscall_step uses: sanitise-bearing
	 * syscalls stash heap pointers into arg slots during
	 * generic_sanitise, and a fresh-args regeneration here would
	 * still route through generate_syscall_args -- but the bias
	 * consumer table is a static NR list, so a NR whose entry
	 * carries .sanitise cannot come out of pick_consumer(); the
	 * gate is defensive against a future table addition slipping a
	 * sanitise-tagged NR through unnoticed. */
	if (entry->sanitise != NULL)
		return FAIL;

	if (!validate_specific_syscall_silent(
			bias_do32 ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)bias_nr))
		return FAIL;

	/* Bias dispatches never credit a bandit arm.  Same rationale as
	 * replay_syscall_step: the arm at shm->current_strategy did not
	 * actually pick this NR; letting its stamp ride through
	 * dispatch_step would leak reward attribution to whichever arm
	 * happens to be current at the time of the override. */
	child->strategy_at_pick = -1;
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

	/* Publish (nr, do32bit) inside the srec bracket so an outside
	 * reader (watchdog, pre_crash_ring decode) cannot see the new
	 * (nr, do32bit) paired with the previous syscall's args.
	 * generate_syscall_args carries its own bracket for the a1..a6
	 * writes, and apply_chain_substitution writes through a1..a6
	 * again, so both come after this publish window closes. */
	srec_publish_begin(rec);
	rec->do32bit = bias_do32;
	rec->nr = bias_nr;
	srec_publish_end(rec);

	rec->postbuffer[0] = '\0';
	generate_syscall_args(rec);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

/*
 * Replay a saved chain step: stage the saved (nr, do32bit, args) into
 * rec, run the saved args through the per-arg mutator chain, apply any
 * Phase 1 retval substitution from the prior step, and dispatch through
 * the same path random_syscall_step uses.  Returns FAIL when the saved
 * syscall is no longer callable in this run (deactivated, AVOID_SYSCALL,
 * needs root we don't have, or has a sanitise that would stash stale
 * pointers); the chain executor falls back to fresh args in that case.
 *
 * The mutator call goes to minicorpus_mutate_args, which is the same
 * splice + weighted-stack-mutate engine the per-syscall mini-corpus
 * replay uses.  Sharing the mutator means chain replay automatically
 * inherits productivity tuning from the existing weighted scheduler
 * rather than duplicating the mutation logic with its own counters.
 */
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long args[6];

	if (saved->nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(saved->nr, saved->do32bit);
	if (entry == NULL)
		return FAIL;

	/* sanitise-bearing syscalls allocate and stash heap pointers into
	 * arg slots during generic_sanitise; replay would feed stale args
	 * to those slots.  Same gate the mini-corpus uses for the same
	 * reason. */
	if (entry->sanitise != NULL)
		return FAIL;

	/* The syscall may have been deactivated since the chain was saved
	 * (returned ENOSYS, hit AVOID_SYSCALL, lost a CAP_*).  Bail out
	 * rather than replay an inert call. */
	if (!validate_specific_syscall_silent(
			saved->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)saved->nr))
		return FAIL;

	memcpy(args, saved->args, sizeof(args));
	minicorpus_mutate_args(args, entry, saved->nr);

	/* Replay steps bypass set_syscall_nr() (which is where the bandit's
	 * per-arm pick stamp normally lands), so the child still holds the
	 * strategy_at_pick value from whichever fresh pick started the
	 * chain.  Letting that stale stamp ride through dispatch_step would
	 * credit replay-step PC/CMP novelty -- and the per-arm completion
	 * bump -- to an arm that did not actually pick the replayed syscall,
	 * contaminating the reward signal the bandit is meant to learn
	 * from.  Reset to the -1 sentinel so the existing strategy_at_pick
	 * gates at the consumer sites (kcov_collect_cmp / bandit_cmp_observe,
	 * the PC-edge per-strategy attribution in dispatch_step, the per-arm
	 * completion bump) all skip attribution for this step.
	 *
	 * The next fresh set_syscall_nr() overwrites strategy_at_pick
	 * unconditionally on the bandit-pool path, so leaving -1 here does
	 * not leak into subsequent non-replay calls. */
	child->strategy_at_pick = -1;

	if (chain_corpus_shm != NULL)
		__atomic_fetch_add(&chain_corpus_shm->replay_steps_dispatched,
				   1UL, __ATOMIC_RELAXED);

	/* Publish the (nr, do32bit) advance, the arg writes, the
	 * postbuffer reset, and the chain substitution as one coherent
	 * step.  An outside reader (watchdog thread, parent inspecting
	 * via shm, pre_crash_ring decode) that samples rec mid-step must
	 * not see the new (nr, do32bit) paired with the previous
	 * syscall's a1..a6 — that torn pairing miscredits args to the
	 * wrong syscall in divergence stats and crash-ring reconstruction.
	 * apply_chain_substitution writes rec->aN, so the publish_end
	 * has to come after it. */
	srec_publish_begin(rec);
	rec->do32bit = saved->do32bit;
	rec->nr = saved->nr;

	rec->a1 = args[0];
	rec->a2 = args[1];
	rec->a3 = args[2];
	rec->a4 = args[3];
	rec->a5 = args[4];
	rec->a6 = args[5];

	rec->postbuffer[0] = '\0';

	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);
	srec_publish_end(rec);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

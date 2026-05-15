/*
 * Call a single random syscall with random args.
 */

#include <errno.h>
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
#include "healer.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

/*
 * Biarch-only: pick which syscall table this call uses, refresh the
 * caller's per-child active_syscalls pointer, and return do32.  Uniarch
 * builds bypass this entirely — child->active_syscalls is set once at
 * init time to shm->active_syscalls and never re-evaluated.
 */
static bool choose_syscall_table(struct childdata *child,
				 unsigned int *nr_syscalls_out)
{
	bool do32 = false;

	/* First, check that we have syscalls enabled in either table.
	 * Read the cached validity bits maintained by validate_syscall_table_*
	 * and the deactivate_syscall{32,64}() paths instead of re-running the
	 * walk on every pick. */
	if (shm->valid_syscall_table_64 == false) {
		use_64bit = false;
		/* If no 64bit syscalls enabled, force 32bit. */
		do32 = true;
	}

	if (shm->valid_syscall_table_32 == false)
		use_32bit = false;

	/* If both tables enabled, pick randomly. */
	if ((use_64bit == true) && (use_32bit == true)) {
		/* 10% possibility of a 32bit syscall */
		if (ONE_IN(10))
			do32 = true;
	}

	if (do32 == false) {
		syscalls = syscalls_64bit;
		child->active_syscalls = shm->active_syscalls64;
		*nr_syscalls_out = max_nr_64bit_syscalls;
	} else {
		syscalls = syscalls_32bit;
		child->active_syscalls = shm->active_syscalls32;
		*nr_syscalls_out = max_nr_32bit_syscalls;
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

/*
 * Pick the syscall to run under STRATEGY_HEURISTIC: uniform draw from
 * active_syscalls, then layered biases — group affinity (70% prefer last
 * group), kcov cold-skip (probabilistic), edgepair freshness (50% skip
 * cold pairs).  This is trinity's pre-rotation default behaviour.
 */
static bool set_syscall_nr_heuristic(struct syscallrecord *rec,
				     struct childdata *child)
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

	/* Pick the syscall table once per call: in uniarch the result is
	 * a constant, and even in biarch the do32 dice rolls once per
	 * pick — re-rolling under the retry budget (up to 10 000 spins
	 * on a sparse table) burned ~5 cycles per iteration for nothing. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

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

	syscallnr = rand() % nr_syscalls;

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	val = child->active_syscalls[syscallnr];
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
 * Pick the syscall to run under STRATEGY_RANDOM: uniform draw from
 * active_syscalls with no further biasing.  The "shake the dust off"
 * pass — useless on its own, but exposes paths the heuristic biases
 * systematically suppress (cold syscalls, productive-pair-only flow).
 *
 * Active_syscalls + EXPENSIVE + AVOID_SYSCALL gating remain because
 * those are correctness gates, not selection biases — bypassing them
 * just wastes iterations on calls we know we can't make.
 */
bool set_syscall_nr_random(struct syscallrecord *rec,
			    struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;

	/* See the matching comment in set_syscall_nr_heuristic — the table
	 * pick is a per-call decision, not a per-retry one. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_random exceeded retry budget\n", getpid());
		return FAIL;
	}

	syscallnr = rand() % nr_syscalls;

	val = child->active_syscalls[syscallnr];
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

	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	return true;
}

/*
 * Pick the syscall to run under STRATEGY_COVERAGE_FRONTIER: uniform draw
 * from active_syscalls, then biased acceptance against the per-syscall
 * frontier-edge weight via rejection sampling.  Each candidate is
 * accepted with probability (frontier_recent_count(nr) + 1) /
 * (max_weight + 1); the +1 keeps cold syscalls from starving completely
 * and lets the strategy still drive forward when no syscall has
 * produced a frontier edge in the last K windows (every weight is 1, so
 * acceptance reduces to uniform).
 *
 * max_weight is read once at the top of the function from the cached
 * shm->frontier_max_weight_cached so the bias mass stays stable across
 * the inner retry loop, and so concurrent kcov_collect-driven bumps to
 * frontier_history during the pick don't perturb the acceptance
 * probability mid-call.  The cache is recomputed authoritatively on
 * each window rotation by frontier_window_advance() and ratcheted
 * upward on new-edge bumps by frontier_record_new_edge(), turning what
 * used to be an O(MAX_NR_SYSCALL) walk per pick into a single RELAXED
 * load.
 *
 * The validate / EXPENSIVE / AVOID_SYSCALL retry budget mirrors the
 * other set_syscall_nr_* variants because those are correctness gates,
 * not selection biases.
 */
static bool set_syscall_nr_coverage_frontier(struct syscallrecord *rec,
					     struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	unsigned int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	unsigned long max_weight;

	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

	max_weight = __atomic_load_n(&shm->frontier_max_weight_cached,
				     __ATOMIC_RELAXED);

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_coverage_frontier exceeded retry budget\n", getpid());
		return FAIL;
	}

	syscallnr = rand() % nr_syscalls;

	val = child->active_syscalls[syscallnr];
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

	/* Frontier-weighted acceptance.  When max_weight is 0 (no syscall
	 * has registered a frontier edge in the last FRONTIER_DECAY_WINDOWS
	 * rotations -- typical at run start or in a heavily-explored
	 * codebase where everything has plateaued), the (w+1)/(max+1) ratio
	 * is 1 for every candidate and the acceptance gate is bypassed,
	 * degenerating gracefully to uniform pick. */
	if (max_weight > 0) {
		unsigned long w = frontier_recent_count(syscallnr);
		unsigned long denom = max_weight + 1UL;
		unsigned long roll = (unsigned long)rand() % denom;

		if (roll >= w + 1UL)
			goto retry;
	}

	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	__atomic_fetch_add(&shm->stats.frontier_strategy_picks, 1UL,
			   __ATOMIC_RELAXED);

	return true;
}

/*
 * Dispatch syscall selection through the active strategy's picker.
 * Reads shm->current_strategy with relaxed atomic — the value can change
 * mid-call (another child wins the rotation CAS) but the worst case is a
 * single misattribution at the boundary, which is acceptable noise over
 * a 1M-op window.  Out-of-range guard preserves correctness even if a
 * wild write into shm corrupts the strategy index.
 */
static bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child)
{
	int strat;

	/* Explorer-pool children bypass the bandit's current pick and run
	 * STRATEGY_RANDOM unconditionally -- including when the bandit has
	 * picked STRATEGY_COVERAGE_FRONTIER.  The pool is the always-on
	 * uniform baseline that lets the bandit's reward signal stay honest
	 * even when its winning arm goes stale. */
	if (child->is_explorer) {
		__atomic_fetch_add(&shm->stats.strategy_explorer_picks, 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	strat = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);

	if (strat < 0 || strat >= NR_STRATEGIES)
		strat = STRATEGY_HEURISTIC;

	switch (strat) {
	case STRATEGY_HEURISTIC:
		return set_syscall_nr_heuristic(rec, child);
	case STRATEGY_RANDOM:
		return set_syscall_nr_random(rec, child);
	case STRATEGY_COVERAGE_FRONTIER:
		return set_syscall_nr_coverage_frontier(rec, child);
	case STRATEGY_HEALER:
		return set_syscall_nr_healer(rec, child);
	default:
		__builtin_unreachable();
	}
}

/*
 * Probability (in percent) that, when a substitute retval is offered by
 * the sequence-chain executor, one randomly-chosen arg slot is overwritten
 * with it.  Exposed here (rather than in sequence.c) because the substitution
 * itself happens between argument generation and dispatch, which lives in
 * this file.  Tunable independently of the chain length distribution.
 */
#define CHAIN_SUBST_PCT 30

/*
 * Substituting the previous syscall's return value (almost always a
 * small integer — fd, retval, error code) into a pointer-typed arg
 * slot produces a wild pointer.  The rendering path then SEGVs in
 * printf("%s", small_int) → strlen(0x402), or the kernel deref'es a
 * wild address, depending on which slot got stomped.  Restrict
 * substitution to slots whose argtype legitimately accepts a numeric
 * value.
 */
static bool argtype_accepts_numeric_substitute(enum argtype t)
{
	switch (t) {
	case ARG_UNDEFINED:
	case ARG_FD:
	case ARG_LEN:
	case ARG_MODE_T:
	case ARG_PID:
	case ARG_KEY_SERIAL:
	case ARG_TIMERID:
	case ARG_AIO_CTX:
	case ARG_SEM_ID:
	case ARG_MSG_ID:
	case ARG_SYSV_SHM:
	case ARG_RANGE:
	case ARG_OP:
	case ARG_LIST:
	case ARG_CPU:
	case ARG_NUMA_NODE:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
	case ARG_FD_BPF_BTF:
	case ARG_FD_BPF_LINK:
	case ARG_FD_BPF_MAP:
	case ARG_FD_BPF_PROG:
	case ARG_FD_EPOLL:
	case ARG_FD_EVENTFD:
	case ARG_FD_FANOTIFY:
	case ARG_FD_FS_CTX:
	case ARG_FD_INOTIFY:
	case ARG_FD_IO_URING:
	case ARG_FD_LANDLOCK:
	case ARG_FD_MEMFD:
	case ARG_FD_MOUNT:
	case ARG_FD_MQ:
	case ARG_FD_PERF:
	case ARG_FD_PIDFD:
	case ARG_FD_PIPE:
	case ARG_FD_SIGNALFD:
	case ARG_FD_SOCKET:
	case ARG_FD_TIMERFD:
		return true;
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_PATHNAME:
	case ARG_IOVEC:
	case ARG_SOCKADDR:
	case ARG_MMAP:
	case ARG_SOCKETINFO:
		return false;
	}
	return false;
}

/*
 * Build the numeric-substitute slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from
 * copy_syscall_table() in tables.c; the cached mask in
 * entry->numeric_substitute_mask then drives apply_chain_substitution()
 * below without re-walking argtype[] or re-running the 23-case
 * argtype_accepts_numeric_substitute() switch on every chain step.
 * Bit k (k=0..5) set means slot (k+1) accepts a numeric substitute.
 */
uint8_t compute_numeric_substitute_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (argtype_accepts_numeric_substitute(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Apply Phase 1 retval substitution to rec in place.  Used by both the
 * fresh-args path (random_syscall_step) and the corpus-replay path
 * (replay_syscall_step) so the chain semantics — substituted args reach
 * the kernel and show up in the trace — are identical regardless of
 * where the args came from.  No-op when no substitute is offered, the
 * dice roll comes up against, the syscall takes zero args, or no arg
 * slot has a numeric-substitute-compatible argtype.
 */
static void apply_chain_substitution(struct syscallrecord *rec,
				     struct syscallentry *entry,
				     bool have_substitute,
				     unsigned long substitute_retval)
{
	unsigned int draw, slot;
	uint8_t mask;

	if (!have_substitute)
		return;
	if (entry == NULL || entry->num_args == 0)
		return;
	if ((unsigned int)(rand() % 100) >= CHAIN_SUBST_PCT)
		return;

	mask = entry->numeric_substitute_mask;
	if (mask == 0)
		return;

	/*
	 * Pick a slot via __builtin_ctz of a masked random draw against
	 * the precomputed mask.  When the masked draw lands on zero (no
	 * eligible slot bit overlapped this iteration's random bits) fall
	 * back to the mask itself so __builtin_ctz still picks the
	 * lowest-numbered eligible slot.  Same slots remain eligible as
	 * the old per-call safe_slots[] walk — only the dispatch
	 * mechanism changes.
	 */
	draw = (unsigned int)rand() & mask;
	if (draw == 0)
		draw = mask;
	slot = (unsigned int)__builtin_ctz(draw) + 1;

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

/*
 * Check the rotation boundary and, if crossed, atomically claim the
 * switch and update shm->current_strategy to whatever the configured
 * picker (round-robin or UCB1 bandit, see strategy.h) selects next.
 *
 * The rotation clock is shm->stats.op_count (fleet-wide ops, including
 * non-syscall alt-ops — every child contributes ticks at the same rate).
 * A child that observes (op_count - syscalls_at_last_switch) >=
 * STRATEGY_WINDOW tries to CAS syscalls_at_last_switch forward to the
 * current op_count; the CAS winner performs the switch and emits the
 * stats line, the losers fall through and continue with the new strategy
 * on their next syscall pick.
 *
 * Per-strategy attribution: the just-finished window's edge delta is
 * computed as edges_by_strategy[prev] - edges_at_window_start.  After
 * the switch, edges_at_window_start is reseeded with the new strategy's
 * current cumulative edge count, so the next switch will compute the
 * delta correctly even if other strategies' counters are bumped during
 * the grace period.
 */
static void maybe_rotate_strategy(void)
{
	unsigned long now;
	unsigned long last;
	int prev, next;
	unsigned long edges_now, edges_in_window, syscalls_in_window;
	unsigned long cmp_now, cmp_in_window;

	/* Read fleet op_count off the parent-published mirror page; the
	 * canonical aggregate is parent-private and not visible to children.
	 * The mirror is republished once per parent main_loop iteration so
	 * a stale read here only delays the rotation by drain cadence. */
	now = (shm_published != NULL)
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	last = __atomic_load_n(&shm->syscalls_at_last_switch, __ATOMIC_RELAXED);

	if (now - last < STRATEGY_WINDOW)
		return;

	if (!__atomic_compare_exchange_n(&shm->syscalls_at_last_switch,
					 &last, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	prev = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	if (prev < 0 || prev >= NR_STRATEGIES)
		prev = STRATEGY_HEURISTIC;

	edges_now = __atomic_load_n(&shm->edges_by_strategy[prev], __ATOMIC_RELAXED);
	edges_in_window = edges_now - shm->edges_at_window_start;
	syscalls_in_window = now - last;

	/* CMP-novelty delta: number of comparison constants the active arm
	 * exposed for the first time within CMP_NOVELTY_DECAY_WINDOWS this
	 * window.  Folded into the bandit reward by bandit_record_pull as
	 * a 0.25-weight secondary signal so an arm whose PC growth has
	 * plateaued but whose validation surface is still mutating doesn't
	 * lose to a noisier arm on PC delta alone. */
	cmp_now = __atomic_load_n(&shm->bandit_cmp_new_constants[prev],
				  __ATOMIC_RELAXED);
	cmp_in_window = cmp_now - shm->bandit_cmp_at_window_start;

	/* Feed the just-finished window into the bandit before asking
	 * the picker to choose the next arm, so UCB1 sees up-to-date
	 * pulls/reward when scoring.  Round-robin mode ignores the
	 * counters but the bookkeeping is harmless and lets the
	 * end-of-run summary print pulls under either picker. */
	bandit_record_pull(prev, edges_in_window, cmp_in_window);

	/* Tick the rotation counter so bandit_cmp_observe()'s per-syscall
	 * bloom decay sees the new window index on subsequent calls.
	 * Bumped after bandit_record_pull so a concurrent observer racing
	 * the rotation either sees the old (still-valid) window or the
	 * fresh one — both attribute correctly. */
	__atomic_fetch_add(&shm->bandit_window_count, 1UL, __ATOMIC_RELAXED);

	/* Roll the per-syscall frontier-edge ring forward and zero the new
	 * slot so it represents only edges discovered in the upcoming
	 * window.  Same K-window decay horizon as the CMP-novelty bloom
	 * above. */
	frontier_window_advance();

	next = pick_next_strategy(prev);
	if (next < 0 || next >= NR_STRATEGIES)
		next = (prev + 1) % NR_STRATEGIES;

	shm->edges_at_window_start =
		__atomic_load_n(&shm->edges_by_strategy[next], __ATOMIC_RELAXED);
	shm->bandit_cmp_at_window_start =
		__atomic_load_n(&shm->bandit_cmp_new_constants[next],
				__ATOMIC_RELAXED);
	__atomic_store_n(&shm->current_strategy, next, __ATOMIC_RELEASE);

	output(0, "strategy: switched to %s (%d) (prev %s (%d): edges=%lu, syscalls=%lu, cmp_novel=%lu)\n",
	       strategy_name(next), next,
	       strategy_name(prev), prev,
	       edges_in_window, syscalls_in_window, cmp_in_window);
}

/*
 * Dispatch a fully-prepared syscallrecord and run the per-call
 * post-dispatch bookkeeping: kcov collection / cmp-hint collection,
 * edge-pair recording, mutator-attribution commit, mini-corpus save,
 * trace output, fd-ring update, group/last_syscall_nr tracking.
 *
 * Caller has already populated rec->nr, rec->do32bit, rec->a1..a6, the
 * postbuffer is already cleared, and any chain substitution has been
 * applied.  The two callers (random_syscall_step and replay_syscall_step)
 * differ only in how they got the args into rec; everything from
 * output_syscall_prefix forward is shared.
 */
static bool dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	bool new_edges;
	unsigned long edges_before = 0, edges_after, edges_delta;
	bool have_kcov_counter = (kcov_shm != NULL);

	/* Stamp the resolved entry on the rec so .sanitise / .post handlers
	 * (and helpers like this_syscallname()) can reach it without
	 * re-running get_syscall_entry(nr, do32bit) on every probe. */
	rec->entry = entry;

	output_syscall_prefix(rec, entry);

	/* PC and CMP coverage now run on separate kcov fds in parallel,
	 * so every syscall produces both — no more 1-in-N tradeoff between
	 * the two.  The only remaining mode toggle is whether to use
	 * KCOV_REMOTE_ENABLE on the PC fd to also pick up softirq /
	 * threaded-irq / kthread coverage. */
	child->kcov.remote_mode = child->kcov.remote_capable &&
				  ONE_IN(KCOV_REMOTE_RATIO);

	do_syscall(rec, entry, &child->kcov, child);

	/* Snapshot edges_found around kcov_collect so the per-syscall
	 * attribution counters below can be bumped by the actual count of
	 * distinct new edges this call produced (kcov_collect() returns a
	 * bool, so the count has to be reconstructed here from the global
	 * counter delta). */
	if (have_kcov_counter)
		edges_before = __atomic_load_n(&kcov_shm->edges_found,
					       __ATOMIC_RELAXED);

	new_edges = kcov_collect(&child->kcov, rec->nr);
	kcov_collect_cmp(&child->kcov, rec->nr, child->is_explorer);

	if (have_kcov_counter) {
		edges_after = __atomic_load_n(&kcov_shm->edges_found,
					      __ATOMIC_RELAXED);
		edges_delta = (edges_after >= edges_before)
			? (edges_after - edges_before) : 0;
	} else {
		edges_delta = 0;
	}

	/* Per-syscall new-edge attribution split by strategy pool.  Skipped
	 * when the call produced no new edges (the dump only consumes the
	 * positive delta side) and when rec->nr falls outside the table.
	 * Biarch attribution follows the same raw-rec->nr indexing the
	 * existing kcov_shm->per_syscall_edges array uses; the dump iterates
	 * only the active 64-bit table when biarch, so 32-bit calls are
	 * effectively ignored there as they are everywhere else. */
	if (edges_delta > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.edges_per_syscall_explorer
			: shm->stats.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], edges_delta,
				   __ATOMIC_RELAXED);
	}

	/* Surface this step's new-coverage signal to the chain executor
	 * (when called via run_sequence_chain). */
	if (found_new != NULL)
		*found_new = new_edges;

	/* Record the (prev, curr) syscall pair for sequence coverage. */
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV)
		edgepair_record(child->last_syscall_nr, rec->nr, new_edges);

	/* Credit each mutator case picked during this call's arg
	 * generation, with wins iff this call found new edges. */
	minicorpus_mut_attrib_commit(new_edges);

	/* Save args that discovered new coverage, but only for
	 * syscalls without sanitise (which may stash pointers). */
	if (unlikely(new_edges)) {
		if (entry->sanitise == NULL)
			minicorpus_save(rec);

		/* HEALER Phase A observer -- credit the (predset -> rec->nr)
		 * relation for this new-edge event.  Reads the per-child
		 * sequence buffer's two predecessor slots; the buffer is
		 * pushed below (alongside last_syscall_nr) so the read here
		 * sees the two completed syscalls before the current one,
		 * which is exactly the predset the new edge should be
		 * credited to. */
		if (!no_healer)
			healer_observe_relation(child, rec->nr);

		/* Single-predecessor companion to the (predset -> nr) bump
		 * above.  Same new-edge gating, but the pair table is the
		 * coarser (immediate-pred -> nr) signal that the static-seed
		 * loader bootstraps from ret_objtype/argtype metadata --
		 * firing the bump alongside the relation observer keeps the
		 * pair side learning from runtime evidence too instead of
		 * staying frozen at the static seed forever.  child->last_
		 * syscall_nr is the immediate predecessor (mirrors the
		 * edgepair_record() call above) and is still the prior
		 * value here -- it gets updated to rec->nr further down,
		 * after this block.  An EDGEPAIR_NO_PREV sentinel value
		 * (0xFFFF, e.g. on the first syscall of a child's life) is
		 * filtered by healer_pair_observe()'s own MAX_NR_SYSCALL
		 * guard, so no extra check is needed here. */
		if (!no_healer)
			healer_pair_observe(child->last_syscall_nr, rec->nr);

		/* Observation-delta-triggered persistence: same shape as the
		 * minicorpus snapshot below, but gated on the cumulative
		 * HEALER observation counter rather than fleet-wide edge
		 * count.  HEALER's table needs ~24-48h to settle; without
		 * this cross-run save the table is reset on every
		 * trinity restart and the picker work in Phase B can never
		 * reach the maturity threshold its bandit-arm activation
		 * depends on. */
		healer_maybe_snapshot();

		/* Coverage-delta-triggered persistence: snapshot the
		 * minicorpus to disk every MINICORPUS_SNAPSHOT_EDGES
		 * fleet-wide edges so a crash mid-run only loses the
		 * last cadence window of state, not the whole run.
		 * Cheap fast path when the gap isn't reached; only one
		 * caller per window actually runs the save. */
		minicorpus_maybe_snapshot();

		if (child->is_explorer) {
			/* Explorer-pool discoveries are real edges and count
			 * toward the run-wide fleet totals, but skip the
			 * per-strategy reward attribution: explorers always
			 * run STRATEGY_RANDOM, so feeding their edges into
			 * the bandit's current arm would either inflate a
			 * non-RANDOM arm's reward (when the bandit picked
			 * something else) or double-count when the bandit
			 * also picked RANDOM. */
			__atomic_fetch_add(&shm->stats.explorer_pool_edges_discovered,
					   1, __ATOMIC_RELAXED);
		} else {
			/* Attribute this new edge to the strategy that was
			 * active when it was discovered.  Cumulative; the
			 * window delta is computed by maybe_rotate_strategy
			 * against shm->edges_at_window_start. */
			int strat = __atomic_load_n(&shm->current_strategy,
						    __ATOMIC_RELAXED);
			if (strat >= 0 && strat < NR_STRATEGIES)
				__atomic_fetch_add(&shm->edges_by_strategy[strat],
						   1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->stats.bandit_pool_edges_discovered,
					   1, __ATOMIC_RELAXED);
		}
	}

	output_syscall_postfix(rec);

	handle_syscall_ret(rec, entry);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	/* Also append a compact record to the per-child pre-crash ring,
	 * dumped on __BUG() to attribute the assertion to a specific
	 * recent syscall.  rec->tp was just refreshed in do_syscall(). */
	pre_crash_ring_record(child, rec, &rec->tp);

	/* Dispatch-time category histogram, surfaced under -vv.
	 * entry->syscall_category is resolved once at table-init
	 * time (copy_syscall_table) so this stays a single indexed
	 * ring enqueue on the hot path; the parent drain folds it
	 * into parent_stats.syscall_category_count[]. */
	stats_ring_enqueue(child->stats_ring,
			   STATS_FIELD_SYSCALL_CATEGORY_COUNT,
			   (uint16_t)entry->syscall_category, 1);

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
		if (entry->is_close_syscall)
			child->fd_closed++;
	}

	/* Track the group for biasing. */
	if (group_bias)
		child->last_group = entry->group;

	/* Track syscall number for edge-pair sequence coverage. */
	child->last_syscall_nr = rec->nr;

	/* Mirror the just-completed syscall into the HEALER Phase A
	 * per-child sequence buffer so the next call's observer-hook
	 * fire sees this nr as one of its two predecessors.
	 *
	 * Skip syscalls that returned -ENOSYS or -EOPNOTSUPP: the kernel
	 * dispatcher rejected the call before its body executed, so kernel
	 * state is unchanged from the previous syscall.  Crediting them as
	 * state-setting predecessors of a subsequent new-edge event would
	 * dilute attribution toward calls that did nothing. */
	if (rec->retval == -1UL &&
	    (rec->errno_post == ENOSYS || rec->errno_post == EOPNOTSUPP)) {
		/* nothing — keep the previous predecessor in place */
	} else {
		healer_seq_push(child, rec->nr);
	}

	/* Cheap end-of-call check for the strategy rotation boundary.
	 * Two relaxed loads + a compare in the common case; the CAS only
	 * fires once per ~STRATEGY_WINDOW ops fleet-wide. */
	maybe_rotate_strategy();

	return true;
}

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

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

	return dispatch_step(child, entry, found_new);
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL);
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
			 bool *found_new)
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

	/* Hold rec->lock across the (nr, do32bit) advance, the arg writes,
	 * the postbuffer reset, and the chain substitution.  An outside
	 * reader (watchdog thread, parent inspecting via shm, pre_crash_ring
	 * decode) that samples rec mid-step must not see the new (nr,
	 * do32bit) paired with the previous syscall's a1..a6 — that torn
	 * pairing miscredits args to the wrong syscall in divergence stats
	 * and crash-ring reconstruction.  apply_chain_substitution writes
	 * rec->aN, so the unlock has to come after it. */
	lock(&rec->lock);
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
	unlock(&rec->lock);

	return dispatch_step(child, entry, found_new);
}

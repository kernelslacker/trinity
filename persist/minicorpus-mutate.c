/*
 * Mini-corpus mutate + replay + attribution island.
 *
 * Applies the per-arg mutator chain (splice, xprop, weighted-stack
 * mutate) to a saved snapshot and replays it as the args for the next
 * dispatch of the same syscall.  The attribution stash that credits
 * per-op wins after the coverage signal lands lives here too because
 * it is a private temporal coupling between mutate and commit -- see
 * the module map in the split plan for why this stays one file.
 */

#include <string.h>

#include "child.h"
#include "fd.h"
#include "minicorpus.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "minicorpus-internal.h"

#define XPROP_RATIO 64

/*
 * Floor on the per-case weight in the weighted scheduler.
 *
 * Weights are scaled to [0, 1000] (see weighted_pick_case() comment).
 * A floor of 50 keeps even a thoroughly-failed case at ~5% of a winning
 * case's weight, so it still gets picked occasionally.  Without a floor,
 * a case that produced zero wins after many trials would asymptote to
 * weight 0 and never be retried — and kernel state changes underneath
 * us, so a previously-dead case can become productive later.
 */
#define MUT_WEIGHT_FLOOR 50

/*
 * Pick a mutator case 0..MUT_NUM_OPS-1 weighted by historical productivity.
 *
 * Each case's weight is the Beta(1,1)-prior posterior mean of its success
 * rate, scaled to [0, 1000]:
 *
 *     w[op] = max(MUT_WEIGHT_FLOOR, (wins[op] + 1) * 1000 / (trials[op] + 2))
 *
 * Why this formula:
 *
 *  - The Beta(1,1) prior (uniform) gives every case w=500 on cold start
 *    when trials=wins=0, so we degrade gracefully to uniform random pick
 *    until evidence accumulates.  No special-casing for the empty-stats
 *    state, no warm-up phase to misconfigure.
 *
 *  - Add-one (Laplace) smoothing in the numerator and add-two in the
 *    denominator keep the formula well-defined at trials=0 and prevent a
 *    single early success from pinning a case to weight 1000.  It's the
 *    closed-form posterior mean of a Beta-binomial, not an ad-hoc fudge.
 *
 *  - We use the posterior MEAN rather than full Thompson sampling
 *    (Beta-distribution sampling).  Thompson would also work and be
 *    technically more exploration-aware, but it requires a Gamma
 *    sampler in libc that doesn't exist; the floor + uniform-prior
 *    combination here gives most of the same exploration benefit with
 *    a few lines of integer arithmetic.
 *
 *  - The floor is on the absolute weight, not on relative pick probability.
 *    With six cases and one heavily winning, the floored cases share the
 *    remaining mass — never starved, never dominant.
 *
 * Called once per primitive mutation (not once per syscall): a 4-deep
 * stack consults the scheduler four times.  All loads are __atomic
 * RELAXED — slightly stale fleet-wide counts are fine, the scheduler
 * is statistical not exact.
 */
static unsigned int weighted_pick_case(enum argtype atype)
{
	unsigned int weights[MUT_NUM_OPS];
	unsigned int total = 0;
	unsigned int r, accum, i;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						  __ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						  __ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[i] = (unsigned int)w;
		total += weights[i];
	}

	/* Case 8 (fd-swap) only does anything useful on fd-typed slots —
	 * pulling a random pool fd into a non-fd arg would just look like
	 * a small-integer noise mutation.  Zero its weight for non-fd args
	 * so the scheduler doesn't waste pick budget on it (and so its
	 * trials/wins ratio stays a meaningful signal of fd-swap value). */
	if (!is_fdarg(atype)) {
		total -= weights[8];
		weights[8] = 0;
	}

	r = rnd_modulo_u32(total);
	accum = 0;
	for (i = 0; i < MUT_NUM_OPS; i++) {
		accum += weights[i];
		if (r < accum)
			return i;
	}
	return MUT_NUM_OPS - 1;
}

/*
 * SHADOW eligibility predicate for the Phase C.3 structure-aware arm
 * picker.  True iff the slot's argtype + arg_param payload would have
 * let try_structured_mutation() fire a type-aware variant for at least
 * one op -- i.e. the same gates that branch already enforces inline.
 * Kept here rather than reaching into try_structured_mutation() so the
 * shadow path can reject degenerate metadata (empty arglist, inverted
 * range) at the same coarse granularity the unstructured fallback
 * currently bypasses it at.
 */
static bool slot_is_structured(enum argtype atype,
		const struct arg_param *params)
{
	if (params == NULL)
		return false;

	switch (atype) {
	case ARG_LIST:
	case ARG_OP:
		return params->list.num != 0 && params->list.values != NULL;
	case ARG_RANGE:
		return params->range.hi >= params->range.low;
	default:
		return false;
	}
}

/*
 * Shadow variant of weighted_pick_case() that adds the existing
 * mut_structured_trials / mut_structured_wins per-op stats as a second
 * Beta arm alongside the live mut_trials / mut_wins arm and draws from
 * the doubled 2 * MUT_NUM_OPS pool.  The op index returned is the
 * arm's op (arm mod MUT_NUM_OPS); the caller treats arms 0..N-1 and
 * N..2N-1 as the same op for divergence accounting, because the live
 * picker only ever returns an op index.  Caller MUST have already
 * confirmed slot_is_structured() -- otherwise the structured half is
 * meaningless and would just double-count the unstructured arm.
 *
 * Uses a fresh rnd_modulo_u32() draw rather than re-using the live
 * picker's r: the doubled-pool total differs from the live total, so
 * the live r does not map onto the same arm interval.  Burns one
 * additional RNG step per shadow sample, which is negligible against
 * the per-call cost.
 *
 * The same fd-only zeroing applied to op 8 in the live picker is
 * applied to both arm copies of op 8 here, so a non-fd structured slot
 * cannot accidentally make the fd-swap op weight non-zero just because
 * the structured arm exists.
 */
static unsigned int weighted_pick_case_shadow_structured(enum argtype atype)
{
	unsigned int weights[2 * MUT_NUM_OPS];
	unsigned int total = 0;
	unsigned int r, accum, i;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						  __ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						  __ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[i] = (unsigned int)w;
	}
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[MUT_NUM_OPS + i] = (unsigned int)w;
	}

	if (!is_fdarg(atype)) {
		weights[8] = 0;
		weights[MUT_NUM_OPS + 8] = 0;
	}

	for (i = 0; i < 2 * MUT_NUM_OPS; i++)
		total += weights[i];

	r = rnd_modulo_u32(total);
	accum = 0;
	for (i = 0; i < 2 * MUT_NUM_OPS; i++) {
		accum += weights[i];
		if (r < accum)
			return i % MUT_NUM_OPS;
	}
	return MUT_NUM_OPS - 1;
}

/*
 * Cross-arg splice ratio.  With probability 1/SPLICE_RATIO, an arg in
 * a replay starts from a sibling arg's snapshot value rather than its
 * own, before the per-arg mutator chain runs on it.
 *
 * Why splice within the same syscall (rather than across syscalls or
 * across snapshots): args within one syscall invocation share semantic
 * structure — flags fields tend to share bit-encodings, length fields
 * tend to share scale, fd fields tend to be related — and splicing
 * preserves that structure while shuffling which slot each value lands
 * in.  Cross-snapshot or cross-syscall splice would mostly produce
 * type-incoherent gibberish; intra-syscall keeps the splice on a chain
 * of values the kernel already validated together.
 *
 * 10% is conservative: too much splice and we lose the per-arg
 * locality the corpus is meant to preserve.  Tunable here without
 * touching call sites.
 */
#define SPLICE_RATIO 10

/*
 * Per-arg mutation stacking depth.
 *
 * Drawing inspiration from AFL's havoc stage, when we mutate an argument
 * we apply 1..STACK_MAX mutations in sequence rather than always exactly
 * one.  Stacking lets us reach states that no single mutator can produce
 * (e.g. bit-flip then add-delta then boundary-replace), which is where the
 * long-tail edges tend to live once the easy single-mutation neighbours
 * have been exhausted.
 *
 * STACK_MAX caps the chain so a single arg can't burn unbounded entropy
 * and so the mutated value keeps some relationship to the snapshot —
 * past ~4 mutations on a scalar the result is indistinguishable from a
 * fresh random value, at which point the corpus snapshot has stopped
 * doing useful guidance work.
 *
 * STACK_MAX is defined in minicorpus.h (shared with stats.c for the
 * stack_depth_histogram array bounds). */

/*
 * Apply a structure-aware variant of mutator @op to @val when the
 * arg's type carries enough metadata to define a "valid neighbour"
 * (ARG_LIST: bitmask vocabulary; ARG_OP: pick-one enum; ARG_RANGE:
 * bounded integer).  Returns true and writes through *val on
 * success; returns false to let the caller fall through to the
 * byte-level switch.
 *
 * Hard rule: coupled tags (ARG_FD / typed FDs / ARG_ADDRESS /
 * ARG_LEN / ARG_STRUCT_PTR_*) are intentionally absent from the
 * switch.  Field-level perturbation of those slots breaks invariants
 * the rest of the generator (fd validity, ptr<->len pairing,
 * address aliasing) is built to preserve, so structured mutation is
 * the wrong tool for them — they fall through to the unstructured
 * ops which already handle them safely.
 *
 * Per-op semantics within each structured type:
 *   ARG_LIST  (bitmask vocabulary in arg_params.list.values[]):
 *     0/6/7 (bit-flip, bswap-add, bswap-sub) -> XOR one listed bit
 *     1 (add)        -> set one listed bit
 *     2 (sub)        -> clear one listed bit
 *     3 (boundary)   -> all listed bits OR'd, or zero
 *     4 (byte-shuf)  -> random subset of listed bits
 *     5 (keep)       -> no-op (still counts as structured firing)
 *   ARG_OP (pick-one vocabulary):
 *     1 (add)        -> next entry (index + 1)
 *     2 (sub)        -> prev entry (index - 1)
 *     3 (boundary)   -> first or last entry
 *     5 (keep)       -> no-op
 *     0/4/6/7        -> any different entry
 *   ARG_RANGE [low, hi]:
 *     1 (add)        -> +1 clamped to hi
 *     2 (sub)        -> -1 clamped to lo
 *     3 (boundary)   -> low or hi
 *     5 (keep)       -> no-op
 *     0/4/6/7        -> adjacent step (+/- 1) clamped
 *
 * Missing or degenerate metadata (NULL values array, num == 0, hi <
 * low) is treated as "no structure available" and the caller falls
 * through.
 */
static bool try_structured_mutation(unsigned long *val, unsigned int op,
		enum argtype atype, const struct arg_param *params)
{
	if (params == NULL)
		return false;

	switch (atype) {
	case ARG_LIST: {
		const struct arglist *list = &params->list;
		unsigned long bit;
		unsigned int j;

		if (list->num == 0 || list->values == NULL)
			return false;

		bit = list->values[rnd_modulo_u32(list->num)];

		switch (op) {
		case 0:
		case 6:
		case 7:
			*val ^= bit;
			return true;
		case 1:
			*val |= bit;
			return true;
		case 2:
			*val &= ~bit;
			return true;
		case 3: {
			unsigned long all = 0;

			if (RAND_BOOL()) {
				*val = 0;
			} else {
				for (j = 0; j < list->num; j++)
					all |= list->values[j];
				*val = all;
			}
			return true;
		}
		case 4: {
			unsigned long mask = 0;

			for (j = 0; j < list->num; j++)
				if (RAND_BOOL())
					mask |= list->values[j];
			*val = mask;
			return true;
		}
		case 5:
			return true;
		}
		return false;
	}
	case ARG_OP: {
		const struct arglist *list = &params->list;
		unsigned int cur, pick, j;

		if (list->num == 0 || list->values == NULL)
			return false;
		if (list->num == 1) {
			*val = list->values[0];
			return true;
		}

		cur = list->num;
		for (j = 0; j < list->num; j++) {
			if (list->values[j] == *val) {
				cur = j;
				break;
			}
		}

		switch (op) {
		case 1:
			pick = (cur < list->num) ?
				(cur + 1) % list->num :
				rnd_modulo_u32(list->num);
			*val = list->values[pick];
			return true;
		case 2:
			pick = (cur < list->num) ?
				(cur + list->num - 1) % list->num :
				rnd_modulo_u32(list->num);
			*val = list->values[pick];
			return true;
		case 3:
			*val = list->values[RAND_BOOL() ? 0 : list->num - 1];
			return true;
		case 5:
			return true;
		case 0:
		case 4:
		case 6:
		case 7:
			do {
				pick = rnd_modulo_u32(list->num);
			} while (pick == cur);
			*val = list->values[pick];
			return true;
		}
		return false;
	}
	case ARG_RANGE: {
		unsigned long lo = params->range.low;
		unsigned long hi = params->range.hi;

		if (hi < lo)
			return false;
		if (lo == hi) {
			*val = lo;
			return true;
		}

		switch (op) {
		case 1:
			*val = (*val >= hi) ? hi : *val + 1;
			return true;
		case 2:
			*val = (*val <= lo) ? lo : *val - 1;
			return true;
		case 3:
			*val = RAND_BOOL() ? lo : hi;
			return true;
		case 5:
			return true;
		case 0:
		case 4:
		case 6:
		case 7:
			if (RAND_BOOL())
				*val = (*val >= hi) ? hi : *val + 1;
			else
				*val = (*val <= lo) ? lo : *val - 1;
			return true;
		}
		return false;
	}
	default:
		return false;
	}
}

/*
 * Apply a small mutation to a single argument value.
 * The mutations are designed to explore nearby input space:
 *   - bit flip: toggle a uniform-random bit
 *   - add/sub:  adjust by a small delta (1..16)
 *   - boundary: replace with a boundary value (0, -1, page_size, etc.)
 *
 * Case selection is biased by historical productivity (see
 * weighted_pick_case()).  The selected case is recorded in mut_attrib[]
 * for post-syscall attribution by minicorpus_mut_attrib_commit().
 *
 * @params (when non-NULL) carries the ABI metadata for the slot --
 * arglist for ARG_LIST/ARG_OP, range for ARG_RANGE -- and lets the
 * picked op fire a type-aware variant instead of a byte-level
 * perturbation.  Structured firings are stashed in
 * mut_structured_attrib[op] alongside the unconditional mut_attrib[op]
 * bump so the commit path can separate structured vs unstructured
 * productivity per op.
 */
static unsigned long mutate_arg(unsigned long val, enum argtype atype,
		const struct arg_param *params)
{
	unsigned int op = weighted_pick_case(atype);

	/* SHADOW: on structured-eligible slots, compare the live op pick
	 * against what a doubled-pool picker (live arm + structured arm
	 * per op) would have chosen, and stamp the divergence rate into
	 * shm.  Does not change which op fires -- the live `op` above is
	 * what mut_attrib[]/try_structured_mutation()/the case switch all
	 * consume.  See struct minicorpus_shared mut_structured_shadow_*
	 * for the why; promoting structured arms to the live picker will
	 * consume this measurement.
	 *
	 * Arm-gated by the per-child mut_structured_arm_b stamp: Arm A
	 * (control) short-circuits before weighted_pick_case_shadow_
	 * structured() so mutate_arg's RNG sequence stays byte-identical
	 * to the pre-shadow (pre-139a829f) behaviour and the live
	 * weighted_pick_case() call above remains the only rnd_modulo_u32
	 * step on the picker path.  An unconditional shadow draw (the
	 * original 139a829f shape) burned an extra rnd_modulo_u32 on
	 * every structured-eligible slot fleet-wide, perturbing the live
	 * RNG with no clean control arm and making the divergence rate
	 * impossible to attribute against an unperturbed baseline. */
	{
		struct childdata *child = this_child();

		if (child != NULL && child->mut_structured_arm_b &&
		    minicorpus_shm != NULL &&
		    slot_is_structured(atype, params)) {
			unsigned int shadow_op =
				weighted_pick_case_shadow_structured(atype);

			__atomic_fetch_add(
				&minicorpus_shm->mut_structured_shadow_samples,
				1UL, __ATOMIC_RELAXED);
			if (shadow_op != op)
				__atomic_fetch_add(
					&minicorpus_shm->mut_structured_shadow_divergences,
					1UL, __ATOMIC_RELAXED);
		}
	}

	mut_attrib[op]++;

	if (try_structured_mutation(&val, op, atype, params)) {
		mut_structured_attrib[op]++;
		return val;
	}

	switch (op) {
	case 0:
		/* flip a uniform-random bit. */
		val ^= 1UL << rnd_modulo_u32(sizeof(unsigned long) * 8);
		break;
	case 1: {
		/* add small delta, saturate at ULONG_MAX */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		val = ((unsigned long)-1 - val < delta) ? (unsigned long)-1 : val + delta;
		break;
	}
	case 2: {
		/* subtract small delta, saturate at 0 */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		val = (val < delta) ? 0 : val - delta;
		break;
	}
	case 3:
		/* replace with boundary */
		val = get_boundary_value();
		break;
	case 4:
		/* byte-level shuffle: randomize one byte */
		{
			unsigned int byte_pos = rnd_modulo_u32(sizeof(unsigned long));
			unsigned long mask = 0xffUL << (byte_pos * 8);
			val = (val & ~mask) | ((unsigned long) RAND_BYTE() << (byte_pos * 8));
		}
		break;
	case 5:
		/* keep original — sometimes the saved value is good as-is */
		break;
	case 6: {
		/* endian-aware add: byte-swap at a width chosen by 50/33/17
		 * bias toward 32/16/64-bit, add a small delta in network-order
		 * interpretation, swap back.  Hits arithmetic neighbours of BE
		 * fields (sockaddr ports/addrs, raw IP headers, netfilter
		 * rules, netlink BE attrs) that native-endian add/sub misses
		 * because the magnitude byte sits at the opposite end of the
		 * word.  Width bias matches the prevalence of __be32/__be16/
		 * __be64 in the kernel API surface. */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		unsigned int w = rnd_modulo_u32(6);
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v + (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v + (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) + delta);
		}
		break;
	}
	case 7: {
		/* endian-aware sub: mirror of case 6.  Subtracts in
		 * network-order interpretation; underflow wraps within the
		 * chosen width, which is fine — the resulting bit pattern is
		 * still an interesting boundary in the post-swap space. */
		unsigned long delta = 1 + rnd_modulo_u32(16);
		unsigned int w = rnd_modulo_u32(6);
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v - (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v - (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) - delta);
		}
		break;
	}
	case 8: {
		/* fd-pool cross-pollination.  Picked only for fd-typed args
		 * (weighted_pick_case() zeros this case for non-fd slots).
		 * With ~50% probability replace val with a different live fd
		 * drawn from the global pool — get_random_fd() picks across
		 * any active fd provider, so an ARG_FD_PIPE slot can land on
		 * a socket / io_uring / memfd / etc., exercising kernel paths
		 * that mix fd flavours (vmsplice between odd pairs, io_uring
		 * registering odd fds, fcntl on weird types).
		 *
		 * The other ~50% applies a small integer add inline, matching
		 * case 1's semantics: fd slots still see arithmetic-neighbour
		 * exploration so we don't lose the "off-by-one fd index"
		 * coverage that case 1 normally provides on this slot.
		 *
		 * If get_random_fd() returns a sentinel (-1, no providers; or
		 * a stdio fd 0/1/2 that the fd-safety pass downstream would
		 * patch anyway), fall through to the integer path so the
		 * mutation isn't a no-op.  Counts as one case-8 trial in the
		 * scheduler regardless of which branch fired. */
		bool swapped = false;

		if (RAND_BOOL()) {
			int fd = get_random_fd();

			if (fd > 2) {
				val = (unsigned long)fd;
				swapped = true;
			}
		}
		if (!swapped) {
			unsigned long delta = 1 + rnd_modulo_u32(16);
			val = ((unsigned long)-1 - val < delta) ?
			      (unsigned long)-1 : val + delta;
		}
		break;
	}
	}
	return val;
}

/*
 * Pick a stacking depth in [1, STACK_MAX] using a capped geometric
 * distribution with rate 1/2: P(1)=1/2, P(2)=1/4, P(3)=1/8, P(4)=1/8
 * (the tail mass collapses into the cap).  The bias toward small N
 * keeps most replays close to the corpus snapshot — only a minority
 * get aggressively stacked into deeper exploration.
 */
static unsigned int pick_stack_depth(void)
{
	unsigned int n = 1;

	while (n < STACK_MAX && RAND_BOOL())
		n++;
	return n;
}

/*
 * Apply mutate_arg n_muts times in sequence.  The stack composes the
 * primitive mutations into a single transformation per call site.
 * @params forwards the slot's ABI metadata so the structure-aware
 * variants can fire on every stacked step rather than just the first.
 */
static unsigned long mutate_arg_stacked(unsigned long val, unsigned int n_muts,
					enum argtype atype,
					const struct arg_param *params)
{
	while (n_muts-- > 0)
		val = mutate_arg(val, atype, params);
	return val;
}

/*
 * Apply the per-arg mutator chain (cross-arg splice + weighted-stack
 * mutate + fd safety) to args[6] in place, using @entry's argtype[]
 * for splice eligibility and fd substitution.  Both the per-syscall
 * mini-corpus replay path and the chain-corpus replay path call this
 * so the mutation logic — and the splice/replay/mut_attrib telemetry
 * it bumps — is a single shared engine.
 *
 * @nr is the syscall table index for the call whose args are being
 * mutated; consulted by the xprop branch to scope the cross-syscall
 * source pool.  Both callers already have the value (rec->nr /
 * saved->nr).
 *
 * Splice and mutate read from a local snapshot of the input so a
 * sibling arg's value used for splice is the original input, not an
 * already-mutated peer; matches the per-syscall behaviour.
 */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry,
		unsigned int nr)
{
	unsigned long snapshot[6];
	unsigned int i;

	if (entry == NULL || minicorpus_shm == NULL)
		return;

	memcpy(snapshot, args, sizeof(snapshot));

	for (i = 0; i < entry->num_args && i < 6; i++) {
		unsigned long val = snapshot[i];

		/* Mutator kill switch.  When set via TRINITY_DISABLE_MUTATORS
		 * the corpus entry is replayed verbatim -- skip splice, xprop
		 * and the weighted-stack mutate.  The fd-safety scrub below
		 * still runs so stale stdio fds in the saved args don't slip
		 * through; that scrub is replay correctness, not mutation. */
		if (mutators_disabled)
			goto fd_safety;

		/* Cross-arg splice: with probability 1/SPLICE_RATIO, replace
		 * this arg's starting value with a sibling arg's value from
		 * the same snapshot.  Runs BEFORE the mutator chain so the
		 * spliced value gets mutated in place rather than passed
		 * straight through.  Requires num_args >= 2 (otherwise there
		 * is no other slot to splice from). */
		if (entry->num_args >= 2 && ONE_IN(SPLICE_RATIO)) {
			unsigned int offset = 1 +
				rnd_modulo_u32(entry->num_args - 1);
			unsigned int src = (i + offset) % entry->num_args;

			val = snapshot[src];
			__atomic_fetch_add(&minicorpus_shm->splice_hits,
					   1UL, __ATOMIC_RELAXED);
			this_replay_spliced = true;
		}

		/* Cross-syscall value propagation: with probability
		 * 1/XPROP_RATIO, override this arg with a value pulled from
		 * a *different* syscall's corpus pool.  Only fd-typed slots
		 * are eligible; the source set is the fd-returning-syscall
		 * whitelist built at init.  Runs after splice so an xprop
		 * hit displaces a spliced value rather than the other way
		 * round (xprop is the rarer event and its picked value is
		 * less likely to have been seen by the mutator before).  The
		 * downstream mutator chain still applies on top, matching
		 * splice's "starting value for the chain" semantics. */
		if (ONE_IN(XPROP_RATIO)) {
			unsigned long xval;

			if (minicorpus_pick_from_other_syscall(nr,
					entry->argtype[i], &xval)) {
				val = xval;
				this_replay_xprop = true;
			}
		}

		/* ~25% chance to mutate each arg.  When we do mutate, apply
		 * a stack of 1..STACK_MAX primitive mutations (geometric,
		 * biased toward small N) rather than a single one. */
		if (ONE_IN(4)) {
			unsigned int depth = pick_stack_depth();

			__atomic_fetch_add(&minicorpus_shm->stack_depth_histogram[depth],
					   1UL, __ATOMIC_RELAXED);
			val = mutate_arg_stacked(val, depth, entry->argtype[i],
					&entry->arg_params[i]);
		}

fd_safety:
		/* Don't let fd args land on stdin/stdout/stderr. */
		if (is_fdarg(entry->argtype[i]) && val <= 2)
			val = (unsigned long) get_random_fd();

		args[i] = val;
	}

	__atomic_fetch_add(&minicorpus_shm->replay_count, 1UL, __ATOMIC_RELAXED);
	this_replay_ran = true;
}

bool minicorpus_replay(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry snapshot;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int slot;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	ring = &minicorpus_shm->rings[nr];

	/* No saved entries yet. */
	if (ring->count == 0)
		return false;

	/* Phase 2 plateau intervention (cmp_rising_pc_flat): when the
	 * classifier has the fleet in the CMP-novelty-climbing /
	 * PC-edges-flat regime, the most recent K saves into any ring are
	 * by construction dominated by CORPUS_SAVE_REASON_CMP entries
	 * (the rule's own predicate says PC-source saves have stopped
	 * landing).  Narrow the slot picker to the K newest slots so
	 * replay biases toward the freshly-admitted CMP-source material
	 * without needing per-slot source tracking, and double the replay
	 * rate (25% -> 50%) so the new material actually gets exercised
	 * inside the plateau window.  Gate is a derived predicate over
	 * shm->plateau_current_hypothesis -- no latched flag; reverts
	 * automatically when the tick driver writes NONE or transitions
	 * to a different hypothesis. */
	const bool cmp_burst_active =
		__atomic_load_n(&shm->plateau_current_hypothesis,
				__ATOMIC_RELAXED) ==
		(int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT;
	const unsigned int K_RECENT = 8;

	/* Replay gate.  Default 25%; raised to 50% inside the burst. */
	if (cmp_burst_active) {
		if (!ONE_IN(2))
			return false;
	} else {
		if (!ONE_IN(4))
			return false;
	}

	if (cmp_burst_active) {
		/* Burst path lockless reader: picks one of K_RECENT newest
		 * slots, so the slot math needs a joint (head, count)
		 * snapshot.  The writer publishes count BEFORE head with
		 * release semantics (foundation commit), so acquire-loading
		 * count first is the synchronisation edge: it pairs with
		 * the entry stores that preceded the writer's count bump
		 * and chains the prior head bump that this count value
		 * implies.  Plain-load head next; release-store ordering
		 * guarantees the load sees a value at least as recent as
		 * what count implied.
		 *
		 * Race between count-load and head-load: a writer that
		 * publishes between the two leaves count snapshotted at
		 * the pre-publish value but head at the post-publish
		 * value, so the slot calc picks ONE entry newer than
		 * count implied.  That entry exists and is valid (the
		 * writer just published it), so num_args is sane --
		 * benign.  The reverse ordering (head before count) would
		 * be unsafe -- head could outrun count beyond the K_RECENT
		 * window and pick against a stale base.  Count-first
		 * acquire-load is load-bearing. */
		unsigned int count = __atomic_load_n(&ring->count,
						     __ATOMIC_ACQUIRE);
		unsigned int head, offset;

		if (count < K_RECENT)
			return false;

		head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
		offset = rnd_modulo_u32(K_RECENT);

		/* head points one past the most recently published slot,
		 * so (head - 1) is the newest and (head - K_RECENT) the
		 * oldest of the K_RECENT window. */
		slot = (head - K_RECENT + offset) % CORPUS_RING_SIZE;
		snapshot = ring->entries[slot];
		if (snapshot.num_args < 1 || snapshot.num_args > 6) {
			__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
					   1UL, __ATOMIC_RELAXED);
			return false;
		}
		__atomic_fetch_add(&minicorpus_shm->cmp_rising_replay_picks,
				   1UL, __ATOMIC_RELAXED);
		this_replay_source_tracked = true;
		this_replay_source_nr = nr;
		this_replay_source_slot = slot;
		/* Source-entry age at pick.  In the
		 * K_RECENT-narrowed path the slot is the offset-th
		 * entry in the K_RECENT window ending at (head - 1),
		 * so age-from-head = K_RECENT - 1 - offset. */
		this_replay_source_age = (K_RECENT - 1u) - offset;
		{
			struct childdata *cc = this_child();

			if (cc != NULL) {
				cc->replay_rq_sourced = snapshot.rq_sourced;
				cc->replay_errno_sourced =
					snapshot.errno_sourced;
			}
		}
	} else {
		/* Common path: uniform over count, lockless.  The writer
		 * publishes count BEFORE head with release semantics, so
		 * an acquire-load on count pairs with the entry stores
		 * that preceded the writer's count bump.  The uniform-
		 * over-count slot pick doesn't reference head, so count
		 * is the only synchronisation edge we need.
		 *
		 * The struct-copy below is the atomic-from-fuzzer-
		 * perspective snapshot.  A torn read during a writer's
		 * slot-publish gives a 50-50 mix of two entries; the
		 * num_args validator post-copy catches the only
		 * consequential damage shape -- downstream args[i] reads
		 * going off-array.  Per the design doc this is no worse
		 * than the mutation noise the fuzzer applies to its other
		 * ~75%+ of iterations, so skip with no retry. */
		unsigned int count = __atomic_load_n(&ring->count,
						     __ATOMIC_ACQUIRE);

		/* Clamp to ring size before indexing.  count is an
		 * unsynchronised invariant on the writer side -- writers
		 * cap it at CORPUS_RING_SIZE -- but a torn or stomped
		 * count load could in principle return a value larger
		 * than the entries[] array.  The burst path above and
		 * the file-save path below both bound their slot picks
		 * by CORPUS_RING_SIZE; do the same here so a garbage
		 * count can't drive entries[slot] off-array.  In normal
		 * operation saves cap count at CORPUS_RING_SIZE, so this
		 * is a no-op on the hot path. */
		if (count > CORPUS_RING_SIZE)
			count = CORPUS_RING_SIZE;
		if (count == 0)
			return false;
		slot = rnd_modulo_u32(count);
		snapshot = ring->entries[slot];
		if (snapshot.num_args < 1 || snapshot.num_args > 6) {
			__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
					   1UL, __ATOMIC_RELAXED);
			return false;
		}
		this_replay_source_tracked = true;
		this_replay_source_nr = nr;
		this_replay_source_slot = slot;
		/* Source-entry age = (head - 1 - slot)
		 * mod CORPUS_RING_SIZE.  Load head with RELAXED --
		 * the uniform-over-count slot pick above doesn't
		 * reference head, so this load is a measurement-only
		 * addition with no ordering constraint.  A stale
		 * head one publish behind just shifts the bin by one
		 * slot, which is well inside the bucket boundaries. */
		{
			unsigned int head_now = __atomic_load_n(
				&ring->head, __ATOMIC_RELAXED);

			this_replay_source_age =
				(head_now - 1u - slot) & (CORPUS_RING_SIZE - 1u);
		}
		{
			struct childdata *cc = this_child();

			if (cc != NULL) {
				cc->replay_rq_sourced = snapshot.rq_sourced;
				cc->replay_errno_sourced =
					snapshot.errno_sourced;
			}
		}
	}

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return false;

	if (!corpus_args_replayable(entry))
		return false;

	minicorpus_mutate_args(snapshot.args, entry, nr);

	rec->a1 = snapshot.args[0];
	rec->a2 = snapshot.args[1];
	rec->a3 = snapshot.args[2];
	rec->a4 = snapshot.args[3];
	rec->a5 = snapshot.args[4];
	rec->a6 = snapshot.args[5];

	return true;
}

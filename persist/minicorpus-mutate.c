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
			unsigned int depth = minicorpus_pick_stack_depth();

			__atomic_fetch_add(&minicorpus_shm->stack_depth_histogram[depth],
					   1UL, __ATOMIC_RELAXED);
			val = minicorpus_mutate_arg_stacked(val, depth,
					entry->argtype[i],
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

/*
 * Mini-corpus replay entry point.
 *
 * Picks a saved snapshot from the per-syscall ring (uniform on the
 * common path; K-newest-window under the CMP-rising-PC-flat plateau
 * hypothesis), runs it through the shared splice-and-mutate driver in
 * persist/minicorpus-splice.c, and stamps the mutated args back into
 * @rec for the next dispatch.
 */

#include "child.h"
#include "minicorpus.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

#include "minicorpus-internal.h"

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

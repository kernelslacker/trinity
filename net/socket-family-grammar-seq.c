/*
 * Per-walk sequence-hash ring and P4 reward-arm credit table for the
 * socket-family grammar executor.  Split out of
 * net/socket-family-grammar.c so the hash/ring accounting is isolated
 * from the coordinator, illegal-step machinery, and AF_ALG lifecycle.
 * The FNV-1a step folding and arm-id derivation are inline in
 * socket-family-grammar-internal.h so the hot per-step call sites in
 * the coordinator don't cross a translation unit boundary.
 */

#include <stdbool.h>
#include <stdint.h>

#include "shm.h"

#include "socket-family-grammar-internal.h"

/*
 * Record a per-walk sequence hash in shm's bounded ring.  Linear scan
 * to skip duplicates; CAS on sfg_seq_count reserves a fresh slot and
 * bumps stats.socket_family_grammar_distinct_seq exactly once per new
 * sequence observed fleet-wide.  Saturates silently once the ring
 * fills (SFG_SEQ_HASH_CAP entries); the variety-signal use case does
 * not need a full inventory.
 *
 * Returns the ring slot holding this hash -- the index found on a
 * duplicate, or the freshly CAS-reserved slot on a first sighting --
 * so a caller can attach per-sequence data (the P4 reward arms) keyed
 * by the same slot.  Returns SFG_SEQ_SLOT_NONE when the ring is full.
 */
unsigned int sfg_seq_record(uint32_t h)
{
	unsigned int count, i, slot;

	count = __atomic_load_n(&shm->sfg_seq_count, __ATOMIC_ACQUIRE);
	for (;;) {
		if (count > SFG_SEQ_HASH_CAP)	/* clamp: shm may be corrupted */
			count = SFG_SEQ_HASH_CAP;
		for (i = 0; i < count; i++) {
			if (__atomic_load_n(&shm->sfg_seq_hashes[i],
					    __ATOMIC_RELAXED) == h)
				return i;
		}
		if (count >= SFG_SEQ_HASH_CAP)
			return SFG_SEQ_SLOT_NONE;
		slot = count;
		if (__atomic_compare_exchange_n(&shm->sfg_seq_count,
						&count, slot + 1,
						false,
						__ATOMIC_ACQ_REL,
						__ATOMIC_ACQUIRE)) {
			__atomic_store_n(&shm->sfg_seq_hashes[slot], h,
					 __ATOMIC_RELEASE);
			__atomic_add_fetch(
				&shm->stats.socket_family_grammar.distinct_seq,
				1, __ATOMIC_RELAXED);
			return slot;
		}
		/* CAS lost: `count` now holds the witnessed slot count;
		 * re-scan (the winning writer may have written OUR hash). */
	}
}

/* Halve reward+attempts for a slot once its attempt count reaches this
 * cap, so a barren-but-historically-lucky arm releases instead of
 * winning forever on a stale lifetime mean (coverage is non-stationary,
 * mirroring the strategy bandit's EMA decay discipline). */
#define SFG_P4_ATTEMPTS_CAP	1024u

/*
 * Credit one legal walk's new-edge reward to its ring slot.  Stamps the
 * owning arm on the slot's first credit (attempts 0 -> 1), accumulates
 * reward + attempts, and decays both by half on reaching the cap to
 * keep the rolled-up mean recent.  Concurrent crediting from sibling
 * children is atomic on the accumulate; the coarse cap-halve races
 * benignly -- a lost increment is noise in a heuristic tilt.
 */
void sfg_seq_credit(unsigned int slot, uint32_t arm_id, uint32_t reward)
{
	if (__atomic_load_n(&shm->sfg_seq_attempts[slot],
			    __ATOMIC_RELAXED) == 0)
		__atomic_store_n(&shm->sfg_seq_arm[slot], arm_id,
				 __ATOMIC_RELAXED);

	__atomic_add_fetch(&shm->sfg_seq_reward[slot], reward,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.socket_family_grammar.reward, reward,
			   __ATOMIC_RELAXED);

	if (__atomic_add_fetch(&shm->sfg_seq_attempts[slot], 1,
			       __ATOMIC_RELAXED) >= SFG_P4_ATTEMPTS_CAP) {
		__atomic_store_n(&shm->sfg_seq_reward[slot],
			__atomic_load_n(&shm->sfg_seq_reward[slot],
					__ATOMIC_RELAXED) / 2,
			__ATOMIC_RELAXED);
		__atomic_store_n(&shm->sfg_seq_attempts[slot],
			__atomic_load_n(&shm->sfg_seq_attempts[slot],
					__ATOMIC_RELAXED) / 2,
			__ATOMIC_RELAXED);
	}
}

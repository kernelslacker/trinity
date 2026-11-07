/*
 * Per-syscall frontier-edge ring window advance.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"		/* biarch */
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "tables.h"		/* max_nr_*_syscalls */

void frontier_window_advance(void)
{
	uint32_t cur, next;
	unsigned int nr;
	unsigned int nr_to_scan;
	unsigned long max_weight = 0;

	/* Clear-then-publish, the opposite of the previous order.  The old
	 * code bumped frontier_slot first and then aged out the slot it had
	 * just published, which opened a window in which a producer could
	 * (a) add into the new slot before we cleared it, (b) have that
	 * write exchanged back to zero, and (c) issue its cached-sum
	 * increment AFTER our subtract.  In the worst case the rotator's
	 * fetch_sub ran with an old_slot value that was larger than the
	 * cached running sum -- because part of the producer's contribution
	 * was already in the slot but not yet in the cached counter -- so
	 * the subtract wrapped negative and the cached count flipped to a
	 * near-UINT32_MAX weight.  That bogus weight is consumed by
	 * random_syscall/pick-frontier.c's frontier roulette wheel; an arm-wide blow-up
	 * either collapses the wheel onto one syscall or pushes the
	 * rejection sampler into an effectively-uniform reject loop.
	 *
	 * We now compute the next slot index without publishing it, age out
	 * the slot's contents from every per-nr running sum while no
	 * producer is targeting that slot (frontier_slot still points to
	 * the previous slot), and only then bump frontier_slot.  A producer
	 * racing the rotation keeps adding into the previous slot for a
	 * handful of instructions -- a bounded window-boundary attribution
	 * error -- instead of having its addition silently dropped or
	 * inverting the cached sum.
	 *
	 * The saturating subtract is kept as a hard guard: even with the
	 * reorder, a CAS-clamped update means a producer that races our
	 * read-modify-write on cached can't drive it negative.  Hitting the
	 * clamp bumps frontier_underflow_prevented -- the metric is
	 * expected to read zero in steady state. */
	cur = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED);
	next = (cur + 1U) & (FRONTIER_DECAY_WINDOWS - 1);

	/* Clamp the rotation sweep to the populated slot range.  The
	 * frontier ring (frontier_history / frontier_recent_count_cached)
	 * is sized MAX_NR_SYSCALL = 1024 but any given arch only fills a
	 * few hundred entries; the tail is permanently zero and every
	 * RELAXED exchange + CAS across those dead slots was pure wasted
	 * work per rotation, and (worse) touched the same cache lines the
	 * per-nr producer fetch_add paths in child processes hit, so the
	 * dead-slot sweep also cost cross-CPU coherence traffic against
	 * live producers.
	 *
	 * The ring is a shared per-nr index space under biarch: both the
	 * 32-bit and 64-bit producer paths call frontier_record_new_edge()
	 * with a bare syscall nr and no do32 discriminator, so under biarch
	 * the array holds contributions from either table at the same slot.
	 * Clamping just to max_nr_64bit_syscalls the way the top-syscalls
	 * dump path does would leave 32-bit-only slots in the [max_nr_64bit
	 * _syscalls, max_nr_32bit_syscalls) range never decayed -- their
	 * cached sums would grow monotonically and their history slots
	 * would never zero out.  So under biarch we clamp to the larger of
	 * the two counts.  Under uniarch max_nr_syscalls is the single
	 * populated bound.  MIN with MAX_NR_SYSCALL is kept as a hard guard
	 * so a future bump to either count beyond the array size cannot
	 * walk past the end. */
	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls > max_nr_32bit_syscalls
				? max_nr_64bit_syscalls
				: max_nr_32bit_syscalls;
	} else {
		nr_to_scan = max_nr_syscalls;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	for (nr = 0; nr < nr_to_scan; nr++) {
		unsigned int ctx;
		bool cool_this_nr = false;

		/* F4(X) per-nr cooldown predicate.  Reuses the F3 per-syscall
		 * LIVE-regime miss-streak (frontier_live_miss_streak_per_syscall
		 * -- bumped strictly after a zero-edge LIVE-regime pick at the
		 * random_syscall_step attribution path, reset on any productive
		 * event via the existing frontier_record_new_edge() /
		 * frontier_record_transition_edge() hooks): when the streak has
		 * crossed FRONTIER_LIVE_MISS_COOLDOWN this nr is a wall-mover
		 * candidate, and the halving step below drives its cached sum
		 * toward zero so frontier_max_weight_cached falls and the
		 * picker reaches the silent decay path on it.
		 *
		 * Loaded once per nr per rotation (NOT inside the CAS loop --
		 * the streak does not change with our CAS retry; only the
		 * cached running sum does).  A racing random_syscall_step bump
		 * that raises the streak across the threshold between this
		 * load and the cached-sum update is picked up by the NEXT
		 * rotation -- bounded one-window lag, same as every other
		 * rotation-boundary attribution.  Hoisted above the per-context
		 * inner sweep because the miss-streak is per-nr, not per-context,
		 * so every context slice sees the same cool-this-nr verdict. */
		{
			unsigned long streak;

			streak = __atomic_load_n(
				&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[nr],
				__ATOMIC_RELAXED);
			if (streak >= FRONTIER_LIVE_MISS_COOLDOWN)
				cool_this_nr = true;
		}

		/* Rotate every picker-context slice of this nr's ring.  The
		 * per-context slices are disjoint memory, so a stale value in
		 * an idle context (baseline: PICKER_CTX_USERNS) is preserved
		 * across rotations unless we age it out here.  At baseline the
		 * USERNS slice is all-zero so the sweep is a no-op past the
		 * INIT slice; the loop is present so a future context that
		 * starts writing does not carry stale ring contributions
		 * indefinitely. */
		for (ctx = 0; ctx < PICKER_NCTX; ctx++) {
			uint32_t old_slot;
			uint32_t old_cached;
			uint32_t new_sum;
			uint64_t halved = 0;
			uint64_t take;

			old_slot = __atomic_exchange_n(
				&shm->frontier_history[nr][ctx][next],
				0U, __ATOMIC_RELAXED);

			/* F4(X) halves the ring itself, not just the cached
			 * sum: the sum is the ring's, and a sum halved alone
			 * has later rotations subtract slots it no longer
			 * holds, clamping it to zero and wiping fresh edges.
			 * Each live slot gives up half of what it held when
			 * read, and the sum takes the same total off below.
			 * A producer's add to the current slot meanwhile
			 * stays on both. */
			if (cool_this_nr) {
				unsigned int s;

				for (s = 0; s < FRONTIER_DECAY_WINDOWS; s++) {
					uint32_t v;

					if (s == next)
						continue;
					v = __atomic_load_n(
						&shm->frontier_history[nr][ctx][s],
						__ATOMIC_RELAXED);
					if (v == 0)
						continue;
					__atomic_fetch_sub(
						&shm->frontier_history[nr][ctx][s],
						v - v / 2, __ATOMIC_RELAXED);
					halved += v - v / 2;
				}
			}
			take = old_slot + halved;

			/* CAS loop so a concurrent producer's fetch_add
			 * against the cached counter cannot be lost and
			 * cannot underflow the sum.  Producers should not
			 * be racing this nr at this point (frontier_slot
			 * still names the previous slot) but the loop costs
			 * at most a handful of retries and removes the
			 * underflow case unconditionally. */
			old_cached = __atomic_load_n(
				&shm->frontier_recent_count_cached[nr][ctx],
				__ATOMIC_RELAXED);
			do {
				if (old_cached >= take)
					new_sum = old_cached - (uint32_t) take;
				else
					new_sum = 0;
			} while (!__atomic_compare_exchange_n(
					 &shm->frontier_recent_count_cached[nr][ctx],
					 &old_cached, new_sum, false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED));
			if (old_cached < take)
				__atomic_add_fetch(
					&shm->stats.frontier.core.underflow_prevented,
					1UL, __ATOMIC_RELAXED);
			if (halved != 0)
				__atomic_add_fetch(
					&shm->stats.frontier.cooldown.live_cooldown_decays,
					1UL, __ATOMIC_RELAXED);
			if (new_sum > max_weight)
				max_weight = new_sum;
		}
	}

	/* Publish the new slot only after every per-nr clear has landed.
	 * From this point producers see the freshly-zeroed slot. */
	__atomic_store_n(&shm->frontier_slot, cur + 1U, __ATOMIC_RELAXED);

	if (max_weight > UINT_MAX)
		max_weight = UINT_MAX;
	__atomic_store_n(&shm->frontier_max_weight_cached,
			 (unsigned int)max_weight, __ATOMIC_RELAXED);
}

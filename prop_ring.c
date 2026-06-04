/*
 * Per-child ring of small-integer return values captured from recent
 * syscall returns, available for re-injection as input arguments to
 * later syscalls.  See include/prop_ring.h for the data shape and
 * Documentation/architecture or the constant-propagation design note
 * for the motivation.
 *
 * Capture side runs in handle_syscall_ret() after register_returned_fd.
 * Consume side runs in gen_undefined_arg() at low probability so the
 * raw-random exploration path keeps its share of the mutation budget.
 *
 * Single-writer / single-reader from the owning child only.  No
 * atomics, no cross-process visibility.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "child.h"
#include "edgepair.h"
#include "edgepair_ring.h"
#include "kcov.h"
#include "objects.h"
#include "prop_ring.h"
#include "rnd.h"

/* Slots older than this (measured in child->op_nr ticks) are skipped
 * by the consumer -- the win is chaining values into multi-step
 * protocols within a short window, not resurrecting stale state from
 * thousands of syscalls ago. */
#define PROP_RING_RECENCY_MAX	64

/* Capture-side acceptance window for "small int that looks like a
 * cookie / id / count, not a kernel pointer or an error code".  The
 * upper bound is well under the lowest plausible userspace address on
 * any supported arch, so a returned address can't slip through this
 * filter and become input to a later syscall -- the wild-write channel
 * that default_address_scrub exists to break stays broken. */
#define PROP_RING_HIGH_PTR	0x40000000UL

/* Baseline inject probability denominator.  Matches the design note's
 * "meaningful share without crowding out random exploration" target --
 * roughly the same per-call injection rate as the cmp_hints case in
 * gen_undefined_arg's mod-9 switch.  Phase 2 doubles this rate for
 * (A, B) pairs whose edgepair total_count clears the top-quartile
 * threshold, via PROP_RING_INJECT_MOD_BOOSTED below. */
#define PROP_RING_INJECT_MOD		12
#define PROP_RING_INJECT_MOD_BOOSTED	6

static unsigned int ring_prev(unsigned int head)
{
	return (head - 1) & (CHILD_PROP_RING_SIZE - 1);
}

void prop_ring_push(struct childdata *child,
		    const struct syscallentry *entry,
		    const struct syscallrecord *rec)
{
	struct child_prop_ring *ring;
	struct prop_slot *prev;
	struct prop_slot *slot;
	long sret;

	if (child == NULL || entry == NULL || rec == NULL)
		return;

	/* Typed returns own their own propagation paths (fd pool, key
	 * serial registrar, pid registrar).  Only general scalars land
	 * here. */
	if (entry->ret_objtype != OBJ_NONE)
		return;

	sret = (long) rec->retval;

	/* -1 is the failure sentinel; small negative values just outside
	 * it (errno-encoded returns from syscalls that don't go through
	 * libc's errno indirection, signal numbers, etc.) are legitimate
	 * cookies and stay in the window. */
	if (sret == -1)
		return;
	if (sret < -32 || sret > INT32_MAX)
		return;

	/* Pointer-shape firewall for positive returns.  Negatives in
	 * [-32, -2] survive the unsigned cast as huge values and would
	 * otherwise be rejected here -- exempt them explicitly. */
	if (sret > 0 && (unsigned long) sret > PROP_RING_HIGH_PTR)
		return;

	/* The fd pool already biases live fds back into ARG_FD slots.
	 * If a generic scalar return happens to alias a registered fd,
	 * skip capture so we don't double-bias. */
	if (sret > 2 && fd_hash_lookup((int) sret) != NULL)
		return;

	ring = &child->prop_ring;

	/* Dedup against the most recent slot so an open/close loop
	 * that keeps returning the same fd doesn't fill the whole ring
	 * with one value. */
	prev = &ring->slots[ring_prev(ring->head)];
	if (prev->valid &&
	    prev->value == rec->retval &&
	    prev->src_nr == rec->nr &&
	    prev->do32bit == rec->do32bit)
		return;

	slot = &ring->slots[ring->head & (CHILD_PROP_RING_SIZE - 1)];
	slot->value = rec->retval;
	slot->captured_at = child->op_nr;
	slot->src_nr = rec->nr;
	slot->do32bit = rec->do32bit;
	slot->valid = true;
	ring->head++;
}

/*
 * Scan the populated range of CHILD's ring looking for any slot whose
 * (src_nr, curr_nr) edgepair total_count clears the top-quartile
 * threshold cached in shm.  Returns true on the first hit -- the gate
 * downstream is binary (boost on / boost off), the per-slot weight is
 * applied implicitly via the outer probability change, so there is no
 * value in counting how many top-q slots the ring holds.
 *
 * THRESHOLD == ULONG_MAX is the cold-start sentinel (no window has
 * recomputed yet); the early-out keeps the per-injection cost at one
 * relaxed atomic load on the fast path while there is no usable
 * edgepair signal.
 */
static bool ring_has_topq_pair(const struct child_prop_ring *ring,
			       unsigned int populated,
			       unsigned int curr_nr,
			       unsigned long threshold)
{
	unsigned int i;

	if (threshold == ULONG_MAX)
		return false;

	for (i = 0; i < populated; i++) {
		const struct prop_slot *slot = &ring->slots[i];
		struct edgepair_stats st;

		if (!slot->valid)
			continue;

		st = edgepair_get_stats(slot->src_nr, curr_nr);
		if (st.total >= threshold)
			return true;
	}
	return false;
}

bool prop_ring_try_get(struct childdata *child,
		       const struct syscallrecord *rec,
		       unsigned long *out,
		       bool *boosted_out)
{
	struct child_prop_ring *ring;
	unsigned long threshold;
	unsigned int populated;
	unsigned int tries;
	unsigned long now;
	bool boost = false;

	if (child == NULL || rec == NULL || out == NULL)
		return false;

	/* Roll the boosted rate (1-in-6) first.  5 in 6 calls return here
	 * with zero ring-scan cost.  When the roll passes we then check
	 * whether the ring contains a top-quartile (A, B) entry; if not,
	 * we downsample by half (one extra rnd_modulo_u32) to keep the
	 * unboosted effective rate at the Phase 1 1-in-12 baseline.  Net
	 * acceptance: boosted = 1/6, unboosted = 1/6 * 1/2 = 1/12.  This
	 * ordering avoids the ring-scan in 5/6 of all calls; evaluating
	 * the boost first would scan on every call. */
	if (rnd_modulo_u32(PROP_RING_INJECT_MOD_BOOSTED) != 0)
		return false;

	ring = &child->prop_ring;
	populated = ring->head < CHILD_PROP_RING_SIZE
		    ? ring->head : CHILD_PROP_RING_SIZE;
	if (populated == 0)
		return false;

	threshold = (kcov_shm != NULL)
		    ? __atomic_load_n(&kcov_shm->prop_edgepair_topq_threshold,
				      __ATOMIC_RELAXED)
		    : ULONG_MAX;
	boost = ring_has_topq_pair(ring, populated, rec->nr, threshold);

	if (!boost && rnd_modulo_u32(2) != 0)
		return false;

	now = child->op_nr;

	/* Uniform pick over the populated range, with a recency filter.
	 * Up to a handful of probes -- if every slot we touch is stale,
	 * the ring as a whole is stale and the caller falls back to
	 * raw-random generation.
	 *
	 * The Phase 2 boost lives on the outer probability gate above;
	 * the inner pick stays uniform across all populated slots even
	 * when boost is set.  Picking a non-top-q slot under boost is
	 * fine -- the boost signal is per-ring ("this ring contains at
	 * least one top-q (A, B) for current B"), not per-slot, and the
	 * design spec calls that out as the all-top-q net effect. */
	for (tries = 0; tries < 4; tries++) {
		unsigned int idx = rnd_modulo_u32(populated);
		struct prop_slot *slot = &ring->slots[idx];

		if (!slot->valid)
			continue;
		if (now - slot->captured_at > PROP_RING_RECENCY_MAX)
			continue;

		*out = slot->value;
		if (boosted_out != NULL)
			*boosted_out = boost;
		return true;
	}

	return false;
}

/*
 * Walk edgepair_published and emit the top-quartile cutoff of
 * total_count across populated slots into
 * kcov_shm->prop_edgepair_topq_threshold.  Called from the CAS-winner
 * in maybe_rotate_strategy once per strategy window.
 *
 * Histogram approach: log2 buckets keep this constant-memory and
 * one-pass.  bin[i] counts slots whose total_count falls in
 * [2^i, 2^(i+1)); bin[0] absorbs the total_count == 0 corner.  Walking
 * the bins high-to-low and accumulating until we reach 25% of the
 * populated count finds the bucket the 75th percentile lives in; we
 * publish its lower bound as the cutoff.  Coarse by a power of two,
 * but the boost gate is binary -- bucket-precision matches what the
 * downstream comparison can act on, and the trade buys a single 262K
 * scan with no allocation.
 *
 * Cost: one read pass over edgepair_published.slots (262K * 32 B =
 * 8 MiB) per strategy window.  STRATEGY_WINDOW is 131,072 ops so this
 * amortises to ~64 B of mirror walk per syscall.  Done in the
 * CAS-winner child so the cost is paid by one child, not fanned out.
 *
 * Memory ordering: acquire-load the published header before the slot
 * walk, mirroring edgepair_get_stats(), so a publish racing the
 * recompute can't surface a slot with stale counters from before the
 * matching header update.
 */
void prop_ring_recompute_edgepair_topq(void)
{
	uint32_t hist[33];
	unsigned long populated = 0;
	unsigned long target;
	unsigned long acc;
	unsigned long threshold;
	unsigned int i;
	int b;

	if (kcov_shm == NULL)
		return;
	if (!edgepair_is_enabled() || edgepair_published == NULL)
		return;

	memset(hist, 0, sizeof(hist));

	(void)__atomic_load_n(&edgepair_published->total_pair_calls,
			      __ATOMIC_ACQUIRE);

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_published_slot *s =
			&edgepair_published->slots[i];
		unsigned long count;
		unsigned int bin;

		if (s->prev_nr == EDGEPAIR_EMPTY)
			continue;

		populated++;
		count = s->total_count;
		if (count == 0) {
			hist[0]++;
			continue;
		}
		bin = (unsigned int)(63 - __builtin_clzll(count));
		if (bin > 32)
			bin = 32;
		hist[bin]++;
	}

	if (populated == 0)
		return;

	/* Top quartile = top 25%, so accumulate from the highest bin
	 * downward until we cover at least populated/4 slots.  The
	 * (+3)/4 keeps the target non-zero on tiny populations where
	 * integer-division to 0 would let every pair clear the bar. */
	target = (populated + 3) / 4;
	acc = 0;
	threshold = ULONG_MAX;
	for (b = 32; b >= 0; b--) {
		acc += hist[b];
		if (acc >= target) {
			threshold = (b == 0) ? 1UL : (1UL << b);
			break;
		}
	}

	__atomic_store_n(&kcov_shm->prop_edgepair_topq_threshold,
			 threshold, __ATOMIC_RELAXED);
}

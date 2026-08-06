/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * collect-internal.h — pure-computation inline helpers shared across
 * the kcov/collect*.c translation units.
 *
 * All helpers in this header are either static inline (zero out-of-line
 * instantiation) or plain static (one instantiation per including TU;
 * any unused copy is dead-code-eliminated by the compiler).  Nothing
 * here touches mutable shared state, holds locks, or has observable
 * side-effects outside the return value.
 *
 * Consumers: kcov/collect.c (main hot path) and kcov/collect-fanout.c
 * (kcov_sample_new_edges read-only probe).
 */

#include <stdbool.h>
#include <stdint.h>

#include "kcov-internal.h"	/* kcov_kaslr_base, KCOV_NUM_EDGES,
				   KCOV_NUM_TRANSITIONS */

/*
 * Strip the runtime KASLR base from a kernel PC so the bucket index for
 * a given instruction is invariant across reboots of the same kernel
 * build.  kcov_kaslr_base is populated by kcov_init_global from the
 * address of _text in /proc/kallsyms; on systems where that lookup
 * failed it stays zero and this is the identity transform (the run
 * then hashes raw PCs, matching the pre-canonicalisation behaviour).
 *
 * Single point of canonicalisation.  Callers route every PC that lands
 * in bucket_seen[] or the transition map through here exactly once at
 * the head of the kcov_collect() PC walk, then feed the canonical
 * value into pc_canon_to_edge() and pair_to_transition() without
 * re-canonicalising.  scripts/check-static/kcov-canonicalise-pcs.sh
 * enforces both halves of the rule: pc_canon_to_edge() must not call
 * kcov_canon_pc (would double-subtract the base), and any function in
 * kcov.c that calls pc_canon_to_edge() must also call kcov_canon_pc.
 */
static inline unsigned long kcov_canon_pc(unsigned long pc)
{
	return pc - (unsigned long)kcov_kaslr_base;
}

/*
 * Hash an already-canonicalised PC into an edge index.
 *
 * The previous xor-shift mixed too few of the bits in a typical kernel PC.
 * Two PCs that landed within the same cacheline (low 6 bits identical) and
 * shared the same upper bits ended up hashed to indices differing only in
 * the low 7 bits, clustering thousands of distinct PCs into a tiny bitmap
 * range and triggering false coverage saturation.
 *
 * Murmur3's 64-bit finalizer mixes every input bit into every output bit
 * with a single multiply/xor pair per round, which is enough to avoid the
 * cacheline clustering without breaking the PC's locality for the rest of
 * the pipeline.
 */
static inline unsigned int pc_canon_to_edge(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc & (KCOV_NUM_EDGES - 1));
}

/*
 * Per-syscall/childop entry sentinel for the shadow transition map.
 * The transition hash needs a stable predecessor for the first PC of a
 * trace so two unrelated calls cannot accidentally join across the
 * boundary (call A's last PC feeding call B's first PC would
 * manufacture a transition that never executed).  The sentinel sets
 * bit 63 so it cannot alias any canonicalised kernel PC (after the
 * KASLR-base subtraction those occupy the low 4 GB), with the
 * (nr, do32) pair encoded below the marker so each call site gets its
 * own predecessor.  The do32 dimension matters because a 32-bit-compat
 * entry into the same syscall slot reaches different kernel entry
 * trampolines than the native path.
 */
static inline unsigned long kcov_entry_sentinel(unsigned int nr, bool do32)
{
	return (1UL << 63) | ((unsigned long)do32 << 32) | (unsigned long)nr;
}

/*
 * Hash a (prev_canon_pc, cur_canon_pc) pair into a transition slot
 * index.  Both inputs are already KASLR-canonicalised — the caller
 * (kcov_collect's PC walk) holds the canonical value for the current
 * PC so it can be threaded into both pc_canon_to_edge() and here
 * without re-running kcov_canon_pc.  Rotates cur left by 1 before
 * xoring so the pair (a, b) hashes differently from (b, a) — a
 * forward and a backward edge through the same two basic blocks are
 * distinct transitions.
 */
static inline unsigned int pair_to_transition(unsigned long prev,
					      unsigned long cur)
{
	unsigned long h = prev * 0x9E3779B97F4A7C15UL;

	h ^= (cur << 1) | (cur >> 63);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdUL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53UL;
	h ^= h >> 33;
	return (unsigned int)(h & (KCOV_NUM_TRANSITIONS - 1));
}

/*
 * AFL-style hit-count classification.  Returns the bucket index 0..7 for
 * a count >= 1.  Counts of 1, 2, 3 each get their own bucket (loops with
 * very small iteration counts are common and worth distinguishing); larger
 * counts collapse into geometric ranges so a 100-iteration loop and a
 * 90-iteration loop don't fight over distinct novelty events.
 */
static unsigned int bucket_for_count(unsigned int n)
{
	if (n <= 1)
		return 0;
	if (n == 2)
		return 1;
	if (n == 3)
		return 2;
	if (n <= 7)
		return 3;
	if (n <= 15)
		return 4;
	if (n <= 31)
		return 5;
	if (n <= 127)
		return 6;
	return 7;
}

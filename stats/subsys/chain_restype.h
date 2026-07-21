#ifndef _TRINITY_STATS_SUBSYS_CHAIN_RESTYPE_H
#define _TRINITY_STATS_SUBSYS_CHAIN_RESTYPE_H

#include "sequence.h"	/* CHAIN_RESTYPE_NR */

/*
 * Resource-type chain-generation telemetry (Phase 3;
 * --chain-resource-typing=off|shadow|live).  All arrays are
 * indexed by enum chain_resource_kind (CHAIN_RESTYPE_NR wide);
 * ordering is defined by that enum and MUST NOT change without
 * updating the resource table in sequence.c.
 *
 * produced[k]     : a chain step matched the (nr, args) pattern for a
 *                   kind-k producer with a non-negative retval.  Bumped
 *                   in every non-OFF mode -- the classifier itself is
 *                   the always-on observability.
 * would_bias[k]   : SHADOW mode only.  Bumped when the next chain link
 *                   EXISTS and a consumer NR for kind k WOULD have been
 *                   picked as the LIVE arm's override.
 * biased[k]       : LIVE mode only.  Bumped when the next chain link
 *                   was actually overridden to a consumer of kind k
 *                   (accept-probability landed inside the bias budget
 *                   AND the biased dispatch did not fall back to fresh).
 * save[k]         : chain got admitted to the corpus and carried at
 *                   least one producer of kind k in its steps.
 * replay_win[k]   : a replayed chain that carried a kind-k producer
 *                   earned any novelty signal on at least one step.
 *                   Ratio replay_win[k] / save[k] answers "does this
 *                   resource family pay for its bias budget".
 *
 * All RELAXED atomics; dashboards read once per stats tick and there
 * is no cross-counter ordering invariant.
 *
 * replay_len_corrupt (scalar): Bumped by run_sequence_chain() when
 * chain_corpus_pick() returns a chain_entry whose len is zero or
 * greater than MAX_SEQ_LEN.  Corpus is shared memory and tolerates
 * lockless reads plus wild-write corruption; an out-of-range len
 * would otherwise index past the stack-local replay.steps array
 * before per-step safety checks ran.  Non-zero values mean a torn
 * lockless read or a real wild write into ring->slots[].len -- both
 * defended (fresh-chain fallback) but tracked so spikes are visible.
 *
 * The surrounding struct stats_s composes an instance of struct
 * chain_restype_stats as its "chain_restype" member.
 */
struct chain_restype_stats {
	unsigned long produced[CHAIN_RESTYPE_NR];
	unsigned long would_bias[CHAIN_RESTYPE_NR];
	unsigned long biased[CHAIN_RESTYPE_NR];
	unsigned long save[CHAIN_RESTYPE_NR];
	unsigned long replay_win[CHAIN_RESTYPE_NR];
	unsigned long replay_len_corrupt;
};

#endif	/* _TRINITY_STATS_SUBSYS_CHAIN_RESTYPE_H */

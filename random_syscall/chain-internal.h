#ifndef _TRINITY_RANDOM_SYSCALL_CHAIN_INTERNAL_H
#define _TRINITY_RANDOM_SYSCALL_CHAIN_INTERNAL_H

/*
 * Internal interface shared by the sequence-chain cluster files under
 * random_syscall/ (chain-restype.c, chain-corpus.c, chain-exec.c,
 * chain-persist.c).
 *
 * Public entry points (run_sequence_chain, chain_corpus_*,
 * chain_restype_{init,classify_producer,pick_consumer}) live in
 * include/sequence.h.  Everything declared here is cross-file
 * cluster-private glue exposed only because a helper defined in one
 * cluster file is consulted from another.  Not a public header:
 * only files under random_syscall/ implementing the sequence-chain
 * subsystem are expected to include it.
 */

#include <stdbool.h>

#include "sequence.h"

/* chain-restype.c -- consumer-side classifier and consumer-table
 * availability check.  chain-exec.c consults these from the
 * chain_restype_apply_bias hook (has_consumer) and from the
 * per-step pair-detection loop in execute_chain_steps
 * (classify_consumer). */
int chain_restype_classify_consumer(enum chain_resource_kind kind,
				    unsigned int nr, bool do32bit,
				    const unsigned long args[6]);
bool chain_restype_has_consumer(enum chain_resource_kind kind,
				bool do32bit_hint);

#endif

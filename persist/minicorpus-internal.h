#pragma once

/*
 * Cross-module surface shared between the minicorpus TUs
 * (core / xprop / save / mutate / file / snapshot).  Everything else
 * stays file-static in its owning TU.
 */

#include "minicorpus.h"

struct syscallentry;

void minicorpus_ring_lock(struct corpus_ring *ring);
void minicorpus_ring_unlock(struct corpus_ring *ring);

bool corpus_args_replayable(const struct syscallentry *entry);

void xprop_build_whitelist(void);
bool minicorpus_pick_from_other_syscall(unsigned int nr,
					enum argtype arg_atype,
					unsigned long *val);

/* init writes, mutate reads -- process-wide runtime kill switch. */
extern bool mutators_disabled;

/*
 * Attribution stash shared across the minicorpus mutate TUs.
 *
 * Written by the field-mutator (mut_attrib / mut_structured_attrib) and
 * the splice-and-mutate driver / replay picker (this_replay_*), consumed
 * and cleared by the accounting TU during minicorpus_mut_attrib_commit.
 * Process-local -- children fork before any mutate call, so each child
 * gets its own copy and no locking is required.
 */
extern unsigned int mut_attrib[MUT_NUM_OPS];
extern unsigned int mut_structured_attrib[MUT_NUM_OPS];
extern bool this_replay_ran;
extern bool this_replay_spliced;
extern bool this_replay_xprop;
extern bool this_replay_source_tracked;
extern unsigned int this_replay_source_nr;
extern unsigned int this_replay_source_slot;
extern unsigned int this_replay_source_age;

/*
 * Per-arg mutator engine surface exposed to the splice-and-mutate
 * driver.  minicorpus_mutate_arg_stacked() applies the weighted-case
 * mutator @n_muts times in sequence; minicorpus_pick_stack_depth()
 * returns the capped-geometric depth the driver bumps into the
 * per-depth histogram before calling the stacker.
 */
unsigned int minicorpus_pick_stack_depth(void);
unsigned long minicorpus_mutate_arg_stacked(unsigned long val,
					    unsigned int n_muts,
					    enum argtype atype,
					    const struct arg_param *params);

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

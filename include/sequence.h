#pragma once

#include "child.h"

/*
 * Sequence-aware fuzzing — Phase 1.
 *
 * Phase 1 dispatches a 2-4 syscall chain per fuzzer iteration instead of
 * a single call.  Between consecutive calls, the previous call's return
 * value may be substituted into one randomly-chosen arg slot of the next
 * call.  Nothing is persisted across iterations: each chain is freshly
 * randomised and discarded.  The aim is to test, with the smallest viable
 * change, whether short retval-threaded chains find edges that single-call
 * fuzzing cannot.
 *
 * Set ENABLE_SEQUENCE_CHAIN to 0 to fall back to the legacy one-call-per
 * iteration dispatch for A/B coverage comparison.
 */
#define ENABLE_SEQUENCE_CHAIN 1

bool run_sequence_chain(struct childdata *child);

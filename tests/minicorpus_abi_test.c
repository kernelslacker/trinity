/*
 * Self-check for the minicorpus ABI split (persist/minicorpus-*.c).  On
 * biarch the 32- and 64-bit syscalls at one nr share a ring, so replay
 * may only take entries saved under the record's ABI.
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* ARCH_IS_BIARCH */
#include "blob_corpus.h"
#include "debug.h"		/* BUG */
#include "minicorpus.h"
#include "persist/minicorpus-internal.h"
#include "shm.h"
#include "strategy.h"		/* PLATEAU_HYPOTHESIS_* */
#include "syscall.h"
#include "tables.h"		/* syscalls_{32,64}bit, max_nr_{32,64}bit_syscalls */

/* Owned by persist/minicorpus-accounting.c in production. */
bool this_replay_source_tracked;
unsigned int this_replay_source_nr;
unsigned int this_replay_source_slot;
unsigned int this_replay_source_age;

/* One nr per case.  Each table's syscall there is named after its
 * argtypes. */
enum {
	NR_SHARED,	/* replay-safe in both tables */
	NR_ABI_END,
};

static struct syscallentry range_range = {
	.name = "range_range",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
};

static struct syscallentry fd_range = {
	.name = "fd_range",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_RANGE },
};

/* [do32][nr]: the tables get_syscall_entry() reads while the test runs. */
static const struct syscalltable abi_table[2][NR_ABI_END] = {
	[0] = {
		[NR_SHARED] = { .entry = &range_range },
	},
	[1] = {
		[NR_SHARED] = { .entry = &fd_range },
	},
};

/* The mutator chain (persist/minicorpus-splice.c) is not linked: replay
 * hands back the picked entry's args unchanged, so they name it. */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry)
{
	(void) args;
	(void) entry;
}

/* args/pools/blob_corpus.c is not linked; no blob stash is pending. */
void blob_corpus_promote_pending(void)
{
}

#define TAG64		0x6400UL
#define TAG32		0x3200UL
#define REPLAY_TRIES	1000U

/* Every replay that runs must hand back an entry of the record's ABI,
 * and a skipped pick must not leave a source tracked for the commit. */
static void replay_takes_own_abi(bool do32, bool burst)
{
	struct syscallrecord rec;
	unsigned int i, hits = 0;

	memset(&rec, 0, sizeof(rec));
	rec.nr = NR_SHARED;
	rec.do32bit = do32;
	__atomic_store_n(&shm->plateau_current_hypothesis,
			 burst ? (int) PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT :
				 (int) PLATEAU_HYPOTHESIS_NONE,
			 __ATOMIC_RELAXED);

	for (i = 0; i < REPLAY_TRIES; i++) {
		this_replay_source_tracked = false;
		if (!minicorpus_replay(&rec)) {
			if (this_replay_source_tracked)
				BUG("minicorpus abi: a skipped replay tracked a source");
			continue;
		}
		if ((rec.a2 & ~0xffUL) != (do32 ? TAG32 : TAG64))
			BUG("minicorpus abi: replay took the other ABI's entry");
		hits++;
	}
	if (hits == 0)
		BUG("minicorpus abi: replay never took its own ABI's entry");

	__atomic_store_n(&shm->plateau_current_hypothesis,
			 (int) PLATEAU_HYPOTHESIS_NONE, __ATOMIC_RELAXED);
}

/* Save both ABIs' calls at one nr, alternating, deeper than the
 * K-newest window the burst path picks from.  The tag rides in a2, the
 * RANGE slot in both tables (the 32-bit a1 is an fd, zeroed on save). */
static void replay_filters_by_abi(void)
{
	struct syscallrecord rec;
	unsigned int i;

	memset(minicorpus_shm, 0, sizeof(*minicorpus_shm));
	memset(&rec, 0, sizeof(rec));
	rec.nr = NR_SHARED;
	for (i = 0; i < 16; i++) {
		rec.do32bit = (i & 1) != 0;
		rec.a1 = i;
		rec.a2 = (rec.do32bit ? TAG32 : TAG64) | i;
		minicorpus_save_with_reason(&rec, CORPUS_SAVE_REASON_PC);
	}
	if (minicorpus_shm->rings[NR_SHARED].count != 16)
		BUG("minicorpus abi: the ring did not take every save");

	replay_takes_own_abi(false, false);
	replay_takes_own_abi(true, false);
	replay_takes_own_abi(false, true);
	replay_takes_own_abi(true, true);
}

void minicorpus_abi_self_check(void);
void minicorpus_abi_self_check(void)
{
#ifndef ARCH_IS_BIARCH
	/* A uniarch get_syscall_entry() ignores do32: there is no split. */
	return;
#endif
	minicorpus_shm = calloc(1, sizeof(*minicorpus_shm));
	if (minicorpus_shm == NULL)
		BUG("minicorpus abi: calloc failed");
	syscalls_64bit = abi_table[0];
	syscalls_32bit = abi_table[1];
	max_nr_64bit_syscalls = NR_ABI_END;
	max_nr_32bit_syscalls = NR_ABI_END;

	replay_filters_by_abi();

	/* Back to the empty tables fake_parent.c provides. */
	syscalls_64bit = NULL;
	syscalls_32bit = NULL;
	max_nr_64bit_syscalls = 0;
	max_nr_32bit_syscalls = 0;
	free(minicorpus_shm);
	minicorpus_shm = NULL;
}

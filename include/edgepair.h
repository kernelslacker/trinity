#pragma once

#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Edge-pair tracking: record (prev_syscall, curr_syscall) pairs and
 * count how many new KCOV edges each pair produces.  This discovers
 * which syscall *sequences* find new kernel code paths, feeding into
 * group biasing so Trinity prioritizes productive sequences.
 *
 * Implementation: open-addressed hash table in shared memory with
 * linear probing.  Lock-free via atomics — multiple children can
 * update concurrently with minor hash collisions being acceptable.
 */

/* Must be power of two for fast modulo. */
#define EDGEPAIR_TABLE_SIZE	4096
#define EDGEPAIR_TABLE_MASK	(EDGEPAIR_TABLE_SIZE - 1)

/* Sentinel value for empty slots. */
#define EDGEPAIR_EMPTY		0xFFFFFFFFU

/* Maximum linear probes before giving up on insert/lookup. */
#define EDGEPAIR_MAX_PROBE	16

/* A pair hasn't produced new edges in this many pair-calls — it's cold. */
#define EDGEPAIR_COLD_THRESHOLD	100000

/* Sentinel for "no previous syscall yet". */
#define EDGEPAIR_NO_PREV	0xFFFFU

struct edgepair_entry {
	unsigned int prev_nr;		/* previous syscall number */
	unsigned int curr_nr;		/* current syscall number */
	unsigned long new_edge_count;	/* times this pair found new edges */
	unsigned long total_count;	/* total times this pair was executed */
	unsigned long last_new_at;	/* global pair-call number when last new */
};

struct edgepair_shared {
	struct edgepair_entry table[EDGEPAIR_TABLE_SIZE];
	unsigned long total_pair_calls;	/* global monotonic counter */
	unsigned long pairs_tracked;	/* number of unique pairs inserted */
};

extern struct edgepair_shared *edgepair_shm;

/* Allocate the shared hash table.  Called from init_shm(). */
void edgepair_init_global(void);

/*
 * Record a pair (prev_nr, curr_nr) after kcov_collect().
 * found_new: whether kcov_collect() reported new edges.
 */
void edgepair_record(unsigned int prev_nr, unsigned int curr_nr,
		     bool found_new);

/*
 * Returns true if the pair (prev_nr, curr_nr) has gone cold —
 * it exists in the table but hasn't found new edges recently.
 * Used by syscall selection to deprioritize stale sequences.
 */
bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr);

/*
 * Returns true if the pair (prev_nr, curr_nr) has found new edges
 * at least once.  Used to boost productive sequences.
 */
bool edgepair_is_productive(unsigned int prev_nr, unsigned int curr_nr);

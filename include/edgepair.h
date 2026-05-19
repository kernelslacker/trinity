#pragma once

#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Edge-pair tracking: record (prev_syscall, curr_syscall) pairs and
 * count how many new KCOV edges each pair produces.  This discovers
 * which syscall *sequences* find new kernel code paths, feeding into
 * group biasing so Trinity prioritizes productive sequences.
 *
 * Implementation: open-addressed hash table.  Canonical lives in
 * parent-private struct edgepair_aggregate (parent_edgepair in
 * edgepair-ring.c), fed by per-child SPSC observation rings the parent
 * drains each main_loop iteration.  Child reads consult the published
 * mirror page (edgepair_published); parent-side consumers walk the
 * canonical directly.  See include/edgepair_ring.h for the retrofit
 * topology and storage discipline.
 */

/* Must be power of two for fast modulo.
 *
 * 4096 slots saturated within minutes once a run started exercising more
 * than ~1024 distinct (prev, curr) pairs — load factor over 25% pushed
 * the linear-probe chains past EDGEPAIR_MAX_PROBE, after which inserts
 * silently dropped on the floor and edgepair-driven boosting / cold
 * detection ran on a stale view of the world.
 *
 * Bumped from 64K to 256K after observing 53,791 unique pairs against a
 * 65,536-slot table (82% load factor) and a 37% insert drop rate in a
 * healthy run -- well into the linear-probe collapse zone the 4K -> 64K
 * bump was already meant to escape.  256K slots brings the load factor
 * for that same workload back down to ~21%, below the 25% probe-chain
 * danger threshold the original sizing note calls out.  Memory cost:
 * the parent-private canonical grows from 2 MiB to 8 MiB (.bss, parent
 * only) and the child-RO published mirror page grows from ~1.5 MiB to
 * ~6 MiB (alloc_shared, single existing call site -- shared-region-
 * budget call-site count unchanged). */
#define EDGEPAIR_TABLE_SIZE	262144
#define EDGEPAIR_TABLE_MASK	(EDGEPAIR_TABLE_SIZE - 1)

/* Sentinel value for empty slots. */
#define EDGEPAIR_EMPTY		0xFFFFFFFFU

/* Maximum linear probes before giving up on insert/lookup.  Bumped
 * alongside the table grow so a healthy hash collision streak still has
 * room to resolve before we drop. */
#define EDGEPAIR_MAX_PROBE	32

/* A pair hasn't produced new edges in this many pair-calls — it's cold. */
#define EDGEPAIR_COLD_THRESHOLD	100000

/* Sentinel for "no previous syscall yet". */
#define EDGEPAIR_NO_PREV	0xFFFFU

/* Magic number for edgepair binary dump files.  Bumped when the on-disk
 * layout changes so edge_analyzer rejects stale dumps cleanly instead of
 * misinterpreting them.  0xEDDA7A03U: EDGEPAIR_TABLE_SIZE grew from
 * 65536 to 262144, so the byte length of the table[] section in the
 * dump quadrupled; old analyzers must reject these dumps cleanly
 * rather than walk past the end of their fixed 65K-slot view.  The
 * previous bump (0xEDDA7A01 -> 0xEDDA7A02) marked the retrofit to a
 * parent-private canonical producer; this one marks the table grow. */
#define EDGEPAIR_DUMP_MAGIC	0xEDDA7A03U

struct edgepair_entry {
	unsigned int prev_nr;		/* previous syscall number */
	unsigned int curr_nr;		/* current syscall number */
	unsigned long new_edge_count;	/* times this pair found new edges */
	unsigned long total_count;	/* total times this pair was executed */
	unsigned long last_new_at;	/* global pair-call number when last new */
};

struct childdata;

/* Set the edgepair_enabled flag.  Called from kcov_init_global() once
 * KCOV is confirmed available.  The parent-private canonical and the
 * child-RO mirror page are allocated and initialised separately in
 * edgepair_published_init() (called unconditionally from init_shm). */
void edgepair_init_global(void);

bool edgepair_is_enabled(void);

/*
 * Record a pair (prev_nr, curr_nr) after kcov_collect().
 * found_new: whether kcov_collect() reported new edges.
 *
 * Enqueues a slot onto the calling child's edgepair_ring; the parent's
 * edgepair_ring_drain_all() applies it under single-writer discipline.
 */
void edgepair_record(struct childdata *child,
		     unsigned int prev_nr, unsigned int curr_nr,
		     bool found_new);

/*
 * Returns true if the pair (prev_nr, curr_nr) has gone cold —
 * it exists in the table but hasn't found new edges recently.
 * Used by syscall selection to deprioritize stale sequences.
 */
bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr);

/*
 * Read-only accessor returning the raw (new_edges, total) counters for a
 * given (prev, curr) pair.  Returns {0, 0} on miss or before the table is
 * initialised.  Callers compute their own productivity ratio (e.g. HEALER's
 * Beta-smoothed coverage multiplier) without exposing the entry pointer.
 */
struct edgepair_stats {
	unsigned long new_edges;
	unsigned long total;
};

struct edgepair_stats edgepair_get_stats(unsigned int prev_nr,
					 unsigned int curr_nr);

/*
 * Dump the edge-pair hash table to a binary file for offline analysis.
 * File format: 4-byte EDGEPAIR_DUMP_MAGIC, then
 *   - struct edgepair_entry table[EDGEPAIR_TABLE_SIZE]
 *   - unsigned long total_pair_calls
 *   - unsigned long pairs_tracked
 *   - unsigned long pairs_dropped
 * Byte layout below the magic matches the pre-retrofit dump prefix; the
 * magic bump from 0xEDDA7A01U to 0xEDDA7A02U marks the producer change.
 */
void edgepair_dump_to_file(const char *path);

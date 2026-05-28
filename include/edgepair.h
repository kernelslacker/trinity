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

/*
 * Shared (prev, curr) -> bucket hash.  static inline so edgepair.c,
 * edgepair-ring.c, and tools/edge_analyzer.c can share one definition
 * without the duplicated-with-comments-saying-keep-in-sync dance the
 * three per-file copies used to require.
 */
static inline unsigned int edgepair_pair_hash(unsigned int prev,
					      unsigned int curr)
{
	unsigned int h = prev * 31 + curr;

	h ^= h >> 16;
	h *= 0x45d9f3bU;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
}

/*
 * Pair classification used by syscall-sequence chooser, the strategy
 * arms, and the rescue / cold-pair heuristics.  Derived from the raw
 * (new_edge_count, total_count, last_new_at) counters in one place so
 * consumers stop re-deriving "is this pair productive and fresh?"
 * inline against the published mirror.
 */
enum edgepair_pair_state {
	EDGEPAIR_STATE_UNSEEN,		/* pair never inserted */
	EDGEPAIR_STATE_SEEN_UNPRODUCTIVE,/* executed, never found a new edge */
	EDGEPAIR_STATE_PRODUCTIVE_FRESH,/* produced a new edge within cooldown */
	EDGEPAIR_STATE_PRODUCTIVE_COLD,	/* produced new edges before, now stale */
};

/*
 * Richer per-pair snapshot.  Superset of edgepair_stats: carries the
 * raw counters plus the classified state and a present bit so a caller
 * can distinguish "miss" from "hit with zeroed counters".
 */
struct edgepair_snapshot {
	unsigned long new_edges;
	unsigned long total;
	unsigned long last_new_at;
	enum edgepair_pair_state state;
	bool present;
};

/*
 * Hint for edgepair_score(): which axis the consumer is optimising
 * along.  EXPLORATION favours unseen pairs, EXPLOITATION favours fresh
 * producers, COLD_PENALTY just downweights stale productive pairs
 * without otherwise reshuffling the ordering.
 */
enum edgepair_score_mode {
	EDGEPAIR_SCORE_EXPLORATION,
	EDGEPAIR_SCORE_EXPLOITATION,
	EDGEPAIR_SCORE_COLD_PENALTY,
};

/* Magic number for edgepair binary dump files.  Bumped when the on-disk
 * layout changes so edge_analyzer rejects stale dumps cleanly instead of
 * misinterpreting them.  0xEDDA7A03U: EDGEPAIR_TABLE_SIZE grew from
 * 65536 to 262144, so the byte length of the table[] section in the
 * dump quadrupled; old analyzers must reject these dumps cleanly
 * rather than walk past the end of their fixed 65K-slot view.  The
 * previous bump (0xEDDA7A01 -> 0xEDDA7A02) marked the retrofit to a
 * parent-private canonical producer; this one marks the table grow.
 *
 * 0xEDDA7A04U: the dump now leads with a fixed-size header carrying
 * version + table_size + CRC32 over the table payload plus the three
 * top-level counters, so a warm-start loader can reject torn / stale
 * files without walking past the end of a partial table.  Old dumps
 * (0xEDDA7A03) get rejected on magic mismatch and the session starts
 * cold.
 *
 * 0xEDDA7A05U: the header now also carries the kernel fingerprint
 * (kallsyms_sha256) plus the syscall-ABI identity fields
 * (max_nr_syscall, biarch_mode) so the loader can fence the warm-
 * start against kernel rebuilds, syscall-table shape changes, and
 * biarch flips.  Old dumps (0xEDDA7A04) get rejected on magic
 * mismatch and the session starts cold. */
#define EDGEPAIR_DUMP_MAGIC	0xEDDA7A05U
/* EDGEPAIR_DUMP_VERSION
 *   1: initial 80-byte header (magic + version + table_size + CRC +
 *      three u64 counters + kallsyms_sha256 + max_nr_syscall +
 *      biarch_mode).
 *   2: 112-byte header -- appends syscall_table_digest[32], a SHA-256
 *      over the active syscall table's (arch_tag, nr, name) tuples.
 *      Catches the case the v1 identity checks miss: two kernels
 *      sharing MAX_NR_SYSCALL but reordering some syscall numbers
 *      pass kallsyms / max_nr / biarch but render every persisted
 *      (prev_nr, curr_nr) entry semantically wrong.  v1 dumps are
 *      rejected on version mismatch -- they have no per-table-shape
 *      identity to warm-start safely against the new loader. */
#define EDGEPAIR_DUMP_VERSION	2U

/* On-disk dump header.  Fixed 112 bytes -- four u32 followed by three
 * u64, followed by a 32-byte kallsyms fingerprint, two more u32 of
 * syscall-ABI identity, and a 32-byte syscall-table digest.  Naturally
 * aligned without internal padding so the loader can read it as a
 * single blob.  Followed immediately by
 * parent_edgepair.table[EDGEPAIR_TABLE_SIZE]; the CRC covers that
 * table payload only -- the counters live inside the header so they
 * ride the header read and aren't re-checksummed separately.  The
 * first 40 bytes are bit-identical to the 0xEDDA7A04 layout so an
 * offline analyzer / recovery tool can still parse the legacy prefix
 * out of a rejected file. */
struct edgepair_dump_header {
	uint32_t magic;			/* EDGEPAIR_DUMP_MAGIC */
	uint32_t version;		/* EDGEPAIR_DUMP_VERSION */
	uint32_t table_size;		/* EDGEPAIR_TABLE_SIZE */
	uint32_t payload_crc32;		/* CRC32 over table[] payload */
	uint64_t total_pair_calls;
	uint64_t pairs_tracked;
	uint64_t pairs_dropped;
	/* Identity fields added in EDGEPAIR_DUMP_MAGIC
	 * 0xEDDA7A05U.  Together they fence the warm-start
	 * against kernel rebuilds, syscall-table shape changes,
	 * and biarch flips -- any of which can rename or remove
	 * entries in the (prev, curr) pair space the saved table
	 * indexes into. */
	uint8_t  kallsyms_sha256[32];	/* kcov_get_kernel_fp() */
	uint32_t max_nr_syscall;	/* MAX_NR_SYSCALL at save */
	uint32_t biarch_mode;		/* biarch ? 1 : 0 at save */
	/* Added in EDGEPAIR_DUMP_VERSION 2: SHA-256 over the
	 * active syscall table(s).  Closes the gap where two
	 * kernels with identical max_nr_syscall but reordered
	 * syscall numbers pass every other identity check and
	 * silently corrupt the (prev_nr, curr_nr)-keyed table on
	 * warm-start.  kcov_get_syscall_table_digest(). */
	uint8_t  syscall_table_digest[32];
};

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
 * Parent-side cold predicate.  Same math as edgepair_is_cold() but
 * keyed by a parent_edgepair.table[] entry pointer and reading the
 * canonical aggregate directly (no child-RO mirror).  For stats / dump
 * walkers that are already iterating parent_edgepair.table[]; using
 * the mirror-keyed edgepair_is_cold() there can disagree with the
 * canonical entry the surrounding code is about to print.
 */
bool edgepair_entry_is_cold_parent(const struct edgepair_entry *e);

/*
 * Read-only accessor returning the raw (new_edges, total) counters for a
 * given (prev, curr) pair.  Returns {0, 0} on miss or before the mirror
 * is populated.  Callers compute their own productivity ratio without
 * exposing the entry pointer.
 *
 * Child-safe: reads the published mirror, refreshed at every drain, so
 * children see the parent's current aggregate instead of the fork-time
 * / warm-start snapshot the COW canonical leaves frozen in child
 * address space.  Lags the canonical by at most one publish interval.
 */
struct edgepair_stats {
	unsigned long new_edges;
	unsigned long total;
};

struct edgepair_stats edgepair_get_stats(unsigned int prev_nr,
					 unsigned int curr_nr);

/*
 * Classify a pair into one of enum edgepair_pair_state.  Child-side
 * safe: reads the published mirror with the same acquire ordering as
 * edgepair_is_cold().  Returns UNSEEN when edgepair is disabled, the
 * mirror is not yet populated, or the pair is absent.
 */
enum edgepair_pair_state edgepair_state(unsigned int prev_nr,
					unsigned int curr_nr);

/*
 * Parent-side richer lookup.  Fills *out with the canonical counters
 * and the mirror-derived state for a (prev, curr) pair.  Returns true
 * on hit, false on miss (out->present is set either way).  Reads
 * parent_edgepair.table[] directly, so it is only safe to call from
 * the parent.
 */
bool edgepair_lookup(unsigned int prev_nr, unsigned int curr_nr,
		     struct edgepair_snapshot *out);

/*
 * Map (prev, curr) -> a relative weight in [0, 1024], using MODE to
 * pick which state buckets dominate.  First-cut placeholder weights:
 * the API surface is the goal here, not the numbers -- once the
 * sequence-chain picker and the frontier strategy arm land they'll
 * tune these against real productivity data.
 */
unsigned int edgepair_score(unsigned int prev_nr, unsigned int curr_nr,
			    enum edgepair_score_mode mode);

/*
 * Dump the edge-pair hash table to a binary file for offline analysis
 * and warm-start of a follow-on process.  File format:
 *   - struct edgepair_dump_header (magic, version, table_size,
 *     payload_crc32, total_pair_calls, pairs_tracked, pairs_dropped)
 *   - struct edgepair_entry table[EDGEPAIR_TABLE_SIZE]
 * The payload_crc32 covers the table[] bytes only; the counters ride
 * inside the header.
 */
void edgepair_dump_to_file(const char *path);

/*
 * Warm-start loader counterpart to edgepair_dump_to_file().  Reads PATH,
 * validates header + payload CRC, and installs the table and the three
 * top-level counters into parent_edgepair before any child has been
 * forked.  Returns true on a clean load, false on missing / truncated /
 * stale / corrupt file (caller treats false as legitimate cold-start).
 * No-op when edgepair is disabled.
 */
bool edgepair_load_from_file(const char *path);

/*
 * Callback signature for edgepair_for_each_parent_entry().  Returns
 * true to keep iterating, false to stop early.  The entry pointer
 * aliases parent_edgepair.table[]; callbacks must not mutate it and
 * must not call into edgepair APIs that take the same internal
 * locking the iterator already holds (just read).  CTX is opaque to
 * the iterator and passed through verbatim.
 */
typedef bool (*edgepair_iter_fn)(const struct edgepair_entry *e,
				 void *ctx);

/*
 * Parent-side walk of the canonical pair table.  Invokes CB on every
 * non-empty entry (skips EDGEPAIR_EMPTY slots).  Returns the number
 * of entries visited.  Reads parent_edgepair.table[] directly so it
 * is only safe to call from the parent, matching edgepair_lookup().
 * No-op when edgepair is disabled.
 */
unsigned int edgepair_for_each_parent_entry(edgepair_iter_fn cb,
					    void *ctx);

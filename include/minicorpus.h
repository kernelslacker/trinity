#pragma once

#include "locks.h"
#include "syscall.h"

/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * When a syscall invocation discovers new KCOV edges, its argument
 * values are saved in a per-syscall ring buffer. During argument
 * generation, a saved arg set may be replayed with small mutations
 * instead of generating entirely fresh values.
 *
 * SAFETY: Only syscalls WITHOUT a sanitise callback are eligible.
 * 65 of 346 syscalls have sanitise callbacks that allocate and stash
 * pointers into arg slots. Replaying those stale pointer values
 * would cause use-after-free. The has_sanitise check gates both
 * save and replay.
 */

/* Number of arg snapshots retained per syscall number.
 *
 * 8 was sized for the original syscall set and very short runs.  Anything
 * busier — long fuzzing sessions, or syscalls that find new edges in
 * bursts — evicted promising snapshots before they got a chance to be
 * replayed.  32 slots (~1.8 MB total shared memory across MAX_NR_SYSCALL
 * rings) widens the replay window without burning meaningful memory. */
#define CORPUS_RING_SIZE 32

struct corpus_entry {
	unsigned long args[6];
	unsigned int num_args;
};

struct corpus_ring {
	lock_t lock;
	unsigned int head;		/* next write slot (mod CORPUS_RING_SIZE) */
	unsigned int count;		/* entries stored (max CORPUS_RING_SIZE) */
	struct corpus_entry entries[CORPUS_RING_SIZE];
};

/* Number of distinct primitive mutator cases inside mutate_arg().
 * The numerical IDs (0=bit-flip, 1=add, 2=sub, 3=boundary, 4=byte-shuffle,
 * 5=keep, 6=bswap-add, 7=bswap-sub, 8=fd-swap) are stable — weighted
 * scheduling counters are indexed by them and any reordering must be
 * reflected in mut_trials/mut_wins below.
 *
 * Cases 6/7 are endian-aware add/sub: byte-swap the value at a
 * randomly-picked width (16/32/64), apply the delta, swap back.  This
 * reaches arithmetic neighbours of values that the kernel interprets
 * with ntohs/ntohl (sockaddr ports, raw IP headers, netfilter rules,
 * netlink BE attrs) — values that look like noise to a native-endian
 * add/sub mutator.
 *
 * Case 8 is fd-pool cross-pollination: only meaningful for fd-typed
 * args (ARG_FD and the typed ARG_FD_* family).  With ~50% probability
 * it replaces the slot with a different live fd drawn from the global
 * pool — any flavour, not necessarily the slot's declared type — so
 * the kernel sees fd cross-feeds (e.g. a timerfd handed to an io_uring
 * register call).  The other ~50% applies a small integer mutation
 * inline so the slot still sees arithmetic-neighbour exploration.  The
 * weighted scheduler zeros this case for non-fd args, so picks here
 * are never wasted on numeric slots. */
#define MUT_NUM_OPS 9

/* Maximum mutation stacking depth per argument (see pick_stack_depth()). */
#define STACK_MAX 4

struct minicorpus_shared {
	struct corpus_ring rings[MAX_NR_SYSCALL];
	/* Per-mutator-case productivity counters used by weighted pick:
	 *   mut_trials[op] = times case `op` was selected fleet-wide
	 *   mut_wins[op]   = times a call whose mutations included `op`
	 *                    discovered new coverage
	 * Both updated via __atomic ops; consumed by weighted_pick_case()
	 * in minicorpus.c. */
	unsigned long mut_trials[MUT_NUM_OPS];
	unsigned long mut_wins[MUT_NUM_OPS];
	/* Replay-path measurement counters for the mutation trio.
	 * All updated via __atomic RELAXED; read at dump_stats() time. */
	unsigned long replay_count;		/* replays that ran (returned true) */
	unsigned long replay_wins;		/* replays that found new coverage */
	unsigned long splice_hits;		/* per-arg splice firings */
	unsigned long splice_wins;		/* replays with splice that found new coverage */
	/* Distribution of stacking depths chosen by pick_stack_depth().
	 * Index is the depth value (1..STACK_MAX); index 0 is unused. */
	unsigned long stack_depth_histogram[STACK_MAX + 1];

	/* Sequence-chain telemetry (Phase 1).  chain_iter_count is bumped
	 * once per chain dispatched; chain_substitution_count is bumped
	 * each time a step's arg slot was overwritten with the previous
	 * step's return value.  The ratio measures the realised substitution
	 * frequency and lets the gating probability inside the chain
	 * executor be tuned against observed coverage outcomes. */
	unsigned long chain_iter_count;
	unsigned long chain_substitution_count;

	/* Edge-count high-water-mark for the last periodic mid-run snapshot.
	 * minicorpus_maybe_snapshot() compares kcov_shm->edges_found against
	 * this value and, when the gap reaches MINICORPUS_SNAPSHOT_EDGES, races
	 * to advance the field via compare-exchange.  The single CAS winner
	 * triggers the save; losers see the new high-water-mark on their next
	 * call and early-return until another window's worth of edges
	 * accumulates. */
	unsigned long edges_at_last_snapshot;
};

extern struct minicorpus_shared *minicorpus_shm;

/* Called once from init_shm() to allocate shared corpus storage. */
void minicorpus_init(void);

/* Save a syscall's args into the corpus ring for its syscall number.
 * Only call when kcov_collect() returned true (new edges found)
 * AND entry->sanitise == NULL. */
void minicorpus_save(struct syscallrecord *rec);

/* Try to replay a saved arg set with mutations into rec.
 * Returns true if replay was performed, false if no corpus entry
 * was available or the dice roll said to generate fresh args.
 * Only call when entry->sanitise == NULL. */
bool minicorpus_replay(struct syscallrecord *rec);

/* Apply the per-arg mutator chain (cross-arg splice + weighted-stack
 * mutate + fd safety) to args[6] in place.  Used by both per-syscall
 * mini-corpus replay and chain-corpus replay so the mutation engine
 * and its productivity counters are shared.  @entry supplies argtype[]
 * and num_args; pass NULL-checked entry.  @nr is the syscall table
 * index — passed through to the bit-flip mutator so it can consult
 * the effector map for per-(syscall, arg) bit weights. */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry,
		unsigned int nr);

/* Mutator-case attribution.
 *
 * mutate_arg() accumulates per-case pick counts in process-local stash
 * during arg generation.  The post-syscall path commits or discards that
 * stash exactly once per syscall:
 *   - commit() folds the stash into shm-wide trials, and (if
 *     found_new) into wins, then clears the stash.  Call from the
 *     normal coverage path after kcov_collect().
 *   - clear() drops the stash without crediting.  Call from paths that
 *     don't produce a found_new signal (cmp-mode syscalls), so a future
 *     commit isn't fed stale counts from a previous call.
 *
 * Exactly one of commit/clear must run per syscall; otherwise a later
 * commit will mis-attribute mutations from an earlier syscall to a
 * coverage event that didn't include them. */
void minicorpus_mut_attrib_commit(bool found_new);
void minicorpus_mut_attrib_clear(void);

/* Persist the in-memory corpus rings to a file at @path.
 * Writes via a per-pid .tmp file and renames atomically — safe under
 * concurrent callers (CAS in minicorpus_maybe_snapshot serialises
 * normal periodic saves, the per-pid suffix is belt-and-braces against
 * a periodic save racing the on-shutdown save).  Returns true on
 * success, false on any I/O failure (caller should treat as advisory). */
bool minicorpus_save_file(const char *path);

/* Load a previously-persisted corpus from @path into the rings.
 * Discards entries silently when the file is missing, the magic/version
 * header doesn't match, the kernel major.minor differs from the running
 * kernel, or a per-entry CRC fails.
 *
 * @loaded and @discarded receive counts for stats reporting; either may
 * be NULL.  Returns true if at least one entry was loaded. */
bool minicorpus_load_file(const char *path,
		unsigned int *loaded, unsigned int *discarded);

/* Default per-arch persistence path (e.g. ~/.cache/trinity/corpus/x86_64).
 * Returned pointer is owned by the callee and remains valid until the
 * next call.  Returns NULL if no suitable path can be derived (no $HOME,
 * mkdir failure, etc.). */
const char *minicorpus_default_path(void);

/* Coverage-delta gap (in newly-discovered edges, fleet-wide) between
 * periodic mid-run snapshots.
 *
 * Why mid-run snapshots: the on-shutdown save in trinity.c only runs on
 * graceful exit.  An shm-corruption trip or hard crash mid-run skips
 * the save entirely and the entire accumulated corpus is lost.  The
 * 2026-04-21 shm-corruption tree dropped ~810k edges of state this way.
 *
 * Triggering off coverage delta rather than wall-time keeps the save
 * cadence proportional to actual fuzzing progress: an idle or stalled
 * run doesn't burn I/O on snapshots that capture nothing new, while a
 * productive burst snapshots quickly enough to bound loss.
 *
 * 100k is the loss-vs-overhead trade.  Smaller gaps cap loss tighter
 * but spend more I/O bandwidth on the save path; larger gaps risk
 * losing more progress per crash.  At observed steady-state edge growth
 * (~10-30k edges/min on a busy fleet) this fires every few minutes. */
#define MINICORPUS_SNAPSHOT_EDGES 100000

/* Configure the path that minicorpus_maybe_snapshot() will save to.
 * Call once from the parent before fork (the path string is copied into
 * a process-local buffer, so children inherit it via COW).  Pass NULL
 * to disable mid-run snapshots — callers honour --no-warm-start by not
 * calling this. */
void minicorpus_enable_snapshots(const char *path);

/* Check the per-snapshot coverage gap and, if reached, race to claim
 * the next snapshot via compare-exchange.  The single winning caller
 * runs minicorpus_save_file() to the configured path; everyone else
 * early-returns.  Cheap fast path on the no-trigger case (one atomic
 * load each from kcov_shm->edges_found and the high-water-mark, plus
 * a comparison).  Safe to call from any child after every kcov edge
 * event. */
void minicorpus_maybe_snapshot(void);

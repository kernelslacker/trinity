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

struct minicorpus_shared {
	struct corpus_ring rings[MAX_NR_SYSCALL];
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

/* Persist the in-memory corpus rings to a file at @path.
 * Writes via a .tmp file and renames atomically.  Returns true on
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

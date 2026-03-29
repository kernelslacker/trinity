#pragma once

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

/* Number of arg snapshots retained per syscall number. */
#define CORPUS_RING_SIZE 8

struct corpus_entry {
	unsigned long args[6];
	unsigned int num_args;
};

struct corpus_ring {
	unsigned char lock;
	pid_t locker_pid;
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

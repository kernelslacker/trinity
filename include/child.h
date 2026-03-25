#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <types.h>
#include "kcov.h"
#include "objects.h"
#include "syscall.h"

struct fd_event_ring;

struct childdata {
	/* The actual syscall records each child uses. */
	struct syscallrecord syscall;

	/* Per-child KCOV state (fd + trace buffer). */
	struct kcov_child kcov;

	struct objhead objects[MAX_OBJECT_TYPES];

	/* last time the child made progress. */
	struct timespec tp;
	unsigned long op_nr;

	unsigned int seed;

	unsigned int num;

	/* Last syscall group executed, for group biasing. */
	unsigned int last_group;

	/* per-child fd caching to avoid cross-child races */
	int current_fd;
	unsigned int fd_lifetime;
	uint32_t cached_fd_generation;	/* generation when current_fd was fetched */

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	unsigned char xcpu_count;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	bool dropped_privs;
};

extern unsigned int max_children;

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void init_child_mappings(void);

void child_process(struct childdata *child, int childno);

void set_dontkillme(struct childdata *child, bool state);

void reap_child(struct childdata *child, int childno);

/* Childops */
bool random_syscall(struct childdata *child);
bool drop_privs(struct childdata *child);

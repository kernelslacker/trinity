#pragma once

#include <sys/types.h>
#include "child.h"
#include "types.h"

extern pid_t *pids;
extern pid_t mainpid;
extern pid_t cached_pid;

/*
 * Cached self pid.  glibc 2.25 (2017) dropped its libc-side getpid()
 * cache to close a fork() race, so every libc getpid() call is now a
 * real syscall.  Profiling showed __getpid as the dominant inclusive
 * cost during fuzz runs; cache the result ourselves and route every
 * caller through this inline accessor.
 *
 * Storage is `cached_pid` (declared above), which already carries the
 * "this process's own pid" semantic: written in the parent right after
 * `mainpid = getpid()` in main(), and overwritten in each forked child
 * by set_child_cache() called from init_child() before any fuzz work
 * begins.  No thread-local storage is needed because trinity children
 * are processes (fork), not threads — each child gets its own private
 * copy of the global via copy-on-write.
 */
static inline pid_t mypid(void)
{
	return cached_pid;
}

#define for_each_child(i)	for (i = 0; i < max_children; i++)

#define CHILD_NOT_FOUND -1
#define EMPTY_PIDSLOT -1

bool pid_alive(pid_t pid);
int find_childno(pid_t pid);
void set_child_cache(int childno, pid_t pid, struct childdata *child);
bool pidmap_empty(void);
void dump_childnos(void);
void dump_pids_page_state(void);
int pid_is_valid(pid_t);
void pids_init(void);

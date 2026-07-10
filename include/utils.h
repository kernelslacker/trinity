#pragma once

#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <time.h>

#include "compiler.h"
#include "rnd.h"

#include "utils-macros.h"
#include "utils-mem.h"
#include "utils-alloc.h"
#include "utils-proc.h"

#define MAX_SHARED_ALLOCS 4096

/*
 * Reserve slots in shared_regions[] that are not consumed by per-child
 * growth (struct shm_s, syscalltable copy, kcov rings, image segments,
 * shared obj/str heaps, deferred-free, pids/children index pages, etc.).
 * Anything left after this reserve is the budget for per-child allocs.
 */
#define SHARED_REGIONS_GLOBAL_RESERVE 256

/*
 * Per-child shared allocations tracked in shared_regions[]:
 *   1. childdata                     (alloc_shared in init_shm)
 *   2. fd_event_ring                 (alloc_shared in init_shm)
 *   3. stats_ring                    (alloc_shared in init_shm)
 *   4. KCOV PC trace buffer          (track_shared_region in kcov.c, only
 *                                     on KCOV-capable kernels)
 *   5. KCOV CMP trace buffer         (track_shared_region in kcov.c, only
 *                                     when KCOV_TRACE_CMP is supported)
 *   6. diag_ring                     (alloc_shared in init_shm, lands with
 *                                     the diag-ring series)
 *
 * The cap formula in derive_max_children_cap() divides the remaining
 * shared_regions[] budget by this number.  We size for the worst case (7)
 * so that on KCOV-capable kernels the per-child KCOV buffers plus the
 * diag ring still fit inside shared_regions[] and remain visible to
 * range_overlaps_shared(), which protects them from fuzzed
 * munmap/mremap/madvise/mprotect.
 *
 * Capacity cost: with MAX_SHARED_ALLOCS=4096 and
 * SHARED_REGIONS_GLOBAL_RESERVE=256 the shared_regions[]-bound cap on
 * max_children drops from (3840 / 6)=640 to (3840 / 7)=548.
 */
#define SHARED_REGIONS_PER_CHILD 7

/*
 * Restartable waitpid() wrapper.  Trinity installs SIGALRM and SIGXCPU
 * without SA_RESTART (signals.c), so any blocking waitpid() in a non-
 * syscall path can return -1/EINTR.  Every reap site needs the wait to
 * either complete or fail terminally; treating EINTR as "done" leaves a
 * child unreaped and, for sites that tear down a shared mapping right
 * after the wait (barrier-racer, futex-storm), leaves a worker that will
 * fault when it next touches the destroyed barrier.
 *
 * WNOHANG semantics are preserved: the wrapper returns 0 (not block) when
 * no child has exited, because rc == 0 falls out of the loop condition;
 * only the EINTR-on-error case is retried.
 */
static inline pid_t waitpid_eintr(pid_t pid, int *status, int flags)
{
	pid_t rc;

	do {
		rc = waitpid(pid, status, flags);
	} while (rc < 0 && errno == EINTR);

	return rc;
}

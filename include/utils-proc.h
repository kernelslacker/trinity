#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/*
 * CLOCK_MONOTONIC nanoseconds since an arbitrary boot-relative epoch.
 * The only correct source for any elapsed-time / lifetime / cadence
 * computation in the codebase: time()/CLOCK_REALTIME can step backwards
 * on an NTP adjustment, and a negative duration then aliases as either
 * a false "fast-die" reap (EXIT_SHM_CORRUPTION panic) or an unbounded
 * snapshot-cadence burst.  Keep time()/localtime_r() strictly for the
 * human-facing wall-clock timestamps in log headers and filenames.
 *
 * Callers that only need seconds can divide by 1000000000ULL at the
 * use site -- one helper avoids proliferating a nsec/sec/msec family.
 */
static inline uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Saturating unsigned-long subtract: the only correct source for
 * a - b when an inversion (concurrent writer / counter reset) must
 * fold to zero rather than wrap. */
static inline unsigned long sat_sub_ul(unsigned long a, unsigned long b)
{ return (a >= b) ? (a - b) : 0UL; }

void sizeunit(unsigned long size, char *buf, size_t buflen);

void kill_pid(pid_t pid);

int get_num_fds(void);

/*
 * Online-CPU count snapshotted on first use, clamped to CPU_SETSIZE so
 * cpumask consumers (sched_setaffinity len picker, ARG_CPUMASK fill)
 * stay within the legality window the kernel enforces on user masks.
 */
unsigned int cached_online_cpus(void);

/*
 * Walk /proc/self/fd at parent startup and close any fd that wasn't
 * deliberately opened by trinity.  Run once, before trinity opens any
 * of its own fds — at that point the keep set is exactly {0, 1, 2}
 * and everything else came in from the launcher (or its parent).
 *
 * Defense in depth against the wedge class where an inherited fd for
 * a stuck filesystem (FUSE, NFS, etc.) ends up adopted into one of
 * trinity's per-child watch sets and a routine syscall on it blocks
 * for the lifetime of the run — stalling the parent's reap path and
 * letting zombie children pile up indefinitely.
 *
 * Bumps shm->stats.fd.parent_inherited_fds_closed for each fd closed,
 * and logs the fd number plus its readlink target so the operator
 * can see what the launcher left behind.
 */
void sanitize_inherited_fds(void);

/*
 * Plain CRC32 (IEEE 802.3 polynomial 0xedb88320, reflected, init/final
 * 0xffffffff).  Lazy 256-entry table built on first call.  Used by the
 * minicorpus, cmp_hints, and kcov-bitmap persistence formats for
 * header/payload checksums.
 */
uint32_t crc32(const void *buf, size_t len);

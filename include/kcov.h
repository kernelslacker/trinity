#pragma once

#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * KCOV coverage collection support.
 *
 * Automatically detects whether the kernel supports KCOV by trying to
 * open /sys/kernel/debug/kcov at child init time. If it works, PC-level
 * edge coverage is collected around each syscall invocation. A shared
 * bitmap tracks which PCs have been seen globally across all children.
 *
 * No command-line flag needed — KCOV is used when available, silently
 * skipped when not.
 */

/* Size of the per-child KCOV trace buffer (number of unsigned longs).
 * 64K entries is 512KB on 64-bit, enough for most syscall paths. */
#define KCOV_TRACE_SIZE (64 << 10)

/* Size of the global coverage bitmap in bytes.
 * 64KB = 512K bits. PCs are hashed into this bitmap. */
#define KCOV_BITMAP_SIZE (64 << 10)

/* KCOV trace modes */
#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1

struct kcov_child {
	int fd;
	unsigned long *trace_buf;
	bool active;    /* true if this child successfully opened kcov */
	bool cmp_mode;  /* true when this syscall should use CMP tracing */
};

/* Shared coverage state, allocated in shared memory. */
struct kcov_shared {
	unsigned char bitmap[KCOV_BITMAP_SIZE];
	unsigned long edges_found;
	unsigned long total_pcs;
	unsigned long per_syscall_edges[MAX_NR_SYSCALL];
};

extern struct kcov_shared *kcov_shm;

/* Called once from init_shm() to allocate shared coverage state. */
void kcov_init_global(void);

/* Called per-child to try to open/mmap the kcov fd.
 * Returns true on success or if kcov is unavailable (not an error).
 * Sets kc->active = true only if kcov is usable. */
void kcov_init_child(struct kcov_child *kc);

/* Called per-child on exit to clean up. */
void kcov_cleanup_child(struct kcov_child *kc);

/* Bracket the actual syscall() call with these. No-ops if !active. */
void kcov_enable_trace(struct kcov_child *kc);
void kcov_enable_cmp(struct kcov_child *kc);
void kcov_disable(struct kcov_child *kc);

/* After disabling, collect PCs and update the global bitmap.
 * Returns true if new coverage was found. nr is the syscall number
 * for per-syscall edge tracking. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr);

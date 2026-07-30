#pragma once

/* Per-child (non-shared) KCOV structs split out of kcov-types.h.
 * These live in each child's private memory (kcov_child on childdata,
 * kcov_child_local_stats behind a pointer on childdata, dedup slots
 * mmap'd child-private).  Included from kcov-types.h so consumers keep
 * seeing these types transparently. */

#include "picker-context.h"	/* PICKER_NCTX */
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "types.h"	/* uint8_t / uint32_t / uint64_t */

/* Per-call dedup slot — counts how many times a single trace hit a given
 * edge so the hit count can be classified into a bucket.  A slot is "live"
 * for the current call only when generation == kcov_child::current_generation;
 * any other value means the slot is stale from a prior call and should be
 * treated as empty. */
struct kcov_dedup_slot {
	uint32_t edge_idx;
	uint32_t count;
	uint64_t generation;
};

struct kcov_child {
	/* Field order is constrained by the hot-cacheline budget in struct
	 * childdata (see static_assert in child.c).  Sized to 48 bytes:
	 * 2 ints (8) + 1 u64 (8) + 6 bools + 1 uint8_t mode (7) + 1 byte
	 * holding the two 4-bit recovery counters + 3 pointers (24).  The
	 * mode byte and the packed recovery counters slot into the bool
	 * block so the struct stays at 48 bytes without disturbing pointer
	 * alignment.  That leaves room in the 64-byte hot leading cacheline
	 * for the childdata fields that follow (last_group, op_nr).
	 * child_id is intentionally not stored here —
	 * kcov_enable_remote() takes it as a parameter (sourced from
	 * childdata->num) so the second fd's metadata fits without
	 * overflowing the cacheline. */
	int fd;
	int cmp_fd;                     /* second fd for KCOV_TRACE_CMP, -1 if unavailable */
	uint64_t current_generation;	/* bumped per kcov_collect() to invalidate dedup */
	bool active;       /* true if this child successfully opened kcov */
	bool cmp_capable;  /* true if cmp_fd was probed and KCOV_TRACE_CMP works */
	bool cmp_enabled_this_call;	/* true between kcov_enable_cmp() and kcov_disable() */
	bool remote_mode;  /* true when using KCOV_REMOTE_ENABLE */
	bool remote_capable; /* true if kernel supports KCOV_REMOTE_ENABLE */
	bool bracket_owned;	/* true between kcov_bracket_begin() and
				 * kcov_bracket_end().  Keeps the bracket
				 * helpers idempotent under nesting: a childop
				 * that recurses into random_syscall() must
				 * not have its inner enable_trace clobbered
				 * by the outer bracket. */
	/* Logically enum kcov_child_mode; stored as uint8_t so the field
	 * lives inside the existing pad bytes after the bool block instead
	 * of forcing an int-sized hole that would push the pointer triplet
	 * out past 48 bytes and break the hot-cacheline budget. */
	uint8_t mode;
	/* Per-slot recovery attempt counters for kcov_recover_fd().  Two
	 * 4-bit fields share the single byte of padding that used to sit
	 * after `mode`, keeping the struct at 48 bytes (a third uint8_t
	 * would force pointer-alignment padding and push the struct to
	 * 56, blowing the hot-cacheline budget).  Each counter caps at
	 * KCOV_RECOVERY_MAX (3) before kcov_enable_trace _exit()s the
	 * child with KCOV_RECOVERY_EXHAUSTED_EXIT_CODE; the counter is
	 * owner-write-only so the bitfield RMW is always sequential
	 * within a single child context. */
	uint8_t recovery_attempts     : 4;
	uint8_t cmp_recovery_attempts : 4;
	unsigned long *trace_buf;
	unsigned long *cmp_trace_buf;	/* mmap of cmp_fd, NULL if unavailable */
	struct kcov_dedup_slot *dedup;	/* KCOV_DEDUP_SIZE entries, child-private */
};

/* Per-child local staging for the kcov global counters
 * (kcov_shared::total_calls / remote_calls / total_pcs).  Bumped on
 * the hot per-syscall path inside the owning child and flushed in
 * batches into the shared atomics via kcov_child_flush_stats() so the
 * shared cacheline stops bouncing on every call.  Lives behind a
 * pointer on struct childdata (NOT inside struct kcov_child, which is
 * pinned to 48 bytes by the static_assert on
 * offsetof(childdata, op_nr) < 64 -- folding scalar counters in would
 * push op_nr out of the leading hot cacheline). */
struct kcov_child_local_stats {
	unsigned long total_calls;
	unsigned long remote_calls;
	unsigned long total_pcs;
	unsigned long total_warm_known_hits;
	/* Per-child staging for the two hot per-syscall kcov_collect()
	 * counters previously bumped as per-call __atomic_fetch_add on
	 * kcov_shm->per_syscall.per_syscall_{calls,edges}[nr][ctx][do32].
	 * Bumped by the owning child on the plain hot path (no atomics
	 * because the memory is child-private) and drained in batches
	 * by kcov_child_flush_stats() via the stats_ring; the parent-side
	 * apply_slot() writes the delta back into the same kcov_shm cell
	 * so every existing reader keeps seeing aggregated post-flush
	 * values through the pre-existing per_syscall_edges_total() /
	 * per_syscall_calls_total() accessors.  Dense layout matches the
	 * shm target shape 1:1 so the flush walk is a straight
	 * MAX_NR_SYSCALL * PICKER_NCTX * 2 sweep with a zero-suppress
	 * gate per slot. */
	unsigned long per_syscall_calls[MAX_NR_SYSCALL][PICKER_NCTX][2];
	unsigned long per_syscall_edges[MAX_NR_SYSCALL][PICKER_NCTX][2];
	/* Running count of syscalls since the last local-stats flush.
	 * Drives the flush-cadence heuristic in kcov_child_flush_stats()
	 * (flush when >= KCOV_LOCAL_STATS_FLUSH_SYSCALLS); bumped
	 * alongside total_calls and cleared on flush. */
	unsigned int local_syscalls_since_flush;
};

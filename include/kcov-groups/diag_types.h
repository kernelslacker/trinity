#pragma once

/* KCOV diagnostic types split out of kcov-types.h -- the per-record
 * kernel wire layout, per-syscall diag counter slot, and the EBADF
 * chronicle snapshot slot.  The two "big" diag structs kcov_cmp_diag
 * and kcov_pc_diag deliberately STAY in kcov-types.h (the shared-type
 * home) since they predate the group refactor.  Included from
 * kcov-types.h so consumers keep seeing these types transparently. */

#include "types.h"	/* uint32_t / uint64_t */

/* On-the-wire layout of a single KCOV_TRACE_CMP record, as the kernel
 * writes it after the count header at trace_buf[0].  type encodes the
 * operand size in its low bits and KCOV_CMP_CONST (1<<0) when one
 * operand was a compile-time constant; arg1/arg2 are the operands;
 * ip is the kernel PC of the comparison. */
struct kcov_cmp_record {
	uint64_t type;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t ip;
};

/* Per-syscall diagnostic counters indexed by [nr][do32].  Mirrors the
 * existing globals (trace_truncated, cmp_trace_truncated,
 * dedup_probe_overflow, dedup_max_probe_seen) but partitions each by
 * syscall slot and arch dimension so post-mortems can pin which (nr,
 * arch) tuple is dominating the global counter.  bucket_bits_real and
 * distinct_pcs are new per-call totals: bucket_bits_real is the count
 * of bucket bits this syscall has ever flipped (kcov_collect()'s
 * edges_this_call summed over all calls); distinct_pcs is the count of
 * distinct edges this syscall has ever touched in a single call summed
 * over all calls (dedup_inc() first-sight events).  All counters are
 * relaxed atomics; max_trace_size uses a CAS-loop-up against the
 * existing dedup_max_probe_seen high-water-mark pattern.  Layout is
 * pinned at 48 bytes per slot — see the _Static_assert below — so the
 * shm cost is predictable: 48 * MAX_NR_SYSCALL * 2 arch dims ≈ 96 KiB. */
struct kcov_per_syscall_diag {
	uint64_t trace_truncated;
	uint64_t cmp_trace_truncated;
	uint64_t dedup_probe_overflow;
	uint64_t bucket_bits_real;
	uint64_t distinct_pcs;
	uint32_t max_trace_size;
	uint32_t pad;
};
_Static_assert(sizeof(struct kcov_per_syscall_diag) == 48,
	"kcov_per_syscall_diag must be 48 bytes; shm budget assumes it");

/* Bound for the chronicle snapshot captured into struct
 * kcov_pc_diag::first_ebadf_chronicle[] at first-EBADF latch time.
 * The owning child's child_syscall_ring is sized at
 * CHILD_SYSCALL_RING_SIZE (16); we copy out a parallel structure
 * here so include/kcov.h does not have to drag in include/child.h
 * (child.h includes kcov.h, so the dependency would cycle).  The
 * cap matches the source ring's size -- a smaller cap would let
 * the closer further back scroll off the snapshot the same way
 * it scrolls off the live ring, defeating the whole point of
 * capturing it at the EBADF crime scene. */
#define KCOV_EBADF_CHRONICLE_MAX 16U
struct kcov_ebadf_chronicle_slot {
	unsigned long a1, a2, a3;	/* post-sanitize args as the kernel saw. */
	unsigned long retval;		/* return value the kernel reported. */
	unsigned int  nr;		/* syscall table index. */
	int           errno_post;	/* errno after return. */
	unsigned char do32bit;		/* selects which table nr indexes. */
	unsigned char valid;		/* false for zero-init slots the producer
					 * had not filled by latch time. */
};

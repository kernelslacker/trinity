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
 * 256K entries is 2MB on 64-bit.  Deep kernel paths (long io_uring
 * chains, deep btrfs ops, multi-level fs walks, large genetlink
 * families) can blow past the previous 64K-entry budget and silently
 * truncate the tail of the trace, dropping uncounted edge coverage
 * on exactly the syscalls the fuzzer would learn the most from. */
#define KCOV_TRACE_SIZE (256 << 10)

/* Number of distinct edge slots PCs hash into.
 * 8M slots preserves the prior bitmap's birthday-paradox headroom: 50%
 * collision threshold is ~1.177 * sqrt(N), so the table stays useful out
 * to ~3400 distinct PCs before false saturation skews the cold-syscall,
 * edgepair, and minicorpus heuristics that all consume the coverage signal.
 * Modern kernel builds easily blow past the old 512K-slot budget within
 * seconds. */
#define KCOV_NUM_EDGES (1 << 23)

/* AFL-style hit-count bucketing.  Each edge stores an 8-bit mask where bit
 * i is set if the edge has ever been hit a count that falls in bucket i:
 *   bucket 0: 1 hit            bucket 4: 8-15 hits
 *   bucket 1: 2 hits           bucket 5: 16-31 hits
 *   bucket 2: 3 hits           bucket 6: 32-127 hits
 *   bucket 3: 4-7 hits         bucket 7: 128+ hits
 * A hit count entering a never-seen bucket for a known edge counts as new
 * coverage — same trigger semantics as a never-seen edge in the old bitmap. */
#define KCOV_NUM_BUCKETS 8

/* Per-child dedup table for counting per-edge hits within a single trace.
 * Open-addressed, linear probing.  Sized so that the typical syscall's
 * unique-edge count fits well below 50% load factor; on probe overflow the
 * caller treats the entry as a single hit (degrades to old behaviour for
 * that edge in that one call).
 *
 * Slot validity is tracked via a generation counter — a slot is "live" only
 * when its generation matches the child's current_generation, otherwise it's
 * stale from a prior call and treated as empty.  Bumping current_generation
 * at the top of kcov_collect() invalidates the entire table in O(1) instead
 * of the per-call wipe the previous sentinel-based design needed. */
#define KCOV_DEDUP_SIZE 16384
#define KCOV_DEDUP_MASK (KCOV_DEDUP_SIZE - 1)
#define KCOV_DEDUP_MAX_PROBE 32

/* If a syscall hasn't found new edges in this many global calls,
 * it's considered "cold" and deprioritized during selection. */
#define KCOV_COLD_THRESHOLD 500000

/* KCOV trace modes */
#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1

/* KCOV remote coverage handle construction.
 * KCOV_SUBSYSTEM_COMMON covers softirqs and threaded IRQ handlers. */
#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)
#define KCOV_SUBSYSTEM_MASK	(0xffULL << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffULL)

/* Fraction of syscalls that use remote mode instead of per-thread mode.
 * 1 in KCOV_REMOTE_RATIO syscalls will use KCOV_REMOTE_ENABLE. */
#define KCOV_REMOTE_RATIO 10

/* Per-call dedup slot — counts how many times a single trace hit a given
 * edge so the hit count can be classified into a bucket.  A slot is "live"
 * for the current call only when generation == kcov_child::current_generation;
 * any other value means the slot is stale from a prior call and should be
 * treated as empty. */
struct kcov_dedup_slot {
	uint32_t edge_idx;
	uint32_t count;
	uint32_t generation;
};

struct kcov_child {
	int fd;
	unsigned long *trace_buf;
	bool active;       /* true if this child successfully opened kcov */
	bool cmp_mode;     /* true when this syscall should use CMP tracing */
	bool remote_mode;  /* true when using KCOV_REMOTE_ENABLE */
	bool remote_capable; /* true if kernel supports KCOV_REMOTE_ENABLE */
	unsigned int child_id; /* unique child id for remote handle */
	struct kcov_dedup_slot *dedup;	/* KCOV_DEDUP_SIZE entries, child-private */
	uint32_t current_generation;	/* bumped per kcov_collect() to invalidate dedup */
};

/* Shared coverage state, allocated in shared memory. */
struct kcov_shared {
	/* Per-edge bucket-seen mask.  See KCOV_NUM_BUCKETS comment above for
	 * the bucket layout.  A child's atomic-OR on this byte that flips a
	 * never-seen bucket bit is the "new coverage" signal that drives the
	 * minicorpus, edgepair, and mutator-attribution feedback loops. */
	unsigned char bucket_seen[KCOV_NUM_EDGES];
	unsigned long edges_found;
	unsigned long total_pcs;
	unsigned long total_calls;
	unsigned long remote_calls;	/* calls using KCOV_REMOTE_ENABLE */
	/* Number of kcov_collect() calls where the kernel filled the entire
	 * trace buffer.  When non-zero a non-trivial fraction of syscalls
	 * are losing tail coverage and KCOV_TRACE_SIZE should be raised. */
	unsigned long trace_truncated;
	unsigned long per_syscall_edges[MAX_NR_SYSCALL];
	unsigned long per_syscall_calls[MAX_NR_SYSCALL];
	unsigned long last_edge_at[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_edges at the previous stats interval.
	 * Used to compute per-interval edge growth rate. */
	unsigned long per_syscall_edges_previous[MAX_NR_SYSCALL];
};

extern struct kcov_shared *kcov_shm;

/* Called once from init_shm() to allocate shared coverage state. */
void kcov_init_global(void);

/* Called per-child to try to open/mmap the kcov fd.
 * child_id is a unique per-child identifier used for remote handles.
 * Sets kc->active = true only if kcov is usable. */
void kcov_init_child(struct kcov_child *kc, unsigned int child_id);

/* Called per-child on exit to clean up. */
void kcov_cleanup_child(struct kcov_child *kc);

/* Bracket the actual syscall() call with these. No-ops if !active. */
void kcov_enable_trace(struct kcov_child *kc);
void kcov_enable_cmp(struct kcov_child *kc);
void kcov_enable_remote(struct kcov_child *kc);
void kcov_disable(struct kcov_child *kc);

/* After disabling, collect PCs and update the global bitmap.
 * Returns true if new coverage was found. nr is the syscall number
 * for per-syscall edge tracking. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr);

/* Returns true if syscall nr hasn't found new edges recently.
 * Used by syscall selection to deprioritize saturated syscalls. */
bool kcov_syscall_is_cold(unsigned int nr);

/* Returns the recommended skip percentage (0-90) for syscall nr based on
 * how stale its coverage is.  0 means "not cold, don't skip"; otherwise
 * the value grows with the staleness gap so persistently cold syscalls
 * are deprioritized harder than ones that just crossed the threshold. */
unsigned int kcov_syscall_cold_skip_pct(unsigned int nr);

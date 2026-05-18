#pragma once

#include <time.h>

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

/* Size of the per-child KCOV comparison-operand buffer (number of
 * unsigned longs).  Each CMP record is 4 u64 (type, arg1, arg2, ip),
 * so 256K u64 entries hold up to (256K - 1)/4 ≈ 64K records (~2MB
 * per child).  Sized to match the PC trace buffer's footprint; CMP
 * record rate per syscall is typically lower than PC rate, but big
 * enough to absorb deep validation paths without truncating tails. */
#define KCOV_CMP_BUFFER_SIZE (256 << 10)
#define KCOV_CMP_RECORDS_MAX ((KCOV_CMP_BUFFER_SIZE - 1) / 4)

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

/* Coverage-plateau detector: window length and trigger threshold.
 * The window is fixed at 600s (10 minutes) so a single below-threshold
 * sample already represents "sustained for ≥ 10 min".  The threshold of
 * 10 new edges per 600s window is exactly < 1 new edge per 60s, the
 * point at which manual observation has shown the fuzzer is wedged at
 * a local minimum and not making forward progress. */
#define KCOV_PLATEAU_WINDOW_SEC 600
#define KCOV_PLATEAU_RATE_THRESHOLD 10

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

struct kcov_child {
	/* Field order is constrained by the hot-cacheline budget in struct
	 * childdata (see static_assert in child.c).  Sized to 48 bytes:
	 * 4 ints/u32 (16) + 5 bools (5) + 3 padding + 3 pointers (24).
	 * That leaves room in the 64-byte hot leading cacheline for the
	 * three childdata fields that follow (last_syscall_nr, last_group,
	 * op_nr).  child_id is intentionally not stored here —
	 * kcov_enable_remote() takes it as a parameter (sourced from
	 * childdata->num) so the second fd's metadata fits without
	 * overflowing the cacheline. */
	int fd;
	int cmp_fd;                     /* second fd for KCOV_TRACE_CMP, -1 if unavailable */
	uint32_t current_generation;	/* bumped per kcov_collect() to invalidate dedup */
	bool active;       /* true if this child successfully opened kcov */
	bool cmp_capable;  /* true if cmp_fd was probed and KCOV_TRACE_CMP works */
	bool cmp_enabled_this_call;	/* true between kcov_enable_cmp() and kcov_disable() */
	bool remote_mode;  /* true when using KCOV_REMOTE_ENABLE */
	bool remote_capable; /* true if kernel supports KCOV_REMOTE_ENABLE */
	unsigned long *trace_buf;
	unsigned long *cmp_trace_buf;	/* mmap of cmp_fd, NULL if unavailable */
	struct kcov_dedup_slot *dedup;	/* KCOV_DEDUP_SIZE entries, child-private */
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
	/* Total CMP records pulled out of per-child KCOV_TRACE_CMP buffers
	 * across all syscalls.  Diagnostic — confirms the second-fd CMP
	 * collection plumbing is producing records, and gauges how much
	 * raw signal reaches the future mutator consumer. */
	unsigned long cmp_records_collected;
	/* Number of kcov_collect_cmp() calls where the cmp buffer filled
	 * up.  Mirror of trace_truncated, sized off KCOV_CMP_BUFFER_SIZE. */
	unsigned long cmp_trace_truncated;
	/* Per-syscall count of CALLS that produced at least one new edge.
	 * NOT a real edge bucket count — a syscall that uncovers 50 distinct
	 * new edges in one call bumps this by 1, not by 50.  The real
	 * bucket-edge count is the kcov_collect() new_edge_count out-param,
	 * accumulated into per-strategy and per-pool fields elsewhere.  The
	 * field name predates the call-count vs edge-count distinction; kept
	 * for ABI compatibility with the cold-skip heuristic and the
	 * top-syscalls dump in stats.c. */
	unsigned long per_syscall_edges[MAX_NR_SYSCALL];
	unsigned long per_syscall_calls[MAX_NR_SYSCALL];
	unsigned long last_edge_at[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_edges at the previous stats interval.
	 * Used to compute per-interval growth rate of the call-count signal
	 * above. */
	unsigned long per_syscall_edges_previous[MAX_NR_SYSCALL];
	/* Sliding-window edge-rate plateau detector state.  Sampled at the
	 * 600s parent stats tick: each tick, delta = edges_found -
	 * plateau_prev_edges is the count of new edges discovered in the
	 * most recent KCOV_PLATEAU_WINDOW_SEC window.  When the delta drops
	 * below KCOV_PLATEAU_RATE_THRESHOLD (rate < 1 edge per 60s sustained
	 * over the 10-minute window) the parent enters PLATEAU state and
	 * emits a one-line warning to stats.log; a matching CLEARED line is
	 * emitted when the rate climbs back above threshold.  Detection only
	 * — no automatic response. */
	time_t plateau_window_start;
	unsigned long plateau_prev_edges;
	unsigned long plateau_last_window_delta;
	time_t plateau_entered_at;
	bool plateau_armed;
	bool plateau_active;
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
void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id);
void kcov_disable(struct kcov_child *kc);

/* After disabling, collect PCs and update the global bitmap.
 *
 * Returns true if new coverage was found (i.e. this call set at least one
 * never-seen bucket bit); the returned bool collapses the per-call count
 * to a {0,1} signal that the caller's name-and-shame attribution paths
 * already expect.
 *
 * If new_edge_count is non-NULL it is written with the actual number of
 * bucket bits this call flipped — the real edge-count signal, distinct
 * from the bool return.  Callers needing only the boolean signal pass
 * NULL.  Computed during the same pass that updates kcov_shm->edges_found,
 * so it costs no extra atomics: the caller would otherwise have to read
 * the global counter before/after and diff it, which is racy under
 * concurrent children that also bump the global.
 *
 * nr is the syscall number for per-syscall edge tracking. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr,
		  unsigned long *new_edge_count);

/* After disabling, drain the CMP buffer into the per-syscall hint pool
 * and bump the CMP-records-collected counter.  No-op when cmp_capable
 * is false.  is_explorer is forwarded to bandit_cmp_observe() so the
 * explorer pool's novelty observations skip per-arm reward attribution
 * (they ran a different strategy than the bandit's current arm).
 * strategy_at_pick is the enum strategy_t snapshotted in set_syscall_nr
 * when this syscall was picked (or -1 for explorers / pre-first-pick);
 * forwarded so bandit_cmp_observe attributes CMP novelty to the arm
 * that picked the call rather than re-reading shm->current_strategy
 * (which may have rotated mid-syscall). */
void kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
		      bool is_explorer, int strategy_at_pick);

/* Accessor for the raw CMP record stream after kcov_disable().
 * On return, *out points at the first record (NULL when cmp_capable
 * is false or the buffer is empty) and *count is the (clamped) record
 * count.  Future mutator-side consumers that want raw operand pairs
 * rather than the deduped hint-pool view call this. */
void kcov_get_cmp_records(struct kcov_child *kc,
			  struct kcov_cmp_record **out,
			  unsigned long *count);

/* Returns true if syscall nr hasn't found new edges recently.
 * Used by syscall selection to deprioritize saturated syscalls. */
bool kcov_syscall_is_cold(unsigned int nr);

/* Returns the recommended skip percentage (0-90) for syscall nr based on
 * how stale its coverage is.  0 means "not cold, don't skip"; otherwise
 * the value grows with the staleness gap so persistently cold syscalls
 * are deprioritized harder than ones that just crossed the threshold. */
unsigned int kcov_syscall_cold_skip_pct(unsigned int nr);

/* Sliding-window edge-rate plateau check.  Self-gates on
 * KCOV_PLATEAU_WINDOW_SEC, so the caller can invoke it once per
 * main_loop tick alongside the other periodic samplers.  Emits a
 * one-line PLATEAU warning to stats.log when the per-window edge
 * discovery rate drops below KCOV_PLATEAU_RATE_THRESHOLD and a matching
 * PLATEAU CLEARED line when the rate recovers.  Detection only — does
 * not touch bandit, explorer, or syscall-pool state. */
void kcov_plateau_check(void);

/* Mid-run snapshot cadence for kcov_bitmap_maybe_snapshot().  The bitmap
 * is 8 MB and writing it is bursty I/O, so the triggers are coarser than
 * the minicorpus or healer snapshot intervals: 1000 new edges OR 300s
 * since the last save, whichever fires first.  Hardcoded -- no operator
 * knob, fleet boxes shouldn't need to retune. */
#define KCOV_BITMAP_SNAPSHOT_EDGES		1000UL
#define KCOV_BITMAP_SNAPSHOT_INTERVAL_SEC	300UL

/* Warm-start persistence for the kcov_shm bucket_seen[] hit-count bitmap
 * and the edges_found counter.  Save/load are gated on a kernel-binary
 * fingerprint -- sha256 over /proc/kallsyms with the address column
 * stripped -- so a rebuilt kernel (even with an unchanged utsname.release
 * / utsname.version pair) gets a fresh bitmap instead of loading stale
 * data against a different edge layout.  The address-stripping step
 * makes the fingerprint identical whether kallsyms is read as root or
 * non-root (kptr_restrict zeroes the addresses for the latter) and also
 * invariant across KASLR vs nokaslr boots of the same build.  Stale or
 * unreadable files are silently discarded and the loader returns false;
 * cold-start is the legitimate first-run state. */
bool kcov_bitmap_save_file(const char *path);
bool kcov_bitmap_load_file(const char *path);
const char *kcov_bitmap_default_path(void);

/* Fill OUT[32] with the cached kallsyms-derived kernel fingerprint
 * (sha256 over /proc/kallsyms with the leading address column stripped
 * and module / BPF runtime symbols filtered out -- see the comment on
 * kcov_fingerprint_kernel() for the precise filter rules).  First call
 * streams /proc/kallsyms and caches; subsequent calls memcpy from the
 * cache.  Returns false (with OUT untouched) when /proc/kallsyms is
 * unreadable; caller should treat that as "warm-start disabled this
 * run".  Exposed so cross-run-state files outside kcov.c (e.g. the
 * cmp-hints pool) can stamp the same fingerprint into their headers
 * and stay in lock-step with the kcov-bitmap warm-start invariants. */
bool kcov_get_kernel_fp(uint8_t out[32]);

/* Wire periodic mid-run snapshots of the bucket_seen bitmap to PATH.
 * Subsequent kcov_bitmap_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied. */
void kcov_bitmap_enable_snapshots(const char *path);

/* Cheap per-tick gate: writes the snapshot if either trigger has elapsed
 * since the last successful save, otherwise returns immediately.  Called
 * from the parent's stats tick and from kcov_plateau_check() when a
 * plateau is first entered. */
void kcov_bitmap_maybe_snapshot(void);

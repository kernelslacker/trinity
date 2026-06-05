#pragma once

#include <time.h>

#include "exit.h"	/* NUM_EXIT_REASONS */
#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */

/* 8-bucket errno classification used by per_syscall_errno[] below.
 * Bucket layout is part of the dump_stats() output contract; keep
 * the order stable so the column headers in stats.c match. */
enum errno_bucket {
	ERRNO_BUCKET_SUCCESS = 0,	/* rec->retval != -1UL */
	ERRNO_BUCKET_EFAULT  = 1,
	ERRNO_BUCKET_EINVAL  = 2,
	ERRNO_BUCKET_ENOSYS  = 3,
	ERRNO_BUCKET_EPERM   = 4,
	ERRNO_BUCKET_EBADF   = 5,
	ERRNO_BUCKET_EAGAIN  = 6,
	ERRNO_BUCKET_OTHER   = 7,
	ERRNO_BUCKET_NR      = 8,
};

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
 * edges_found counts unique occupied slots in this 8M-entry table.
 * The birthday-paradox figure (50% chance of *any* collision at
 * ~1.177 * sqrt(N) ~= 3400 PCs) is the first-collision threshold, not
 * a practical saturation point: an isolated collision does not skew
 * the cold-syscall, edgepair, or minicorpus heuristics that read
 * edges_found.  What skews them is fractional occupancy -- expected
 * unique slots after k inserts is N * (1 - (1 - 1/N)^k), reaching 50%
 * at k ~= N * ln(2) ~= 5.8M PCs.  Real runs see edges_found in the
 * hundreds of thousands without measurable bias.  Modern kernel builds
 * easily blow past the old 512K-slot budget within seconds. */
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

/*
 * Per-child KCOV mode.  The kernel rejects a second KCOV_ENABLE on the
 * same task with -EBUSY (the one-`t->kcov`-per-task rule in kernel/kcov.c),
 * so PC and CMP collection cannot run simultaneously inside a single
 * child.  Each child picks one mode at init and keeps it for its
 * lifetime; the fleet-wide PC/CMP signal split comes from the population
 * mix of children, not from per-call mode toggling.
 */
enum kcov_child_mode {
	KCOV_MODE_PC = 0,
	KCOV_MODE_CMP,
};

/*
 * Reciprocal probability that a child runs in CMP-only mode.  CMP records
 * feed the constant-comparison hint pool, which helps the fuzzer break
 * plateaus by unblocking comparison-gated kernel branches; PC coverage is
 * the load-bearing signal for everything else (bandit reward attribution,
 * edge-discovery rate, cold-syscall skipping).
 * Biased toward PC mode so the high-frequency signal isn't starved; retune
 * after A/B if cmp_records throughput is the bottleneck.
 */
#define KCOV_CMP_CHILD_RECIPROCAL 4   /* 1-in-4 children run CMP-only */

/* KCOV remote coverage handle construction.
 * KCOV_SUBSYSTEM_COMMON covers softirqs and threaded IRQ handlers. */
#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)
#define KCOV_SUBSYSTEM_MASK	(0xffULL << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffULL)

/* Fraction of syscalls that use remote mode instead of per-thread mode.
 * 1 in KCOV_REMOTE_RATIO syscalls will use KCOV_REMOTE_ENABLE.  This is
 * the default rate for syscalls that do most of their kernel work on the
 * calling task: remote sampling is comparatively expensive (extra
 * KCOV_REMOTE_ENABLE/disable round-trip plus a softirq/threaded-IRQ
 * coverage merge) and a 1-in-10 trickle is enough to keep softirq-only
 * edges from going completely cold. */
#define KCOV_REMOTE_RATIO 10

/* Heavier sampling rate for syscalls flagged with KCOV_REMOTE_HEAVY in
 * their per-syscall flags (see include/syscall.h).  These are the calls
 * whose interesting kernel work is scheduled onto kthreads / workqueues
 * / softirqs and is therefore *only* visible through the remote KCOV
 * handle: netlink async delivery, io_uring SQ/IO workers, BPF attach
 * paths, mount workqueues, cgroup migration, namespace setup, etc.  At
 * the default 1-in-10 rate those deferred-work edges are persistently
 * under-sampled and stay cold long after the synchronous syscall
 * surface has saturated, so flagged syscalls bump to 1-in-2.  Cost is
 * ~5x more remote enables on those specific calls, not a fleet-wide
 * regression. */
#define KCOV_REMOTE_RATIO_HEAVY 2

#define CHILDOP_KCOV_NR_BASE  0x10000UL
/*
 * Childops borrow the kcov_collect() nr parameter to bypass
 * the per_syscall_*[] arrays (gated on nr < MAX_NR_SYSCALL
 * in kcov.c).  Reserve the >= 0x10000 range so syscall ids
 * never collide.
 */

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

/* Per-failure-site diagnostic slots for the KCOV_TRACE_CMP setup and
 * runtime paths.  Written from child context (post-dup2-to-/dev/null,
 * so output() to stdout is silently swallowed) but read by the parent
 * via shared memory, which is how the data survives back out.  First
 * failure wins for *_errno (CAS-from-zero); *_count tallies every
 * failure at that site across all children. */
struct kcov_cmp_diag {
	int init_open_errno;
	int init_init_trace_errno;
	int init_mmap_errno;
	int init_enable_errno;
	int init_disable_errno;
	int runtime_enable_errno;
	unsigned int init_open_count;
	unsigned int init_init_trace_count;
	unsigned int init_mmap_count;
	unsigned int init_enable_count;
	unsigned int init_disable_count;
	unsigned int runtime_enable_count;
};

/* EINTR retry budget for KCOV_ENABLE / KCOV_REMOTE_ENABLE.  Eight is
 * generous enough to ride out a signal storm without turning a real
 * driver issue into a stall. */
#define KCOV_ENABLE_EINTR_MAX 8

/* Per-slot cap on how many times kcov_recover_fd() may rebuild a
 * vanished kcov fd before kcov_enable_trace gives up and _exit()s
 * the child so the parent's reaper respawns it with a fresh slot.
 * The closer driving these EBADFs is not transient — fleet evidence
 * shows the first hit on a child usually arrives within seconds and
 * recovery cost is essentially init cost (open + INIT_TRACE + mmap +
 * F_DUPFD_CLOEXEC), so a low cap keeps blast radius bounded without
 * leaving recoverable slots silently degraded.  Counters are uint8_t
 * 4-bit bitfields and KCOV_RECOVERY_MAX must stay <= 15. */
#define KCOV_RECOVERY_MAX 3

/* Exit status used by kcov_enable_trace / kcov_enable_remote when the
 * per-slot recovery budget is exhausted (or kcov_recover_fd() itself
 * fails) and the child has to bail so the reaper can hand it a fresh
 * init_child slot.  Must be non-zero so reap_entry_is_fast_die() in
 * main.c treats the reap as a fast-die candidate — a fork→exit(0)→
 * respawn loop would otherwise slip past the circuit breaker, because
 * the breaker only counts exit_status > 0.  Must also be >=
 * NUM_EXIT_REASONS so decode_exit() in bail_fast_die_loop() does not
 * mislabel the ring-dump line as one of the named fleet-terminator
 * reasons (the [1, NUM_EXIT_REASONS) range belongs to enum
 * exit_reasons).  NUM_EXIT_REASONS + 1 satisfies both and stays
 * distinct even if enum exit_reasons grows. */
#define KCOV_RECOVERY_EXHAUSTED_EXIT_CODE (NUM_EXIT_REASONS + 1)

/* Per-failure-site diagnostic slots for the PC and remote KCOV enable/
 * disable paths.  Same shape as struct kcov_cmp_diag: first failure
 * wins for *_errno (CAS-from-zero), *_count tallies every failure at
 * that site across all children. */
struct kcov_pc_diag {
	int pc_enable_errno;
	int pc_disable_errno;
	int remote_enable_errno;
	unsigned int pc_enable_count;
	unsigned int pc_disable_count;
	unsigned int remote_enable_count;
	unsigned int remote_fallback_to_pc;
	unsigned int pc_enable_eintr_retries;
	unsigned int remote_enable_eintr_retries;
	unsigned int remote_fallback_pc_enable_eintr_retries;
	/* First-failure-wins capture of which fuzzed syscall was in
	 * flight (or had just retired) when kcov_enable_trace observed
	 * its first EBADF in this run.  CAS-from-zero on
	 * first_ebadf_op_nr selects the winner so the four fields below
	 * are consistent w.r.t. each other.  Used to pin down the
	 * close-race source: the syscall_nr field should resolve via
	 * the syscall table to close / close_range if the chain-
	 * substitution hypothesis holds; anything else points at an
	 * unaudited closer.  fd_value preserves the slot number at
	 * failure for cross-reference with KCOV_FD_HIGH_BASE. */
	unsigned long first_ebadf_op_nr;	/* CAS gate, 0 == empty */
	unsigned long first_ebadf_pid;
	unsigned int  first_ebadf_syscall_nr;
	int           first_ebadf_fd_value;
};

/* Selector for kcov_cmp_diag_format() — keeps stats.c's two-line split
 * (init vs runtime sites) while still allowing main.c to fold all six
 * sites into a single one-line summary. */
enum kcov_cmp_diag_part {
	KCOV_CMP_DIAG_INIT,	/* init_open, init_init_trace, init_mmap */
	KCOV_CMP_DIAG_RUNTIME,	/* init_enable, init_disable, runtime_enable */
	KCOV_CMP_DIAG_ALL,
};

/* Build a " name=<errno>/<count>" segment per non-zero cmp_diag site
 * into buf.  Each segment starts with a single space so the caller
 * concatenates straight into a log line.  Returns the number of bytes
 * written (excluding the trailing NUL); zero if no site has any
 * recorded failures, or if kcov_shm is NULL. */
int kcov_cmp_diag_format(char *buf, size_t bufsz, enum kcov_cmp_diag_part part);

/* Build a one-line summary of the PC/remote enable/disable
 * diagnostic counters defined in struct kcov_pc_diag.  Each
 * non-zero error site contributes a `" name=ERRNO_MACRO(errno)/count"`
 * token; each non-zero retry/success counter contributes a
 * `" name=count"` token; absent counters contribute nothing.
 * Same shape as kcov_cmp_diag_format so the two callsites in
 * stats.c periodic dump and main.c summary stay in lockstep.
 * Returns the number of bytes written (excluding the trailing
 * NUL); zero if every counter is zero or kcov_shm is NULL. */
int kcov_pc_diag_format(char *buf, size_t bufsz);

struct kcov_child {
	/* Field order is constrained by the hot-cacheline budget in struct
	 * childdata (see static_assert in child.c).  Sized to 48 bytes:
	 * 2 ints (8) + 1 u64 (8) + 6 bools + 1 uint8_t mode (7) + 1 byte
	 * holding the two 4-bit recovery counters + 3 pointers (24).  The
	 * mode byte and the packed recovery counters slot into the bool
	 * block so the struct stays at 48 bytes without disturbing pointer
	 * alignment.  That leaves room in the 64-byte hot leading cacheline
	 * for the three childdata fields that follow (last_syscall_nr,
	 * last_group, op_nr).  child_id is intentionally not stored here —
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

/* Shared coverage state, allocated in shared memory. */
struct kcov_shared {
	/* Per-edge bucket-seen mask.  See KCOV_NUM_BUCKETS comment above for
	 * the bucket layout.  A child's atomic-OR on this byte that flips a
	 * never-seen bucket bit is the "new coverage" signal that drives the
	 * minicorpus, edgepair, and mutator-attribution feedback loops. */
	unsigned char bucket_seen[KCOV_NUM_EDGES];
	/* Count of (edge, bucket) bit-flips ever observed.  Since the
	 * bucket-seen table was introduced this is NOT the count of distinct
	 * edges -- a re-hit of a known edge that lands in a previously-unseen
	 * hit-count bucket bumps this counter, so it conflates "new code
	 * reached" with "known code reached at a new iteration depth".  Kept
	 * as the fine-grained feedback signal for the minicorpus / mutator-
	 * attribution / edgepair consumers that want every novel bucket
	 * transition to register.  For the cardinality of edges ever reached
	 * -- the signal the coverage-plateau detector needs -- read
	 * distinct_edges below instead. */
	unsigned long edges_found;
	/* Count of distinct edges ever seen in any bucket: incremented exactly
	 * once per edge, on the bucket_seen[edge] == 0 -> first-bit transition
	 * in kcov_collect().  This is the true "new code reached" signal and
	 * the one the plateau detector samples; edges_found above grows with
	 * bucket churn on already-known edges and so its delta never falls to
	 * zero even when no new code is being reached. */
	unsigned long distinct_edges;
	/* Count of edges seeded into bucket_seen[] / edges_found by the
	 * warm-start cache loader at startup.  Zero on a cold-start run
	 * (no cache file, version/fingerprint mismatch, CRC failure, etc.).
	 * Set once after the cache-load loop completes and never mutated
	 * thereafter, so cold = edges_found - edges_warm_loaded is the
	 * subset of coverage actually discovered by this process — the
	 * operator-facing split that distinguishes "plateau near the prior
	 * corpus ceiling" from "plateau after genuinely exhausting easy
	 * edges this run". */
	unsigned long edges_warm_loaded;
	/* Mirror of edges_warm_loaded for the distinct_edges counter.
	 * Snapshotted to distinct_edges at warm-start load so a later
	 * (distinct_edges - distinct_edges_warm_loaded) subtraction is the
	 * count of truly new edges this process has discovered itself.
	 * Zero on a cold-start run. */
	unsigned long distinct_edges_warm_loaded;
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
	/* Total number of dedup_inc() calls that walked the full probe chain
	 * without finding either an empty slot or the matching edge.  When
	 * this happens, the call's bucket fidelity collapses to old any-hit
	 * semantics (count forced to 1).  Non-zero suggests KCOV_DEDUP_SIZE
	 * may need to grow. */
	unsigned long dedup_probe_overflow;
	/* Largest probe distance observed by dedup_inc() so far.  Monotonic
	 * across the run; useful for sizing KCOV_DEDUP_SIZE relative to the
	 * fattest single-call edge load actually seen. */
	unsigned long dedup_max_probe_seen;
	/* Per-record CMP hints skipped because the calling child's seen-bloom
	 * indicated the (cmp_ip, value, size) tuple had already been pushed
	 * to the per-syscall pool within the recent window.  Each skip avoids
	 * a pool_lock + linear-scan dedup-refresh round-trip; the per-record
	 * granularity (vs per-cmp_hints_collect-call) makes the saved work
	 * directly comparable to cmp_records_collected. */
	unsigned long cmp_hints_bloom_skipped;
	/* Per-record CMP hints skipped because cmp_hints_strip[nr] is set
	 * for the calling syscall -- the entire trace buffer is short-
	 * circuited at cmp_hints_collect() entry, bypassing both the bloom
	 * lookup and the pool_add_locked path.  Targets are syscalls whose
	 * comparisons fire on task_struct / cred / ucounts / aio-table
	 * internal state set by prior syscalls or kernel init, not on
	 * values driven by the current syscall's argument surface; the
	 * resulting pool entries are unreachable from any consumer and
	 * only displace useful constants via LRU eviction.  Bumped at the
	 * per-record granularity (same units as cmp_hints_bloom_skipped
	 * and cmp_records_collected) so the avoided work is directly
	 * comparable across the three counters. */
	unsigned long cmp_hints_strip_skipped;
	/* Per-record CMP hints that produced an actual content change in a
	 * per-syscall pool — either a fresh insert into a non-full pool or an
	 * evict-replace once the pool was saturated.  Dedup-refresh hits (the
	 * tuple was already in the pool, only its last_used stamp was bumped)
	 * are NOT counted.  This is the right denominator for "how much unique
	 * signal did KCOV_TRACE_CMP actually contribute": cmp_records_collected
	 * counts every raw record the kernel emitted (hugely inflated by
	 * repetition on hot syscalls), bloom_skipped counts the per-child
	 * short-circuits, and unique_inserts is what's left — the records that
	 * survived bloom + pool dedup and changed pool state. */
	unsigned long cmp_hints_unique_inserts;
	/* cmp_hints_try_get() calls that passed the cmp_hints_shm / nr guard
	 * and reached the pool-snapshot lookup.  Counts consumer demand for
	 * hints, not setup-time queries: early-return on a NULL shm or an
	 * out-of-range nr does NOT bump.  Pair with cmp_hints_try_get_returned
	 * to read the hit rate of the pool from the generator side — a low
	 * ratio means consumers are asking for hints in syscall slots whose
	 * pools have not yet accumulated any. */
	unsigned long cmp_hints_try_get_attempts;
	/* cmp_hints_try_get() calls that returned true with a populated *out.
	 * Subset of cmp_hints_try_get_attempts.  Distinct from
	 * cmp_hints_unique_inserts (producer-side, counts what arrived in the
	 * pool) — this is consumer-side, counts what left the pool toward an
	 * argument generator.  Together with the new cmp_hints_injected
	 * counter at the callsite layer, the chain
	 * collected → unique_inserts → try_get_returned → injected makes the
	 * end-to-end CMP-hint pipeline observable. */
	unsigned long cmp_hints_try_get_returned;
	/* cmp_hints_try_get() return values that the calling argument
	 * generator actually committed to the produced syscall argument
	 * (returned the hint directly, or OR'd it into a flags mask).
	 * Aggregated across all callsites -- granularity is per-counter,
	 * not per-callsite, because the operator question this answers
	 * ("does the hint pipeline reach syscall args at all?") doesn't yet
	 * need the per-callsite split.  Subset of cmp_hints_try_get_returned:
	 * the gap between the two is callsites that pulled a hint but then
	 * discarded it (none today, but the slot exists for future
	 * branchier consumers). */
	unsigned long cmp_hints_injected;
	/* Bumped by gen_undefined_arg when prop_ring_try_get returns
	 * a value the per-child propagation ring captured from an
	 * earlier syscall return.  Sibling counter to cmp_hints_injected:
	 * same callsite, different value source (trinity-observed return
	 * vs kernel KCOV_TRACE_CMP).  Cumulative; stats.c reports the
	 * per-window delta alongside the cmp_hints counters. */
	unsigned long propagation_injected;
	/* cmp_hints_try_get() calls that the chaos-mode gate forced to
	 * return false.  Bumped after the shm/nr guard, before the pool
	 * lookup, when cmp_hints_chaos_active() is true for the current
	 * rotation window.  Subtracted from the apparent attempt->returned
	 * funnel: a window where chaos is active inflates attempts without
	 * a matching returned bump and the difference shows up here.
	 * Cumulative -- chaos windows fire on a fixed modulo of the bandit
	 * window rotation, so the delta over a stats interval is roughly
	 * try_get_attempts * (1 / CHAOS_WINDOW_MODULO) in steady state. */
	unsigned long cmp_hints_chaos_suppressed;
	/* Chaos-mode state.  Window count + active flag both live in shm
	 * so all children see the same chaos schedule -- the CAS-winning
	 * child in maybe_rotate_strategy updates them, every child reads
	 * the flag in cmp_hints_try_get.  When these were file-scope
	 * statics in cmp_hints.c each child had its own copy and the
	 * schedule never crossed a fork: cmp_hints_chaos_suppressed
	 * stayed at 0 across long multi-child runs. */
	unsigned long cmp_hints_chaos_window_count;
	unsigned int  cmp_hints_chaos_active;
	/* Flat per-event WARN-fires counter, bumped from kmsg_monitor_thread
	 * each time classify_kmsg_event() returns a non-UNKNOWN kind --
	 * every classified WARN / BUG / OOPS / RCU / lockdep splat counts
	 * once regardless of flavour.  Cohort attribution against
	 * cmp_hints_chaos_active happens at bandit window close in
	 * maybe_rotate_strategy: a delta over the window is bucketed into
	 * the chaos-on or chaos-off slot per arm, so the operator can see
	 * whether chaos-suppressed cmp-hint generation actually produces
	 * more kernel diagnostic fires than the baseline.  Flat (no
	 * per-flavour split) for V2 -- per-flavour breakdown is V2.1 once
	 * any signal exists to slice. */
	unsigned long kmsg_warn_fires;
	/* Wild-write detection in the cmp_hints SHM pool.  Bumped when a
	 * read path (cmp_hints_try_get / pool_add_locked) observes a
	 * pool->count value above the CMP_HINTS_PER_SYSCALL hard cap --
	 * the only way that can happen is a kernel-side store through a
	 * fuzzed syscall arg pointer landing on the count field.  Without
	 * this gate the bogus count drives rnd_modulo_u32 to a wild index
	 * and the entries[].value load walks off the 1.1 MB SHM mapping. */
	unsigned long cmp_hints_count_oob;
	/* Companion canary-channel counters bumped from the same gate.
	 * Probed only on a count_oob hit, so the cost is paid only when
	 * a stomp has already happened; in steady state these stay at 0
	 * and the canary loads never run.  A direct stomp that lands
	 * exactly on the count field (4 bytes at the cap-violating
	 * offset) trips NONE of these -- only cmp_hints_count_oob -- so
	 * a real wild-write event commonly surfaces as count_oob > 0
	 * with all three canary counters at 0.  Non-zero canary deltas
	 * narrow the stomp's width and direction:
	 *  - canary_lock_post: write overshot the lock or undershot
	 *    the count area, landing between offset 24 and 32 in the
	 *    pool (gap between lock_t and count).
	 *  - canary_pre: write reached entries[] from the header side
	 *    (overshot last_used_stamp into entries).
	 *  - canary_post: write reached entries[] from the tail side
	 *    (overran entries[] from beyond the last slot). */
	unsigned long cmp_hints_canary_lock_post_corrupt;
	unsigned long cmp_hints_canary_pre_corrupt;
	unsigned long cmp_hints_canary_post_corrupt;
	/* See struct kcov_cmp_diag — child-context writes are routed here
	 * because the child's stdout has already been dup2'd to /dev/null
	 * by the time KCOV_TRACE_CMP setup runs. */
	struct kcov_cmp_diag cmp_diag;
	struct kcov_pc_diag pc_diag;
	/* Per-mode child population counters, bumped once per child in
	 * kcov_init_child after the cmp_capable probe.  Surfaced through
	 * print_kcov_cmp_diag so the operator can confirm the realised
	 * mode mix matches KCOV_CMP_CHILD_RECIPROCAL.  Diagnostic only —
	 * nothing depends on these for control flow. */
	unsigned int pc_mode_children;
	unsigned int cmp_mode_children;
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
	/* Warm-loaded priors from the previous session's bitmap save.
	 * Never bumped during this run -- frozen at warm-start.  Empty
	 * (all-zero) on cold-start or when the priors blob in the bitmap
	 * file failed its CRC check.  Consumers treat these as soft
	 * priors -- current-run evidence in per_syscall_edges[] /
	 * per_syscall_calls[] overrides them as soon as it accumulates. */
	unsigned long per_syscall_edges_prior[MAX_NR_SYSCALL];
	unsigned long per_syscall_calls_prior[MAX_NR_SYSCALL];
	/* Per-syscall warm-known hit counter.  Bumped from kcov_collect()
	 * when the kernel emitted PCs into the trace buffer for this
	 * call (count > 0) but no new bucket bit flipped (found_new ==
	 * false) -- i.e. the syscall is exercising kernel code that's
	 * already in bucket_seen[].  Useful both as a liveness signal
	 * (the syscall is doing real work even if no new coverage) and
	 * as a divisor for productivity ratios.  Conflates "warm from
	 * prior session" with "already-seen this run"; the loss matters
	 * less than the cold-skip gate's need to distinguish dead
	 * syscalls from quietly-exercised ones. */
	unsigned long per_syscall_warm_known_hits[MAX_NR_SYSCALL];
	/* Sum of per_syscall_warm_known_hits[] across all nr.  Run-wide
	 * counter for the periodic stats dump so the warm-known signal
	 * is visible without iterating MAX_NR_SYSCALL slots. */
	unsigned long total_warm_known_hits;
	/* Per-syscall 8-bucket errno histogram.  Sibling to the
	 * per_syscall_edges/calls counters above: those track coverage-side
	 * activity per syscall; this tracks the shape of what the kernel
	 * returned.  Bumped from handle_syscall_ret() once per completed
	 * syscall (state == AFTER), bucket index selected by the
	 * ERRNO_BUCKET_* enum below.  Surfaced via dump_stats() as a
	 * sibling block to the top-edges / cold-syscalls tables so the
	 * operator can tell at a glance which syscalls are EFAULT-heavy
	 * vs EINVAL-heavy.  Per-syscall entry->errnos[] already exists but
	 * is sized NR_ERRNOS (133) per syscall and is the per-syscallentry
	 * tally consumed by dump_entry(); this is the kcov_shm-resident
	 * compact view that pairs with the coverage tables above and lives
	 * in the same dump section. */
	unsigned long per_syscall_errno[MAX_NR_SYSCALL][ERRNO_BUCKET_NR];
	/* Sibling of last_edge_at: stamps total_calls at the moment the
	 * most recent EFAULT return was observed for this syscall slot.
	 * Lets a future picker pass bias selection away from syscalls
	 * stuck in pure-EFAULT regimes (no recent edges + a recent EFAULT
	 * stamp is the diagnostic signature).  Stored as the same
	 * total_calls counter last_edge_at uses so the two fields are
	 * directly comparable (delta = last_edge_at[nr] - last_efault_at[nr]
	 * is a signed "has progress outrun the fault?" signal). */
	unsigned long last_efault_at[MAX_NR_SYSCALL];
	/* Per-syscall counterpart of cmp_hints_unique_inserts: every fresh
	 * insert or evict-replace in pools[nr] bumps slot nr.  Dedup-refresh
	 * hits are NOT counted, matching the global counter's semantics.
	 * Drives the "Top syscalls by CMP unique inserts" sibling block in
	 * dump_stats() that pairs with "Top syscalls by recent edge growth"
	 * -- a syscall whose CMP insert rate is high while its edge-growth
	 * rate is flat is generating CMP signal that is not translating into
	 * coverage, the diagnostic signature of the CMP-rising-PC-flat
	 * plateau pattern. */
	unsigned long per_syscall_cmp_inserts[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_cmp_inserts at the previous dump_stats()
	 * call, matching the per_syscall_edges_previous pattern above so the
	 * sibling top-N block can compute the same kind of delta. */
	unsigned long per_syscall_cmp_inserts_previous[MAX_NR_SYSCALL];
	/* See struct kcov_per_syscall_diag.  Indexed by [nr][do32 ? 1 : 0]
	 * so the 32-bit-record vs 64-bit-record arch dimension is preserved
	 * alongside the syscall slot.  ~96 KiB of shm. */
	struct kcov_per_syscall_diag per_syscall_diag[MAX_NR_SYSCALL][2];
	/* Sliding-window edge-rate plateau detector state.  Sampled at the
	 * 600s parent stats tick: each tick, delta = edges_found -
	 * plateau_prev_edges is the count of new edges discovered in the
	 * most recent KCOV_PLATEAU_WINDOW_SEC window.  When the delta drops
	 * below KCOV_PLATEAU_RATE_THRESHOLD (rate < 1 edge per 60s sustained
	 * over the 10-minute window) the parent enters PLATEAU state and
	 * emits a one-line warning to stats.log; a matching CLEARED line is
	 * emitted when the rate climbs back above threshold.  Entry into
	 * PLATEAU also fires strategy_plateau_response(), which forces an
	 * immediate strategy rotation into the plateau-intervention layer.
	 * That layer is a flat round-robin among RRC-biased replay, anti-
	 * prior accept gating, and uniform random; the rotation does not
	 * pin a mode based on the hypothesis classifier.  The published
	 * hypothesis is consumed separately at per-call gates in child.c
	 * (CHILDOP_DOMINANT raises the alt-op burst threshold) and in
	 * minicorpus.c (CMP_RISING_PC_FLAT doubles the replay rate and
	 * narrows the slot picker) -- see the strategy.h header for the
	 * full consumer contract.  Interventions unwind automatically on
	 * the matching CLEARED edge. */
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

bool kcov_bracket_begin(struct kcov_child *kc);
unsigned long kcov_bracket_end(struct kcov_child *kc,
				unsigned long op_nr);

/*
 * Per-childop KCOV attribution mode (--childop-kcov-attribution).
 *
 *   OFF  - default.  Childop dispatch path is unchanged; nothing
 *          is bracketed and childop_edges_clean[] stays at zero.
 *   DUAL - bracket every eligible childop and publish the per-call
 *          delta to childop_edges_clean[] in parallel with the
 *          existing global-delta path's writes to
 *          childop_edges_discovered[].  Consumers (adapt_budget,
 *          canary queue) keep reading the noisy counter; the clean
 *          counter is for offline comparison while the bracket
 *          design soaks.
 *   ON   - reserved for a follow-up commit that flips consumers
 *          to the clean counter.  Today identical to DUAL.
 */
enum childop_kcov_attribution_mode {
	CHILDOP_KCOV_ATTR_OFF = 0,
	CHILDOP_KCOV_ATTR_DUAL,
	CHILDOP_KCOV_ATTR_ON,
};

extern enum childop_kcov_attribution_mode childop_kcov_attr_mode;

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
 * nr is the syscall number for per-syscall edge tracking.  do32 is the
 * KCOV mode bit indicating 32-bit-record collection (snapshotted from the
 * child's current syscall record at set_syscall_nr time, matching how
 * kcov_collect_cmp already receives it).  Threaded into dedup_inc() and
 * reserved for per-syscall diagnostic indexing in a follow-up commit. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr, bool do32,
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
 * (which may have rotated mid-syscall).
 *
 * Returns the count of bloom-novel KCOV_CMP_CONST constants observed
 * on this call (the bandit_cmp_observe return value).  0 means no
 * novelty; any positive value means "this call exercised at least one
 * new compile-time-constant comparison and is a candidate for
 * CMP-source corpus save".  Returns 0 when cmp_capable is false, the
 * buffer is empty, or the kernel only produced non-CONST records. */
unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick);

/* Accessor for the raw CMP record stream after kcov_disable().
 * On return, *out points at the first record (NULL when cmp_capable
 * is false or the buffer is empty) and *count is the (clamped) record
 * count.  Future mutator-side consumers that want raw operand pairs
 * rather than the deduped hint-pool view call this. */
void kcov_get_cmp_records(struct kcov_child *kc,
			  struct kcov_cmp_record **out,
			  unsigned long *count);

/*
 * Per-child kcov PC fd and cmp fd are protected from fuzz close /
 * dup2 / dup3 / close_range targeting via fd_is_protected() /
 * range_contains_protected_fd() / lowest_protected_fd_in_range() in
 * include/fd.h -- the same registry that protects STDERR_FILENO and
 * the stderr capture memfd.  See those declarations for the contract.
 */

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
 * PLATEAU CLEARED line when the rate recovers.  On the PLATEAU rising
 * edge it also fires strategy_plateau_response(), which forces a
 * strategy rotation into the plateau-intervention layer (RRC-biased
 * replay, anti-prior accept gating, or uniform random in a flat
 * round-robin -- the rotation does not pin a mode based on the
 * hypothesis classifier).  Interventions unwind on CLEARED. */
void kcov_plateau_check(void);

/* Mid-run snapshot cadence for kcov_bitmap_maybe_snapshot().  The bitmap
 * is 8 MB and writing it is bursty I/O, so the triggers are coarser than
 * the minicorpus snapshot interval: 1000 new edges OR 300s since the
 * last save, whichever fires first.  Hardcoded -- no operator knob,
 * fleet boxes shouldn't need to retune. */
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

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Shared between the
 * kcov bitmap save/load path and the edgepair warm-start save/load path
 * so both persistence formats checksum their payloads with the same
 * implementation. */
uint32_t kcov_bitmap_crc32(const void *buf, size_t len);

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

/* Fill OUT[32] with the cached SHA-256 digest of the active syscall
 * table shape -- (arch_tag, nr, name) tuples for every slot in the
 * uniarch or biarch tables that are live this run.  Catches the case
 * the existing max_nr_syscall / biarch / kallsyms identity checks
 * miss: two kernels that share MAX_NR_SYSCALL but reorder or rename
 * any syscall produce different digests, so persisted (prev_nr,
 * curr_nr)-keyed state can refuse to load against a table whose
 * semantics have shifted.  Always succeeds; the syscall tables are
 * statically compiled in. */
bool kcov_get_syscall_table_digest(uint8_t out[32]);

/* Wire periodic mid-run snapshots of the bucket_seen bitmap to PATH.
 * Subsequent kcov_bitmap_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied. */
void kcov_bitmap_enable_snapshots(const char *path);

/* Cheap per-tick gate: writes the snapshot if either trigger has elapsed
 * since the last successful save, otherwise returns immediately.  Called
 * from the parent's stats tick and from kcov_plateau_check() when a
 * plateau is first entered. */
void kcov_bitmap_maybe_snapshot(void);

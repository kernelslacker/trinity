#pragma once

#include "child-api.h"

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "types.h"
#include "blob_mutator.h"
#include "breadcrumb_ring.h"
#include "bug_backtrace.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "objects.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "socket-family-grammar.h"
#include "syscall.h"

#include "kernel/if_packet.h"

#include "childop-outcome.h"

/*
 * Layout note — the leading 64 bytes are the per-syscall hot block.
 *
 * Every field in the leading cacheline is read or written on (almost)
 * every syscall by the dispatch_step / __do_syscall / kcov_collect path
 * or the random-syscall picker.  Keeping them packed in one line saves
 * the 1-3 cacheline misses per call the previous layout incurred when
 * the giant 4 KiB syscallrecord (with PREBUFFER_LEN=4096) sat at the
 * front of the struct and pushed every other hot field out into
 * cachelines that had to be re-fetched on each call.
 *
 * The static_assert in child.c pins op_nr (the last hot field) to an
 * offset under 64 so a future field reorder that breaks this property
 * fails the build instead of silently regressing the hot path.
 *
 * struct childdata itself is aligned to 64 bytes so each per-child
 * allocation starts on a fresh cacheline; without this, alloc_shared
 * could hand out a struct whose first 8 bytes share a line with the
 * preceding allocation's tail.
 */

/* Cap on fuzzed SysV shm segments tracked per child for parent-side reap
 * (see fuzz_shm_ids in struct childdata).  A child that creates more RMIDs
 * its oldest tracked segment on overflow, bounding the live orphan set. */
#define MAX_FUZZ_SHM_IDS 128

/* Same cap for fuzzed SysV message queues (see fuzz_msg_ids in struct
 * childdata) -- msgget-created queues need the same parent-side RMID at
 * reap because their OBJ_LOCAL destructor is also skipped on SIGKILL. */
#define MAX_FUZZ_MSG_IDS 128

/* Same cap for fuzzed SysV semaphore sets (see fuzz_sem_ids in struct
 * childdata) -- semget-created sets need the same parent-side RMID at
 * reap because their OBJ_LOCAL destructor is also skipped on SIGKILL. */
#define MAX_FUZZ_SEM_IDS 128

struct childdata {
	/* ---- Hot leading cacheline (64 bytes) ---- */

	/* Per-child KCOV state (PC fd + CMP fd + trace buffers + active/
	 * cmp_capable/remote flags).  Touched on every syscall: dispatch_step
	 * gates remote_mode off kcov.remote_capable, __do_syscall hands
	 * &kcov to the kcov_enable_X / kcov_disable wrappers (PC and CMP
	 * always run together on every syscall), and kcov_collect /
	 * kcov_collect_cmp mutate dedup + current_generation + the shared
	 * CMP-records counter per call. */
	struct kcov_child kcov;

	/* Last syscall group executed, for group biasing.
	 * Read every call (group_bias gate) and conditionally written. */
	unsigned int last_group;

	/* Per-iteration child-op counter, written every loop iteration in
	 * child_process and consulted by the stall detector. */
	unsigned long op_nr;

	/* ---- End of hot leading cacheline ---- */

	/* Per-child staging for the kcov global counters.  See struct
	 * kcov_child_local_stats in include/kcov.h for the field set and
	 * the flush contract.  MUST sit after op_nr -- folding the
	 * counters into struct kcov_child itself would push op_nr past
	 * the 64-byte hot cacheline budget (the static_assert in child.c
	 * pins op_nr there) and the static_assert below pins this field
	 * to >= 64 so a future reorder that drags it into the hot line
	 * fails the build. */
	struct kcov_child_local_stats *local_stats;

	/* Warm fields: read or written per call but not in inner retry
	 * loops.  Kept adjacent so the second cacheline absorbs whatever
	 * the first one missed. */

	/* Pointer to the active-syscall lookup table for this child's
	 * current pick.  Uniarch: set once at child init to
	 * shm->active_syscalls and never written again.  Biarch: refreshed
	 * by choose_syscall_table on every pick (the do32 dice picks one
	 * of shm->active_syscalls{32,64}).  Per-child storage so the
	 * biarch update doesn't need an atomic store on a process-global. */
	int *active_syscalls;

	/* last time the child made progress. */
	struct timespec tp;

	enum child_op_type op_type;

	/* per-child fd caching to avoid cross-child races */
	int current_fd;
	unsigned int fd_lifetime;
	/* Per-slot generation snapshot from current_fd's fd_hash entry,
	 * taken when the fd was fetched.  A mismatch on the next iteration
	 * indicates the slot was emptied or the fd number was recycled
	 * onto a fresh object; either way the cached fd is no longer
	 * trustworthy. */
	uint32_t cached_fd_generation;

	/* fd to /proc/self/fail-nth, opened once per child.  -1 means
	 * fault injection is unavailable on this kernel/config.  Read on
	 * every call by maybe_inject_fault. */
	int fail_nth_fd;

	unsigned int seed;

	unsigned int num;

	/* Snapshot of shm->sibling_freeze_gen taken when we last ran the
	 * sibling-childdata mprotect sweep.  Read at the top of every
	 * child_process loop iteration; on mismatch we re-run the sweep so
	 * any sibling spawned since our last pass joins our PROT_READ set.
	 * See the comment on shm_s::sibling_freeze_gen for the race this
	 * closes. */
	unsigned int last_seen_freeze_gen;

	/* Stall detection state: consecutive alarm timeouts without progress. */
	unsigned int stall_count;
	unsigned int stall_last;

	unsigned char xcpu_count;

	unsigned char kill_count;

	/* Set when the watchdog sends a SIGKILL to a stuck child; cleared
	 * on reap.  Suppresses the per-cycle re-print of the kill banner
	 * (and the stuck-syscall dump that produces it) while the kill is
	 * in flight — without this, is_child_making_progress's ~25 ms poll
	 * re-fires the banner every cycle until kill_count saturates. */
	bool kill_in_flight;

	/* One-shot latch for the D-state diagnostic snapshot fired by
	 * is_child_making_progress() when it first observes the child in
	 * TASK_UNINTERRUPTIBLE.  Set true after the snapshot lands; cleared
	 * on reap (clean_childdata) so a fresh occupant of this slot can
	 * snapshot its own first wedge.  Independent of kill_in_flight so a
	 * future change to the kill-cadence gating cannot accidentally
	 * un-throttle the snapshot. */
	bool dstate_diag_dumped;

	/* SHADOW-ONLY stuck-child accounting latch.  Set true by
	 * is_child_making_progress() on the first detection of diff>=30s for
	 * this child, alongside an increment of
	 * shm->stats.syscall_wedge.count[wedge_nr] and
	 * shm->stats.childop.wedge_count[wedge_op_type].  reap_child() then
	 * adds the CLOCK_MONOTONIC elapsed (now - wedge_start_tp) into
	 * shm->stats.syscall_wedge.total_us[wedge_nr] and
	 * shm->stats.childop.wedge_total_us[wedge_op_type] before the slot
	 * is recycled.  wedge_start_tp is seeded from child->tp (the child's
	 * last-progress timestamp) rather than from the detection moment so
	 * the accumulated duration covers the FULL window the slot was
	 * unreusable -- the watchdog's 30 s grace period included -- and
	 * matches the semantics the operator expects when reading "wedged
	 * total".  Latched per-child so a child that survives many watchdog
	 * ticks contributes one event with a real duration, not one event
	 * per tick with zero duration.  Cleared in clean_childdata so the
	 * next occupant of the slot starts fresh.  Diagnostic-only -- no
	 * live-path decision reads either array yet.  See the comments on
	 * shm->stats.syscall_wedge.count[] / childop_wedge_count[] in
	 * include/stats.h for the exit_reason=19 motivation. */
	bool wedge_accounted;
	bool wedge_do32;
	unsigned int wedge_nr;
	enum child_op_type wedge_op_type;
	struct timespec wedge_start_tp;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	/* Hybrid bandit/explorer split: true for the explorer slice
	 * [alt_op_children, alt_op_children + explorer_children) of the
	 * child array.  Slots strictly below alt_op_children are dedicated
	 * alt-op children; slots at or above the explorer end run the
	 * default/bandit mix.  Stamped once in init_child() and never
	 * mutated for the child's lifetime, so the syscall picker can
	 * branch off it without an atomic load and the bandit-reward
	 * attribution can filter explorer contributions out of
	 * pc_edge_calls_by_strategy[] / pc_edge_count_by_strategy[] /
	 * bandit_cmp_new_constants[].  Always false when
	 * explorer_children is 0. */
	bool is_explorer;

	/* Mid-chain step (i >= 1) of a sequence-chain iteration.  Set by
	 * run_sequence_chain around steps that need to distinguish a
	 * mid-chain dispatch from step 0 / a standalone call.  Lives
	 * outside the leading hot cacheline because the static_assert in
	 * child.c pins op_nr at the end of that line -- adding a field
	 * anywhere ahead of op_nr would push it past 64 bytes and break
	 * the hot-path budget. */
	bool in_chain_mid_step;

	/* Set across the duration of an alt-op op_fn dispatch by
	 * child_process()'s per-op bracket; cleared immediately after.
	 * Read at the call-complete enqueue site in random_syscall_step()
	 * so a random_syscall() invocation made from inside a childop
	 * recipe (e.g. sched_cycler) lands in the syscalls_in_childops
	 * bucket of the childop_split telemetry instead of being
	 * mis-attributed to syscalls_random.  Owner-only field (the
	 * child is the sole writer and the sole reader). */
	bool in_childop;

	/* Strategy enum (enum strategy_t) snapshotted in set_syscall_nr()
	 * at the moment this child's current syscall was picked.  Read by
	 * the post-syscall reward attribution sites (PC edges in
	 * random_syscall_step and CMP novelty in bandit_cmp_observe) so a
	 * strategy rotation that lands between pick and reward credits the
	 * new edges/constants to the arm that actually selected the
	 * syscall, not whichever arm happens to be shm->current_strategy by
	 * the time the syscall returns.  -1 is the "unstamped" sentinel;
	 * both reward sites gate on (strat >= 0 && strat < NR_STRATEGIES)
	 * so the sentinel naturally skips attribution for explorer children
	 * (who bypass the stamp write entirely) and for any pre-first-pick
	 * reads.  Owner-only field, no cross-process coherence needed. */
	int strategy_at_pick;

	/* FD leak instrumentation: count fds created and closed by
	 * this child's syscalls, with per-group breakdown.
	 * On child exit, if fd_created - fd_closed > threshold,
	 * we log which syscall groups are responsible. */
	unsigned long fd_created;
	unsigned long fd_closed;
	unsigned long fd_created_by_group[NR_GROUPS];

	/* Heuristic-arm group-bias anti-lock-in damper state -- F-RSEQ.
	 * Per-pin streak + windowed coverage watermark + fd-warm flag.
	 * Owner-only writes from the dispatch_step tail
	 * (account_fd_and_group); no cross-process coherence, no shm, no
	 * atomics.  See Documentation/strategy.md for the F-RSEQ design
	 * rationale, per-field semantics, and dispatch-tail bookkeeping
	 * order. */
	unsigned int group_streak_len;
	unsigned int last_cov_at_streak;
	unsigned int group_fd_created_in_streak;

	/* Per-child storm-containment counter.  Bumped in lock-step with
	 * the global stats.post_handler_corrupt_ptr from the same call
	 * sites; the global counter loses attribution across the fleet, so
	 * this per-child shadow is what the storm-rate check below scores
	 * against.  Owner-only writes from inside the child, no cross-process
	 * coherence needed.  Reset in clean_childdata so a fresh occupant of
	 * the slot starts from zero.  See storm_check_last_* below for the
	 * sliding-window accounting. */
	unsigned long local_post_handler_corrupt_ptr;

	/*
	 * Per-child bump-cursor into the parent's writable_pool (see
	 * writable_pool_init in rand/random-address.c).  COW-inherited
	 * from the parent's zero-init at fork; get_writable_address()
	 * advances it forward and wraps when the next allocation would
	 * overrun the pool.  Owner-only writes from inside the child,
	 * no cross-process coherence needed.
	 */
	unsigned long writable_pool_cursor;

	/* Rate limiter for the OBJ_LOCAL ANON pool lazy top-up in
	 * get_map_handle().  Bumped on every draw exhaustion; once it
	 * reaches MAPS_LOCAL_REFILL_PERIOD we re-clone the OBJ_GLOBAL
	 * ANON snapshot into the child's OBJ_LOCAL pool and zero the
	 * counter again.  Per-child so the cost is bounded regardless
	 * of fleet width.  Reset in clean_childdata so a slot's fresh
	 * occupant does not inherit the previous child's near-trigger
	 * state. */
	unsigned int maps_local_refill_credit;

	/* Per-child bitmask of nonempty OBJ_LOCAL OBJ_MMAP_* pools, used
	 * by get_map_handle() to skip pools that are guaranteed to return
	 * NULL from get_random_object().  Bit 0 = OBJ_MMAP_ANON,
	 * bit 1 = OBJ_MMAP_FILE, bit 2 = OBJ_MMAP_TESTFILE, matching the
	 * map_pool_types[] order used by the handle picker.
	 *
	 * The picker chooses one of the set bits uniformly (1/popcount)
	 * rather than weighting by num_entries: an equal-pool pick over
	 * {ANON, FILE, TESTFILE} restricted to the nonempty subset, with
	 * no iterations wasted on empty pools.
	 *
	 * Maintained at the 0<->1 transitions of head->num_entries in
	 * add_object_publish (set bit on first insert) and
	 * __destroy_object (clear bit on last removal); destroy_objects()
	 * also flows through __destroy_object so a teardown of a whole
	 * pool clears the bit too.  Reset in clean_childdata so a slot's
	 * fresh occupant starts from "all empty" and re-discovers
	 * non-emptiness through the post-fork init_child_mappings /
	 * clone_global_mmap_pool seeding (which goes through add_object
	 * and so naturally re-sets the bits). */
	unsigned int mmap_pool_nonempty_mask;

	/* Sliding-window state for the per-child storm-rate check.
	 * storm_check_last_time is the monotonic timestamp at which the
	 * local_post_handler_corrupt_ptr counter above last passed the
	 * rate gate (or the time clean_childdata ran, whichever is most
	 * recent).  The snapshot is the value of the counter at that same
	 * instant.  The check (in child_process) re-reads CLOCK_MONOTONIC
	 * and the counter every LOCAL_STORM_CHECK_PERIOD iterations and
	 * triggers a recycle when (counter_now - snapshot) / (now -
	 * last_time) exceeds LOCAL_STORM_RATE_THRESHOLD events/sec AND the
	 * window has been open for at least LOCAL_STORM_WINDOW_SEC
	 * seconds.  The window-floor is what suppresses single-spike false
	 * positives; a transient burst that cannot sustain over 10 s gets
	 * absorbed into the next snapshot roll instead of recycling the
	 * child. */
	struct timespec storm_check_last_time;
	unsigned long storm_check_last_post_handler;

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	/* Ring buffer for child-produced stats deltas drained by the parent
	 * into struct stats_aggregate.  Allocated in shared memory, one per
	 * child, write-only-by-this-child / read-only-by-parent.  See
	 * include/stats_ring.h for the field set and overflow policy. */
	struct stats_ring *stats_ring;

	/* Name of the recipe currently executing inside recipe_runner(),
	 * or NULL when no recipe is in flight.  Read by post-mortem to
	 * attribute a kernel taint to a specific multi-syscall sequence. */
	const char *current_recipe_name;

	/* Set by __BUG() in the child immediately before _exit() so the
	 * parent's reap path can attribute a "child gone" event to a self-
	 * inflicted assertion failure rather than a kernel zombie or wild
	 * SIGKILL.  bug_text is a string-literal pointer (the bugtxt arg
	 * passed to __BUG, which is always a literal at the call site).
	 * bug_lineno + bug_func let the parent print the call site too. */
	bool hit_bug;
	/* Latched once the parent's dump_child_bug() has surfaced this
	 * child's BUG to the real stderr.  Idempotent gate so the per-tick
	 * poll and the zombie watchdog (and any future caller) print the
	 * forensic exactly once; hit_bug stays set so the zombie watchdog
	 * can still attribute "child gone" to the assertion. */
	bool bug_dumped;
	const char *bug_text;
	const char *bug_func;
	unsigned int bug_lineno;
	/* Raw backtrace frame pointers captured inside __BUG() before the
	 * child starts spinning; symbolised in parent context by
	 * dump_child_bug() so the backtrace survives init_child's
	 * stderr->/dev/null redirect.  See include/bug_backtrace.h. */
	struct bug_backtrace bug_backtrace;

	/* Signal-time fault context stamped by child_fault_handler before
	 * any libc-touching call, so the parent can surface the death
	 * class even when the in-handler backtrace_symbols_fd / open /
	 * dup2 chain re-faults walking a corrupted ld.so writable segment.
	 * Re-symbolised in parent context by dump_child_fault_beacon().
	 * See include/bug_backtrace.h. */
	struct child_fault_beacon fault_beacon;
	/* Latched once the parent's dump_child_fault_beacon() has surfaced
	 * this beacon to the real stderr.  Mirrors bug_dumped above:
	 * idempotent gate so the per-tick poll and any future caller print
	 * the forensic exactly once; fault_beacon.written stays set so
	 * post-reap diagnostics can still see the child died with a
	 * stamped beacon. */
	bool fault_beacon_dumped;

	/* Per-child taint watcher.  tainted_fd is opened once at child init
	 * against /proc/sys/kernel/tainted and cached for the child's
	 * lifetime; -1 means the open failed and the watcher is disabled.
	 * last_tainted holds the most recent kernel taint mask we observed,
	 * baseline-read at init.  The dispatch loop XORs a fresh read against
	 * this on each non-syscall childop completion to catch soft taints
	 * (lockdep WARN, RCU stall, reckless module load) tied to a specific
	 * op even when no oops fires. */
	int tainted_fd;
	unsigned long last_tainted;

	/* ---- Cold tail: large rings and the per-call syscallrecord with
	 * its 4 KiB prebuffer.  Pushed past every hot/warm field so reads
	 * of any field above land in the leading cacheline(s) instead of
	 * dragging the prebuffer's lines into L1. ---- */

	/* Ring of fds returned by recent fd-creating syscalls.
	 * Consulted preferentially when generating ARG_FD arguments. */
	struct child_fd_ring live_fds;

	/* Sibling of live_fds for non-fd returns: small-int scalars
	 * (cookies, key serials, queue ids, signal numbers, ...) that
	 * arrive on RET_NONE syscalls and get propagated forward into
	 * ARG_UNDEFINED slots of subsequent calls.  Capture happens in
	 * handle_syscall_ret() after register_returned_fd; consume
	 * happens at low probability in gen_undefined_arg(). */
	struct child_prop_ring prop_ring;

	/*
	 * Per-child OBJ_LOCAL objhead array.  Allocated lazily by
	 * init_object_lists() in the owning child's private heap (zmalloc).
	 * Unreachable from any other process's address space, so a sibling
	 * fuzzed value-result write cannot land here and the parent must
	 * not deref it for foreign-child diagnostic dumps.  The pointer
	 * itself sits in the writable section of struct childdata (in
	 * MAP_SHARED), but every byte it addresses is private to this
	 * child.
	 */
	struct objhead *objects;

	/*
	 * Per-child snapshot copy of the parent's pre-fork OBJ_GLOBAL
	 * pool.  Populated by clone_global_objects_to_child() in init_child
	 * right after the fork-time OBJ_LOCAL bring-up; sized
	 * MAX_OBJECT_TYPES.  Each objhead's array[] holds shallow copies of
	 * the parent's slot pointers — the obj structs themselves and any
	 * kernel resources they describe (fds, mmap regions) are reached
	 * via fork's table dup, so a snapshot of bookkeeping is the only
	 * per-child state this lift adds.  Mutations from inside this
	 * child stay local; sibling pools cannot reach each other through
	 * cross-process scribble.  NULL between fork and the clone — the
	 * resolver (get_objhead) falls back to shm->global_objects in that
	 * window so any early lookup degrades gracefully instead of
	 * dereferencing NULL.
	 */
	struct objhead *global_objects;

	/*
	 * Per-child snapshot of the parent's pre-fork fd->object hash and
	 * its parallel compact live-fd list.  Captures every entry the
	 * parent published via fd_hash_insert before fork; child lookups
	 * resolve against this snapshot instead of the shm-resident table,
	 * which lets the shm table die alongside the OBJ_GLOBAL pool.
	 * Allocated by clone_global_objects_to_child(); NULL between fork
	 * and the clone, in which case the per-process router falls back
	 * to shm->fd_hash / shm->fd_live the same way the objhead resolver
	 * does for early lookups.
	 */
	struct fd_hash_entry *fd_hash;
	int *fd_live;
	unsigned int fd_hash_count;
	unsigned int fd_live_count;

	/* Per-child shards of the corrupted-pointer attribution rings.
	 * Sole writer is the owning child (the *_record functions in
	 * utils.c); sole reader is the parent at periodic-dump time,
	 * which merges every child's shard into a single ranked table.
	 * No cross-process lock because the writer and reader sets are
	 * each a single context.  this_child()==NULL callers (parent
	 * post-mortem paths, deferred-free tick on the main process)
	 * drop the record -- per-child storage has no parent fallback,
	 * and those callers are vanishingly rare relative to the per-
	 * child rejection volume the dump is summarising. */
	struct corrupt_ptr_attr_entry local_corrupt_ptr_attr[CORRUPT_PTR_ATTR_SLOTS];
	struct corrupt_ptr_pc_entry local_corrupt_ptr_pc[CORRUPT_PTR_PC_SLOTS];
	struct deferred_free_reject_pc_entry local_deferred_free_reject_pc[CORRUPT_PTR_PC_SLOTS];

	/* Per-fire payload that the (nr, do32bit) / (nr, do32bit, pc)
	 * attribution shards drop on the floor: the scribbled pointer
	 * value, the arg slot it was caught on (when the caller knows),
	 * and a short site tag.  Owner-only writes from inside the child;
	 * parent reads at periodic-dump time.  See include/breadcrumb_ring.h
	 * for the coherence model. */
	struct corrupt_ptr_breadcrumb_ring breadcrumb_ring;

	/* Last socket-family-grammar illegal-step this child fired, or
	 * {SFG_ILLEGAL_NONE, SFG_CONN_INIT, 0} if the child has never
	 * fired one.  Mirrors the corrupt_ptr breadcrumb model:
	 * owner-only writes from inside the child (sfg_publish_illegal in
	 * net/socket-family-grammar.c, called immediately before the raw
	 * illegal syscall), read by the parent's post-mortem walk to
	 * label the crash context when the kernel oopses inside the
	 * illegal path.  No cross-process coherence needed -- the parent
	 * reads only after the child is quiesced by panic(). */
	struct {
		enum sfg_illegal_op op;
		enum sfg_conn_state at;
		int family;
	} last_sfg_illegal;

	/* Ring of recently completed syscall records, drained by the parent
	 * during post-mortem to reconstruct a fleet-wide chronology. */
	struct child_syscall_ring syscall_ring;

	/* Compact rolling history of recently completed syscalls, drained
	 * on __BUG() to recover what this child was doing just before an
	 * assertion failure (most often a parent-side list/fd-event drain
	 * crash caused by a child wild write hundreds of syscalls back). */
	struct pre_crash_ring pre_crash;

	/* Previous-tick reading for the periodic_work divergence sentinel.
	 * .valid is false on the first tick after clean_childdata so the
	 * first sample populates without a (meaningless) compare. */
	struct sentinel_reading sentinel_prev;

	/* Per-child tick counter for the divergence sentinel.  Bumped on
	 * each tick after the initial full-populate; parity selects which
	 * syscall family is refreshed this tick (even=uname, odd=sysinfo)
	 * so a tick pays one of the two kernel-rwsem syscalls instead of
	 * both.  Reset in clean_childdata so a fresh slot occupant starts
	 * the staggered cycle from a known phase. */
	unsigned int sentinel_tick_ix;

	/* Per-child seen-bloom over (cmp_ip, value, size) tuples consulted
	 * by cmp_hints_collect() to short-circuit pool_add_locked's per-call
	 * linear-scan dedup when this child has already pushed the tuple into
	 * the pool within the last CMP_HINTS_BLOOM_RESET CMP records.
	 * See include/cmp_hints.h for the size / FPR tradeoff and the
	 * "false positives are benign" argument.  Owner-only writes from
	 * inside the child, no cross-process coherence needed.
	 *
	 * Indexed by [do32 ? 1 : 0] for the same reason the shm pools and
	 * cmp_novelty arrays are 2D: under biarch, the same numeric (ip,
	 * value, size) tuple may legitimately be a fresh observation in
	 * one arch's pool even if it was just inserted by the other arch's,
	 * and a single shared bloom would falsely suppress the second
	 * insert. */
	struct cmp_hints_bloom cmp_hints_seen[2];

	/* Greedy CMP RedQueen re-exec per-child state.
	 *
	 * reexec_pending[] is the per-call attribution scratch the per-record
	 * loop in cmp_hints_collect() writes to: each (cmp_ip, value, size,
	 * slot) tuple is one (kernel comparison, runtime operand match)
	 * proposal that the dispatch_step tail will optionally drain into a
	 * fresh dispatch with the named slot pinned to value.
	 *
	 * reexec_pending_count counts how many slots in [0, MAX_REEXEC_PENDING)
	 * are populated; the per-dispatch cap (initially 1) lives
	 * at the consumer site, not here -- the buffer always reflects the
	 * full attribution census the harvest pass produced, regardless of
	 * how many the consumer chooses to spend.
	 *
	 * in_reexec is the recursion guard: set true around redqueen_reexec_step
	 * so the re-exec's own kcov_collect_cmp pass does NOT emit fresh
	 * attribution into the buffer (which would self-reinforce a runaway
	 * loop) and the dispatch_step tail does NOT drain a second tier of
	 * re-execs.  The pool / bloom inserts still run inside the re-exec --
	 * those records are real harvest signal.
	 *
	 * redqueen_enabled is the A/B-comparison stamp: half the CMP-mode
	 * children get true (re-exec active), half get false (the control
	 * group).  Stamped once at child init and never mutated, so per-
	 * window comparisons of (reexec-enabled vs control) cohort metrics
	 * isolate the re-exec's contribution from time-of-day environmental
	 * drift.
	 *
	 * Owner-only writes from inside the child; the buffer is per-call
	 * scratch and the two booleans are read-only after child init / drain
	 * boundary.  No cross-process coherence needed.
	 */
	struct reexec_pending reexec_pending[MAX_REEXEC_PENDING];
	unsigned int reexec_pending_count;
	bool in_reexec;
	bool redqueen_enabled;
	/* A/B-comparison stamp for the plateau_burst per-call drain cap.
	 * When true AND the dispatch_step tail classifies the current call
	 * as inside a CMP_RISING_PC_FLAT plateau (plateau_burst), the drain
	 * loop caps at REDQUEEN_REEXEC_BURST_DRAIN entries (default 4) and
	 * breaks on a helper FAIL (per-window ceiling hit).  Arm A (false)
	 * leaves the greedy drain-all baseline (b86f2e77a846) untouched so
	 * the two arms measure "surgical top-K drain during plateau" vs
	 * "greedy drain-all during plateau" on distinct-edge lift per
	 * attempt.  Independent of redqueen_enabled (an arm-B child with
	 * redqueen_enabled == false still bumps its cohort denominators but
	 * no burst fires because the outer redqueen_enabled gate short-
	 * circuits first).  Stamped once at child init via ONE_IN(2)
	 * alongside the other A/B rows and never mutated; owner-only writes,
	 * no cross-process coherence needed. */
	bool burst_drain_arm_b;

	/* SysV shm segments this child created via fuzzed shmget.  They are also
	 * tracked in the OBJ_LOCAL pool, but that lives in child-private heap the
	 * parent cannot read, and its RMID destructor only runs on a clean child
	 * exit -- a child SIGKILL'd by the watchdog/OOM leaks every segment it
	 * made (~10GB of orphaned shmem OOM-killed the whole run, 2026-07-13).
	 * Mirror the ids directly in the (shared) childdata so reap_child() can
	 * RMID them parent-side no matter how the child died.  Bounded ring:
	 * register_sysv_shm() RMIDs the oldest on overflow so one long-lived
	 * child can't leak unboundedly.  fuzz_shm_count is release-stored by the
	 * child and acquire-loaded by the parent, which reads only after waitpid
	 * (happens-before), so no lock is needed. */
	int fuzz_shm_ids[MAX_FUZZ_SHM_IDS];
	unsigned int fuzz_shm_count;

	/* SysV message queues this child created via fuzzed msgget.  Same
	 * OBJ_LOCAL-destructor-skipped-on-SIGKILL problem as fuzz_shm_ids above:
	 * an orphaned queue is a kernel-persistent object that survives the
	 * child, and once the fleet accumulates MSGMNI (~32000) orphans every
	 * subsequent msgget returns ENOSPC and coverage dies.  Mirror the same
	 * bounded-ring / release-store / acquire-load-at-reap shape so the
	 * parent can IPC_RMID the ids no matter how the child died.  Double
	 * RMID (fuzzed msgctl already freed the id, or two children shared a
	 * key) returns EINVAL/EIDRM and is ignored. */
	int fuzz_msg_ids[MAX_FUZZ_MSG_IDS];
	unsigned int fuzz_msg_count;

	/* SysV semaphore sets this child created via fuzzed semget.  Same
	 * OBJ_LOCAL-destructor-skipped-on-SIGKILL problem as fuzz_shm_ids /
	 * fuzz_msg_ids above: an orphaned sem set is a kernel-persistent object
	 * that survives the child, and once the fleet accumulates SEMMNI
	 * (~32000) orphans every subsequent semget returns ENOSPC and coverage
	 * dies.  Mirror the same bounded-ring / release-store / acquire-load-
	 * at-reap shape so the parent can IPC_RMID the ids no matter how the
	 * child died.  Double RMID (fuzzed semctl already freed the id, or two
	 * children shared a key) returns EINVAL/EIDRM and is ignored. */
	int fuzz_sem_ids[MAX_FUZZ_SEM_IDS];
	unsigned int fuzz_sem_count;
	/* A/B-comparison stamp for the cmp_hints "uninteresting constant"
	 * substitution-pool drop mask.  Half the children get Arm A (the
	 * historical ~3UL mask -- drop 0/1/2/3) and half get Arm B (~7UL --
	 * also drop 4/5/6/7).  The widened band crosses common meaningful
	 * bounds (struct sizes, low flag bits), so per-arm cohort metrics
	 * (unique pool inserts, downstream new-edge wins per substituted
	 * hint) reveal whether those low values were carrying real signal
	 * or were just bloat in the 16-slot per-syscall pool.  Stamped once
	 * at child init and never mutated, matching the redqueen_enabled
	 * stamp pattern so time-of-day environmental drift is common to
	 * both arms.  Read-only after stamp; owner-only writes; no
	 * cross-process coherence needed.  Strategy.c's
	 * cmp_novelty_interesting() intentionally stays at val < 4 -- the
	 * in-tree comment there keeps the two filters decoupled so the
	 * novelty signal can drift independently of the pool-substitution
	 * threshold; this stamp drives only the pool-side filter. */
	bool boring_filter_arm_b;
	/* Per-child A/B stamp for the frontier_cold_weight blend promotion.
	 * Arm A (false) returns the historical OLD weight to the live picker
	 * so selection stays byte-identical to the pre-blend baseline; Arm B
	 * (true) returns the BLENDED weight (call-count + ilog2(bucket_bits)
	 * + 2*ilog2(distinct_pcs) + ilog2(transition_edges_real_local)) so
	 * the operator can read the live divergence between cohorts off the
	 * frontier_blend_* shm counters.  Stamped once at child init via
	 * ONE_IN(2) and never mutated, matching the boring_filter_arm_b
	 * stamp pattern so time-of-day environmental drift is common to
	 * both arms.  Read-only after stamp; owner-only writes; no
	 * cross-process coherence needed. */
	bool frontier_blend_arm_b;
	/* A/B-comparison stamp for the errno-plateau decay in the coverage-
	 * frontier picker's silent-regime accept site.  Arm A (false) is the
	 * control: shadow counters bump but no live reject, so selection
	 * stays byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) additionally engages the REJECT_DENOM-1 / REJECT_DENOM
	 * probabilistic reject in the picker when the predicate fires, so the
	 * operator can read the live divergence between cohorts off the
	 * frontier_errno_decay_live_rejects shm counter (Arm B only) against
	 * the symmetric frontier_errno_decay_would_skip shm counter (both
	 * arms).  Stamped once at child init via ONE_IN(2) and never mutated,
	 * matching the frontier_blend_arm_b pattern above so time-of-day
	 * environmental drift is common to both arms.  Read-only after stamp;
	 * owner-only writes; no cross-process coherence needed. */
	bool frontier_errno_decay_arm_b;
	/* A/B-comparison stamp for the silent-streak decay at the coverage-
	 * frontier picker's silent-regime accept site.  Arm A (false) is the
	 * control: the shadow counters (frontier_decay_candidates /
	 * frontier_decay_would_skip) still bump in lock-step but selection
	 * stays byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) additionally engages the FRONTIER_SILENT_DECAY_REJECT_DENOM-1
	 * / FRONTIER_SILENT_DECAY_REJECT_DENOM probabilistic reject when the
	 * predicate fires (streak >= FRONTIER_SHADOW_DECAY_STREAK AND the
	 * no-CMP-and-no-SUCCESS-errno-shift UNLESS clause holds), so the
	 * operator can read the live divergence between cohorts off the
	 * frontier_silent_decay_live_rejects shm counter (Arm B only) against
	 * the symmetric frontier_decay_would_skip shm counter (both arms).
	 * Independent of the sibling frontier_errno_decay_arm_b above so the
	 * two decay-axis cohort comparisons stay un-confounded; the goto retry
	 * the silent-streak reject takes preempts the errno-plateau check that
	 * follows it at the picker site, so a single pick can never be
	 * double-demoted within one accept iteration regardless of how the two
	 * arm-B stamps cross.  Stamped once at child init via ONE_IN(2) and
	 * never mutated, matching the frontier_errno_decay_arm_b pattern above
	 * so time-of-day environmental drift is common to both arms.  Read-
	 * only after stamp; owner-only writes; no cross-process coherence
	 * needed. */
	bool frontier_silent_decay_arm_b;
	/* Per-pick frontier accept-regime stamp.  Written by set_syscall_nr_
	 * coverage_frontier at the two accept sites (LIVE for max_weight > 2,
	 * SILENT for max_weight <= 2) and consumed by random_syscall_step's
	 * post-call attribution path so the per-syscall frontier_productive_
	 * wins / frontier_live_misses arrays (include/stats.h) can attribute
	 * the outcome to the accept regime that owned the pick.  Reset to
	 * FRONTIER_PICK_NONE at the top of set_syscall_nr() before strategy
	 * dispatch so non-frontier strategy picks naturally leave the slot
	 * unstamped and the post-call attribution gate skips them.  Cleared
	 * in clean_childdata() so a fresh slot occupant starts from NONE.
	 * Owner-only writes from inside the child; no cross-process coherence
	 * needed.  See enum frontier_pick_regime above for the contract. */
	enum frontier_pick_regime frontier_pick_regime;
	/* A/B-comparison stamp for the adaptive remote-KCOV mode decision in
	 * dispatch_step.  Arm A (false) is the control: the static policy
	 * (per-syscall KCOV_REMOTE_HEAVY flag + ONE_IN(remote_reciprocal))
	 * runs unchanged and the live remote_mode for the upcoming dispatch
	 * is byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) replaces the static decision with the adaptive read of the
	 * per-syscall mode-keyed yield counters (remote_pc_calls /
	 * remote_pc_edge_calls / local_pc_calls / local_pc_edge_calls in
	 * struct kcov_shared) -- a HEAVY-flagged syscall whose lifetime
	 * remote samples have failed to produce a single edge is demoted off
	 * the heavy rate, and an unflagged syscall whose remote edge rate
	 * beats its local edge rate by the configured margin is promoted to
	 * remote sampling.  The shadow disposition counters
	 * remote_adaptive_{samples,would_demote,would_promote,agree} in
	 * shm->stats are bumped in lock-step from BOTH arms so the would-be
	 * divergence stays observable across the cohort split, regardless of
	 * which arm this child was stamped into.  Stamped once at child init
	 * via ONE_IN(2) and never mutated, matching the
	 * frontier_errno_decay_arm_b pattern above so time-of-day
	 * environmental drift is common to both arms.  Read-only after
	 * stamp; owner-only writes; no cross-process coherence needed. */
	bool remote_adaptive_arm_b;
	/* Replay-side companion to corpus_entry::rq_sourced.  Set inside
	 * minicorpus_replay() right after the snapshot picks an entry whose
	 * args were captured under in_reexec; cleared unconditionally at the
	 * top of minicorpus_mut_attrib_commit() so the next iteration starts
	 * with a known-clear flag.  Consumed by frontier_record_new_edge()
	 * (strategy.c) to credit later PC-edge wins from RedQueen-sourced
	 * corpus saves to rq_sourced_pcedge_wins_per_syscall[], separate
	 * from the in_reexec/redqueen_enabled axes above which describe the
	 * current dispatch's RedQueen role rather than the source provenance
	 * of the corpus entry being replayed.  Owner-only writes from inside
	 * the child; no cross-process coherence needed. */
	bool replay_rq_sourced;
	/* Replay-side companion to corpus_entry::errno_sourced for
	 * errno-gradient-save.  Same lifecycle as replay_rq_sourced:
	 * set by minicorpus_replay() from the picked snapshot, cleared by
	 * minicorpus_mut_attrib_commit().  Consumed by
	 * frontier_record_new_edge() to credit later PC-edge wins from
	 * errno-sourced corpus saves to
	 * errno_sourced_pcedge_wins_per_syscall[] -- the conversion-rate
	 * counter that pairs with errno_sourced_saves_per_syscall[].  Owner-
	 * only writes from inside the child; no cross-process coherence
	 * needed. */
	bool replay_errno_sourced;
	/* Sliding-window cap on greedy re-exec dispatches.  The design caps
	 * the per-child rate at STRATEGY_WINDOW / 4 (~25% of the bandit's
	 * rotation budget) so a hot attributing syscall can't burn the
	 * window's whole syscall budget on re-execs.  Reset cadence is
	 * STRATEGY_WINDOW child iterations from window_start_op; cap
	 * exceedance bumps reexec_window_cap_hit in kcov_shm and skips
	 * the would-be re-exec.  Per-child storage means no cross-process
	 * atomic and the cap is enforced symmetrically across the fleet. */
	unsigned long reexec_count_window;
	unsigned long reexec_window_start_op;

	/* per-call latch, set from any of the four
	 * cmp_hints_try_get() callsites in generate-args.c that commit the
	 * returned hint to a produced syscall arg.  Cleared at the top of
	 * generate_syscall_args() so each new call starts with a fresh
	 * status, and read in kcov_collect()'s found_new branch to attribute
	 * a PC-edge win to the cmp-hint pipeline when the call that flipped
	 * the new edge had a hint injected into its arg surface.  Owner-only
	 * writes from inside the child; the parent's stats consumer reads
	 * the resulting per_syscall_cmp_hint_pc_wins[] counter, never this
	 * flag directly. */
	bool cmp_hint_injected_this_call;

	/* --blob-ab-mode within-run A/B stamp: the mode picked by the
	 * most recent blob_fill() on this call.  Reset to
	 * BLOB_AB_MODE_NONE at the top of generate_syscall_args()
	 * alongside cmp_hint_injected_this_call; set from inside
	 * blob_fill() on the ab-mode branch to the HAVOC or CMPDICT
	 * coin-flip outcome.  Read at the dispatch-site novelty-gate
	 * credit block in random_syscall/dispatch.c to attribute this
	 * call's new_edges to the mode that produced them.  When the
	 * flag is absent this stamp stays BLOB_AB_MODE_NONE for every
	 * call and the credit block short-circuits, keeping the flag-
	 * off arm byte-identical.  Latest-fill wins if a single call
	 * fires multiple blob_fill() invocations (rare on the
	 * ARG_BUF_SIZED surface; design accepts the simplification). */
	enum blob_ab_child_mode blob_ab_mode_last;

	/* A/B-comparison stamp for the cmp-hint baseline injection denom.
	 * Half the children are stamped Arm A (false: ONE_IN(BASELINE) =
	 * the historical 1-in-16 baseline rate) and half are stamped Arm B
	 * (true: ONE_IN(BASELINE_ARM_B) = the more aggressive 1-in-12 rate).
	 * Read at the three baseline callsites in generate-args.c via
	 * cmp_hint_baseline_should_inject(); the amplified callsites are
	 * NOT branched on this flag (the SR_PLATEAU_FORCE / CMP_RISING_PC_
	 * FLAT path already overrides the denom to AMPLIFIED for both arms,
	 * and the separate denom(9)/denom(10) amplified callsites are out of
	 * scope by design).  Stamped once in init_child_runtime_config() at
	 * ONE_IN(2), independent of the KCOV mode pick so the comparison is
	 * not entangled with [redqueen_enabled]'s CMP-mode-only split, and
	 * cleared in clean_childdata so a fresh slot occupant restamps.
	 * Owner-only writes from inside the child; the parent's stats
	 * consumer reads the kcov_shm-resident cmp_inject_arm_* counters
	 * the helper bumps, not this flag directly. */
	bool cmp_hint_inject_arm_b;

	/* A/B-comparison stamp for the prop_ring injection at handle_arg_op's
	 * ARG_OP callsite (the second prop_ring consumer; the first lives in
	 * gen_undefined_arg and is not gated by this stamp).  Arm A (false) is
	 * the control: no prop_ring_try_get pull, the handle_arg_op RNG
	 * sequence stays byte-identical to the pre-row behaviour.  Arm B (true)
	 * attempts a low-prob pull after the existing cmp_hints try has missed;
	 * a successful pull returns a recent kernel-handed-back scalar as the
	 * ARG_OP command code.  Stamped once in init_child_runtime_config() at
	 * ONE_IN(2), independent of cmp_hint_inject_arm_b / redqueen_enabled /
	 * boring_filter_arm_b / frontier_blend_arm_b so the five A/B axes can
	 * cross without confounding each other's cohort comparisons, and
	 * cleared in clean_childdata so a fresh slot occupant restamps.
	 * Owner-only writes from inside the child; the parent's stats consumer
	 * reads the kcov_shm-resident prop_ring_argop_arm_* counters the
	 * callsite bumps, not this flag directly. */
	bool prop_ring_argop_arm_b;

	/* A/B-comparison stamp for the SHADOW structure-aware arm picker in
	 * mutate_arg (the doubled-pool weighted_pick_case_shadow_structured()
	 * draw).  Arm A (false) is the control: the shadow picker is not
	 * called, so mutate_arg's RNG sequence stays byte-identical to the
	 * pre-shadow (pre-139a829f) behaviour and the live weighted_pick_case()
	 * draw is the only rnd_modulo_u32() step on the picker path.  Arm B
	 * (true) calls the shadow picker on structured-eligible slots after
	 * the live op is already in hand, burns one extra rnd_modulo_u32 from
	 * the doubled 2 * MUT_NUM_OPS pool, and bumps mut_structured_shadow_
	 * samples / mut_structured_shadow_divergences for the cohort.  The
	 * per-child stamp is the only correct way to measure the shadow's
	 * downstream effect: an unconditional shadow draw (the 139a829f shape)
	 * perturbs the live RNG fleet-wide on every structured-eligible slot,
	 * leaving no clean control arm.  Stamped once in init_child_runtime_
	 * config() at ONE_IN(2), independent of cmp_hint_inject_arm_b /
	 * redqueen_enabled / boring_filter_arm_b / frontier_blend_arm_b /
	 * prop_ring_argop_arm_b so the six A/B axes can cross without
	 * confounding each other's cohort comparisons, and cleared in
	 * clean_childdata so a fresh slot occupant restamps.  Owner-only writes
	 * from inside the child; the parent's stats consumer reads the
	 * minicorpus_shm-resident mut_structured_arm_* counters bumped at fork
	 * + the mut_structured_shadow_* counters bumped at the callsite, not
	 * this flag directly. */
	bool mut_structured_arm_b;

	/* A/B-comparison stamp for the typed prop_ring consumer rows at the
	 * gen_arg_* sites in generate-args.c.  Arm A (false) skips the
	 * typed pull entirely, leaving the existing kind-agnostic
	 * prop_ring_try_get() callsites in gen_undefined_arg /
	 * handle_arg_op as the only consumers and the per-call RNG
	 * sequence byte-identical to the pre-typing baseline.  Arm B
	 * (true) calls prop_ring_try_get_kind() at the typed callsites
	 * (currently gen_arg_key_serial) and bumps the per-kind consume
	 * counters in kcov_shm so the operator can read the typed-pull
	 * fire rate against the population split.  Stamped once in
	 * init_child_runtime_config() at ONE_IN(2), independent of all
	 * other A/B axes so they can cross without confounding each
	 * other's cohort comparisons, and cleared in clean_childdata so
	 * a fresh slot occupant restamps.  Owner-only writes from inside
	 * the child; the parent reads the kcov_shm-resident counters the
	 * callsite bumps, not this flag directly. */
	bool prop_ring_typed_arm_b;

	/* SHADOW per-entry feedback scoring scratch ([11-feedback-loop]
	 * PHASE 4).  cmp_hints_try_get_ex() pushes one entry per successful
	 * pull (capped at CMP_HINT_CONSUMED_STASH_MAX; overflow drops the
	 * excess).  Cleared at the top of generate_syscall_args() (via
	 * cmp_hints_feedback_reset_stash) and drained by exactly ONE of the
	 * cmp_hints_feedback_credit_* calls in dispatch_step's post-call
	 * bookkeeping, which credit per-entry wins/misses on the matching
	 * pool entries and bump the flat cmp_hint_wins / cmp_hint_misses /
	 * cmp_hint_cmp_novelty_wins counters.  Owner-only writes from
	 * inside the child; no cross-process coherence needed. */
	struct cmp_hint_consumed_entry
		cmp_hints_consumed_stash[CMP_HINT_CONSUMED_STASH_MAX];
	unsigned int cmp_hints_consumed_count;

	/* SHADOW-ONLY topology-pair latch.
	 * Tracks the most recent non-syscall childop ("setup") this child
	 * has dispatched, plus the op_nr at which it was stamped.  Stamped
	 * from child_process() at the top of the dispatch arm for is_alt_op
	 * iterations (before op_fn runs, so a setup that itself produces
	 * new coverage attributes to its own op rather than the prior one)
	 * and read by frontier_record_new_edge() / _transition_edge() to
	 * build a per-event {setup_op, age_in_syscalls, syscall_nr, reason}
	 * tuple in shm->stats.topo_pair.ring[].  NR_CHILD_OP_TYPES is the
	 * "no setup observed yet on this child" sentinel; productive events
	 * that fire before any setup has run bump
	 * topo_pair.no_setup_observed instead of being recorded.  Owner-only
	 * writes from inside the child; no cross-process coherence needed.
	 * Reset in clean_childdata so a fresh slot occupant does not inherit
	 * the previous child's latched setup. */
	enum child_op_type last_setup_op;
	unsigned long last_setup_op_nr;

	/* The actual syscall records each child uses.  Dominated by a 4 KiB
	 * prebuffer + 128 B postbuffer used by -v rendering — only nr / a1..a6
	 * / retval / lock / state are touched on the hot path, and those are
	 * already in the rec's own first cacheline. */
	struct syscallrecord syscall;
} __attribute__((aligned(64)));

/*
 * Compute the adaptive iteration count for an opt-in childop.  Reads
 * the per-op multiplier (Q8.8 fixed point) maintained by adapt_budget()
 * out of shm->stats.childop.budget_mult[op] and scales `base` by it.
 *
 * If the slot is zero (uninitialised, or wild-write zeroed), fall back
 * to `base` so the loop never collapses to zero iterations — this is
 * the fixed childop budget used before adaptive budget multipliers, and
 * it remains the safe default.
 *
 * Caller must have shm.h in scope (childop .c files already do).  The
 * macro evaluates `op` and `base` exactly once each via statement-
 * expression locals, which matters because callers sometimes pass
 * expressions with side effects for `base` (none today, but cheap to
 * future-proof).
 */
#define BUDGETED(op, base) ({						\
	uint16_t _m = __atomic_load_n(&shm->stats.childop.budget_mult[(op)], \
				      __ATOMIC_RELAXED);		\
	unsigned int _b = (unsigned int)(base);				\
	_m ? ((_b * (unsigned int)_m) >> 8) : _b;			\
})

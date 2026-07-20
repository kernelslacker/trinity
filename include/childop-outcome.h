#pragma once

/*
 * Per-childop outcome record + SHADOW telemetry helpers, plus the
 * corruption-attribution ring entry types (post_handler_corrupt_ptr
 * per-handler and caller-PC shards, deferred-free reject PC shard).
 * Included via child.h; relies on enum child_op_type being visible.
 */

/* Per-childop one-shot latch reason codes published to
 * shm->stats.childop.latch_reason[op] when a childop disables itself for
 * the remainder of the run.  Compact enum (rendered as the integer code
 * in stats; no string table is materialised at this layer -- decoding is
 * the operator's job).  CHILDOP_LATCH_NONE = 0 matches the create_shm()
 * memset so a never-latched op renders as absent in the per-op dump.
 *
 * Keep this list small and generic -- the reason a childop latches off
 * usually reduces to one of "this kernel can't do it" (missing config /
 * netns scope / cap), "the one-shot init step returned an error", or "a
 * persistent resource exhaustion is happening".  Childop-specific detail
 * stays in that childop's own counters; this enum is the cross-childop
 * summary the per-arm-yield telemetry consumes. */
enum childop_latch_reason {
	CHILDOP_LATCH_NONE = 0,
	CHILDOP_LATCH_UNSUPPORTED,		/* kernel feature absent / built out */
	CHILDOP_LATCH_NS_UNSUPPORTED,		/* namespace or capability scope refused */
	CHILDOP_LATCH_INIT_FAILED,		/* one-shot setup/init step returned error */
	CHILDOP_LATCH_RESOURCE_EXHAUSTED,	/* persistent ENOMEM/EMFILE/EAGAIN at setup */
	CHILDOP_LATCH_OTHER,
};

/* Per-pick regime stamp written by set_syscall_nr_coverage_frontier at the
 * two accept sites and consumed by the post-call attribution path in
 * random_syscall_step.  Lets the post-call yield attribution
 * (frontier_productive_wins_per_syscall, frontier_live_misses_per_syscall
 * in include/stats.h) know which accept regime owned the pick that
 * produced the call -- the same regime split the scalar frontier_live_
 * picks / frontier_silent_picks counters surface fleet-wide, but kept
 * per-call instead of per-window so the productive_win / live_miss
 * decision can be attributed against the live-vs-silent split.
 *
 *   FRONTIER_PICK_NONE    Reset value, written at the top of
 *                         set_syscall_nr() before strategy dispatch so a
 *                         non-frontier strategy pick (RANDOM / HEURISTIC)
 *                         naturally leaves the slot at NONE and the
 *                         post-call attribution path skips it.
 *   FRONTIER_PICK_LIVE    Live-ring regime: max_weight > 2 in
 *                         set_syscall_nr_coverage_frontier, the picker is
 *                         biasing off frontier_recent_count.
 *   FRONTIER_PICK_SILENT  Silent-ring regime: max_weight <= 2, the
 *                         plateau-fallback cold-weight path is steering
 *                         the pick.
 *
 * Owner-only writes from inside the child; no cross-process coherence
 * needed.  Read by no live-path code -- the per-call attribution path is
 * the sole consumer, and the picker accept/retry math does not consume
 * this stamp, so any drift cannot perturb live selection. */
enum frontier_pick_regime {
	FRONTIER_PICK_NONE = 0,
	FRONTIER_PICK_LIVE,
	FRONTIER_PICK_SILENT,
};

/* Unified per-childop outcome record (AGGREGATED across the run, NOT a
 * per-invocation event).  One coherent snapshot for consumers that want
 * a single record per op instead of scraping a dozen parallel
 * shm->stats.childop.* arrays.
 *
 * Telemetry-only.  No policy decision reads this record; no field has
 * back-pressure on the picker, canary queue, or promote / demote
 * heuristic.  Fields without a backing per-childop counter today
 * (direct_syscalls, transition_edges, crashes, dstate_wedges,
 * asan_runtime_failure) stay at 0 / false until producers are wired,
 * mirroring the skip-zero convention the existing per-childop dumps
 * use.
 *
 * Counter mapping for the populated fields (see include/stats.h):
 *   clean_edges       shm->stats.childop.edges_clean[op]
 *   noisy_edges       shm->stats.childop.edges_discovered[op] - clean_edges
 *   wall_ns           shm->stats.childop.wall_ns[op]
 *   wedges            shm->stats.childop.wedge_count[op]
 *   timeout_observed  shm->stats.childop.timeout_observed[op]
 *   timeout_missed    shm->stats.childop.timeout_missed[op]
 *   setup_failures    shm->stats.childop.invocations[op]
 *                     - shm->stats.childop.setup_accepted[op]
 *   taint_transition  shm->stats.childop.taint_transitions[op] > 0
 *
 * Subtractions are clamped at zero: the source counters race under
 * RELAXED add-fetch from multiple producers, and a few childops bump
 * setup_accepted more than once per dispatch (the existing setup-yield
 * permille dump in dump_stats clamps for the same reason), so the
 * minuend can momentarily trail the subtrahend across a non-atomic pair
 * of reads. */
struct childop_outcome {
	enum child_op_type op;
	uint64_t wall_ns;
	uint64_t direct_syscalls;
	uint64_t clean_edges;
	uint64_t noisy_edges;
	uint64_t transition_edges;
	uint32_t crashes;
	uint32_t wedges;
	uint32_t dstate_wedges;
	uint32_t setup_failures;
	uint32_t timeout_observed;
	uint32_t timeout_missed;
	bool asan_runtime_failure;
	bool taint_transition;
};

/* Snapshot the aggregated outcome record for one childop.  Reads shm
 * counters under RELAXED loads; the resulting record is a coincident-
 * point-in-time view, not a transactional one (sibling producers can
 * advance any source counter between two field reads).  Safe to call
 * from any context that already has shm mapped; never modifies shm. */
void childop_outcome_snapshot(enum child_op_type op,
			      struct childop_outcome *out);

/* Render a per-childop window summary line via output(1, ...) for every
 * op that has been invoked at least once this run.  Skips
 * CHILD_OP_SYSCALL (the syscall path attributes its work through the
 * per-strategy counters, matching the surrounding per-childop tables)
 * and skips never-invoked ops (skip-zero convention).  No-op until a
 * caller is wired in. */
void childop_outcome_window_dump(void);

/* SHADOW telemetry: derive utility + penalty scores from the outcome
 * record and emit two ranked tables -- top by good-utility (clean and
 * noisy edges per second of wall time, fixed-point integer) and top
 * by bad-utility (sum of wedge / dstate / crash / setup-failure /
 * asan-failure accumulators).  Surfaces the "clean-canary-zero but
 * noisy-wins" shape (clean_edges=0 with noisy_edges large) the per-op
 * window dump leaves at default rank.  No scheduler / canary picker /
 * promotion or demotion path reads these scores -- compute and dump
 * only.
 *
 * Under __SANITIZE_ADDRESS__ a third ranked table is emitted: an
 * ASAN-adjusted bad-utility score that re-weights the failure classes
 * whose runtime cost is several times higher in an ASAN build
 * (poisoning CHECK aborts, allocator / mmap reservation failures
 * against the 32-512 GiB shadow steal, sigaltstack reentry from
 * wedged childops with no canary edges), and a one-third wall-time
 * budget hint.  The failure class is detected from the existing
 * outcome fields, not a hardcoded childop list.  Compile-detected; no
 * CLI knob.  Same shadow contract as the other two tables. */
void childop_score_dump(void);

/* SHADOW per-childop decaying edge+wall recency ring helpers.  The bump
 * helpers add into the active ring slot
 * (childop_edge_history[op][childop_decay_slot & mask] /
 * childop_wall_history[op][...]) and bump the matching cached running
 * sum in lockstep, mirroring the multi-producer frontier_record_new_
 * edge() discipline (RELAXED add-fetch; per-window child-count drift
 * tolerated).  Called from child_process()'s per-dispatch wall and
 * clean-edge accumulation sites in child.c.  No-op for op values
 * outside [0, NR_CHILD_OP_TYPES) and for zero deltas, so the producer
 * sites need no extra guards.
 *
 * childop_window_advance() ages the oldest slot out of the ring and
 * recomputes the cached running sums; runs from the periodic-surface
 * tick that drives the operator-visibility dumps.  Clear-then-publish:
 * the next slot is exchanged to zero under the old cursor, the cached
 * sums are subtracted under a CAS retry (saturating-subtract guard
 * against a racing producer fetch-add), and only then is
 * childop_decay_slot bumped -- a producer racing the rotation keeps
 * bumping the previous slot for a handful of instructions (bounded
 * window-boundary attribution error), never has its addition silently
 * dropped, and never drives the cached sum negative.  Deliberately not
 * borrowing strategy-frontier.c's frontier_window_advance() -- the two
 * ring lifecycles stay disjoint, per the C2 spec. */
void childop_decay_record_edges(enum child_op_type op, unsigned long edges);
void childop_decay_record_wall(enum child_op_type op, unsigned long ns);
void childop_window_advance(void);

/* Per-handler attribution ring for the post_handler_corrupt_ptr counter.
 * Sized to comfortably hold the long tail of distinct handlers without
 * inflating the per-child footprint -- 32 entries cover the unique
 * post-handler count with headroom (the syscall table currently has
 * ~30 .post hooks that call looks_like_corrupted_ptr).  A reserved nr
 * value tags the non-syscall (rec==NULL) pseudo-handler bucket. */
#define CORRUPT_PTR_ATTR_SLOTS		32
#define CORRUPT_PTR_ATTR_NR_NONE	((unsigned int) ~0u)

/* Caller-PC sub-attribution ring keyed by (nr, do32bit, pc).  Sized to
 * comfortably hold ~30 hot post handlers x ~2 distinct caller PCs each
 * plus the deferred-free call sites and headroom. */
#define CORRUPT_PTR_PC_SLOTS		64

struct corrupt_ptr_attr_entry {
	unsigned int nr;
	bool do32bit;
	unsigned long count;
};

struct corrupt_ptr_pc_entry {
	unsigned int nr;
	bool do32bit;
	void *pc;
	/* Optional site tag passed by the caller of
	 * post_handler_corrupt_ptr_bump_site to disambiguate distinct
	 * rejection sites that share a single PC bucket after LTO
	 * inlining (e.g. the four add_object: defence-in-depth walls
	 * that all collapse onto dispatch_step+0x336 under
	 * __builtin_return_address(0) capture).  NULL when the caller
	 * passed no tag; the dump path then renders the bare PC. */
	const char *site;
	unsigned long count;
};

struct deferred_free_reject_pc_entry {
	void *pc;
	unsigned long count;
};

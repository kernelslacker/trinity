#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "spsc-ring.h"
#include "stats.h"	/* NR_SYSCAT */
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Per-child SPSC ring carrying stats deltas from the child (sole producer)
 * to the parent (sole consumer).  Replaces direct child writes to
 * shm->stats for the hot per-syscall counters: those fields move into
 * a parent-private aggregate (struct stats_aggregate) that no kernel-
 * visible shared mapping points at, structurally removing the wild-
 * write attack surface for those fields.
 *
 * Same shape and topology as struct fd_event_ring (fd-event.c) which is
 * already proven in this codebase under hostile fuzzed workload for the
 * write-only-by-child / read-only-by-parent contract.
 *
 * Overflow policy: drop the slot silently, bump a per-ring overflow
 * counter the parent surfaces in the aggregate.  Stats accuracy is
 * best-effort; blocking a child on a stats enqueue is not.
 */

#define STATS_RING_SIZE 1024	/* power of 2; 16 KiB at 16 B/slot */

/*
 * One enum value per stats counter that has moved from shm into the
 * parent aggregate.  The drain switches on field_id; aux carries the
 * sub-index for fields that are arrays (per-syscall reject buckets,
 * the syscall-category histogram), and is unused (0) for plain scalars.
 */
enum stats_field {
	STATS_FIELD_OP_COUNT = 0,	/* alt-op bumps only; dispatched syscalls
					 * fold op_count into CALL_COMPLETE */
	STATS_FIELD_FAULT_INJECTED,
	STATS_FIELD_FAULT_CONSUMED,
	STATS_FIELD_SHARED_BUFFER_REDIRECTED,
	STATS_FIELD_LIBC_HEAP_REDIRECTED,
	STATS_FIELD_LIBC_HEAP_EMBEDDED_REDIRECTED,
	/* asb_relocate() saw an overlapping range whose source was not
	 * fully readable -- redirection still happened, but the memcpy
	 * was skipped to avoid faulting inside the sanitiser. */
	STATS_FIELD_ASB_RELOCATE_READABLE_SKIP,
	/* asb_relocate()'s best-effort memcpy faulted on the source: the
	 * shared-region / heap tracker reported the source as readable
	 * but a sibling tore the underlying mapping down (raw munmap /
	 * mremap that never went through untrack_shared_region()) before
	 * we copied.  The child fault handler longjmp'd back, the
	 * sanitiser fell through to the no-copy redirect path, and this
	 * counter records the recovery. */
	STATS_FIELD_ASB_RELOCATE_COPY_FAULT,
	/* range_overlaps_libc_heap() saw a query that falls inside the
	 * bounding box of captured allocator regions but matched no
	 * specific slot -- the canonical staleness shape of a post-init
	 * secondary mmap landing between captured arenas. */
	STATS_FIELD_HEAP_POINTER_OUTSIDE_CACHE,
	/* range_overlaps_libc_heap() observed an address that fell in the
	 * brk-cache staleness window: addr >= heap_start, addr >= the
	 * last-sampled cached_brk_end, but addr < the live sbrk(0).  The
	 * cached snapshot would judge the address not-heap and let it
	 * through, even though brk has since grown to cover it.  Diagnostic
	 * counter only -- the predicate's return value is unchanged. */
	STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT,
	STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS,
	STATS_FIELD_CHILDREN_RECYCLED_ON_STORM,
	STATS_FIELD_WATCHDOG_FD_EVICT,	/* in-child 1s SIGALRM watchdog evicted
						 * a stuck-on-fd syscall.  Bumped
						 * once per fired-eviction event,
						 * not once per fd. */
	STATS_FIELD_UNSHARE_NEWNET_THROTTLED,
	STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64,	/* aux = syscall nr */
	STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32,	/* aux = syscall nr */
	STATS_FIELD_POST_HANDLER_CORRUPT_PTR,
	/*
	 * Structural pre-dispatch reject from validate_arg_coupling().
	 * Split out of STATS_FIELD_POST_HANDLER_CORRUPT_PTR so the
	 * headline counts only genuine scribble-catches: coupling
	 * rejects fire on perfectly-fine-but-DOA argument shapes the
	 * kernel would EFAULT at its earliest validation step, not on
	 * memory the .post handlers detected as scribbled.
	 */
	STATS_FIELD_VALIDATOR_REJECTED,
	/*
	 * Per-disposition observability for validate_arg_coupling()'s
	 * repair path.  A coupled (buf, len) or iovec (iov_base, iov_len)
	 * pair whose length overshoots the base's writable extent is
	 * probabilistically clamped down to the extent: the repaired
	 * arm bumps _REPAIRED and now walks real kernel code instead of
	 * copy-faulting at import; the skipped arm bumps _KEPT_INCOHERENT
	 * so the kernel's copy_from_user()/import_iovec() rejection paths
	 * still see traffic and stay in coverage.  Rejects (NULL base with
	 * a positive length) continue to route through the existing
	 * STATS_FIELD_VALIDATOR_REJECTED path, so the three dispositions
	 * are visible independently without a per-family fanout here.
	 */
	STATS_FIELD_ARG_CONSTRAINT_REPAIRED,
	STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT,
	STATS_FIELD_DEFERRED_FREE_REJECT,
	STATS_FIELD_DEFERRED_FREE_REJECT_PATHNAME,
	STATS_FIELD_DEFERRED_FREE_REJECT_IOVEC,
	STATS_FIELD_DEFERRED_FREE_REJECT_SOCKADDR,
	STATS_FIELD_DEFERRED_FREE_REJECT_OTHER,
	STATS_FIELD_SNAPSHOT_NON_HEAP_REJECT,
	STATS_FIELD_RING_EVICTION_CORRUPT,
	STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR,
	/*
	 * get_arg_snapshot() observed shadow != live for an opted-in slot
	 * between the snapshot taken at the tail of generate_syscall_args()
	 * and the post handler's read.  The handler still gets the stable
	 * shadow value back; this counter surfaces "how often is a sibling
	 * actually scribbling the slot" so we can tell whether the
	 * arg-shadow pattern is silently saving us or doing nothing useful.
	 * Aggregate-only for now; per-syscall attribution comes via the
	 * existing post_handler_corrupt_ptr_bump rings when an opted-in
	 * handler later still chooses to bump corrupt_ptr.
	 */
	STATS_FIELD_ARG_SHADOW_STOMP,
	/*
	 * Combined "call complete" slot.  A single enqueue carries the
	 * three bumps every completed dispatched syscall used to emit
	 * separately (op_count, success/failure, syscall_category_count):
	 *   - aux        = enum syscall_category
	 *   - delta      = op_count delta (always 1 on the hot path)
	 *   - _reserved  = enum stats_result_class in low byte
	 * Drain expands one slot into three logical bumps, cutting the
	 * SPSC enqueue count per dispatched syscall from three to one.
	 */
	STATS_FIELD_CALL_COMPLETE,
	/* kcov_collect()'s per-call total_calls bump.  Children stage the
	 * count in kcov_child_local_stats and flush in batches (on a
	 * found-new-edge piggyback, or once per N syscalls), which keeps
	 * the kcov_shm->coverage.total_calls shared cacheline off the per-call
	 * atomic-bump path for dump-side accounting; that shm field is
	 * the stamp source for last_edge_at[] / last_efault_at[] and the
	 * cold-skip gap denominator, so it stays. */
	STATS_FIELD_TOTAL_CALLS,
	/* kcov_collect()'s remote_mode call counter.  Same staging /
	 * batched-flush model as STATS_FIELD_TOTAL_CALLS: bumped on the
	 * per-child kcov_child_local_stats slot when kc->remote_mode is
	 * set, drained into parent_stats.remote_calls via the stats_ring
	 * on the found-new-edge piggyback or the syscalls-since-flush
	 * cadence cap.  Dump-only reader, no per-call branch reads it,
	 * so the batched delta is the authoritative dump-path value;
	 * kcov_shm->coverage.remote_calls has no stamp-role consumer, which is
	 * why keeping it in sync with a per-call atomic would buy
	 * nothing and cost a shared-cacheline write per syscall. */
	STATS_FIELD_REMOTE_CALLS,
	/* kcov_collect()'s per-call PC-count bump.  Already a batched
	 * "+count" delta at the bump site (count = PCs returned by the
	 * kernel for this syscall, often dozens-to-hundreds), so the
	 * staging slot folds the per-syscall accumulation into a single
	 * ring enqueue per flush rather than one atomic-add per call.
	 * Drained into parent_stats.total_pcs; same flush cadence as the
	 * other two kcov staging counters. */
	STATS_FIELD_TOTAL_PCS,
	/* kcov_collect()'s warm-known-hit counter (one bump per call that
	 * returned coverage where every PC was already in bucket_seen[]).
	 * Same staging / batched-flush model as STATS_FIELD_REMOTE_CALLS:
	 * +1 onto the per-child kcov_child_local_stats slot, drained into
	 * parent_stats.total_warm_known_hits via the stats_ring on the
	 * found-new-edge piggyback or the syscalls-since-flush cadence
	 * cap.  Dump-only reader, no per-call branch reads it, so the
	 * batched delta is the authoritative dump-path value; the
	 * kcov_shm->total_warm_known_hits slot has no stamp-role
	 * consumer, which is why re-bumping it on every call would
	 * only cost a shared-cacheline write with no reader to serve. */
	STATS_FIELD_WARM_KNOWN_HITS,
	/* cmp_hints_try_get_ex() bumps these on every consumer call that
	 * passed the cmp_hints_shm / nr guard and reached the pool-snapshot
	 * lookup.  Direct +1 enqueue per call -- no local staging like the
	 * kcov counters above, because cmp_hints_try_get fires far less
	 * often than kcov_collect (consumer-side, gated on argument
	 * generation rather than per-syscall dispatch) and the per-call
	 * SPSC slot cost is well within budget.  Stale-by-one-drain
	 * tolerance is identical to the precedent counters: the periodic
	 * dump reader is the only consumer and reports cumulative deltas
	 * across a multi-second window. */
	STATS_FIELD_CMP_HINTS_TRY_GET_ATTEMPTS,
	STATS_FIELD_CMP_HINTS_TRY_GET_RETURNED,
	/* Per-syscall partition of the cmp_hints_try_get() consumer-demand
	 * and pool-hit counters.  Companion to the scalar
	 * CMP_HINTS_TRY_GET_ATTEMPTS / _RETURNED above; aux carries the
	 * calling syscall nr (already gated nr < MAX_NR_SYSCALL at the
	 * cmp_hints_try_get_ex producer).  Both write-only-by-child --
	 * no cross-child reader -- so moving them off kcov_shm purely
	 * shrinks the wild-write attack surface for diagnostic counters
	 * the dump path reads off parent_stats. */
	STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS,	/* aux = syscall nr */
	STATS_FIELD_PER_SYSCALL_CMP_RETURNED,	/* aux = syscall nr */
	/* Per-syscall partition of the typed-inject (LIVE hypothesis-store)
	 * denominator: a strict subset of PER_SYSCALL_CMP_RETURNED that only
	 * counts pulls where the typed derive-and-inject arm replaced the raw
	 * pool value.  cmp_hyp_live_injected is the scalar sibling in
	 * kcov_shm; this partition lets a coverage consumer join
	 * (typed inject count per nr) x local/remote_pc_edge_count[nr] to
	 * see whether typed inject is aimed at the movers or away from them,
	 * a signal PER_SYSCALL_CMP_RETURNED (raw + typed conflated) can't
	 * answer.  Bumped from the same accept-gated commit point the scalar
	 * bumps from, and gated on nr < MAX_NR_SYSCALL at the drain. */
	STATS_FIELD_PER_SYSCALL_CMP_HYP_LIVE_INJECTED,	/* aux = syscall nr */
	/* log_mm_syscall_post_gate_heap_slip() observed an mm-syscall arg
	 * that passed range_overlaps_libc_heap() but a fresh sbrk(0)
	 * proved to lie inside the live brk arena -- the gate's cached
	 * snapshot was stale at the point the arg reached the kernel.
	 * Non-zero rate signals that the brk-overlap widening is still
	 * incomplete or that a sanitise->syscall race window the gate
	 * never sees is the actual slip source. */
	STATS_FIELD_MM_GATE_POST_SLIP,
	STATS_FIELD_NR,
};

/*
 * Result class encoded in stats_ring_slot._reserved low byte for
 * STATS_FIELD_CALL_COMPLETE.  INCOMPLETE covers EXTRA_FORK grandchildren
 * that were SIGKILL'd before reaching __do_syscall's AFTER block: the
 * dispatched call still earned its op_count and category bumps but
 * neither successes nor failures applies.  Any other byte value seen on
 * drain is treated as INCOMPLETE so a scribbled slot can't manufacture
 * a success/failure attribution.
 */
enum stats_result_class {
	STATS_RESULT_INCOMPLETE = 0,
	STATS_RESULT_SUCCESS = 1,
	STATS_RESULT_FAILURE = 2,
};

struct stats_ring_slot {
	uint16_t field_id;	/* enum stats_field */
	uint16_t aux;		/* per-array index, or 0 for scalars */
	uint32_t delta;		/* +1 per syscall on the common paths;
				 * larger values reserved for future batched
				 * paths */
	uint64_t _reserved;	/* pad to 16 B; future use (e.g. caller PC) */
};

struct stats_ring {
	struct spsc_ring base;
	struct stats_ring_slot slots[STATS_RING_SIZE];
};

/*
 * Parent-private aggregate.  Lives in the parent's MAP_PRIVATE heap
 * (post-fork .bss); no kernel-visible shared mapping addresses it, so
 * a wild kernel write through any child syscall arg cannot scribble
 * these fields.  Children inherit a COW copy at fork time and can
 * locally mutate it without affecting the parent's view -- but the
 * convention is that children only ever write to their stats_ring;
 * parent_stats is read-only from child context.
 *
 * Field set is the hot per-syscall counters lifted out of struct
 * stats_s (op_count, successes/failures, fault and redirection
 * tallies, the per-syscall reject arrays and the syscall-category
 * histogram) plus a selection of defense / corruption-attribution
 * counters, all drained here from the stats ring.  The ring drain is
 * the only writer (beyond the parent's own reset/init paths).
 */
struct stats_aggregate {
	unsigned long op_count;
	unsigned long previous_op_count;
	unsigned long successes;
	unsigned long failures;
	unsigned long fault_injected;
	unsigned long fault_consumed;
	unsigned long shared_buffer_redirected;
	unsigned long libc_heap_redirected;
	unsigned long libc_heap_embedded_redirected;
	unsigned long asb_relocate_readable_skip;
	unsigned long asb_relocate_copy_fault;
	unsigned long heap_pointer_outside_cache;
	unsigned long heap_brk_stale_window_hit;
	unsigned long range_overlaps_shared_rejects;
	unsigned long children_recycled_on_storm;
	unsigned long watchdog_fd_evict;
	unsigned long unshare_newnet_throttled;
	unsigned long range_overlaps_shared_rejects_per_syscall_64[MAX_NR_SYSCALL];
	unsigned long range_overlaps_shared_rejects_per_syscall_32[MAX_NR_SYSCALL];
	unsigned long syscall_category_count[NR_SYSCAT];

	/* Group B headline counters lifted out of struct stats_s alongside
	 * the corruption-attribution shards.  Children enqueue +1 deltas via
	 * the stats_ring; the parent drain accumulates here.  The defense-
	 * counter periodic dump reads these via the from_aggregate path. */
	unsigned long post_handler_corrupt_ptr;
	/*
	 * Structural pre-dispatch reject count from validate_arg_coupling().
	 * Formerly folded into post_handler_corrupt_ptr; split so the
	 * spike-detector on the headline reacts only to genuine scribble-
	 * catches.  Drained from STATS_FIELD_VALIDATOR_REJECTED.
	 */
	unsigned long validator_rejected;
	/*
	 * Drained from STATS_FIELD_ARG_CONSTRAINT_REPAIRED /
	 * STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT.  Each over-extent
	 * (buf, len) or iovec entry validate_arg_coupling() detects bumps
	 * exactly one of these: the clamp-applied arm increments
	 * arg_constraint_repaired, the probabilistic skip arm increments
	 * arg_constraint_kept_incoherent.  DOA rejects continue to bump
	 * validator_rejected via the -1 return path, so the ratio of
	 * repaired:kept:rejected across a window shows which arm the
	 * repair policy is driving traffic into.
	 */
	unsigned long arg_constraint_repaired;
	unsigned long arg_constraint_kept_incoherent;
	unsigned long deferred_free_reject;
	unsigned long deferred_free_reject_pathname;
	unsigned long deferred_free_reject_iovec;
	unsigned long deferred_free_reject_sockaddr;
	unsigned long deferred_free_reject_other;
	unsigned long snapshot_non_heap_reject;
	unsigned long ring_eviction_corrupt;
	unsigned long deferred_free_corrupt_ptr;
	unsigned long arg_shadow_stomp;

	/* Drained from STATS_FIELD_TOTAL_CALLS.  Aggregate of every child's
	 * kcov_collect() invocations.  Reported by the dump path (stats.c
	 * JSON + Scuba rows, post-mortem, strategy plateau snapshots) in
	 * place of the kcov_shm->coverage.total_calls atomic; the shm field stays as
	 * the stamp source for last_edge_at[] / last_efault_at[] and the
	 * cold-skip gap denominator only. */
	unsigned long total_calls;

	/* Drained from STATS_FIELD_REMOTE_CALLS.  Subset of total_calls
	 * that took the kc->remote_mode branch (KCOV_REMOTE_ENABLE-backed
	 * collection).  Reported by the same dump readers as total_calls;
	 * staging on childdata->local_stats keeps the hot kcov_shm
	 * cacheline out of the per-call path, and because no stamp-role
	 * consumer references kcov_shm->coverage.remote_calls the staged delta is
	 * the authoritative value for this counter. */
	unsigned long remote_calls;

	/* Drained from STATS_FIELD_TOTAL_PCS.  Sum of PC counts pulled
	 * out of per-call KCOV trace buffers across every child; the
	 * pre-existing kcov_shm->coverage.total_pcs atomic was a relaxed +count
	 * (not +1) batched delta at the same site, so the staging slot
	 * folds the per-syscall accumulation into one ring enqueue per
	 * flush. */
	unsigned long total_pcs;

	/* Drained from STATS_FIELD_WARM_KNOWN_HITS.  Run-wide count of
	 * kcov_collect() calls that returned coverage where every PC was
	 * already in bucket_seen[] (warm-loaded or seen earlier this run).
	 * Reported by the periodic stats dump as a liveness signal;
	 * staging on childdata->local_stats keeps the hot kcov_shm
	 * cacheline out of the per-call path, and because no stamp-role
	 * consumer references kcov_shm->total_warm_known_hits the staged
	 * delta is the authoritative value for this counter.  The
	 * per-syscall split lives in kcov_shm->per_syscall_warm_known_hits[]
	 * and is left untouched here -- only the cross-child run-wide
	 * counter migrates. */
	unsigned long total_warm_known_hits;

	/* Drained from STATS_FIELD_CMP_HINTS_TRY_GET_ATTEMPTS /
	 * STATS_FIELD_CMP_HINTS_TRY_GET_RETURNED.  Consumer-side cmp-hint
	 * pull demand and pool-hit count, lifted out of kcov_shm so a wild
	 * kernel write through a fuzzed syscall arg cannot scribble the
	 * counters that observe whether the cmp-hint pipeline is delivering
	 * to argument generators.  The dump reader (stats.c periodic
	 * window) now sources both from here. */
	unsigned long cmp_hints_try_get_attempts;
	unsigned long cmp_hints_try_get_returned;

	/* Drained from STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS /
	 * STATS_FIELD_PER_SYSCALL_CMP_RETURNED.  Per-syscall partition of
	 * the cmp-hint consumer-demand / pool-hit counters above.  Same
	 * write-only-by-child / no cross-child reader profile as the
	 * scalars, so the move off kcov_shm shrinks the wild-write attack
	 * surface for diagnostic counters without changing any reader. */
	unsigned long per_syscall_cmp_attempts[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_returned[MAX_NR_SYSCALL];

	/* Drained from STATS_FIELD_PER_SYSCALL_CMP_HYP_LIVE_INJECTED.  Per-nr
	 * partition of the scalar kcov_shm->cmp_hyp_live_injected: counts
	 * only typed-inject (hypothesis-store) live injects, so
	 * per_syscall_cmp_returned[nr] - per_syscall_cmp_hyp_live_injected[nr]
	 * isolates the raw-pool arm's per-nr yield.  Same write-only-by-child
	 * discipline as the two per_syscall_cmp_* siblings above. */
	unsigned long per_syscall_cmp_hyp_live_injected[MAX_NR_SYSCALL];

	/* Drained from STATS_FIELD_MM_GATE_POST_SLIP.  Per-run total of
	 * mm-syscall sanitiser slips: addrs that range_overlaps_libc_heap
	 * passed but a fresh sbrk(0) at the tail of the sanitiser proved
	 * to lie inside the live brk arena.  Each slip also emits an
	 * MM-GATE-POST-SLIP outputerr line (rate-limited) carrying the
	 * syscall name, addr, len and per-call detail (advice / prot /
	 * flags) so the upstream gate gap can be pinned without another
	 * speculative widening. */
	unsigned long mm_gate_post_slip;

	/* Visibility / health counters surfaced via dump_stats. */
	unsigned long ring_overflow_total;	/* sum of dropped enqueues across all rings */
	unsigned long shm_published_corrupt;	/* mirror page disagreed with parent_stats */

	/* Ring-drain health, updated once per drained child in
	 * stats_ring_drain_all(). Parent is sole writer; readers use
	 * __ATOMIC_RELAXED. */
	unsigned long ring_slots_processed_total;    /* slots drained across all children */
	unsigned long ring_drain_children_visited;   /* (child x cycle) pairs actually drained */
	unsigned long ring_children_overflow_events; /* (child x cycle) pairs whose drain saw overflow>0 */

	/* check_lock() observed LOCK_RESERVED_DIRTY(state) on the periodic
	 * sanity walk and called force_bust_lock() to recover.  Bumped from
	 * main context only (sole walker), so plain ++ is safe.  Lives in
	 * parent_stats rather than shm->stats so a wild kernel write through
	 * a fuzzed syscall arg -- the very class of event this counter
	 * tracks -- cannot scribble the diagnostic that detects it. */
	unsigned long lock_word_scribbled;
};

extern struct stats_aggregate parent_stats;

/*
 * Mirror page: parent-write / child-read.  Carries the coarse fleet
 * op_count that random-syscall.c's rotation clock and child.c's
 * syscalls_todo termination need to see.  The parent republishes on
 * each drain.
 */
struct stats_published {
	unsigned long fleet_op_count;
};

extern struct stats_published *shm_published;

void stats_ring_init(struct stats_ring *ring);

/*
 * Enqueue a stats delta from child context.  Lock-free, returns false
 * if the ring is full (slot dropped, overflow counter bumped).
 */
bool stats_ring_enqueue(struct stats_ring *ring, enum stats_field field,
			uint16_t aux, uint32_t delta);

/*
 * Enqueue one combined "call complete" slot covering op_count,
 * success/failure, and syscall_category_count[] in a single SPSC
 * operation.  Use from the dispatch path after handle_syscall_ret()
 * has settled rec->retval and rec->state.
 */
bool stats_ring_enqueue_call_complete(struct stats_ring *ring,
				      uint16_t category,
				      enum stats_result_class result);

/*
 * Drain all pending slots from one child's ring, applying deltas to
 * parent_stats.  Single-consumer: only the parent writes tail.
 * Returns the number of slots processed.
 */

/*
 * Drain every child's ring and republish the mirror page.  Called from
 * the parent main loop alongside fd_event_drain_all().
 */
void stats_ring_drain_all(void);

/*
 * Allocate the shm_published mirror page.  Called from init_shm().
 */
void stats_published_init(void);

/*
 * Per-child mprotect freeze of the shm_published mirror page to
 * PROT_READ.  Called from init_child() so children see a read-only
 * view of the parent-write / child-read mirror.
 */
void stats_published_freeze(void);

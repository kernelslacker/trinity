#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "syscall.h"

/*
 * Deferred-free queue for syscall argument allocations.
 *
 * Instead of freeing sanitise-allocated memory immediately in post
 * callbacks, we queue it for delayed release after a random number of
 * additional syscalls (5-50).  This creates temporal overlap between
 * allocations, increasing the chance of finding UAF / stale-reference /
 * double-free bugs in the kernel.
 *
 * The queue is process-local — each forked child has its own copy.
 * No locking required.
 */

void deferred_free_init(void);

/*
 * Record a heap pointer that will later be passed back through
 * deferred_free_enqueue() / deferred_freeptr().  Opt-in: called
 * from zmalloc_tracked() (and any other allocation site that intends
 * deferred-free ownership), NOT unconditionally from __zmalloc().
 * Pointers are kept in a small per-process ring (LRU eviction);
 * deferred_free_enqueue() consumes the matching entry to confirm the
 * pointer is a real malloc result before queuing it for free().
 *
 * Process-local — must be called after fork inherits the COW heap.
 * NULL is silently ignored.  @size is the allocation extent recorded
 * alongside @ptr so consumers that need the real-buffer length
 * (e.g. cmp_hints field-scan bounds) can recover it via
 * alloc_track_lookup_size().  Pass 0 only when the caller genuinely
 * does not know the extent; downstream lookups treat 0 as "unknown"
 * and bail conservatively.
 */
void deferred_alloc_track(void *ptr, size_t size);

/*
 * Non-consuming probe: returns true if @ptr was registered via
 * deferred_alloc_track() (typically via zmalloc_tracked) and still
 * sits in the alloc-track ring.  Lets readers that hold a stored
 * pointer (e.g. an object-pool slot) validate it against the live
 * tracked-allocation set BEFORE the first deref, without perturbing
 * the consume-on-free invariant deferred_free_enqueue relies on.
 * Returns false if the pointer was never tracked, was already
 * consumed, or was evicted by ring rollover.
 */
bool alloc_track_lookup(void *ptr) __must_check;

/*
 * Recover the allocation extent recorded for @ptr at
 * deferred_alloc_track() time.  Returns the byte count on hit, 0 on
 * miss (never tracked / consumed / rotated out / inserted with an
 * unknown size).  Callers that need a hard upper bound on a tracked
 * buffer (e.g. cmp_hints field-scan bounding reads against the real
 * sanitiser allocation rather than a catalog struct_size that can
 * overshoot variable-length / over-large descs) gate on a non-zero
 * return and treat 0 as "cannot prove the extent, skip the read".
 */
size_t alloc_track_lookup_size(void *ptr) __must_check;

/*
 * Refresh an existing tracked allocation's LRU position.  Use this
 * when an already-tracked pointer is re-referenced (mm/maps.c dedup-skip,
 * objects/registry.c add_object OBJ_LOCAL pool touch) and you want it to survive
 * subsequent LRU rotation.  Bumps alloc_track_refresh_consume_miss and
 * leaves the alloc_track state unchanged when @ptr is not currently
 * tracked (rotated out, or never tracked -- the two are indistinguishable
 * from the refresh site, and the latter is a corruption-shaped caller
 * ref the consume gate must reject).  See alloc_track_refresh() in
 * deferred-free.c for the design rationale.
 */
void alloc_track_refresh(void *ptr);

/*
 * tracked_free_now() removes ptr from alloc_track[] LRU and
 * alloc_track_hash[], then calls free().  Use this when a caller
 * wants to synchronously dispose of a zmalloc_tracked() allocation
 * instead of routing it through the deferred ring.  Direct free() on
 * a tracked pointer leaves a stale entry behind that subsequent
 * alloc_track_lookup() callers (OBJ_LOCAL validation, deferred-free
 * gating) will falsely accept; this helper keeps the side-set in
 * lock-step with the heap.
 *
 * Safe to call with NULL.
 */
void tracked_free_now(void *ptr);

/*
 * Generic .cleanup helper: release a zmalloc_tracked() buffer that the
 * matching .sanitise stashed in rec->post_state.  Used by the family of
 * cleanup_<syscall> handlers that all follow the same pattern --
 * sanitise allocates a csfu/snap buffer with zmalloc_tracked() and
 * parks it in post_state; .cleanup must release it unconditionally
 * after dispatch.
 *
 * Steps, in order:
 *   1. Clear rec->post_state up front so any early return below leaves
 *      the record in a known-clean state (matches the pre-helper
 *      handlers and the .post idiom).
 *   2. NULL-bail.
 *   3. Shape guard via looks_like_corrupted_ptr_pc().  Shape-only:
 *      rejects NULL-ish / non-canonical / misaligned addresses.
 *   4. Ownership gate via alloc_track_lookup().  Critical: the shape
 *      guard passes any heap-shaped pointer, including FOREIGN ones
 *      produced by a sibling stomp on the shm-resident syscallrecord.
 *      Without this probe the unconditional free() inside
 *      tracked_free_now() would hand a non-malloc'd address to free(),
 *      a glibc/ASAN abort indistinguishable from a real finding.
 *      A miss leaks the slot -- bounded, child exit reclaims, matches
 *      the old deferred_free_enqueue_or_leak() pressure-path behaviour.
 *   5. tracked_free_now() on a hit (consumes alloc_track + frees).
 *
 * Caller PC is captured via __builtin_return_address(0) and forwarded
 * to looks_like_corrupted_ptr_pc(), so per-handler attribution in the
 * shape-reject sub-ring still resolves to the individual
 * cleanup_<syscall> callsite rather than collapsing onto a single
 * helper PC.
 *
 * Handlers with extra per-syscall release work (e.g. zeroing a specific
 * aN slot) should do that work at the call site, then call this helper.
 */
void cleanup_release_post_state(struct syscallrecord *rec);

/*
 * Per-rec owned-pointer registration.  Append @ptr to rec->owned[],
 * marking the dispatcher's cleanup phase responsible for releasing it
 * via tracked_free_now() after dispatch.  Idempotent on NULL.
 *
 * This is the unified carrier for sanitiser-owned heap allocations
 * (and, in later phases, generator-owned struct fills): registration
 * happens at allocation time, the actual free happens after the
 * kernel has consumed the buffer, and the cleanup phase runs
 * unconditionally -- so the buffer cannot be freed before the kernel
 * has read it (no early-drain UAF) and cannot be leaked when .post
 * is skipped (retfd_rejected / killed EXTRA_FORK grandchild / etc.).
 *
 * Overflow handling: rec->owned[] is bounded at REC_OWNED_MAX.  On
 * saturation we fall back to deferred_free_enqueue(ptr) and bump
 * shm->stats.deferred_free.rec_owned_overflow_to_ring so the rate is observable.
 * This intentionally trades the owned-list's no-UAF guarantee for a
 * (still bounded) leak / sync-free under the ring's pressure rails:
 * REC_OWNED_MAX is sized so the fallback is a safety net, not a
 * steady-state path -- non-zero overflow rate is a bug to surface,
 * not a workload to tolerate.
 */
void rec_own(struct syscallrecord *rec, void *ptr);

/*
 * Drain rec->owned[]: release every registered pointer via
 * tracked_free_now() (which keeps the alloc_track[] side-set in
 * lock-step with the heap), then reset owned_count to zero.
 *
 * Called exactly once per dispatched call from the tail of
 * handle_syscall_ret(), between the per-syscall .cleanup hook and
 * generic_free_arg().  The drain is itself the "default" cleanup
 * hook -- most migrated callsites need only register their pointer
 * via rec_own() at sanitise time; only callers with cleanup logic
 * richer than "free these pointers" (none today) need a per-syscall
 * .cleanup function.
 *
 * Drain discipline: null each owned[i] BEFORE calling
 * tracked_free_now(), and decrement owned_count as we go, so a
 * signal that longjmps mid-drain cannot leave a freed pointer in the
 * carrier for a second pass (or for deferred_free_flush() on child
 * exit) to free again.
 */
void rec_owned_drain(struct syscallrecord *rec);

/*
 * Enqueue a pointer for deferred freeing.  Always released with free()
 * when the entry's TTL expires; the function-pointer parameter was
 * removed to eliminate the ROP/JOP surface a corrupted ring entry's
 * free_func slot would otherwise hand an attacker.
 *
 * Under VMA / ENOMEM / ring-full pressure the queue cannot admit the
 * pointer; this variant falls back to a SYNCHRONOUS free() in that
 * case so the caller's "no longer your problem" contract holds.  Use
 * this from .post handlers and other post-dispatch sites where the
 * kernel has already consumed the buffer — the sync free is safe
 * because nothing is about to read the memory.  For pre-dispatch
 * callers (sanitise sites that enqueue a buffer the kernel/post
 * handler still needs to deref), use deferred_free_enqueue_or_leak
 * instead.
 */
void deferred_free_enqueue(void *ptr);

/*
 * Pre-dispatch variant of deferred_free_enqueue.  Same NULL / shape /
 * heap-bounds / shared-region / alloc-track gates and same ring-admit
 * path on the success case; ONLY the under-pressure fallback paths
 * differ.  Where deferred_free_enqueue() falls back to a synchronous
 * free() under VMA / ENOMEM / ring-full pressure, this variant
 * INTENTIONALLY LEAKS — does nothing, returns — and lets the child's
 * eventual exit reclaim the buffer.
 *
 * Use this when the caller does NOT yet own the buffer's lifecycle:
 *
 *   - sanitise enqueues a buffer that the kernel is about to read or
 *     write during the syscall (io_uring_params, openat2 how,
 *     perf_event_attr, sched_attr, mount_attr, file_attr,
 *     xattr_args, ns_id_req, mnt_id_req, landlock_ruleset_attr, ...);
 *
 *   - sanitise enqueues a post_state snap that the .post handler
 *     still needs to deref after the syscall returns (mq_open snap).
 *
 * The plain deferred_free_enqueue() is correct for post-dispatch
 * sites where the buffer has already been consumed (.post handlers,
 * teardown helpers); the synchronous-free fallback is safe there
 * because no one is about to read the memory.  At a pre-dispatch
 * site, that same sync free becomes a use-after-free: the syscall
 * sanitiser returned "queued for later" but the buffer was actually
 * freed before the kernel got to read it.
 *
 * The leak is bounded by the child's per-process rlimits and
 * max_map_count; trinity child lifetimes are short, so a buffer
 * leaked on the pressure path is reclaimed by the kernel when the
 * child exits.  A bounded leak is a strictly better failure mode
 * than a kernel-side UAF on the input buffer.
 */
void deferred_free_enqueue_or_leak(void *ptr);

/*
 * Save the pointer value, zero the source field, and enqueue the
 * saved value for deferred free().
 */
void deferred_freeptr(unsigned long *p);

/*
 * Tick the queue — called once per syscall iteration.  Decrements TTLs
 * and frees any entries that have expired.
 */
void deferred_free_tick(void);

/*
 * Flush the entire queue — free everything immediately.
 * Called on child exit.
 */
void deferred_free_flush(void);

/*
 * Tag the argtype currently being processed by the generic_free_arg
 * cleanup loop, so deferred_free_reject_bump can attribute rejects to
 * the cleanup hook that drove them.  Set to the argtype just before
 * ops->cleanup() is called and reset to ARG_UNDEFINED immediately
 * after.  Direct (non-cleanup-loop) callers leave the tag at
 * ARG_UNDEFINED so their rejects fall into the OTHER shard.
 */
void deferred_free_set_cleanup_argtype(enum argtype t);
enum argtype deferred_free_get_cleanup_argtype(void);

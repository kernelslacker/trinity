#pragma once

#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compiler.h"
#include "rnd.h"

#define MB(_x) ((_x) * 1024UL * 1024UL)
#define GB(_x) ((_x) * 1024UL * MB(1))

#define MAX_SHARED_ALLOCS 4096

/*
 * Reserve slots in shared_regions[] that are not consumed by per-child
 * growth (struct shm_s, syscalltable copy, kcov rings, image segments,
 * shared obj/str heaps, deferred-free, pids/children index pages, etc.).
 * Anything left after this reserve is the budget for per-child allocs.
 */
#define SHARED_REGIONS_GLOBAL_RESERVE 256

/*
 * Per-child shared allocations tracked in shared_regions[]:
 *   1. childdata                     (alloc_shared in init_shm)
 *   2. fd_event_ring                 (alloc_shared in init_shm)
 *   3. stats_ring                    (alloc_shared in init_shm)
 *   4. KCOV PC trace buffer          (track_shared_region in kcov.c, only
 *                                     on KCOV-capable kernels)
 *   5. KCOV CMP trace buffer         (track_shared_region in kcov.c, only
 *                                     when KCOV_TRACE_CMP is supported)
 *   6. diag_ring                     (alloc_shared in init_shm, lands with
 *                                     the diag-ring series)
 *
 * The cap formula in derive_max_children_cap() divides the remaining
 * shared_regions[] budget by this number.  We size for the worst case (7)
 * so that on KCOV-capable kernels the per-child KCOV buffers plus the
 * diag ring still fit inside shared_regions[] and remain visible to
 * range_overlaps_shared(), which protects them from fuzzed
 * munmap/mremap/madvise/mprotect.
 *
 * Capacity cost: with MAX_SHARED_ALLOCS=4096 and
 * SHARED_REGIONS_GLOBAL_RESERVE=256 the shared_regions[]-bound cap on
 * max_children drops from (3840 / 6)=640 to (3840 / 7)=548.
 */
#define SHARED_REGIONS_PER_CHILD 7

extern unsigned int nr_shared_regions;

#ifdef CONFIG_GUARD_SHARED
/*
 * Runtime scope for the guard-page armour wired into __alloc_shared().
 * See utils.c for the per-value semantics and the gating rationale.
 * Defaults to GUARD_SCOPE_OFF; the only writer is parse_args().
 */
enum guard_scope {
	GUARD_SCOPE_OFF = 0,
	GUARD_SCOPE_POOLS,
	GUARD_SCOPE_ALL,
};
extern enum guard_scope guard_shared_scope;
#endif

void * alloc_shared(size_t size) __must_check;

#ifdef CONFIG_GUARD_SHARED
/*
 * Pool-tagged shared-region allocator.  Names the long-lived regions
 * the corruption-witness clusters keep pointing at (kcov_shm, the
 * shared str/obj heap, per-child childdata) so --guard-shared=pools
 * focuses the guard-page VMA cost on those without dragging every
 * per-child tiny alloc into the budget.  Without CONFIG_GUARD_SHARED
 * the pool tag is meaningless and the macro form collapses to plain
 * alloc_shared() so the legacy single-mmap path stays byte-identical.
 *
 * free_shared() is the inverse: untracks the region and munmaps either
 * the legacy (p, size) range or, when the region was guarded, the full
 * leading-guard + usable-pages + trailing-guard span derived from the
 * stored size.  Free-path symmetry the spec calls out as correctness:
 * future destructors that release a pool region must route through
 * free_shared() so the guard VMAs are not leaked.
 */
void * __alloc_shared(size_t size, bool is_pool) __must_check;
void * alloc_shared_pool(size_t size) __must_check;
void free_shared(void *p, size_t size);

/*
 * Classify a fault address against the guarded regions.  Returns true
 * iff @fault_addr lands in either the leading or trailing PROT_NONE
 * page abutting a guarded region; fills the outs in that case.
 * Async-signal-safe -- the only consumer is child_fault_handler.
 *
 * region_addr_out/region_size_out: the INNER buffer (addr, size) the
 * scribble was aimed past.
 * trailing_out: true iff the trailing guard was struck (forward
 * overflow), false for a leading-guard hit (gross underflow).
 * delta_out: bytes past the region end (trailing) or before the
 * region start (leading).  Bounded by page_size by construction.
 */
bool guard_pages_classify(uintptr_t fault_addr,
			  uintptr_t *region_addr_out,
			  size_t *region_size_out,
			  bool *trailing_out,
			  unsigned long *delta_out);

/*
 * Diagnostic accessors for the startup banner emitted from main() once
 * pre-fork init has finished populating shared_regions[].  The banner
 * makes guard-shared activation a positive signal in the run log -- the
 * recurring corruption-hunt failure mode is mis-attributing a clean-OFF
 * run to "armour was on and the witness still landed" because nothing in
 * the log distinguished the two.
 *
 *   guard_shared_scope_name()    : "off" | "pools" | "all", stable
 *                                  string that mirrors the operator
 *                                  spelling.  Safe to call before
 *                                  parse_args (returns "off").
 *   guard_shared_count_guarded() : number of entries in
 *                                  shared_regions[] + overflow tail
 *                                  whose .guarded bit is set.  Reflects
 *                                  exactly what guard_pages_classify
 *                                  iterates, so a 0 here means no
 *                                  guard-page VMA exists regardless of
 *                                  scope.
 */
const char *guard_shared_scope_name(void);
unsigned int guard_shared_count_guarded(void);
#else
#define alloc_shared_pool(size)	alloc_shared(size)
#endif

/*
 * Checked size = a * b for shared-allocation call sites with a variable
 * count multiplier (max_children, files_in_index, syscall table size).
 * Returns true and writes the product when it fits in size_t; returns
 * false on overflow without touching *out.  Callers are expected to
 * outputerr() and bail on a false return -- truncated size would let
 * a downstream alloc succeed with a buffer too small for the indexing
 * the caller is about to do.
 */
bool shared_size_mul(size_t a, size_t b, size_t *out);
void * alloc_shared_str(size_t size) __must_check;
char * alloc_shared_strdup(const char *src) __must_check;
void free_shared_str(void *p, size_t size);
/*
 * Self-check the address-keyed shared_region_bitmap AND the size-keyed
 * tracked_size_bm: a refactor that wires alloc_shared() / track_shared_
 * region() to update one bitmap but forgets the parallel call to the
 * other would silently flip the affected accelerator's safety
 * invariant.  Single positive assert per process: both bitmaps only
 * grow with new registrations until an untrack drops a slot, so a
 * positive at init proves the wiring is in place.
 */
void shared_bitmap_self_check(void);
bool range_overlaps_shared(unsigned long addr, unsigned long len);
/*
 * Inverse-polarity check: returns true iff [addr, addr+len) is fully
 * contained within at least one registered shared region.  Walks
 * shared_regions[] precisely (no bitmap rounding) and does not bump
 * the range_overlaps_shared_rejects stat -- callers use this to
 * validate that a freshly-picked writable-pool address still belongs
 * to a tracked mapping, not to score a sanitiser rejection.
 */
bool range_in_tracked_shared(unsigned long addr, unsigned long len);
void track_shared_region(unsigned long addr, unsigned long size);
/*
 * Inverse of track_shared_region() / alloc_shared().  Removes the
 * matching shared_regions[] entry (exact addr+size) and undoes the
 * bitmap refcount/bit it contributed.  Call from destructors that
 * munmap a previously-tracked region BEFORE the munmap, so a
 * concurrent range_overlaps_shared() check that fires between untrack
 * and munmap sees the now-permissive gate against a still-valid
 * mapping rather than the still-rejecting gate against a freed one
 * (the unsafe direction).  A miss returns silently -- intentional, see
 * the rationale in utils.c.
 */
void untrack_shared_region(unsigned long addr, unsigned long size);
void register_loaded_image_segments(void);
void log_load_bases(void);

/*
 * Log an mprotect() failure as:
 *   mprotect(addr=%p, len=%zu, prot=0x%x [READ|WRITE|EXEC]) failed at
 *   <binary>+0xOFFSET: <strerror>
 *
 * `caller` should be __builtin_return_address(0) from the call site so
 * the resolved PC points back through the wrapper to the strategy that
 * triggered the mprotect.  `err` is the captured errno value.
 */
void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err);

void * __zmalloc(size_t size, const char *func);
#define zmalloc(size)	__zmalloc(size, __func__)

/*
 * Opt-in tracking variant.  Identical to zmalloc() but additionally
 * registers the returned pointer with the deferred-free alloc-track
 * ring.  Use at allocation sites whose pointer is bound to flow
 * through deferred_free_enqueue() / deferred_freeptr(); plain
 * zmalloc() stays at sites freed directly (process-lifetime tables,
 * direct-free error fallbacks).  See utils.c __zmalloc_tracked() and
 * the alloc-tracking audit for the opt-in-vs-default rationale.
 */
void * __zmalloc_tracked(size_t size, const char *func);
#define zmalloc_tracked(size)	__zmalloc_tracked(size, __func__)

/*
 * Ownership table for syscall handlers that snapshot state into a
 * zmalloc'd struct hung off rec->post_state.  Register at allocation
 * time, unregister immediately before the deferred_freeptr() that
 * releases the chunk, and lookup in the post handler to verify the
 * snap pointer wasn't redirected to a foreign chunk by a sibling-stomp
 * write.  See utils.c for the full rationale and the libsanitizer-UB
 * regression in the prior malloc_usable_size-based guard this replaces.
 */
void post_state_register(void *p);
void post_state_unregister(void *p);
bool post_state_is_owned(const void *p);

/*
 * Correct-by-construction helpers for the post_state ownership bracket.
 *
 * Every .post handler that hangs a snapshot off rec->post_state must
 * perform the same three-step dance, in this exact order:
 *
 *   1. sanitise: assign rec->post_state, then register the pointer in
 *      the ownership table.  Doing them in one operation closes the
 *      sibling-scribble window that opens the instant rec->post_state
 *      is observable but the table entry is not yet present.
 *
 *   2. .post entry: shape-check snap, then post_state_is_owned(snap),
 *      then compare snap->magic against the expected cookie.  Ordering
 *      is load-bearing -- the ownership gate MUST precede the magic
 *      read, because a foreign chunk that survived the shape gate may
 *      not even be sizeof(unsigned long) bytes in size and reading
 *      snap->magic on a non-snap allocation is a wild read.
 *      post-state-deref.sh enforces this ordering at build time;
 *      prctl.c / pipe.c are the reference shape.
 *
 *   3. .post exit: post_state_unregister(snap) BEFORE
 *      deferred_freeptr(&rec->post_state), on every exit path.  A
 *      registered-but-freed slot poisons the next allocation that
 *      hashes to the same bucket -- post_state_is_owned() would then
 *      return true for memory that is no longer ours.
 *
 * Hand-rolling the dance at every call site is one chance per file to
 * fumble the ordering.  The three helpers below collapse it into three
 * named operations so the bracket is correct-by-construction:
 *
 *   post_state_install(rec, snap)                          step 1
 *   snap = post_state_claim_owned(rec, MAGIC, __func__)    step 2
 *   post_state_release(rec, snap)                          step 3
 *
 * Convention: every post_state snapshot struct MUST begin with
 * `unsigned long magic` as its first field (already enforced by
 * scripts/check-static/post-state-magic.sh).  The claim helper reads
 * the magic word via *(const unsigned long *)snap rather than
 * snap->magic so it has no compile-time dependency on the caller's
 * struct type.
 */
struct syscallrecord;

/*
 * Step 1.  Assign rec->post_state and register in the ownership table,
 * in that order, with no statements between -- closes the observable
 * window where snap is reachable but unregistered.
 *
 * Captures the install-time owner (rec->nr / rec->do32bit), the
 * snap's leading-word magic, and the allocation size into the
 * ownership table so post_state_release() can reject double frees,
 * wrong-owner frees, and stomped magic before letting the chunk reach
 * libc free().  See utils.c struct post_state_entry for the tag
 * field semantics and the four-gate reject contract.
 *
 * Implemented as a macro that forwards sizeof(*snap) to
 * post_state_install_sized() at the call site -- every existing
 * caller already holds @snap as a typed pointer, so the size
 * capture is automatic.  Out-of-line for the same reason as the
 * underlying helper: struct syscallrecord is not visible here and
 * pulling its definition in would create a circular include.
 */
void post_state_install_sized(struct syscallrecord *rec, void *snap,
			      size_t size);
#define post_state_install(rec, snap) \
	post_state_install_sized((rec), (snap), sizeof(*(snap)))

/*
 * Step 2.  Read rec->post_state, run it through the canonical
 * shape -> ownership -> magic gate, and return the validated snap
 * pointer.  Returns NULL on any gate failure; the helper has already
 * cleared rec->post_state, emitted the appropriate outputerr() line,
 * and (on ownership / magic failure) bumped the
 * post_handler_corrupt_ptr counter via post_handler_corrupt_ptr_bump.
 *
 * Callers MUST early-return on NULL -- snap is unsafe to touch and
 * the helper has already done all the bookkeeping.
 *
 * The shape gate uses looks_like_corrupted_ptr_pc() with the caller
 * PC (__builtin_return_address(0) inside the helper), so per-handler
 * attribution lands on the .post handler that called us, not on this
 * wrapper.
 *
 * @magic_expected is the *_POST_STATE_MAGIC value the caller's struct
 * carries in its leading `unsigned long magic` field.
 * @handler_name is the human-readable tag used in outputerr() lines;
 * pass __func__ from the .post handler so log readers see the
 * caller's name.
 */
__must_check
void *post_state_claim_owned(struct syscallrecord *rec,
			     unsigned long magic_expected,
			     const char *handler_name);

/*
 * Step 3.  Unregister the ownership-table slot, then route the chunk
 * through deferred_freeptr().  Always paired 1:1 with a prior
 * post_state_install() on the success path.  Safe on NULL snap (the
 * .post handler short-circuited before claim and there is nothing
 * registered to remove).
 *
 * The unregister-before-free ordering is what keeps the ownership
 * table consistent: the slot must not describe an allocation that has
 * already been queued for release.
 */
void post_state_release(struct syscallrecord *rec, void *snap);

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * swap - swap value of @a and @b
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline long IS_ERR(unsigned long x)
{
	return IS_ERR_VALUE(x);
}

void sizeunit(unsigned long size, char *buf, size_t buflen);

void kill_pid(pid_t pid);

/*
 * Heuristic: does `p` look like a fuzzed value-result syscall scribbled
 * a non-pointer (typically a pid/tid or a small int) into a slot trinity
 * was about to deref or free?  Returns true if the value cannot plausibly
 * be a heap pointer we handed out.  See utils.c for the rationale and
 * the cluster-1/2/3 crash signature this guards against.
 *
 * @rec is the syscallrecord context the call originates from, used for
 * per-handler attribution of the global post_handler_corrupt_ptr counter.
 * Pass NULL when called outside a syscall post-handler (e.g. from inside
 * deferred_free_enqueue) -- those rejections fold into a single
 * pseudo-handler bucket in the attribution ring.  The caller is expected
 * to log its own descriptive outputerr() line; this function only handles
 * the heuristic decision and the bookkeeping that follows it.
 */
struct syscallrecord;

/*
 * Shape-only predicate split out of looks_like_corrupted_ptr_pc so
 * callers that want the same heuristic but want to bump a different
 * counter (deferred_free_enqueue, into deferred_free_reject) can share
 * the band definition without going through the post_handler bumper.
 * Returns true when @p does NOT look like a heap pointer we could have
 * handed out -- i.e. NULL-ish, non-canonical, or misaligned.
 */
__must_check
static inline bool is_corrupt_ptr_shape(const void *p)
{
	unsigned long v = (unsigned long) p;

	return !(v >= 0x10000 && v < (1UL << 47) && (v & 0x7) == 0);
}

/*
 * Variant that additionally records @caller_pc into the per-callsite
 * sub-attribution ring on a positive result.  Used directly from
 * deferred_free_enqueue (rec==NULL) so the recorded PC identifies the
 * deferred_free_enqueue caller; the looks_like_corrupted_ptr() inline
 * wrapper below routes every other call site through here with
 * __builtin_return_address(0) so per-handler rows in the dump can be
 * broken down by the specific looks_like_corrupted_ptr() callsite.
 */
bool looks_like_corrupted_ptr_pc(struct syscallrecord *rec, const void *p,
				 void *caller_pc) __must_check;

/*
 * Inline wrapper so each call site automatically supplies its own
 * caller PC without source change.  Kept as static inline in the header
 * (rather than a regular function in utils.c that captures
 * __builtin_return_address(0)) so the recorded PC is the syscall
 * handler's own callsite rather than this wrapper's.
 */
__must_check
static inline bool looks_like_corrupted_ptr(struct syscallrecord *rec,
					    const void *p)
{
	return looks_like_corrupted_ptr_pc(rec, p, __builtin_return_address(0));
}

/*
 * Bump the post_handler_corrupt_ptr counter and record per-handler
 * attribution.  Use directly only at sites that detect corruption via a
 * mechanism other than looks_like_corrupted_ptr (e.g. the alloc-track
 * ring miss inside deferred_free_enqueue) -- shape-heuristic callers
 * should go through looks_like_corrupted_ptr() above, which calls this
 * internally on a positive result.  rec==NULL for non-syscall callers.
 *
 * @caller_pc, when non-NULL, additionally feeds the (nr, do32bit, pc)
 * sub-attribution ring so each per-handler row of the dump can be
 * broken down by the specific call site that fired -- distinguishing
 * the per-syscall .post bumps (via looks_like_corrupted_ptr) from the
 * dispatcher-level RZS / RET_FD blanket validators that also bump for
 * the same (nr, do32bit) row.  Pass NULL only when caller-PC attribution
 * is unavailable; a NULL skips the PC ring but still records the
 * (nr, do32bit) attribution.
 */
/*
 * @site is an optional human-readable tag identifying the specific
 * rejection site, used to disambiguate distinct call sites that share
 * one __builtin_return_address(0) PC bucket after LTO inlining (e.g.
 * the four add_object: defence-in-depth walls that all symbolise as
 * dispatch_step+0x336).  Pass NULL when the caller PC alone is
 * unambiguous; the dump path then renders the bare PC.  Most callers
 * use the post_handler_corrupt_ptr_bump() compatibility macro below
 * which forwards site=NULL.
 */
void post_handler_corrupt_ptr_bump_site(struct syscallrecord *rec,
					void *caller_pc, const char *site);
/*
 * Richer entry point that additionally feeds the per-fire breadcrumb
 * ring with the scribbled pointer value and the arg slot it was caught
 * on.  Callers that know the bad pointer (the shape-heuristic helpers,
 * the snapshot-shadow tripwire) should prefer this over the legacy
 * _bump_site entry; tagless callers stay on _bump_site, which forwards
 * with arg_idx=CORRUPT_PTR_BREADCRUMB_NO_ARG and bad_ptr=0 so the
 * breadcrumb still names the syscall even when the value is unknown.
 */
void post_handler_corrupt_ptr_bump_full(struct syscallrecord *rec,
					void *caller_pc, const char *site,
					unsigned int arg_idx,
					unsigned long bad_ptr);
#define post_handler_corrupt_ptr_bump(rec, caller_pc) \
	post_handler_corrupt_ptr_bump_site((rec), (caller_pc), NULL)

/*
 * Per-callsite attribution buckets for post_handler_corrupt_ptr.  The
 * headline counter is the sum of every bump from every site; the
 * spike-detector reacts to that sum but cannot tell whether a spike is
 * dominated by structural-validator noise (every validate_arg_coupling
 * reject from __do_syscall folds into this) or by a genuinely-detected
 * scribble.  Off by default; enabled at runtime by setting the
 * TRINITY_CORRUPT_ATTRIB=1 environment variable, in which case each
 * named site additionally bumps an SHM-resident slot counted in this
 * enum and the periodic dump renders the per-site breakdown.
 *
 * Anything bumped through the legacy macro at a site without an enum
 * tag stays anonymous: at dump time, the implicit "post_generic" bucket
 * = headline - sum(named slots).  A non-trivial residual is the lead
 * for hunting the next call site to instrument.
 */
enum corrupt_ptr_site {
	CORRUPT_PTR_SITE_VALIDATOR_REJECTED = 0,
	CORRUPT_PTR_SITE_ENFORCE_COUNT_BOUND,
	CORRUPT_PTR_SITE_RETFD_INVALID,
	CORRUPT_PTR_SITE_CLAIM_OWNED_NOT_OWNED,
	CORRUPT_PTR_SITE_CLAIM_OWNED_BAD_MAGIC,
	CORRUPT_PTR_SITE_SHAPE_HEURISTIC,
	CORRUPT_PTR_SITE_MQ_NOTIFY,
	CORRUPT_PTR_SITE_GETITIMER,
	CORRUPT_PTR_SITE_TIMER_GETTIME,
	CORRUPT_PTR_SITE_TIMERFD_GETTIME,
	CORRUPT_PTR_SITE__COUNT,
};

extern const char *const corrupt_ptr_site_names[CORRUPT_PTR_SITE__COUNT];

/*
 * Combined "bump the headline + record site enum" entrypoint.  Use at
 * any named site so the dump can break out which categories dominate
 * the headline counter.  The per-site slot bump is gated on the
 * TRINITY_CORRUPT_ATTRIB env var so production callers pay only one
 * branch on a cached bool when the gate is off.
 */
void post_handler_corrupt_ptr_bump_at(struct syscallrecord *rec,
				      void *caller_pc,
				      enum corrupt_ptr_site site);

/*
 * Cheap per-site bump used by callers that need to keep the existing
 * bump_full() invocation (because they pass a known bad_ptr to the
 * breadcrumb ring -- looks_like_corrupted_ptr_pc, the retfd wrapper)
 * but still want a per-site slot bump.  Same env-gate as
 * post_handler_corrupt_ptr_bump_at; no-op when the gate is off.
 */
void corrupt_ptr_site_record(enum corrupt_ptr_site site);

/*
 * True when TRINITY_CORRUPT_ATTRIB=1 is in the environment.  Latched on
 * first call so a getenv() doesn't fire on the hot path; subsequent
 * calls return the cached bool.  Exposed for the dump path which gates
 * its rendering on the same flag.
 */
bool corrupt_ptr_attrib_active(void);

/*
 * Bump the deferred_free_reject counter and record per-callsite
 * attribution into deferred_free_reject_pc.  Use from the two reject
 * sites inside deferred_free_enqueue (shape heuristic + alloc-track
 * miss) so obj-pool-release-time corruption gets a dedicated channel
 * instead of conflating with syscall .post handler corruption on
 * post_handler_corrupt_ptr.  @caller_pc identifies the
 * deferred_free_enqueue caller (release_obj, generic_free_arg, etc.);
 * a NULL skips the PC ring but still bumps the headline counter.
 */
void deferred_free_reject_bump(void *caller_pc);

/*
 * Per-validator wrapper for the RET_FD blanket validator in
 * reject_corrupt_retfd().  Kept as a separate non-inline function so
 * __builtin_return_address(0) resolves to a distinct PC in the caller
 * -- without that, every dispatcher-level RET_FD rejection of
 * (nr, do32bit) collapses onto the same row as that syscall's own
 * .post handler rejections and the dump can no longer tell whether a
 * hot row is the .post handler or the blanket validator firing.
 */
void post_handler_corrupt_ptr_bump_retfd(struct syscallrecord *rec);

/*
 * Inner-pointer-field free guard for post handlers that walk a
 * snapshotted struct (msghdr / mmsghdr / etc.) and free its inner
 * pointer fields.  The OUTER snapshot pointer is alignment-checked at
 * handler entry, but the inner pointer fields live in the snapshotted
 * struct's heap bytes and can be partially overwritten by a sibling
 * syscall that scribbles bytes into that allocation.  A scribble that
 * preserves the high bits (still heap-shaped) but clobbers the low byte
 * leaves a misaligned heap-shaped value, which then trips libasan's
 * PoisonShadow alignment CHECK at asan_poisoning.cpp:37 once it reaches
 * free().
 *
 * Returns true if @p is safe to hand to free().  NULL is treated as a
 * legitimate "field not populated" value (e.g. msg_name when no
 * sockaddr was generated, msg_control when sanitise_*msg chose not to
 * populate it) and does not count as a rejection.  When the rejected
 * value matches the libasan-CHECK trigger band -- heap-shaped
 * (>= 0x10000) but misaligned ((v & 0x7) != 0) -- emit an outputerr()
 * line tagged with @site so the interception is visible in logs and
 * the per-PC attribution ring (post_handler_corrupt_ptr) names the
 * offending field.
 */
bool inner_ptr_ok_to_free(struct syscallrecord *rec, const void *p,
			  const char *site) __must_check;

/*
 * Cache the [heap] extent plus every non-brk allocator region tagged
 * via prctl(PR_SET_VMA_ANON_NAME) ("[anon:NAME]" lines in
 * /proc/self/maps -- glibc mmap arenas, libasan primary / secondary /
 * shadow, etc.).  Called once before fork by the parent and once per
 * child from init_child(); the per-child refresh atomically rewrites
 * the COW-inherited snapshot in the child's now-private pages so
 * glibc arenas spawned post-fork are captured before the syscall
 * fuzz loop starts.
 */
void heap_bounds_init(void);

/*
 * Bounds check: is @p inside the cached glibc brk arena?  Returns
 * true if the heap extent is unknown (validator is permissive in
 * that case so a misconfigured init can't reject every legitimate
 * free).  Cheap: two compares, no syscalls.
 */
bool is_in_glibc_heap(const void *p);

/*
 * Range-overlap variant for the avoid_shared_buffer() redirect path.
 * Returns true when [addr, addr+len) intersects the cached brk arena
 * or any captured non-brk allocator region (glibc mmap arenas, libasan
 * primary / secondary / shadow, scudo / jemalloc / tcmalloc tagged
 * regions).  A fully unknown layout (no [heap] line and no captured
 * allocator regions) returns false so we never redirect every write
 * on a misconfigured init.
 */
bool range_overlaps_libc_heap(unsigned long addr, unsigned long len);

/*
 * Conservative source-readability check for the asb_relocate() memcpy
 * path.  Cached-state only -- returns true iff [addr, addr+len) is
 * fully covered by a mapping trinity itself already tracks.
 *
 *   - len == 0, addr == NULL and ranges that wrap user VA return
 *     false.  The caller treats false as "skip the copy", and a
 *     zero-byte memcpy is uninteresting anyway.
 *   - Returns true when the range is fully inside a tracked shared
 *     region (range_in_tracked_shared) or fully inside the cached
 *     libc brk arena / any captured non-brk allocator region.  Those
 *     are mappings trinity or libc itself manage, so VMA presence
 *     implies user-readable pages.
 *   - Returns false for any other layout (a fuzz-introduced VMA
 *     outside every cached snapshot).  False means "unproven", not
 *     "known unreadable"; the caller treats either as skip-copy and
 *     falls through to asb_relocate()'s no-copy fallback, which is
 *     strictly safer than chasing an unproven source.
 *
 * The intent is to gate the source-side read in avoid_shared_buffer_
 * inout(): the range_overlaps_* predicates only prove intersection
 * with a protected region, not that the source is fully mapped.  A
 * wrapped pointer or a range that walks off the end of a VMA (ASAN
 * redzone, allocator-guard page) can pass the overlap gate and then
 * fault inside the memcpy, masking the kernel behaviour we are
 * trying to fuzz with a userspace SIGSEGV.
 */
bool range_readable_user(const void *addr, size_t len);

/*
 * Copy a NUL-terminated user string into a fixed sanitise-time buffer
 * so the post oracle reads the bytes from its own snapshot and never
 * re-derefs the user pointer after the syscall returned.
 *
 * Without this helper, the snapshot-by-pointer pattern in the path /
 * xattr-name oracles strncpy(dst, snap->ptr, ...) at .post time -- the
 * pointed-to bytes may have been changed by a sibling between sanitise
 * and post (TOCTOU between the two reads creates false oracle
 * anomalies), or a wholesale stomp may have left snap->ptr heap-shaped
 * but pointing at a foreign, smaller allocation that
 * looks_like_corrupted_ptr (shape-only) waved through.  Snapshotting
 * the bytes at sanitise time, when the pointer is still the one the
 * kernel is about to deref, removes both failure modes.
 *
 * @dst   : destination buffer (must be non-NULL, dstsz > 0).
 * @dstsz : destination size in bytes.  The output is always NUL-
 *          terminated on success; bytes are copied up to dstsz - 1.
 * @src   : user-space source pointer.
 *
 * Returns true and populates @dst on success.  Returns false when @src
 * is NULL or not provably readable for the full dstsz window via
 * range_readable_user(); callers MUST treat false as "skip the .post
 * sample" rather than dereferencing @src later.
 */
__must_check
bool post_snapshot_str(char *dst, size_t dstsz, const char *src);

/*
 * Snapshot @len bytes of a user-space source into @dst, or tell the
 * caller to skip the .post sample.  The bytes-shaped sibling of
 * post_snapshot_str(): same NULL + range_readable_user gate, plain
 * memcpy underneath.  Use at every .post oracle site that currently
 * pairs a NULL/shape check with memcpy(local, snap->field, len) -- the
 * single guarded call retires the shape-only looks_like_corrupted_ptr
 * reliance for the source-read path so a non-NULL but stale/unmapped
 * snap->field can no longer fault inside trinity between the syscall
 * return and the post sample.
 *
 * @dst : destination buffer (must be non-NULL).
 * @src : user-space source pointer.
 * @len : copy length in bytes (already clamped by the caller to the
 *        destination size and any snapshotted allocation bound).
 *
 * Returns true after copying @len bytes from @src to @dst.  Returns
 * false when @src is NULL or not provably readable for the full @len
 * window via range_readable_user(); callers MUST treat false as "skip
 * the .post sample" rather than dereferencing @src later.
 */
__must_check
bool post_snapshot_or_skip(void *dst, const void *src, size_t len);

/*
 * Coarse-grained refresh hook for the cached sbrk(0) snapshot consumed
 * by is_in_glibc_heap() / range_overlaps_libc_heap().  Called from
 * alloc_object() so the cache moves forward roughly in step with the
 * allocations that could grow brk, without paying a syscall on every
 * heap-overlap check.  Only one sbrk(0) every BRK_REFRESH_INTERVAL
 * calls; cheap enough to drop in on the alloc path unconditionally.
 */
void heap_brk_maybe_refresh(void);

int get_num_fds(void);

/*
 * Online-CPU count snapshotted on first use, clamped to CPU_SETSIZE so
 * cpumask consumers (sched_setaffinity len picker, ARG_CPUMASK fill)
 * stay within the legality window the kernel enforces on user masks.
 */
unsigned int cached_online_cpus(void);

/*
 * Walk /proc/self/fd at parent startup and close any fd that wasn't
 * deliberately opened by trinity.  Run once, before trinity opens any
 * of its own fds — at that point the keep set is exactly {0, 1, 2}
 * and everything else came in from the launcher (or its parent).
 *
 * Defense in depth against the wedge class where an inherited fd for
 * a stuck filesystem (FUSE, NFS, etc.) ends up adopted into one of
 * trinity's per-child watch sets and a routine syscall on it blocks
 * for the lifetime of the run — stalling the parent's reap path and
 * letting zombie children pile up indefinitely.
 *
 * Bumps shm->stats.parent_inherited_fds_closed for each fd closed,
 * and logs the fd number plus its readlink target so the operator
 * can see what the launcher left behind.
 */
void sanitize_inherited_fds(void);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define unreachable() __builtin_unreachable()

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define RAND_ELEMENT(_array, _element) \
	_array[rnd_modulo_u32(ARRAY_SIZE(_array))]._element

#define RAND_ARRAY(_array) _array[rnd_modulo_u32(ARRAY_SIZE(_array))]

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)

/*
 * Initial-mappings arena band.  setup_initial_mappings() in mm/maps-
 * initial.c lays the per-page-protection initial pool entries between
 * 0x40000000 and 0x44000000; the literal here matches that span and is
 * stable across kernels (the band is fixed by the trinity-side mmap
 * hints, not by the kernel's ASLR layout).  Used by is_in_arena_band()
 * below as the heuristic STALE classifier for the handle_syscall_ret()
 * liveness probe: a page-aligned pointer landing inside this range that
 * neither range_in_tracked_shared() nor addr_in_local_runtime_map()
 * accepts is structurally an arena slot whose mapping is gone.
 *
 * A runtime CHILD_ANON mmap above ARENA_BAND_HI falls through to the
 * probe's UNKNOWN bucket -- a false negative, not a false positive,
 * acceptable for the telemetry-only first landing.  A stamped-from-init
 * variant is a follow-up worth doing before any rejection policy lands
 * on top of this counter.
 */
#define ARENA_BAND_LO	0x40000000UL
#define ARENA_BAND_HI	0x44000000UL

static inline bool is_in_arena_band(unsigned long p)
{
	return p >= ARENA_BAND_LO && p < ARENA_BAND_HI;
}

/*
 * Plain CRC32 (IEEE 802.3 polynomial 0xedb88320, reflected, init/final
 * 0xffffffff).  Lazy 256-entry table built on first call.  Used by the
 * minicorpus, cmp_hints, and kcov-bitmap persistence formats for
 * header/payload checksums.
 */
uint32_t crc32(const void *buf, size_t len);

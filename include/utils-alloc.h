#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

struct syscallrecord;
struct childdata;

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
 * Attribution overlay for the SELF-corruption cluster.  The
 * kcov_local_stats_plausible() gates in kcov/collect.c, the
 * objpool_check() sites in mm/maps.c, and the dispatch-boundary
 * check in random_syscall/dispatch.c all short-circuit the bad
 * deref when they fire, but the stats-counter bump on its own
 * records nothing about which syscall ran immediately before
 * the wild write.  This helper emits that attribution record to
 * stderr (child-side: memfd → bug-log on the SIGSEGV
 * that a scribbled pointer typically produces a few calls later)
 * so triage can attribute the scribble to the culprit syscall
 * arg-gen instead of the innocent kcov reader that trips.
 *
 * @site is a short kebab-case tag naming the specific gate that
 * fired (e.g. "kcov:local_stats:calls", "mm:mmap-pool:objpool",
 * "dispatch:objects").  @wild is the scribbled pointer/value the
 * gate rejected.  @rec is the just-dispatched syscallrecord (pass
 * &this_child()->syscall from a child-context gate); NULL is
 * handled and renders "nr=0 name=?" for parent-context callers
 * that reach a shared gate.
 *
 * Log-only.  Consumes no RNG, does not change control flow, and
 * runs off the reject path -- when the gate does not fire (the
 * overwhelming steady state) this function is not called at all.
 * Callers that already resolve struct childdata for their own use
 * pass &cc->syscall directly; the name is resolved fresh via
 * get_syscall_entry(nr, do32bit) rather than off rec->entry so a
 * scribbled entry pointer in the just-corrupted rec cannot itself
 * be followed.
 */
void log_self_corrupt_culprit(const char *site, unsigned long wild,
			      const struct syscallrecord *rec);

/*
 * --self-corrupt-canary companion helpers.  OFF by default (see
 * self_corrupt_canary in include/params.h): every call short-circuits
 * on the flag before any allocation, checksum computation, or memcmp.
 * When ON, catches mid-struct scribbles the always-on gate loggers
 * cannot see -- a wild write that leaves child->local_stats /
 * ->objects inside the userspace-VA bracket but rewrites, say,
 * child->kcov.trace_buf or a byte in the middle of an OBJ_LOCAL slot
 * would pass every VA-bracket check silently.  The signature is a
 * bounded XOR over a small set of pointers plus an 8-word trinity-
 * heap sentinel (init'd to SELF_CORRUPT_CANARY_MAGIC), so the checked
 * surface is fixed and independent of the OBJ_LOCAL / dedup ring
 * dimensions -- no growth as fuzz state accumulates.
 *
 * self_corrupt_canary_init_child(): called once per child from
 * init_child.  No-op when the flag is OFF.  Allocates the 64-byte
 * sentinel buffer via zmalloc (owned by this child; freed with the
 * process at exit) and stashes it in a file-static per-process
 * variable -- each child is a separate process so a plain static is
 * private to the child that init'd it.
 *
 * self_corrupt_canary_signature(child): compute the current
 * signature.  Returns 0 when the flag is OFF (short-circuit; the
 * caller compares pre==post, and 0==0 skips the log path).  Bounded:
 * five pointer XORs + eight u64 sentinel-word XORs, no atomics, no
 * loops that scale with fuzz state.
 */
void self_corrupt_canary_init_child(void);
uint64_t self_corrupt_canary_signature(const struct childdata *child);

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
 * Bump the standalone validator_rejected counter used by the
 * pre-dispatch structural check in validate_arg_coupling().  Kept
 * separate from post_handler_corrupt_ptr_bump_at() so the arg-
 * coupling reject stream (perfectly-fine-but-DOA (buf, count)
 * shapes the kernel would EFAULT at ep_send_events()) does not
 * count toward the scribble-detector headline.  Still records the
 * per-site slot under TRINITY_CORRUPT_ATTRIB
 * so the attribution dump continues to show the class; skips the
 * per-handler PC / attr / breadcrumb rings because a structural
 * coupling reject carries no scribbled pointer to attribute.
 */
void validator_rejected_bump(void);

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

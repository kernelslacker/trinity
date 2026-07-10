#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "compiler.h"

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
 * Dedicated shared allocator for regions whose start MUST be page
 * aligned -- notably the per-child childdata struct that the sibling
 * freeze then mprotects.  Bypasses the guard_pages_alloc end-alignment
 * layout (which returned a non-page-aligned inner pointer and made
 * mprotect() EINVAL on every sibling).  Returns a MAP_SHARED
 * MAP_ANONYMOUS mapping whose start is page-aligned by construction
 * and whose length is inner_size rounded up to a page multiple.  The
 * rounded length is written back through *out_rounded_len so the
 * matching mprotect() call in freeze_sibling_childdata covers the same
 * span the mapping owns.
 */
void *alloc_shared_page_aligned(size_t inner_size, size_t *out_rounded_len)
	__must_check;

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
/*
 * Bytes remaining from @addr to the end of the tracked shared region
 * containing it, or 0 if @addr is not inside any tracked region.  Used
 * by the object-size-relative ARG_LEN generator to cap a length pick
 * at the writable extent the kernel can legitimately scribble.
 */
unsigned long shared_region_size_for(unsigned long addr);
void track_shared_region(unsigned long addr, unsigned long size);
#ifdef CONFIG_GUARD_SHARED
/*
 * Tagged variant: registers a shared region together with a short
 * origin string used by the diagnostic audit to name the offending
 * region in fast-vs-slow disagreement logs and on-fault dumps.  The
 * @origin pointer is stored verbatim, so callers must pass a string
 * with static storage duration (a string literal).  Behaves
 * identically to track_shared_region() otherwise.
 */
void track_shared_region_tagged(unsigned long addr, unsigned long size,
				const char *origin);

/*
 * Pure linear scan over shared_regions[] and the overflow tail.
 * Bypasses the bitmap / size-bucket accelerators entirely and answers
 * the authoritative byte-overlap question.  range_overlaps_shared_-
 * audited() pairs this against the fast path and logs any divergence
 * via the per-child audit ring; the fault diagnostic re-uses the same
 * scan to attribute the buffer it just SEGV'd on to a registered
 * region (and its origin tag).  When @entry_addr / @entry_size /
 * @entry_origin are non-NULL they are filled with the first matching
 * region's fields.
 */
bool range_overlaps_shared_slow(unsigned long addr, unsigned long len,
				unsigned long *entry_addr,
				unsigned long *entry_size,
				const char **entry_origin);

/*
 * Audited wrapper used by the mm-syscall sanitisers (mprotect / mmap /
 * munmap / mremap).  Calls range_overlaps_shared() for the fast
 * verdict, range_overlaps_shared_slow() for the authoritative verdict,
 * and on mismatch logs both via outputerr() and pushes a one-line
 * record onto the per-child audit ring so the on-fault diagnostic can
 * recall the recent disagreement history.  Returns the fast verdict
 * verbatim so the sanitiser's reject behaviour is unchanged.
 */
bool range_overlaps_shared_audited(const char *site,
				   unsigned long addr, unsigned long len);

/*
 * Macro shim: keeps the no-CONFIG_GUARD_SHARED build byte-identical
 * by collapsing back to the plain range_overlaps_shared() call.  Mm-
 * sanitiser call sites read RANGE_OVERLAPS_SHARED_AUDITED("site",
 * addr, len) verbatim; the @site label is preserved in the audit ring
 * for attribution under the guard build, and discarded by the
 * preprocessor without it.
 */
#define RANGE_OVERLAPS_SHARED_AUDITED(site, addr, len) \
	range_overlaps_shared_audited((site), (addr), (len))

/*
 * Dump up to the last KCOV_AUDIT_RING_SIZE fast-vs-slow audit
 * disagreement lines for the current child via outputerr().  Called
 * from the kcov_enable_trace on-fault path so the immediate history
 * of accelerator desync events is visible alongside the fault
 * diagnostic.
 */
void kcov_audit_ring_dump(const char *prefix);

/*
 * Internal mprotect overlap check.  Walks shared_regions[] for entries
 * whose origin starts with "kcov-" and warns when [addr, addr+len)
 * intersects them.  Called from the three internal mprotect sites
 * (freeze_sibling_childdata, init_child's pids[] freeze, get_writable_
 * address's own mprotect) so an internal-protect path that strips a
 * kcov buffer's PROT_WRITE is caught as a distinct mechanism from the
 * externally-fuzzed mm-sanitiser route.  @prot is the requested
 * protection bits (passed through to the log line).
 */
void internal_mprotect_audit_kcov(const char *who, unsigned long addr,
				  unsigned long len, int prot);

/*
 * Parse /proc/self/maps for the entry covering @addr and outputerr()
 * its protection bits (rwxp shape) alongside its VMA bounds.  Used at
 * kcov registration time (to localise a setup-side strip) and from
 * the on-fault diagnostic (to localise the runtime strip the SEGV is
 * the symptom of).  Best-effort -- a missing /proc, a buffer
 * boundary, or an addr that falls in a gap all degrade to a single
 * outputerr() line rather than a hard failure.
 */
void log_buffer_prot_from_proc_maps(const char *who, unsigned long addr,
				    unsigned long size);

/*
 * True iff [addr, addr+size) still maps to a registered shared_regions[]
 * entry whose origin tag matches @origin exactly.  The on-fault path
 * uses this to answer "has the kcov-pc registration been silently
 * untracked since registration?" without re-deriving the slot.
 */
bool kcov_registration_still_present(unsigned long addr, unsigned long size,
				     const char *origin);
#else
#define RANGE_OVERLAPS_SHARED_AUDITED(site, addr, len) \
	range_overlaps_shared((addr), (len))
#endif
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

/*
 * Diagnostic hook for the mm-syscall arg sanitisers.  Called at the
 * tail of each mm-syscall sanitiser (madvise / mmap / mprotect /
 * mremap / mseal / remap_file_pages) AFTER range_overlaps_libc_heap()
 * has returned "not heap" for [addr, addr+len) and any per-syscall
 * addr rewrites have settled.  Pays one fresh sbrk(0) and -- if the
 * address now proves to lie inside the live brk arena -- bumps a
 * counter and (rate-limited) logs the slipping syscall so the next
 * live run pins exactly which call passed the gate with a stale
 * cached_brk_end snapshot.
 *
 * Pure observability: does NOT rewrite the slipping addr.  The
 * @detail arg carries the per-syscall context (madvise advice /
 * mprotect prot / mmap flags / mremap newaddr / mseal flags /
 * remap_file_pages prot) verbatim in the log line so post-hoc filters
 * can split slips by class without re-running.
 */
void log_mm_syscall_post_gate_heap_slip(const char *syscall_name,
					unsigned long addr,
					unsigned long len,
					unsigned long detail);

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

#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "debug.h"
#include "deferred-free.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"



/*
 * Ownership table for syscall handlers that snapshot state into a
 * zmalloc'd struct hung off rec->post_state.  Currently only execve /
 * execveat use it, but the API is shape-agnostic so any post handler
 * that needs the same guarantee can call in.
 *
 * Background: rec->post_state is private to the post handler in the
 * syscall ABI sense, but the whole syscallrecord is reachable from
 * sibling fuzz writes -- a value-result write that lands on the
 * post_state slot can redirect it to a different, smaller heap
 * allocation that another syscall's own post_state owns.  The
 * post handler then copies sizeof(struct ...) bytes out of the foreign
 * chunk and trips an OOB read.
 *
 * The original guard against this was malloc_usable_size(snap) <
 * sizeof(*snap), which reads glibc's chunk-header allocation size.
 * That works under glibc but is undefined behaviour on a
 * non-malloc-owned pointer; libsanitizer treats it as a runtime error
 * and aborts the child with a SIGABRT cascade -- the guard meant to
 * catch sibling-stomp redirection becomes the new crash site under
 * ASAN.
 *
 * Replace the chunk-header probe with an explicit ownership table:
 * each handler registers its post_state pointer at allocation time and
 * unregisters before the deferred_freeptr() that releases it.  A snap
 * value that doesn't appear in the table cannot be a chunk we
 * produced, so the post handler bails without dereferencing.  The
 * lookup is pure pointer comparison -- well-defined under both glibc
 * and ASAN.
 *
 * Storage layout: 64-slot fixed pointer table in BSS, COW-shared at
 * fork, written single-threaded by the owning child.  No locking
 * needed.  Each child has at most one in-flight execve post_state at a
 * time (syscalls execute sequentially within a child), so the typical
 * working set is 0-1 entries; 64 slots leaves ample headroom for
 * collision tolerance and silent-drop on the rare table-full case.
 *
 * Hash: top bits of the pointer above glibc's 16-byte chunk
 * alignment.  Open addressing with linear probing for insert.  Lookup
 * and delete scan the table (bounded by POST_STATE_TABLE_SIZE) instead
 * of stopping at the first NULL slot, so a delete-induced gap can't
 * truncate a collision chain and leave a registered pointer
 * unreachable.  The scan cost is a couple of cache lines on the hot
 * path (per-syscall post handler) -- the typical hit lands at the
 * hash slot on the first probe.
 *
 * Scope: this is for the post_state ownership question specifically,
 * not a general validator for every __zmalloc() return.  Wrap the
 * allocation site at each interested caller rather than hooking
 * __zmalloc itself -- the vast majority of zmalloc callers don't need
 * this and the indirection cost would be wasted.
 */
#define POST_STATE_TABLE_SIZE	64
#define POST_STATE_TABLE_MASK	(POST_STATE_TABLE_SIZE - 1)

/*
 * Each slot carries the ptr plus a tag describing who installed the
 * snap, what magic word it carries, how large the allocation was, and
 * whether it has already been released.  The tag drives the
 * release-side rejection contract (wrong-owner / already-released /
 * untracked / bad-magic) so a sibling-stomped post_state can no longer
 * walk into libc free() and abort.
 *
 * Field semantics:
 *   ptr         - chunk address, or NULL if the slot is empty.
 *   syscall_nr  - rec->nr at install time, or UINT_MAX when the
 *                 installer used the untagged post_state_register()
 *                 entry point (legacy / non-canonical sites).  The
 *                 release path skips the wrong-owner check on
 *                 UINT_MAX so untagged sites retain prior behaviour
 *                 minus the abort-on-double-free.
 *   do32bit     - rec->do32bit at install time (paired with
 *                 syscall_nr to disambiguate the biarch table).
 *   magic       - leading-word cookie expected at *(unsigned long *)ptr.
 *                 Captured at install time from the freshly-stamped
 *                 snap[0]; check-static post-state-magic.sh enforces
 *                 that every post_state struct opens with `unsigned
 *                 long magic` so the read is well-defined.  Zero when
 *                 the installer used the untagged
 *                 post_state_register() entry point.
 *   size        - allocation size handed to zmalloc_tracked() at the
 *                 install site, threaded through for telemetry on
 *                 reject lines.  Zero when unknown; the release path
 *                 never gates on size (calling malloc_usable_size on a
 *                 stomped pointer would itself be UB under ASAN, the
 *                 same regression the ownership-table replaced).
 *   released    - flipped true by post_state_release() the first time
 *                 a snap is accepted for free; the second release call
 *                 on the same address sees released=true and rejects
 *                 (already-released) instead of double-freeing.  The
 *                 entry stays in the table with released=true until a
 *                 future post_state_register() probe lands on the slot
 *                 and overwrites it.
 */
struct post_state_entry {
	void *ptr;
	unsigned int syscall_nr;
	bool do32bit;
	bool released;
	unsigned long magic;
	size_t size;
};

static struct post_state_entry post_state_table[POST_STATE_TABLE_SIZE];

static unsigned int post_state_hash(const void *p)
{
	return (unsigned int) (((uintptr_t) p >> 4) & POST_STATE_TABLE_MASK);
}

/*
 * Locate the table entry for @p, including stale released entries so
 * post_state_release() can answer "already-released" specifically.
 * Returns NULL when no slot carries @p.  Scans the full table (the
 * unregister path leaves holes mid-chain) so a NULL slot in the
 * collision chain does not truncate the search.
 */
static struct post_state_entry *post_state_table_find(const void *p)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return NULL;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx].ptr == p)
			return &post_state_table[idx];
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
	return NULL;
}

/*
 * Insert @p with the supplied tag.  Reuses slots that are empty or
 * carry a released==true entry (the chunk those described is gone, the
 * slot is a stale telemetry record).  An idempotent re-insert of @p at
 * a still-live slot is a no-op.  Table full → silently drop the
 * registration; lookup will miss, the post handler will bail without
 * dereferencing, the chunk leaks until child exit (benign).
 */
static void post_state_register_full(void *p, unsigned int syscall_nr,
				     bool do32bit, unsigned long magic,
				     size_t size)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx].ptr == NULL ||
		    post_state_table[idx].released) {
			post_state_table[idx].ptr = p;
			post_state_table[idx].syscall_nr = syscall_nr;
			post_state_table[idx].do32bit = do32bit;
			post_state_table[idx].released = false;
			post_state_table[idx].magic = magic;
			post_state_table[idx].size = size;
			return;
		}
		if (post_state_table[idx].ptr == p)
			return;
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
}

void post_state_register(void *p)
{
	post_state_register_full(p, UINT_MAX, false, 0, 0);
}

void post_state_unregister(void *p)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx].ptr == p) {
			post_state_table[idx].ptr = NULL;
			post_state_table[idx].syscall_nr = 0;
			post_state_table[idx].do32bit = false;
			post_state_table[idx].released = false;
			post_state_table[idx].magic = 0;
			post_state_table[idx].size = 0;
			return;
		}
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
}

bool post_state_is_owned(const void *p)
{
	struct post_state_entry *e = post_state_table_find(p);

	return e != NULL && !e->released;
}

/*
 * Tagged install: the canonical entry point invoked via the
 * post_state_install() macro in include/utils.h, which supplies @size
 * as sizeof(*snap) at the call site.  Captures the snap's magic word
 * from snap[0] at install time -- by post-state-magic.sh convention
 * every post_state struct opens with `unsigned long magic` and the
 * .sanitise body must stamp it BEFORE calling this helper, so the
 * leading-word read aliases snap->magic without needing the caller's
 * struct type.  Storing the magic in the ownership table closes the
 * "snap chunk was freed and reallocated under us by another path"
 * window the release-side reject contract checks against.
 */
void post_state_install_sized(struct syscallrecord *rec, void *snap,
			      size_t size)
{
	unsigned long magic = 0;

	rec->post_state = (unsigned long) snap;
	if (snap != NULL)
		magic = *(const unsigned long *) snap;
	post_state_register_full(snap, rec->nr, rec->do32bit, magic, size);
}

/*
 * Canonical .post-entry gate.  See the helper-block comment in
 * include/utils.h for the rationale and the three-step ordering this
 * encodes.  Diagnostic strings and counter bumps mirror the prior
 * hand-rolled gates so log readers and stat dashboards keep working.
 *
 * The shape gate calls looks_like_corrupted_ptr_pc() directly with the
 * caller PC fetched by __builtin_return_address(0); that preserves the
 * per-callsite PC attribution that the static-inline looks_like_corrupted_ptr()
 * wrapper would otherwise lose now that we are a separate function.
 *
 * The magic word is read via *(const unsigned long *)snap rather than
 * snap->magic; every post_state struct puts `unsigned long magic`
 * first by convention (post-state-magic.sh enforces it), so the
 * leading-word read aliases the magic field without the helper needing
 * to know the caller's struct type.
 */
void *post_state_claim_owned(struct syscallrecord *rec,
			     unsigned long magic_expected,
			     const char *handler_name)
{
	void *snap = (void *) rec->post_state;
	unsigned long magic_found;

	if (snap == NULL)
		return NULL;

	if (looks_like_corrupted_ptr_pc(rec, snap, __builtin_return_address(0))) {
		outputerr("%s: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", handler_name, snap);
		rec->post_state = 0;
		return NULL;
	}

	/*
	 * Ownership gate -- MUST run before reading any field of snap,
	 * including the magic cookie below.  A foreign chunk that survived
	 * the shape gate may not even be sizeof(unsigned long) bytes in
	 * size; reading the leading word on a non-snap allocation is a
	 * wild read.  post_state_is_owned() is pure pointer comparison
	 * against the table and is well-defined regardless of what snap
	 * points at.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("%s: rejected post_state=%p not in ownership table "
			  "(post_state-redirected?)\n", handler_name, snap);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_CLAIM_OWNED_NOT_OWNED);
		rec->post_state = 0;
		return NULL;
	}

	/*
	 * Ownership confirmed -- snap really is one of our chunks, so
	 * reading the leading word is now safe.  By convention every
	 * post_state struct puts `unsigned long magic` first, so this read
	 * aliases snap->magic without a typed deref.
	 */
	magic_found = *(const unsigned long *) snap;
	if (magic_found != magic_expected) {
		outputerr("%s: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  handler_name, magic_found);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_CLAIM_OWNED_BAD_MAGIC);
		rec->post_state = 0;
		return NULL;
	}

	return snap;
}

/*
 * Idempotent release contract.  Every rejection path leaves the chunk
 * alive (no libc free()), clears rec->post_state so a second .post /
 * .cleanup invocation on the same rec can no longer rediscover the
 * stale pointer, and bumps a structured counter so the rate is
 * visible without grepping outputerr lines.  The four rejections,
 * checked in order:
 *
 *   1. untracked   - snap is not in the ownership table.  Either it was
 *      never registered (pure sibling stomp landed on rec->post_state),
 *      or its table slot was already overwritten by a later
 *      registration after a prior release.  Both shapes mean we have
 *      no proof @snap is a real malloc-returned chunk; handing it to
 *      free() is the libc abort the spec asked us to stop.
 *
 *   2. already-released - snap is in the table but a prior
 *      post_state_release() already accepted it.  The .post and
 *      .cleanup helpers both route through here, and an .post that
 *      released followed by a .cleanup that releases the same snap
 *      would currently double-free.  Idempotence drops the second
 *      call without touching libc.
 *
 *   3. wrong-owner - snap is live, but the installer was a different
 *      (syscall_nr, do32bit) than the caller.  This is the
 *      sibling-stomp redirect class: another handler's snap got
 *      pointed at by our rec->post_state via a fuzzed value-result
 *      write; we would otherwise free the other handler's chunk and
 *      it would crash when its own .post handler tries to read it
 *      back.  Untagged installers (post_state_register-only,
 *      syscall_nr==UINT_MAX) skip this gate so legacy sites retain
 *      prior behaviour modulo the abort-on-double-free.
 *
 *   4. bad-magic - snap is live and tagged to us, but the leading
 *      word no longer matches the magic captured at install time.
 *      The chunk's contents have been overwritten by something that
 *      is not our post_state snap; freeing it would be freeing
 *      something we no longer own.  Untagged installers (magic==0)
 *      skip this gate.
 *
 * Only after all four gates pass do we mark the entry released and
 * hand the chunk to deferred_freeptr(), which performs its own
 * shape / heap-bounds / alloc_track / shared-region cascade as the
 * second wall.
 */
void post_state_release(struct syscallrecord *rec, void *snap)
{
	struct post_state_entry *e;
	unsigned long magic_found;

	if (snap == NULL)
		return;

	e = post_state_table_find(snap);
	if (e == NULL) {
		outputerr("post_state_release: rejected untracked snap=%p "
			  "(caller nr=%u do32bit=%d) -- leaking, not freeing\n",
			  snap, rec->nr, rec->do32bit);
		__atomic_add_fetch(&shm->stats.deferred_free.post_state_release_reject_untracked,
				   1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (e->released) {
		outputerr("post_state_release: rejected already-released snap=%p "
			  "(prior owner nr=%u do32bit=%d, caller nr=%u do32bit=%d)\n",
			  snap, e->syscall_nr, e->do32bit, rec->nr, rec->do32bit);
		__atomic_add_fetch(&shm->stats.deferred_free.post_state_release_reject_released,
				   1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (e->syscall_nr != UINT_MAX &&
	    (e->syscall_nr != rec->nr || e->do32bit != rec->do32bit)) {
		outputerr("post_state_release: rejected wrong-owner snap=%p "
			  "(owner nr=%u do32bit=%d, caller nr=%u do32bit=%d, "
			  "size=%zu) -- leaking, not freeing\n",
			  snap, e->syscall_nr, e->do32bit, rec->nr, rec->do32bit,
			  e->size);
		__atomic_add_fetch(&shm->stats.deferred_free.post_state_release_reject_wrong_owner,
				   1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (e->magic != 0) {
		magic_found = *(const unsigned long *) snap;
		if (magic_found != e->magic) {
			outputerr("post_state_release: rejected snap=%p bad magic "
				  "(found 0x%lx, expected 0x%lx, owner nr=%u) -- "
				  "leaking, not freeing\n",
				  snap, magic_found, e->magic, e->syscall_nr);
			__atomic_add_fetch(&shm->stats.deferred_free.post_state_release_reject_bad_magic,
					   1, __ATOMIC_RELAXED);
			rec->post_state = 0;
			return;
		}
	}

	e->released = true;
	/*
	 * Free the validated snap, not the live slot: rec->post_state lives
	 * in shared childdata and a wild writer can redirect it to another
	 * live tracked chunk between the gates above and this free.  If the
	 * slot still matches snap, clear it; if it does not, leave the
	 * scribbled value in place so the canary / bad-magic detectors keep
	 * firing on the writer instead of being papered over here.
	 */
	if (rec->post_state == (unsigned long)(uintptr_t)snap)
		rec->post_state = 0;
	deferred_free_enqueue(snap);
}

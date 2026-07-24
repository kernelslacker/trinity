/*
 * Arena stale/liveness probes carved out of dispatch/syscall.c.
 */

#include <stddef.h>
#include <time.h>

#include "maps.h"
#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "utils.h"

/*
 * Rate-limited (at most once per second per child) WARNING for stale
 * arena-pointer detections.  A single munmap storm from one sibling can
 * fire the probe on many syscalls in quick succession; mirror the
 * canary_stomp_warn_ratelimited cadence so the log stays useful rather
 * than flooding.  Per-process static; the headline counter still
 * accumulates every detection.
 */
static void arena_stale_warn_ratelimited(const struct syscallentry *entry,
					 const char *site, unsigned long v)
{
	static struct timespec last_warn;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec == last_warn.tv_sec)
		return;
	last_warn = now;

	outputerr("WARNING: arena_ptr_stale caught during %s [%s]: v=0x%lx (page-aligned, in arena band, no live tracker)\n",
		  entry->name, site, v);
}

/*
 * Classify v as live (tracked) / stale (page-aligned arena-band shape
 * with no live tracker) / unknown (out of scope for this probe).
 * Telemetry-only -- callers bump a counter on STALE but do not coerce
 * the slot or skip the post handler.
 *
 * Ordering rationale (matches spec §3):
 *   1. is_corrupt_ptr_shape() -> UNKNOWN: defer to the existing shape
 *      gate; double-firing would double-count the structurally-broken
 *      class under both counters.
 *   2. range_in_tracked_shared() -> LIVE: linear walk of
 *      shared_regions[] + overflow, no LRU window.
 *   3. addr_in_local_runtime_map() -> LIVE: walk of OBJ_LOCAL
 *      OBJ_MMAP_{ANON,FILE,TESTFILE} pools, no LRU window.
 *   4. page-aligned AND inside the literal arena band -> STALE.
 *   5. Anything else -> UNKNOWN (a runtime CHILD_ANON above the band
 *      lands here; out of scope for the literal-band Phase 1).
 */
enum arena_ptr_status {
	ARENA_PTR_LIVE,
	ARENA_PTR_STALE,
	ARENA_PTR_UNKNOWN,
};

static enum arena_ptr_status arena_ptr_liveness(unsigned long v, size_t need)
{
	if (is_corrupt_ptr_shape((const void *) v))
		return ARENA_PTR_UNKNOWN;
	if (range_in_tracked_shared(v, need))
		return ARENA_PTR_LIVE;
	if (addr_in_local_runtime_map(v, need))
		return ARENA_PTR_LIVE;
	if ((v & ((unsigned long) page_size - 1)) == 0 && is_in_arena_band(v))
		return ARENA_PTR_STALE;
	return ARENA_PTR_UNKNOWN;
}

/*
 * Dispatcher-level liveness probe.  Walks the ARG_ADDRESS /
 * ARG_NON_NULL_ADDRESS slots and the rec->post_state tail looking for
 * page-aligned arena-band pointers that no live tracker owns -- the
 * structural shape of the bug 1279961 SEGV at handle_syscall_ret+0x24a
 * (si_addr=0x4037e000) which is_corrupt_ptr_shape() by design admits.
 *
 * Telemetry-only.  Runs AFTER the kernel has returned, so the kernel
 * has already observed whatever value sat in the slot; coercing it now
 * cannot influence the syscall and would itself be a post-dispatch
 * scribble of the shared rec -- exactly the class of bug the wider
 * arg_shadow / canary machinery is meant to surface.  On detection we
 * bump the headline counter, rate-limited warn, and return; downstream
 * consumers must take their own EXPLICIT skip path on a stale slot
 * rather than rely on this probe to coerce.
 */
void arena_liveness_probe(struct syscallentry *entry,
			  struct syscallrecord *rec)
{
	size_t need = (size_t) page_size;
	unsigned int i;

	for_each_arg(entry, i) {
		enum argtype t = entry->argtype[i - 1];
		unsigned long slot;

		if (t != ARG_ADDRESS && t != ARG_NON_NULL_ADDRESS)
			continue;

		switch (i) {
		case 1: slot = rec->a1; break;
		case 2: slot = rec->a2; break;
		case 3: slot = rec->a3; break;
		case 4: slot = rec->a4; break;
		case 5: slot = rec->a5; break;
		case 6: slot = rec->a6; break;
		default: continue;
		}

		if (arena_ptr_liveness(slot, need) != ARENA_PTR_STALE)
			continue;

		__atomic_add_fetch(&shm->stats.diag.arena_ptr_stale_caught_arg,
				   1, __ATOMIC_RELAXED);
		arena_stale_warn_ratelimited(entry, "arg", slot);
	}

	if (rec->post_state != 0 &&
	    arena_ptr_liveness(rec->post_state, need) == ARENA_PTR_STALE) {
		__atomic_add_fetch(&shm->stats.diag.arena_ptr_stale_caught_post_state,
				   1, __ATOMIC_RELAXED);
		arena_stale_warn_ratelimited(entry, "post_state",
					     rec->post_state);
	}
}

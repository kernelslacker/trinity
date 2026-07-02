#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "deferred-free.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

void * __zmalloc(size_t size, const char *func)
{
	void *p;

	/*
	 * Tick the brk-cache refresh on the malloc path as well as the
	 * alloc_object() path.  Heavy __zmalloc users (cmp-hints /
	 * RedQueen pool inflation, per-syscall sequence records) can
	 * drive billions of malloc()s in a session without ever calling
	 * alloc_object(), and a malloc that triggers a brk grow leaves
	 * cached_brk_end behind by exactly that grow until the next
	 * alloc_object() refresh fires -- which on those workloads can
	 * be never.  Refreshing here closes the diagnostic-window race
	 * the heap_brk_stale_window_hit counter exists to measure.
	 */
	heap_brk_maybe_refresh();

	p = malloc(size);
	if (p == NULL) {
		/* Maybe we mlockall'd everything. Try and undo that, and retry. */
		munlockall();
		p = malloc(size);
		if (p != NULL)
			goto done;

		outputerr("%s: malloc(%zu) failure.\n", func, size);
		exit(EXIT_FAILURE);
	}

done:
	memset(p, 0, size);
	return p;
}

/*
 * Opt-in variant of __zmalloc() that additionally registers the
 * returned pointer with the deferred-free alloc-track ring.  Callers
 * use this when the allocation is bound to flow through
 * deferred_free_enqueue() / deferred_freeptr() so that the consume-on-
 * free invariant has a matching tracker entry to remove.  Plain
 * __zmalloc() must be used at sites whose allocations are released
 * via direct free() (process-lifetime / per-child tables / error-path
 * fallbacks); registering those would leave stale entries in the ring
 * that a fuzzed value can match against -- the bug Option B of the
 * 2026-05-19 alloc-tracking audit narrows the tracker to avoid.
 */
void * __zmalloc_tracked(size_t size, const char *func)
{
	void *p = __zmalloc(size, func);

	deferred_alloc_track(p, size);
	return p;
}

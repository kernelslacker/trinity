#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include "signals.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

bool range_readable_user(const void *addr, size_t len)
{
	unsigned long a = (unsigned long) addr;

	if (len == 0)
		return false;
	if (addr == NULL)
		return false;
	if (a > ULONG_MAX - len)
		return false;

	/*
	 * Fast path 1: range is fully inside a tracked shared region.
	 * Trinity owns those mappings outright -- alloc_shared() creates
	 * them PROT_READ|PROT_WRITE and they live for the run, so VMA
	 * presence implies the source bytes are readable.
	 */
	if (range_in_tracked_shared(a, len))
		return true;

	/*
	 * Fast path 2: range is fully inside the cached libc heap (brk
	 * arena) or any captured non-brk allocator region.  Allocator
	 * mappings are PROT_READ|PROT_WRITE by construction; the
	 * heap_bounds_init() snapshot only records writable private VMAs.
	 */
	if (range_inside_libc_heap(a, len))
		return true;

	/*
	 * Unknown layout: a fuzz-introduced VMA outside every cached
	 * snapshot.  Treat as unproven and let the caller route to
	 * asb_relocate()'s no-copy fallback -- chasing the source via a
	 * /proc/self/maps walk on every hot-path call is what this code
	 * was retired to avoid.
	 */
	return false;
}

bool post_snapshot_str(char *dst, size_t dstsz, const char *src)
{
	size_t i;

	if (dst == NULL || dstsz == 0)
		return false;
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate.  range_readable_user proves the
	 * full dstsz-byte window of src is mapped (tracked-shared region
	 * or cached libc heap); the copy loop below then never reads past
	 * what we proved.  False here means src is not provably readable
	 * and the caller skips the .post sample rather than feeding a
	 * stale heap-shaped pointer into a downstream strncpy that would
	 * walk off an unrelated allocation.  ASAN catches that walk-off in
	 * test; in production it silently surfaces as an oracle anomaly
	 * against a foreign byte pattern.
	 */
	if (!range_readable_user(src, dstsz))
		return false;

	/*
	 * Same TOCTOU window as post_snapshot_or_skip: a sibling
	 * mprotect/munmap between the readability proof and the read can
	 * fault the src[i] load.  Guard the copy loop with the
	 * asb_copy_active sigsetjmp slot so the fault degrades to a
	 * skipped sample rather than a child crash.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	for (i = 0; i + 1 < dstsz; i++) {
		char c = src[i];

		dst[i] = c;
		if (c == '\0') {
			asb_copy_active = 0;
			return true;
		}
	}
	dst[i] = '\0';
	asb_copy_active = 0;
	return true;
}

bool post_snapshot_or_skip(void *dst, const void *src, size_t len)
{
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate, identical in shape to the one
	 * in post_snapshot_str().  The post oracle's NULL + shape-only
	 * looks_like_corrupted_ptr guard waves through a heap-shaped but
	 * stale/unmapped snap->field; range_readable_user proves the
	 * full len-byte window is mapped (tracked-shared region or
	 * cached libc heap), so the memcpy below cannot fault on the
	 * sibling free / unmap / fuzz-redirect window between the
	 * syscall return and the post sample.  False here means the
	 * caller skips the .post sample rather than feeding the
	 * downstream oracle a foreign byte pattern.
	 */
	if (!range_readable_user(src, len))
		return false;

	/*
	 * range_readable_user() proves src is mapped per trinity's
	 * shared/heap bookkeeping, but a sibling syscall can mprotect or
	 * munmap the tracked region in the window between that check and
	 * this copy.  Guard the memcpy with the asb_copy_active sigsetjmp
	 * slot (the same recovery the get_writable_struct relocate-copy
	 * uses) so a TOCTOU fault skips the .post sample instead of
	 * killing the child.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	memcpy(dst, src, len);
	asb_copy_active = 0;
	return true;
}

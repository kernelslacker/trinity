#pragma once

#include <stddef.h>

/*
 * Value-result buffer helper.
 *
 * Many syscalls take a (buf, *len_io) pair where the caller writes
 * the buffer's capacity into *len_io, the kernel writes up to that
 * many bytes into buf, and the kernel rewrites *len_io with the
 * actual transferred count.  The interesting fuzz axis is the
 * mismatch between the advertised capacity and what the kernel
 * thinks the natural size is for that request: too small triggers
 * truncation / EINVAL, exact hits the happy path, oversize exercises
 * bounds and overflow checks.
 *
 * This helper centralises the shape catalogue so the same mutation
 * distribution is applied at every value-result call site as
 * consumers are migrated over.  Consumers ask for a "natural"
 * initial capacity; the helper picks the actual capacity according
 * to the shape and allocates a tracked buffer + a tracked size_t
 * slot wired to it.
 *
 * len_io is allocated as a full size_t even when the kernel-side
 * counter is narrower (int / socklen_t).  On little-endian hosts the
 * low bytes of *len_io coincide with the narrower view, which is the
 * primary fuzz target; consumers that care about big-endian can cast
 * vrb.len_io before submission.
 */
enum valresult_shape {
	VALRESULT_EXACT,		/* cap == initial_cap (happy path) */
	VALRESULT_UNDER,		/* cap < initial_cap (short buffer) */
	VALRESULT_EXACT_PLUS_ONE,	/* cap == initial_cap + 1 (boundary) */
	VALRESULT_HUGE,			/* cap >> initial_cap (bounds probe) */
	VALRESULT_ZERO,			/* cap == 0 (canonical short-write) */
};

struct valresult_buf {
	void *buf;		/* output buffer; NULL iff cap == 0 */
	size_t cap;		/* buf capacity in bytes; *len_io == cap initially */
	size_t *len_io;		/* heap slot holding the in/out length */
};

/*
 * Construct a value-result buffer for the requested shape.  buf and
 * len_io are zmalloc_tracked() so consumers can hand them to
 * deferred_free_enqueue() via valresult_free() once the kernel has
 * finished with them.
 */
struct valresult_buf valresult_alloc(size_t initial_cap,
				     enum valresult_shape shape);

/*
 * Release a buffer previously returned by valresult_alloc().  Safe to
 * call with vrb == NULL or with a vrb whose fields are already NULL.
 * Both slots route through deferred_free_enqueue() so callers that
 * snapshot the originals before avoid_shared_buffer_*() relocation
 * still free the right (tracked) allocations.
 */
void valresult_free(struct valresult_buf *vrb);

/*
 * Pick a shape from the weighted distribution.  EXACT dominates so
 * most fuzz iterations stay on the happy path; the corner shapes
 * each fire on a few percent of calls to keep the boundary, bounds-
 * probe and short-write paths in steady rotation.  Callers that
 * want deterministic shape coverage should hand-pick instead.
 */
enum valresult_shape valresult_pick_shape(void);

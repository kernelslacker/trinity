#include <stddef.h>

#include "deferred-free.h"
#include "random.h"
#include "utils.h"
#include "valresult.h"

/*
 * Capacity bump for VALRESULT_HUGE.  Picked large enough to exceed
 * the optname / iovec / buffer sizes for any value-result consumer
 * we currently fuzz, but small enough that allocating one per child
 * per call does not OOM a typical fuzz host.
 */
#define VALRESULT_HUGE_BYTES (4UL * 1024 * 1024)

static size_t shape_to_cap(size_t initial_cap, enum valresult_shape shape)
{
	switch (shape) {
	case VALRESULT_EXACT:
		return initial_cap;
	case VALRESULT_UNDER:
		/*
		 * Half is short enough to truncate without collapsing
		 * into the ZERO shape (which is selected separately).
		 * initial_cap <= 1 has no meaningful "under" so fall
		 * back to ZERO behaviour for those edge inputs.
		 */
		return initial_cap > 1 ? initial_cap / 2 : 0;
	case VALRESULT_EXACT_PLUS_ONE:
		return initial_cap + 1;
	case VALRESULT_HUGE:
		return VALRESULT_HUGE_BYTES;
	case VALRESULT_ZERO:
	default:
		return 0;
	}
}

struct valresult_buf valresult_alloc(size_t initial_cap,
				     enum valresult_shape shape)
{
	struct valresult_buf vrb;
	size_t cap = shape_to_cap(initial_cap, shape);

	vrb.cap = cap;
	vrb.buf = cap ? zmalloc_tracked(cap) : NULL;
	vrb.len_io = zmalloc_tracked(sizeof(*vrb.len_io));
	*vrb.len_io = cap;
	return vrb;
}

void valresult_free(struct valresult_buf *vrb)
{
	if (vrb == NULL)
		return;
	/* deferred_free_enqueue() is NULL-safe; no extra guard needed. */
	deferred_free_enqueue(vrb->buf);
	deferred_free_enqueue(vrb->len_io);
	vrb->buf = NULL;
	vrb->len_io = NULL;
	vrb->cap = 0;
}

enum valresult_shape valresult_pick_shape(void)
{
	/*
	 * EXACT-dominant ladder.  Each corner shape fires on roughly
	 * 1/32 of calls; ZERO is rarer (1/64) because it short-
	 * circuits most consumers into an immediate EFAULT / EINVAL
	 * and yields less kernel-side coverage than the other
	 * corners.  Net distribution is ~88% EXACT and ~12% corner.
	 */
	if (ONE_IN(64))
		return VALRESULT_ZERO;
	if (ONE_IN(32))
		return VALRESULT_HUGE;
	if (ONE_IN(32))
		return VALRESULT_UNDER;
	if (ONE_IN(32))
		return VALRESULT_EXACT_PLUS_ONE;
	return VALRESULT_EXACT;
}

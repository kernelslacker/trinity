#pragma once

#include <assert.h>

/* Picker-context axis: identifies which caller-context stamped the
 * current pick.  Baseline runs use PICKER_CTX_INIT exclusively; the
 * axis exists so a future user-namespace helper can distinguish its
 * own picks from the default init-user context.  Kept in its own
 * header so shm-side per-context storage can size arrays by
 * PICKER_NCTX without pulling in the whole child.h. */
enum picker_context {
	PICKER_CTX_INIT		= 0,
	PICKER_CTX_USERNS	= 1,
	PICKER_NCTX,
};

/* Acceptance-gate invariants for the per-context storage widening:
 *
 * (a) PICKER_CTX_INIT MUST be the first enumerator so the INIT slice
 *     lives at ctx-index 0 of every widened [nr][PICKER_NCTX][...]
 *     array.  Under baseline INIT-only operation clean_childdata
 *     stamps every child's context_id to PICKER_CTX_INIT and no
 *     writer ever reaches a non-INIT slice, so the INIT slice
 *     receives every bump and every read.  Combined with the enum-0
 *     placement, that makes the INIT slice the direct successor of
 *     the pre-widening flat counter -- same array offset math for
 *     nr, same relative offset within the row.
 *
 * (b) PICKER_NCTX MUST be at least two so a follow-up context (the
 *     user-namespace helper the axis is being built for) has a slot
 *     to write into without another storage widening.
 */
_Static_assert((int)PICKER_CTX_INIT == 0,
	"PICKER_CTX_INIT must be enumerator 0 so widened [nr][ctx][...] "
	"arrays keep the INIT slice byte-identical to the pre-widening flat "
	"counter under baseline INIT-only operation");
_Static_assert(PICKER_NCTX >= 2,
	"PICKER_NCTX must be at least 2 so the axis has a follow-up context "
	"slot to grow into without another storage widening");

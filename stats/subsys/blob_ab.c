#include <stddef.h>
#include "stats-internal.h"

/* --blob-ab-mode within-run A/B harness (default off, opt-in only).
 * Separate category so a run with --blob-mutator=havoc / cmpdict but
 * WITHOUT --blob-ab-mode does not render eight zero rows for the ab
 * counters.  Gate on blob_ab.havoc_fills: the harness coin-flips
 * 50/50, so at any observable run length both counters are non-zero
 * together; picking one for the gate suppresses the whole block on
 * every non-ab run.  Verdict per mode: hit_cmp / fills on warm /
 * PC-plateau runs (the fleet default -- new_edges is ~0 there),
 * new_edges / fills on cold runs.  sum_cmp is a non-gating shadow
 * (CMP-novelty magnitude) for diagnostics only, never the verdict.
 * Per-fill rates are the clean comparison because both arms share
 * the same warm corpus / kcov state at every moment. */
static const struct stat_field blob_ab_mode_fields[] = {
	STAT_FIELD_SUB(blob_ab, havoc_fills),
	STAT_FIELD_SUB(blob_ab, havoc_new_edges),
	STAT_FIELD_SUB(blob_ab, havoc_hit_cmp),
	STAT_FIELD_SUB(blob_ab, havoc_sum_cmp),
	STAT_FIELD_SUB(blob_ab, cmpdict_fills),
	STAT_FIELD_SUB(blob_ab, cmpdict_new_edges),
	STAT_FIELD_SUB(blob_ab, cmpdict_hit_cmp),
	STAT_FIELD_SUB(blob_ab, cmpdict_sum_cmp),
};

const struct stat_category blob_ab_mode_category =
	STAT_CATEGORY("blob_ab_mode",
	              blob_ab.havoc_fills,
	              blob_ab_mode_fields);

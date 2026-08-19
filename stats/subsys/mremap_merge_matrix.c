#include <stddef.h>
#include "stats-internal.h"

/* mremap_merge_matrix: content and topology oracle counters.
 * checks_run counts every do_move() invocation; tag_mismatch counts
 * invocations where verify_pages() returned false (wrong cookie at
 * dst/src after the remap); topology_unexpected counts invocations
 * where post_vmas > pre_vmas despite an expected same-prot merge. */
static const struct stat_field mremap_merge_matrix_fields[] = {
	STAT_FIELD_SUB(mremap_merge_matrix, checks_run),
	STAT_FIELD_SUB(mremap_merge_matrix, tag_mismatch),
	STAT_FIELD_SUB(mremap_merge_matrix, topology_unexpected),
};

const struct stat_category mremap_merge_matrix_category =
	STAT_CATEGORY("mremap_merge_matrix",
	              mremap_merge_matrix_fields);

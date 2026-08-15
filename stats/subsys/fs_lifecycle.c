#include <stddef.h>
#include "stats-internal.h"

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * emits every category unconditionally; the current text dump stays
 * hand-coded in dump_stats_childop_runs_local().  If stat_category_emit_text()
 * is wired onto these tables it will emit when any field is non-zero.
 */
static const struct stat_field fs_lifecycle_fields[] = {
	STAT_FIELD_SUB(fs_lifecycle, tmpfs),
	STAT_FIELD_SUB(fs_lifecycle, ramfs),
	STAT_FIELD_SUB(fs_lifecycle, rdonly),
	STAT_FIELD_SUB(fs_lifecycle, overlay),
	STAT_FIELD_SUB(fs_lifecycle, quota),
	STAT_FIELD_SUB(fs_lifecycle, bind),
	STAT_FIELD_SUB(fs_lifecycle, unsupported),
};

const struct stat_category fs_lifecycle_category =
	STAT_CATEGORY("fs_lifecycle",
	              fs_lifecycle.tmpfs,
	              fs_lifecycle_fields);

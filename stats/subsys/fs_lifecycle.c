#include <stddef.h>
#include "stats-internal.h"

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * ignores gate_offset (it emits every category unconditionally) so the gate
 * field here only matters if a future change wires stat_category_emit_text()
 * onto these tables; the current text dump for these two categories stays
 * hand-coded in dump_stats_childop_runs_local().
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

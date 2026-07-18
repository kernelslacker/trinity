#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field deep_path_nesting_fields[] = {
	STAT_FIELD_SUB(deep_path, runs),
	STAT_FIELD_SUB(deep_path, setup_failed),
	STAT_FIELD_SUB(deep_path, max_depth_reached),
	STAT_FIELD_SUB(deep_path, reader_ok),
	STAT_FIELD_SUB(deep_path, reader_failed),
};

const struct stat_category deep_path_nesting_category =
	STAT_CATEGORY("deep_path_nesting",
	              deep_path.runs,
	              deep_path_nesting_fields);

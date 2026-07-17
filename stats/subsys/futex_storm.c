#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field futex_storm_fields[] = {
	STAT_FIELD_SUB(futex_storm, runs),
	STAT_FIELD_SUB(futex_storm, inner_crashed),
	STAT_FIELD_SUB(futex_storm, iters),
};

const struct stat_category futex_storm_category =
	STAT_CATEGORY("futex_storm",
	              futex_storm.runs,
	              futex_storm_fields);

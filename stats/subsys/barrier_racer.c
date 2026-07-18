#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field barrier_racer_fields[] = {
	STAT_FIELD_SUB(barrier_racer, runs),
	STAT_FIELD_SUB(barrier_racer, inner_crashed),
};

const struct stat_category barrier_racer_category =
	STAT_CATEGORY("barrier_racer",
	              barrier_racer.runs,
	              barrier_racer_fields);

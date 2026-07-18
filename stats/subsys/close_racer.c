#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field close_racer_fields[] = {
	STAT_FIELD_SUB(close_racer, runs),
	STAT_FIELD_SUB(close_racer, pairs),
	STAT_FIELD_SUB(close_racer, failed),
	STAT_FIELD_SUB(close_racer, thread_spawn_fail),
};

const struct stat_category close_racer_category =
	STAT_CATEGORY("close_racer",
	              close_racer.runs,
	              close_racer_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sched_cycler_fields[] = {
	STAT_FIELD_SUB(sched_cycler, runs),
	STAT_FIELD_SUB(sched_cycler, eperm),
};

const struct stat_category sched_cycler_category =
	STAT_CATEGORY("sched_cycler",
	              sched_cycler.runs,
	              sched_cycler_fields);

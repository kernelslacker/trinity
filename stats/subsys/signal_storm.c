#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field signal_storm_fields[] = {
	STAT_FIELD_SUB(signal_storm, runs),
	STAT_FIELD_SUB(signal_storm, kill),
	STAT_FIELD_SUB(signal_storm, probe),
	STAT_FIELD_SUB(signal_storm, sigqueue),
	STAT_FIELD_SUB(signal_storm, no_targets),
};

const struct stat_category signal_storm_category =
	STAT_CATEGORY("signal_storm",
	              signal_storm.runs,
	              signal_storm_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field fork_storm_fields[] = {
	STAT_FIELD_SUB(fork_storm, runs),
	STAT_FIELD_SUB(fork_storm, forks),
	STAT_FIELD_SUB(fork_storm, failed),
	STAT_FIELD_SUB(fork_storm, nested),
	STAT_FIELD_SUB(fork_storm, reaped_signal),
};

const struct stat_category fork_storm_category =
	STAT_CATEGORY("fork_storm",
	              fork_storm.runs,
	              fork_storm_fields);

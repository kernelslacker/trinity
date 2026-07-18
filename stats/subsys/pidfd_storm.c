#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field pidfd_storm_fields[] = {
	STAT_FIELD_SUB(pidfd_storm, runs),
	STAT_FIELD_SUB(pidfd_storm, signals),
	STAT_FIELD_SUB(pidfd_storm, getfds),
	STAT_FIELD_SUB(pidfd_storm, failed),
	STAT_FIELD_SUB(pidfd_storm, iters),
	STAT_FIELD_SUB(pidfd_storm, reap_slow),
	STAT_FIELD_SUB(pidfd_storm, reap_zombies),
};

const struct stat_category pidfd_storm_category =
	STAT_CATEGORY("pidfd_storm",
	              pidfd_storm.runs,
	              pidfd_storm_fields);

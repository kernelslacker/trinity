#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field perf_event_chains_fields[] = {
	STAT_FIELD_SUB(perf_chains, runs),
	STAT_FIELD_SUB(perf_chains, groups_created),
	STAT_FIELD_SUB(perf_chains, ioctl_ops),
};

const struct stat_category perf_event_chains_category =
	STAT_CATEGORY("perf_event_chains",
	              perf_chains.runs,
	              perf_event_chains_fields);

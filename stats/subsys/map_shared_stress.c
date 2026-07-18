#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field map_shared_stress_fields[] = {
	STAT_FIELD_SUB(map_shared_stress, runs),
	STAT_FIELD_SUB(map_shared_stress, setup_failed),
	STAT_FIELD_SUB(map_shared_stress, writeback_ok),
	STAT_FIELD_SUB(map_shared_stress, dontfork_ok),
	STAT_FIELD_SUB(map_shared_stress, append_ok),
};

const struct stat_category map_shared_stress_category =
	STAT_CATEGORY("map_shared_stress",
	              map_shared_stress.runs,
	              map_shared_stress_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field cpu_hotplug_rider_fields[] = {
	STAT_FIELD_SUB(cpu_hotplug, runs),
	STAT_FIELD_SUB(cpu_hotplug, affinity_calls),
	STAT_FIELD_SUB(cpu_hotplug, sysfs_writes),
	STAT_FIELD_SUB(cpu_hotplug, open_eperm),
	STAT_FIELD_SUB(cpu_hotplug, write_eperm),
	STAT_FIELD_SUB(cpu_hotplug, write_ok),
	STAT_FIELD_SUB(cpu_hotplug, actual_offlines),
};

const struct stat_category cpu_hotplug_rider_category =
	STAT_CATEGORY("cpu_hotplug_rider",
	              cpu_hotplug.runs,
	              cpu_hotplug_rider_fields);

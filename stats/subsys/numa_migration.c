#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field numa_migration_fields[] = {
	STAT_FIELD_SUB(numa_migration, runs),
	STAT_FIELD_SUB(numa_migration, calls),
	STAT_FIELD_SUB(numa_migration, failed),
	STAT_FIELD_SUB(numa_migration, no_numa),
	STAT_FIELD_SUB(numa_migration, sysfs_unreadable),
};

const struct stat_category numa_migration_category =
	STAT_CATEGORY("numa_migration",
	              numa_migration.runs,
	              numa_migration_fields);

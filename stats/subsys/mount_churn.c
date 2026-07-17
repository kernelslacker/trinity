#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field mount_churn_fields[] = {
	STAT_FIELD_SUB(mount_churn, runs),
	STAT_FIELD_SUB(mount_churn, mounts),
	STAT_FIELD_SUB(mount_churn, umounts),
	STAT_FIELD_SUB(mount_churn, failed),
};

const struct stat_category mount_churn_category =
	STAT_CATEGORY("mount_churn",
	              mount_churn.runs,
	              mount_churn_fields);

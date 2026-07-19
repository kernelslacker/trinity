#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field cgroup_churn_fields[] = {
	STAT_FIELD_SUB(cgroup_churn, runs),
	STAT_FIELD_SUB(cgroup_churn, mkdirs),
	STAT_FIELD_SUB(cgroup_churn, rmdirs),
	STAT_FIELD_SUB(cgroup_churn, failed),
	STAT_FIELD_SUB(cgroup_churn, psi_race_runs),
	STAT_FIELD_SUB(cgroup_churn, psi_race_writes),
	STAT_FIELD_SUB(cgroup_churn, psi_race_failed),
};

const struct stat_category cgroup_churn_category =
	STAT_CATEGORY("cgroup_churn",
	              cgroup_churn.runs,
	              cgroup_churn_fields);

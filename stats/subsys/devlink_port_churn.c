#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field devlink_port_churn_fields[] = {
	STAT_FIELD_SUB(devlink_port_churn, iterations),
	STAT_FIELD_SUB(devlink_port_churn, split_ok),
	STAT_FIELD_SUB(devlink_port_churn, split_fail),
	STAT_FIELD_SUB(devlink_port_churn, reload_ok),
	STAT_FIELD_SUB(devlink_port_churn, reload_fail),
	STAT_FIELD_SUB(devlink_port_churn, create_skipped),
};

const struct stat_category devlink_port_churn_category =
	STAT_CATEGORY("devlink_port_churn",
	              devlink_port_churn.iterations,
	              devlink_port_churn_fields);

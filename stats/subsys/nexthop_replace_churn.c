#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field nexthop_replace_churn_fields[] = {
	STAT_FIELD_SUB(nexthop_replace_churn, runs),
	STAT_FIELD_SUB(nexthop_replace_churn, setup_failed),
	STAT_FIELD_SUB(nexthop_replace_churn, nh_setup_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, sentinel_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, replace_single_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, replace_group_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, route_add_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, route_del_ok),
	STAT_FIELD_SUB(nexthop_replace_churn, teardown_ok),
};

const struct stat_category nexthop_replace_churn_category =
	STAT_CATEGORY("nexthop_replace_churn",
		      nexthop_replace_churn_fields);

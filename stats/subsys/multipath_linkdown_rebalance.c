#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field multipath_linkdown_rebalance_fields[] = {
	STAT_FIELD_SUB(multipath_linkdown_rebalance, runs),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, setup_failed),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, v4_runs),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, v6_runs),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, legs_ok),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, route_ok),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, rebalance_triggers),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, flip_attempts),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, flip_writes_ok),
	STAT_FIELD_SUB(multipath_linkdown_rebalance, completed_ok),
};

const struct stat_category multipath_linkdown_rebalance_category =
	STAT_CATEGORY("multipath_linkdown_rebalance",
	              multipath_linkdown_rebalance_fields);

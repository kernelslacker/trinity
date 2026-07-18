#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field rtnl_vf_broadcast_getlink_fields[] = {
	STAT_FIELD_SUB(rtnl_vf_broadcast, runs),
	STAT_FIELD_SUB(rtnl_vf_broadcast, setup_ok),
	STAT_FIELD_SUB(rtnl_vf_broadcast, setup_failed),
	STAT_FIELD_SUB(rtnl_vf_broadcast, getlink_ok),
};

const struct stat_category rtnl_vf_broadcast_getlink_category =
	STAT_CATEGORY("rtnl_vf_broadcast_getlink",
	              rtnl_vf_broadcast.runs,
	              rtnl_vf_broadcast_getlink_fields);

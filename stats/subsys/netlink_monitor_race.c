#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field netlink_monitor_race_fields[] = {
	STAT_FIELD_SUB(netlink_monitor_race, runs),
	STAT_FIELD_SUB(netlink_monitor_race, setup_failed),
	STAT_FIELD_SUB(netlink_monitor_race, mon_open),
	STAT_FIELD_SUB(netlink_monitor_race, mut_open),
	STAT_FIELD_SUB(netlink_monitor_race, mut_op_ok),
	STAT_FIELD_SUB(netlink_monitor_race, recv_drained),
	STAT_FIELD_SUB(netlink_monitor_race, group_drop),
	STAT_FIELD_SUB(netlink_monitor_race, group_add),
};

const struct stat_category netlink_monitor_race_category =
	STAT_CATEGORY("netlink_monitor_race",
	              netlink_monitor_race.runs,
	              netlink_monitor_race_fields);

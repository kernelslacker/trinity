#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field netconf_inetdev_race_fields[] = {
	STAT_FIELD_SUB(netconf_inetdev_race, runs),
	STAT_FIELD_SUB(netconf_inetdev_race, setup_failed),
	STAT_FIELD_SUB(netconf_inetdev_race, getconf_v4_ok),
	STAT_FIELD_SUB(netconf_inetdev_race, getconf_v6_ok),
	STAT_FIELD_SUB(netconf_inetdev_race, dellink_ok),
	STAT_FIELD_SUB(netconf_inetdev_race, completed_ok),
};

const struct stat_category netconf_getdevconf_inetdev_teardown_race_category =
	STAT_CATEGORY("netconf_getdevconf_inetdev_teardown_race",
	              netconf_inetdev_race.runs,
	              netconf_inetdev_race_fields);

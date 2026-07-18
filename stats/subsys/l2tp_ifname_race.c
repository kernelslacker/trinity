#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field l2tp_ifname_race_fields[] = {
	STAT_FIELD_SUB(l2tp_ifname_race, runs),
	STAT_FIELD_SUB(l2tp_ifname_race, setup_failed),
	STAT_FIELD_SUB(l2tp_ifname_race, iter),
	STAT_FIELD_SUB(l2tp_ifname_race, tunnel_ok),
	STAT_FIELD_SUB(l2tp_ifname_race, tunnel_fail),
	STAT_FIELD_SUB(l2tp_ifname_race, fork_failed),
	STAT_FIELD_SUB(l2tp_ifname_race, spawn_pair_ok),
	STAT_FIELD_SUB(l2tp_ifname_race, sibling_reaped_ok),
	STAT_FIELD_SUB(l2tp_ifname_race, sibling_crashed),
};

const struct stat_category l2tp_ifname_race_category =
	STAT_CATEGORY("l2tp_ifname_race",
		l2tp_ifname_race.runs,
		l2tp_ifname_race_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field fnhe_pmtu_mtu_race_fields[] = {
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, runs),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, setup_failed),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, exceptions_installed),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, inject_failed),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, evictions_observed),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, mtu_flaps),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, negative_ctrl_runs),
	STAT_FIELD_SUB(fnhe_pmtu_mtu_race, completed_ok),
};

const struct stat_category fnhe_pmtu_mtu_race_category =
	STAT_CATEGORY("fnhe_pmtu_mtu_race",
	              fnhe_pmtu_mtu_race.runs,
	              fnhe_pmtu_mtu_race_fields);

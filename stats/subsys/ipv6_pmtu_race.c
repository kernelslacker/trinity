#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ipv6_pmtu_race_fields[] = {
	STAT_FIELD_SUB(ipv6_pmtu_race, runs),
	STAT_FIELD_SUB(ipv6_pmtu_race, setup_failed),
	STAT_FIELD_SUB(ipv6_pmtu_race, ptb_sent_ok),
	STAT_FIELD_SUB(ipv6_pmtu_race, dellink_ok),
	STAT_FIELD_SUB(ipv6_pmtu_race, completed_ok),
};

const struct stat_category ipv6_pmtu_race_category =
	STAT_CATEGORY("ipv6_pmtu_race",
	              ipv6_pmtu_race.runs,
	              ipv6_pmtu_race_fields);

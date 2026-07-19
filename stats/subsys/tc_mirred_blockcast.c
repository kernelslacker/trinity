#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tc_mirred_blockcast_fields[] = {
	STAT_FIELD_SUB(tc_mirred_blockcast, runs),
	STAT_FIELD_SUB(tc_mirred_blockcast, setup_failed),
	STAT_FIELD_SUB(tc_mirred_blockcast, qdisc_ok),
	STAT_FIELD_SUB(tc_mirred_blockcast, qdisc_fail),
	STAT_FIELD_SUB(tc_mirred_blockcast, filter_ok),
	STAT_FIELD_SUB(tc_mirred_blockcast, filter_fail),
	STAT_FIELD_SUB(tc_mirred_blockcast, packet_sent_ok),
};

const struct stat_category tc_mirred_blockcast_category =
	STAT_CATEGORY("tc_mirred_blockcast",
	              tc_mirred_blockcast.runs,
	              tc_mirred_blockcast_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tc_live_traffic_fields[] = {
	STAT_FIELD_SUB(tc_live_traffic, runs),
	STAT_FIELD_SUB(tc_live_traffic, setup_failed),
	STAT_FIELD_SUB(tc_live_traffic, qdisc_ok),
	STAT_FIELD_SUB(tc_live_traffic, qdisc_fail),
	STAT_FIELD_SUB(tc_live_traffic, filter_ok),
	STAT_FIELD_SUB(tc_live_traffic, filter_fail),
	STAT_FIELD_SUB(tc_live_traffic, filter_del_ok),
	STAT_FIELD_SUB(tc_live_traffic, filter_replace_ok),
	STAT_FIELD_SUB(tc_live_traffic, packet_sent_ok),
	STAT_FIELD_SUB(tc_live_traffic, link_del_ok),
	STAT_FIELD_SUB(tc_live_traffic, bpf_load_ok),
	STAT_FIELD_SUB(tc_live_traffic, xdp_load_ok),
	STAT_FIELD_SUB(tc_live_traffic, xdp_attach_ok),
};

const struct stat_category tc_live_traffic_category =
	STAT_CATEGORY("tc_live_traffic",
	              tc_live_traffic.runs,
	              tc_live_traffic_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field packet_qdisc_bypass_unanchored_l2_fields[] = {
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, runs),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, setup_failed),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, lane_a_sends),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, lane_b_sends),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, lane_a_errors),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, lane_b_errors),
	STAT_FIELD_SUB(packet_qdisc_bypass_unanchored_l2, completed_ok),
};

const struct stat_category packet_qdisc_bypass_unanchored_l2_category =
	STAT_CATEGORY("packet_qdisc_bypass_unanchored_l2",
	              packet_qdisc_bypass_unanchored_l2.runs,
	              packet_qdisc_bypass_unanchored_l2_fields);

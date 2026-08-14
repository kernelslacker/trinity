#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tc_standalone_action_fields[] = {
	STAT_FIELD_SUB(tc_standalone_action, runs),
	STAT_FIELD_SUB(tc_standalone_action, setup_failed),
	STAT_FIELD_SUB(tc_standalone_action, qdisc_ok),
	STAT_FIELD_SUB(tc_standalone_action, qdisc_fail),
	STAT_FIELD_SUB(tc_standalone_action, action_create_ok),
	STAT_FIELD_SUB(tc_standalone_action, action_create_fail),
	STAT_FIELD_SUB(tc_standalone_action, filter_ok),
	STAT_FIELD_SUB(tc_standalone_action, filter_fail),
	STAT_FIELD_SUB(tc_standalone_action, packet_sent_ok),
	STAT_FIELD_SUB(tc_standalone_action, action_replace_ok),
	STAT_FIELD_SUB(tc_standalone_action, tc_action_replace_concurrent),
	STAT_FIELD_SUB(tc_standalone_action, action_del_ok),
	STAT_FIELD_SUB(tc_standalone_action, link_del_ok),
};

const struct stat_category tc_standalone_action_category =
	STAT_CATEGORY("tc_standalone_action",
	              tc_standalone_action.runs,
	              tc_standalone_action_fields);

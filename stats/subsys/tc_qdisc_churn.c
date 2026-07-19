#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tc_qdisc_churn_fields[] = {
	STAT_FIELD_SUB(tc_qdisc_churn, runs),
	STAT_FIELD_SUB(tc_qdisc_churn, setup_failed),
	STAT_FIELD_SUB(tc_qdisc_churn, link_create_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, qdisc_create_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, tclass_create_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, tfilter_create_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, packet_sent_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, qdisc_replace_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, tfilter_del_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, qdisc_del_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, link_del_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, peek_stack_runs),
	STAT_FIELD_SUB(tc_qdisc_churn, peek_stack_install_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, peek_stack_install_fail),
	STAT_FIELD_SUB(tc_qdisc_churn, peek_stack_burst_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, bridge_parent_runs),
	STAT_FIELD_SUB(tc_qdisc_churn, bridge_dellink_race_ok),
	STAT_FIELD_SUB(tc_qdisc_churn, gso_burst_ok),
};

const struct stat_category tc_qdisc_churn_category =
	STAT_CATEGORY("tc_qdisc_churn",
	              tc_qdisc_churn.runs,
	              tc_qdisc_churn_fields);

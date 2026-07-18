#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field vlan_filter_churn_fields[] = {
	STAT_FIELD_SUB(vlan_filter_churn, runs),
	STAT_FIELD_SUB(vlan_filter_churn, setup_failed),
	STAT_FIELD_SUB(vlan_filter_churn, veth_create_ok),
	STAT_FIELD_SUB(vlan_filter_churn, vlan_add_ok),
	STAT_FIELD_SUB(vlan_filter_churn, vlan_del_ok),
};

const struct stat_category vlan_filter_churn_category =
	STAT_CATEGORY("vlan_filter_churn",
	              vlan_filter_churn.runs,
	              vlan_filter_churn_fields);

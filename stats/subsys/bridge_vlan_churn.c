#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_vlan_churn_fields[] = {
	STAT_FIELD_SUB(bridge_vlan_churn, runs),
	STAT_FIELD_SUB(bridge_vlan_churn, setup_failed),
	STAT_FIELD_SUB(bridge_vlan_churn, bridge_create_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, veth_create_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, vlan_add_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, vlan_del_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, tunnel_add_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, mst_set_ok),
	STAT_FIELD_SUB(bridge_vlan_churn, raw_send_ok),
};

const struct stat_category bridge_vlan_churn_category =
	STAT_CATEGORY("bridge_vlan_churn",
	              bridge_vlan_churn.runs,
	              bridge_vlan_churn_fields);

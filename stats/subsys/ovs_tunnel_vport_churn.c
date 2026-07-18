#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ovs_tunnel_vport_churn_fields[] = {
	STAT_FIELD_SUB(ovs_tunnel_vport_churn, runs),
	STAT_FIELD_SUB(ovs_tunnel_vport_churn, setup_failed),
	STAT_FIELD_SUB(ovs_tunnel_vport_churn, create_ok),
	STAT_FIELD_SUB(ovs_tunnel_vport_churn, delete_ok),
	STAT_FIELD_SUB(ovs_tunnel_vport_churn, race_dellink_attempted),
};

const struct stat_category ovs_tunnel_vport_churn_category =
	STAT_CATEGORY("ovs_tunnel_vport_churn",
	              ovs_tunnel_vport_churn.runs,
	              ovs_tunnel_vport_churn_fields);

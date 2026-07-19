#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field vxlan_encap_churn_fields[] = {
	STAT_FIELD_SUB(vxlan_encap_churn, runs),
	STAT_FIELD_SUB(vxlan_encap_churn, setup_failed),
	STAT_FIELD_SUB(vxlan_encap_churn, link_create_ok),
	STAT_FIELD_SUB(vxlan_encap_churn, fdb_add_ok),
	STAT_FIELD_SUB(vxlan_encap_churn, link_up_ok),
	STAT_FIELD_SUB(vxlan_encap_churn, packet_sent_ok),
	STAT_FIELD_SUB(vxlan_encap_churn, link_del_ok),
};

const struct stat_category vxlan_encap_churn_category =
	STAT_CATEGORY("vxlan_encap_churn",
	              vxlan_encap_churn.runs,
	              vxlan_encap_churn_fields);

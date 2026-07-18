#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field flowtable_encap_vlan_fields[] = {
	STAT_FIELD_SUB(flowtable_vlan, runs),
	STAT_FIELD_SUB(flowtable_vlan, setup_ok),
	STAT_FIELD_SUB(flowtable_vlan, setup_failed),
	STAT_FIELD_SUB(flowtable_vlan, offloaded_pkts),
	STAT_FIELD_SUB(flowtable_vlan, gso_sends),
	STAT_FIELD_SUB(flowtable_vlan, vlan_teardown_races),
	STAT_FIELD_SUB(flowtable_vlan, unsupported_latched),
};

const struct stat_category flowtable_encap_vlan_category =
	STAT_CATEGORY("flowtable_encap_vlan",
	              flowtable_vlan.runs,
	              flowtable_encap_vlan_fields);

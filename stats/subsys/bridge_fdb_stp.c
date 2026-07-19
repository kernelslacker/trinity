#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_fdb_stp_fields[] = {
	STAT_FIELD_SUB(bridge_fdb_stp, runs),
	STAT_FIELD_SUB(bridge_fdb_stp, setup_failed),
	STAT_FIELD_SUB(bridge_fdb_stp, bridge_create_ok),
	STAT_FIELD_SUB(bridge_fdb_stp, veth_create_ok),
	STAT_FIELD_SUB(bridge_fdb_stp, raw_send_ok),
	STAT_FIELD_SUB(bridge_fdb_stp, stp_toggle_ok),
	STAT_FIELD_SUB(bridge_fdb_stp, fdb_del_ok),
	STAT_FIELD_SUB(bridge_fdb_stp, link_del_ok),
	STAT_FIELD_JSON_SUB(bridge_fdb_stp, bridge_vlan_mass_runs, "vlan_mass_runs"),
	STAT_FIELD_JSON_SUB(bridge_fdb_stp, bridge_vlan_mass_max_n, "vlan_mass_max_n"),
	STAT_FIELD_JSON_SUB(bridge_fdb_stp, bridge_vlan_mass_enotbufs, "vlan_mass_enotbufs"),
};

const struct stat_category bridge_fdb_stp_category =
	STAT_CATEGORY("bridge_fdb_stp",
	              bridge_fdb_stp.runs,
	              bridge_fdb_stp_fields);

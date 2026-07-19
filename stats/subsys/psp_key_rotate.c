#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field psp_key_rotate_fields[] = {
	STAT_FIELD_SUB(psp_key_rotate, runs),
	STAT_FIELD_SUB(psp_key_rotate, setup_failed),
	STAT_FIELD_SUB(psp_key_rotate, netdev_create_ok),
	STAT_FIELD_SUB(psp_key_rotate, family_resolve_ok),
	STAT_FIELD_SUB(psp_key_rotate, dev_get_ok),
	STAT_FIELD_SUB(psp_key_rotate, key_install_ok),
	STAT_FIELD_SUB(psp_key_rotate, spi_set_ok),
	STAT_FIELD_SUB(psp_key_rotate, send_ok),
	STAT_FIELD_SUB(psp_key_rotate, rotate_ok),
	STAT_FIELD_SUB(psp_key_rotate, spi_switch_ok),
	STAT_FIELD_SUB(psp_key_rotate, shutdown_ok),
	STAT_FIELD_SUB(psp_key_rotate, devlink_port_churn_runs),
	STAT_FIELD_SUB(psp_key_rotate, devlink_port_churn_port_add_ok),
	STAT_FIELD_SUB(psp_key_rotate, devlink_port_churn_port_del_ok),
	STAT_FIELD_SUB(psp_key_rotate, devlink_port_churn_vf_spawn_ok),
	STAT_FIELD_SUB(psp_key_rotate, devlink_port_churn_unsupported_latched),
};

const struct stat_category psp_key_rotate_category =
	STAT_CATEGORY("psp_key_rotate",
	              psp_key_rotate.runs,
	              psp_key_rotate_fields);

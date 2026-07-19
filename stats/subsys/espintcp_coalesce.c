#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field espintcp_coalesce_fields[] = {
	STAT_FIELD_SUB(espintcp_coalesce, runs),
	STAT_FIELD_SUB(espintcp_coalesce, setup_failed),
	STAT_FIELD_SUB(espintcp_coalesce, ulp_install_ok),
	STAT_FIELD_SUB(espintcp_coalesce, ulp_install_failed),
	STAT_FIELD_SUB(espintcp_coalesce, send_ok),
	STAT_FIELD_SUB(espintcp_coalesce, keepalive_ok),
	STAT_FIELD_SUB(espintcp_coalesce, no_ingress_arm_ok),
	STAT_FIELD_SUB(espintcp_coalesce, no_ingress_setup_failed),
	STAT_FIELD_SUB(espintcp_coalesce, no_ingress_dellink_ok),
};

const struct stat_category espintcp_coalesce_category =
	STAT_CATEGORY("espintcp_coalesce_churn",
	              espintcp_coalesce.runs,
	              espintcp_coalesce_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tipc_link_churn_fields[] = {
	STAT_FIELD_SUB(tipc_link_churn, runs),
	STAT_FIELD_SUB(tipc_link_churn, setup_failed),
	STAT_FIELD_SUB(tipc_link_churn, bearer_enable_ok),
	STAT_FIELD_SUB(tipc_link_churn, sock_rdm_ok),
	STAT_FIELD_SUB(tipc_link_churn, topsrv_connect_ok),
	STAT_FIELD_SUB(tipc_link_churn, sub_ports_sent),
	STAT_FIELD_SUB(tipc_link_churn, publish_ok),
	STAT_FIELD_SUB(tipc_link_churn, bearer_disable_ok),
};

const struct stat_category tipc_link_churn_category =
	STAT_CATEGORY("tipc_link_churn",
	              tipc_link_churn.runs,
	              tipc_link_churn_fields);

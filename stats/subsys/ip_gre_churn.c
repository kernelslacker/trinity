#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ip_gre_churn_fields[] = {
	STAT_FIELD_SUB(ip_gre_churn, runs),
	STAT_FIELD_SUB(ip_gre_churn, setup_failed),
	STAT_FIELD_SUB(ip_gre_churn, link_create_ok),
	STAT_FIELD_SUB(ip_gre_churn, link_up_ok),
	STAT_FIELD_SUB(ip_gre_churn, packet_sent_ok),
	STAT_FIELD_SUB(ip_gre_churn, link_del_ok),
};

const struct stat_category ip_gre_churn_category =
	STAT_CATEGORY("ip_gre_churn",
	              ip_gre_churn.runs,
	              ip_gre_churn_fields);

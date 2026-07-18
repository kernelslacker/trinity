#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field igmp_mld_source_churn_fields[] = {
	STAT_FIELD_SUB(igmp_mld_source_churn, runs),
	STAT_FIELD_SUB(igmp_mld_source_churn, setup_failed),
	STAT_FIELD_SUB(igmp_mld_source_churn, join_ok),
	STAT_FIELD_SUB(igmp_mld_source_churn, leave_ok),
	STAT_FIELD_SUB(igmp_mld_source_churn, block_ok),
	STAT_FIELD_SUB(igmp_mld_source_churn, msfilter_ok),
	STAT_FIELD_SUB(igmp_mld_source_churn, drop_ok),
	STAT_FIELD_SUB(igmp_mld_source_churn, send_ok),
};

const struct stat_category igmp_mld_source_churn_category =
	STAT_CATEGORY("igmp_mld_source_churn",
	              igmp_mld_source_churn.runs,
	              igmp_mld_source_churn_fields);

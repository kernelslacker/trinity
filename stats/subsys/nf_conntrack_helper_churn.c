#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field nf_conntrack_helper_churn_fields[] = {
	STAT_FIELD_SUB(nf_conntrack_helper_churn, runs),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, setup_failed),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, no_helper),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, attach_ok),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, attach_fail),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, exp_ok),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, packet_sent),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, delete_ok),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, zone_swap),
	STAT_FIELD_SUB(nf_conntrack_helper_churn, detach_ok),
};

const struct stat_category nf_conntrack_helper_churn_category =
	STAT_CATEGORY("nf_conntrack_helper_churn",
	              nf_conntrack_helper_churn.runs,
	              nf_conntrack_helper_churn_fields);

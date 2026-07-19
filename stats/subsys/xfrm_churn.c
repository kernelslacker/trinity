#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field xfrm_churn_fields[] = {
	STAT_FIELD_SUB(xfrm_churn, runs),
	STAT_FIELD_SUB(xfrm_churn, setup_failed),
	STAT_FIELD_SUB(xfrm_churn, sa_added),
	STAT_FIELD_SUB(xfrm_churn, tunnel_sa_added),
	STAT_FIELD_SUB(xfrm_churn, iptfs_sa_added),
	STAT_FIELD_SUB(xfrm_churn, sa_updated),
	STAT_FIELD_SUB(xfrm_churn, sa_deleted),
	STAT_FIELD_SUB(xfrm_churn, pol_added),
	STAT_FIELD_SUB(xfrm_churn, pol_deleted),
	STAT_FIELD_SUB(xfrm_churn, esp_sent),
	STAT_FIELD_SUB(xfrm_churn, zc_sent),
	STAT_FIELD_SUB(xfrm_churn, zc_errq_drained),
	STAT_FIELD_SUB(xfrm_churn, pfkey_send_ok),
	STAT_FIELD_SUB(xfrm_churn, burn_runs),
	STAT_FIELD_SUB(xfrm_churn, burn_throttled),
	STAT_FIELD_SUB(xfrm_churn, burn_completed),
};

const struct stat_category xfrm_churn_category =
	STAT_CATEGORY("xfrm_churn",
	              xfrm_churn.runs,
	              xfrm_churn_fields);

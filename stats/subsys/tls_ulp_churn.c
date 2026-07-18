#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tls_ulp_churn_fields[] = {
	STAT_FIELD_SUB(tls_ulp_churn, runs),
	STAT_FIELD_SUB(tls_ulp_churn, setup_failed),
	STAT_FIELD_SUB(tls_ulp_churn, ulp_install_ok),
	STAT_FIELD_SUB(tls_ulp_churn, tx_install_ok),
	STAT_FIELD_SUB(tls_ulp_churn, send_ok),
	STAT_FIELD_SUB(tls_ulp_churn, splice_ok),
	STAT_FIELD_SUB(tls_ulp_churn, rekey_ok),
	STAT_FIELD_SUB(tls_ulp_churn, recv_ok),
};

const struct stat_category tls_ulp_churn_category =
	STAT_CATEGORY("tls_ulp_churn",
	              tls_ulp_churn.runs,
	              tls_ulp_churn_fields);

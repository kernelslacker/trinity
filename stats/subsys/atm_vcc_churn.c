#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field atm_vcc_churn_fields[] = {
	STAT_FIELD_SUB(atm_vcc_churn, runs),
	STAT_FIELD_SUB(atm_vcc_churn, unsupported),
	STAT_FIELD_SUB(atm_vcc_churn, socket_ok),
	STAT_FIELD_SUB(atm_vcc_churn, ioctls_sent),
	STAT_FIELD_SUB(atm_vcc_churn, kernel_rejected),
};

const struct stat_category atm_vcc_churn_category =
	STAT_CATEGORY("atm_vcc_churn",
	              atm_vcc_churn.runs,
	              atm_vcc_churn_fields);

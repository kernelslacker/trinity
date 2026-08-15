#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD_SUB(nat_t_churn, runs),
	STAT_FIELD_SUB(nat_t_churn, setup_failed),
	STAT_FIELD_SUB(nat_t_churn, sa_added),
	STAT_FIELD_SUB(nat_t_churn, sa_deleted),
	STAT_FIELD_SUB(nat_t_churn, frames_sent),
	STAT_FIELD_SUB(nat_t_churn, xfrm6_setup_ok),
	STAT_FIELD_SUB(nat_t_churn, xfrm6_setup_fail),
	STAT_FIELD_SUB(nat_t_churn, xfrm6_sendto_runs),
	STAT_FIELD_SUB(nat_t_churn, xfrm6_delsa_races),
	STAT_FIELD_SUB(nat_t_churn, lo_up_fail),
};

/* NOTE: text-walker conversion must gate on (runs || lo_up_fail); see
 * 3db4b71cae43 ("stats: render lo_up_fail outside nat_t_churn.runs gate").
 * STAT_CATEGORY supports a single gate_offset only; split the gate at
 * the walker call site when converting. */
const struct stat_category nat_t_churn_category =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn.runs,
	              nat_t_churn_fields);

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
};

const struct stat_category nat_t_churn_category =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn.runs,
	              nat_t_churn_fields);

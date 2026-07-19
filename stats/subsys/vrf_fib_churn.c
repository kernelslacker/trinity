#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field vrf_fib_churn_fields[] = {
	STAT_FIELD_SUB(vrf_fib_churn, runs),
	STAT_FIELD_SUB(vrf_fib_churn, setup_failed),
	STAT_FIELD_SUB(vrf_fib_churn, link_ok),
	STAT_FIELD_SUB(vrf_fib_churn, addr_ok),
	STAT_FIELD_SUB(vrf_fib_churn, up_ok),
	STAT_FIELD_SUB(vrf_fib_churn, rule_added),
	STAT_FIELD_SUB(vrf_fib_churn, bound),
	STAT_FIELD_SUB(vrf_fib_churn, sendto_ok),
	STAT_FIELD_SUB(vrf_fib_churn, rule2_added),
	STAT_FIELD_SUB(vrf_fib_churn, rule_removed),
	STAT_FIELD_SUB(vrf_fib_churn, link_removed),
};

const struct stat_category vrf_fib_churn_category =
	STAT_CATEGORY("vrf_fib_churn",
	              vrf_fib_churn.runs,
	              vrf_fib_churn_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ipset_churn_fields[] = {
	STAT_FIELD_SUB(ipset_churn, runs),
	STAT_FIELD_SUB(ipset_churn, setup_failed),
	STAT_FIELD_SUB(ipset_churn, create_ok),
	STAT_FIELD_SUB(ipset_churn, create_fail),
	STAT_FIELD_SUB(ipset_churn, add_ok),
	STAT_FIELD_SUB(ipset_churn, test_ok),
	STAT_FIELD_SUB(ipset_churn, del_ok),
	STAT_FIELD_SUB(ipset_churn, header_ok),
	STAT_FIELD_SUB(ipset_churn, list_ok),
	STAT_FIELD_SUB(ipset_churn, swap_ok),
	STAT_FIELD_SUB(ipset_churn, flush_ok),
	STAT_FIELD_SUB(ipset_churn, destroy_ok),
};

const struct stat_category ipset_churn_category =
	STAT_CATEGORY("ipset_churn",
	              ipset_churn.runs,
	              ipset_churn_fields);

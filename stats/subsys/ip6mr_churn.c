#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ip6mr_churn_fields[] = {
	STAT_FIELD_SUB(ip6mr_churn, iters),
	STAT_FIELD_SUB(ip6mr_churn, eperm),
	STAT_FIELD_SUB(ip6mr_churn, emit_ok),
};

const struct stat_category ip6mr_churn_category =
	STAT_CATEGORY("ip6mr_churn",
	              ip6mr_churn.iters,
	              ip6mr_churn_fields);

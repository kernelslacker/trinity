#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_conntrack_churn_fields[] = {
	STAT_FIELD_SUB(bridge_ct, runs),
	STAT_FIELD_SUB(bridge_ct, flushes),
	STAT_FIELD_SUB(bridge_ct, pkts_sent),
};

const struct stat_category bridge_conntrack_churn_category =
	STAT_CATEGORY("bridge_conntrack_churn",
	              bridge_ct.runs,
	              bridge_conntrack_churn_fields);

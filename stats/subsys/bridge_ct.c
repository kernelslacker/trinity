#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_conntrack_churn_fields[] = {
	STAT_FIELD_SUB(bridge_ct, runs),
	STAT_FIELD_SUB(bridge_ct, flushes),
	STAT_FIELD_SUB(bridge_ct, pkts_sent),
	STAT_FIELD_SUB(bridge_ct, pkts_conntracked),
	STAT_FIELD_SUB(bridge_ct, ct_timeout_obj_ok),
	STAT_FIELD_SUB(bridge_ct, ct_mangle_ok),
};

const struct stat_category bridge_conntrack_churn_category =
	STAT_CATEGORY("bridge_conntrack_churn",
	              bridge_conntrack_churn_fields);

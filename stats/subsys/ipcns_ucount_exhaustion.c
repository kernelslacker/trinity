#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ipcns_ucount_exhaustion_fields[] = {
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, runs),
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, inner_crashed),
};

const struct stat_category ipcns_ucount_exhaustion_category =
	STAT_CATEGORY("ipcns_ucount_exhaustion",
	              ipcns_ucount_exhaustion.runs,
	              ipcns_ucount_exhaustion_fields);

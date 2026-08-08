#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ipcns_ucount_exhaustion_fields[] = {
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, runs),
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, inner_crashed),
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, limit_install_failed),
	STAT_FIELD_SUB(ipcns_ucount_exhaustion, inner_timeout),
};

const struct stat_category ipcns_ucount_exhaustion_category =
	STAT_CATEGORY("ipcns_ucount_exhaustion",
	              ipcns_ucount_exhaustion.runs,
	              ipcns_ucount_exhaustion_fields);

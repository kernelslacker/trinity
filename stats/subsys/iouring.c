#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_flood_fields[] = {
	STAT_FIELD_SUB(iouring, runs),
	STAT_FIELD_SUB(iouring, submits),
	STAT_FIELD_SUB(iouring, reaped),
	STAT_FIELD_SUB(iouring, failed),
};

const struct stat_category iouring_flood_category =
	STAT_CATEGORY("iouring_flood",
	              iouring.runs,
	              iouring_flood_fields);

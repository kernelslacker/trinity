#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field madvise_cycler_fields[] = {
	STAT_FIELD_SUB(madvise_cycler, runs),
	STAT_FIELD_SUB(madvise_cycler, calls),
	STAT_FIELD_SUB(madvise_cycler, failed),
};

const struct stat_category madvise_cycler_category =
	STAT_CATEGORY("madvise_cycler",
	              madvise_cycler.runs,
	              madvise_cycler_fields);

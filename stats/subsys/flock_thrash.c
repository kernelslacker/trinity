#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field flock_thrash_fields[] = {
	STAT_FIELD_SUB(flock_thrash, runs),
	STAT_FIELD_SUB(flock_thrash, locks),
	STAT_FIELD_SUB(flock_thrash, failed),
};

const struct stat_category flock_thrash_category =
	STAT_CATEGORY("flock_thrash",
	              flock_thrash.runs,
	              flock_thrash_fields);

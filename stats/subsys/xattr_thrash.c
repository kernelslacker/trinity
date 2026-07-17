#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field xattr_thrash_fields[] = {
	STAT_FIELD_SUB(xattr_thrash, runs),
	STAT_FIELD_SUB(xattr_thrash, set),
	STAT_FIELD_SUB(xattr_thrash, get),
	STAT_FIELD_SUB(xattr_thrash, remove),
	STAT_FIELD_SUB(xattr_thrash, list),
	STAT_FIELD_SUB(xattr_thrash, failed),
};

const struct stat_category xattr_thrash_category =
	STAT_CATEGORY("xattr_thrash",
	              xattr_thrash.runs,
	              xattr_thrash_fields);

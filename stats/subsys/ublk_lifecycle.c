#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ublk_lifecycle_fields[] = {
	STAT_FIELD_SUB(ublk_lifecycle, iters),
	STAT_FIELD_SUB(ublk_lifecycle, eperm),
	STAT_FIELD_SUB(ublk_lifecycle, add_ok),
	STAT_FIELD_SUB(ublk_lifecycle, fetch_ok),
	STAT_FIELD_SUB(ublk_lifecycle, del_ok),
	STAT_FIELD_SUB(ublk_lifecycle, race_observed),
};

const struct stat_category ublk_lifecycle_category =
	STAT_CATEGORY("ublk_lifecycle",
	              ublk_lifecycle.iters,
	              ublk_lifecycle_fields);

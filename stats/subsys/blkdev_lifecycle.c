#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field blkdev_lifecycle_race_fields[] = {
	STAT_FIELD_SUB(blkdev_lifecycle, runs),
	STAT_FIELD_SUB(blkdev_lifecycle, setup_failed),
	STAT_FIELD_SUB(blkdev_lifecycle, set_fd_ok),
	STAT_FIELD_SUB(blkdev_lifecycle, clr_fd),
	STAT_FIELD_SUB(blkdev_lifecycle, ebusy),
	STAT_FIELD_SUB(blkdev_lifecycle, rescans),
};

const struct stat_category blkdev_lifecycle_race_category =
	STAT_CATEGORY("blkdev_lifecycle_race",
	              blkdev_lifecycle.runs,
	              blkdev_lifecycle_race_fields);

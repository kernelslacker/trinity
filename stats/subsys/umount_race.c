#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field umount_race_fields[] = {
	STAT_FIELD_SUB(umount_race, runs),
	STAT_FIELD_SUB(umount_race, picks),
	STAT_FIELD_SUB(umount_race, forks),
	STAT_FIELD_SUB(umount_race, umounts),
	STAT_FIELD_SUB(umount_race, umount_failed),
	STAT_FIELD_SUB(umount_race, setup_failed),
};

const struct stat_category umount_race_category =
	STAT_CATEGORY("umount_race",
	              umount_race.runs,
	              umount_race_fields);

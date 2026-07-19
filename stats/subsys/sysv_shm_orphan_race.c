#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sysv_shm_orphan_race_fields[] = {
	STAT_FIELD_SUB(sysv_shm_orphan_race, runs),
	STAT_FIELD_SUB(sysv_shm_orphan_race, setup_failed),
	STAT_FIELD_SUB(sysv_shm_orphan_race, shmget_ok),
	STAT_FIELD_SUB(sysv_shm_orphan_race, shmget_failed),
	STAT_FIELD_SUB(sysv_shm_orphan_race, attach_ok),
	STAT_FIELD_SUB(sysv_shm_orphan_race, attach_failed),
	STAT_FIELD_SUB(sysv_shm_orphan_race, rmid_ok),
	STAT_FIELD_SUB(sysv_shm_orphan_race, rmid_failed),
	STAT_FIELD_SUB(sysv_shm_orphan_race, sibling_spawn_ok),
	STAT_FIELD_SUB(sysv_shm_orphan_race, sibling_spawn_failed),
	STAT_FIELD_SUB(sysv_shm_orphan_race, sibling_reaped_ok),
	STAT_FIELD_SUB(sysv_shm_orphan_race, sibling_crashed),
};

const struct stat_category sysv_shm_orphan_race_category =
	STAT_CATEGORY("sysv_shm_orphan_race",
	              sysv_shm_orphan_race.runs,
	              sysv_shm_orphan_race_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field pfkey_spd_walk_fields[] = {
	STAT_FIELD_SUB(pfkey_spd_walk, runs),
	STAT_FIELD_SUB(pfkey_spd_walk, setup_failed),
	STAT_FIELD_SUB(pfkey_spd_walk, iter),
	STAT_FIELD_SUB(pfkey_spd_walk, fork_failed),
	STAT_FIELD_SUB(pfkey_spd_walk, spawn_pair_ok),
	STAT_FIELD_SUB(pfkey_spd_walk, sibling_reaped_ok),
	STAT_FIELD_SUB(pfkey_spd_walk, sibling_crashed),
	STAT_FIELD_SUB(pfkey_spd_walk, spdget_resolved),
	STAT_FIELD_SUB(pfkey_spd_walk, spdget_missed),
};

const struct stat_category pfkey_spd_walk_category =
	STAT_CATEGORY("pfkey_spd_walk",
	              pfkey_spd_walk.runs,
	              pfkey_spd_walk_fields);

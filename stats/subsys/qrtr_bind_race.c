#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field qrtr_bind_race_fields[] = {
	STAT_FIELD_SUB(qrtr_bind_race, runs),
	STAT_FIELD_SUB(qrtr_bind_race, setup_failed),
	STAT_FIELD_SUB(qrtr_bind_race, iter),
	STAT_FIELD_SUB(qrtr_bind_race, fork_failed),
	STAT_FIELD_SUB(qrtr_bind_race, spawn_pair_ok),
	STAT_FIELD_SUB(qrtr_bind_race, sibling_reaped_ok),
	STAT_FIELD_SUB(qrtr_bind_race, sibling_crashed),
	STAT_FIELD_SUB(qrtr_bind_race, setup_fail),
};

const struct stat_category qrtr_bind_race_category =
	STAT_CATEGORY("qrtr_bind_race",
	              qrtr_bind_race.runs,
	              qrtr_bind_race_fields);

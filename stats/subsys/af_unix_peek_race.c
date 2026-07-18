#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field af_unix_peek_race_fields[] = {
	STAT_FIELD_SUB(af_unix_peek_race, runs),
	STAT_FIELD_SUB(af_unix_peek_race, setup_failed),
	STAT_FIELD_SUB(af_unix_peek_race, pair_open_ok),
	STAT_FIELD_SUB(af_unix_peek_race, peek_off_armed),
	STAT_FIELD_SUB(af_unix_peek_race, peek_off_rejected),
	STAT_FIELD_SUB(af_unix_peek_race, send_ok),
	STAT_FIELD_SUB(af_unix_peek_race, shutdown_ok),
	STAT_FIELD_SUB(af_unix_peek_race, pair_rebuilds),
	STAT_FIELD_SUB(af_unix_peek_race, sibling_spawn_ok),
	STAT_FIELD_SUB(af_unix_peek_race, sibling_spawn_failed),
	STAT_FIELD_SUB(af_unix_peek_race, sibling_reaped_ok),
	STAT_FIELD_SUB(af_unix_peek_race, sibling_crashed),
};

const struct stat_category af_unix_peek_race_category =
	STAT_CATEGORY("af_unix_peek_race",
		af_unix_peek_race.runs,
		af_unix_peek_race_fields);

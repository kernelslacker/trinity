#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field process_mrelease_race_fields[] = {
	STAT_FIELD_SUB(process_mrelease_race, runs),
	STAT_FIELD_SUB(process_mrelease_race, kill_rounds),
	STAT_FIELD_SUB(process_mrelease_race, success),
	STAT_FIELD_SUB(process_mrelease_race, esrch),
	STAT_FIELD_SUB(process_mrelease_race, einval),
	STAT_FIELD_SUB(process_mrelease_race, eintr),
	STAT_FIELD_SUB(process_mrelease_race, other_fail),
	STAT_FIELD_SUB(process_mrelease_race, reap_slow),
	STAT_FIELD_SUB(process_mrelease_race, racer_unreported),
	STAT_FIELD_SUB(process_mrelease_race, control_esrch),
	STAT_FIELD_SUB(process_mrelease_race, control_einval),
	STAT_FIELD_SUB(process_mrelease_race, control_unexpected_success),
};

const struct stat_category process_mrelease_race_category =
	STAT_CATEGORY("process_mrelease_race",
	              process_mrelease_race_fields);

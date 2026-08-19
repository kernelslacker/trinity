#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sockmap_cork_race_fields[] = {
	STAT_FIELD_SUB(sockmap_cork_race, runs),
	STAT_FIELD_SUB(sockmap_cork_race, setup_failed),
	STAT_FIELD_SUB(sockmap_cork_race, map_failed),
	STAT_FIELD_SUB(sockmap_cork_race, prog_failed),
	STAT_FIELD_SUB(sockmap_cork_race, attach_failed),
	STAT_FIELD_SUB(sockmap_cork_race, enroll_failed),
	STAT_FIELD_SUB(sockmap_cork_race, races_run),
};

const struct stat_category sockmap_cork_race_category =
	STAT_CATEGORY("sockmap_cork_race",
	              sockmap_cork_race_fields);

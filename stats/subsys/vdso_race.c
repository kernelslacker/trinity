#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field vdso_mremap_race_fields[] = {
	STAT_FIELD_SUB(vdso_race, runs),
	STAT_FIELD_SUB(vdso_race, mutations),
	STAT_FIELD_SUB(vdso_race, helper_segvs),
};

const struct stat_category vdso_mremap_race_category =
	STAT_CATEGORY("vdso_mremap_race",
	              vdso_race.runs,
	              vdso_mremap_race_fields);

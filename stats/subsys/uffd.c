#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field uffd_churn_fields[] = {
	STAT_FIELD_SUB(uffd, runs),
	STAT_FIELD_SUB(uffd, registers),
	STAT_FIELD_SUB(uffd, unregisters),
	STAT_FIELD_SUB(uffd, failed),
};

const struct stat_category uffd_churn_category =
	STAT_CATEGORY("uffd_churn",
	              uffd.runs,
	              uffd_churn_fields);

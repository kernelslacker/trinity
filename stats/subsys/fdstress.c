#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field fdstress_fields[] = {
	STAT_FIELD_SUB(fdstress, close_reopen),
	STAT_FIELD_SUB(fdstress, dup2_replace),
	STAT_FIELD_SUB(fdstress, type_confusion),
	STAT_FIELD_SUB(fdstress, cloexec_toggle),
};

const struct stat_category fdstress_category =
	STAT_CATEGORY("fdstress",
	              fdstress.close_reopen,
	              fdstress_fields);

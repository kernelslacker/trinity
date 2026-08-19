#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field posix_timer_fields[] = {
	STAT_FIELD_SUB(posix_timer, sigev_delivered),
	STAT_FIELD_SUB(posix_timer, sigev_missed),
	STAT_FIELD_SUB(posix_timer, sigev_cookie_bad),
};

const struct stat_category posix_timer_category =
	STAT_CATEGORY("posix_timer",
	              posix_timer_fields);

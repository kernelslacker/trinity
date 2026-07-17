#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field pipe_thrash_fields[] = {
	STAT_FIELD_SUB(pipe_thrash, runs),
	STAT_FIELD_SUB(pipe_thrash, pipes),
	STAT_FIELD_SUB(pipe_thrash, socketpairs),
	STAT_FIELD_SUB(pipe_thrash, alloc_failed),
};

const struct stat_category pipe_thrash_category =
	STAT_CATEGORY("pipe_thrash",
	              pipe_thrash.runs,
	              pipe_thrash_fields);

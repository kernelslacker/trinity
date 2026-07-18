#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_eventfd_fields[] = {
	STAT_FIELD_SUB(iouring_eventfd, register_ok),
	STAT_FIELD_SUB(iouring_eventfd, register_fail),
	STAT_FIELD_SUB(iouring_eventfd, recursive_runs),
	STAT_FIELD_SUB(iouring_eventfd, recursive_cqes),
};

const struct stat_category iouring_eventfd_category =
	STAT_CATEGORY("iouring_eventfd",
	              iouring_eventfd.register_ok,
	              iouring_eventfd_fields);

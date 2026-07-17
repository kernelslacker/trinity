#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field epoll_volatility_fields[] = {
	STAT_FIELD_SUB(epoll_volatility, runs),
	STAT_FIELD_SUB(epoll_volatility, ctl_calls),
	STAT_FIELD_SUB(epoll_volatility, failed),
};

const struct stat_category epoll_volatility_category =
	STAT_CATEGORY("epoll_volatility",
	              epoll_volatility.runs,
	              epoll_volatility_fields);

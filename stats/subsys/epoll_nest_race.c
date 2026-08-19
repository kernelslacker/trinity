#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field epoll_nest_race_fields[] = {
	STAT_FIELD_SUB(epoll_nest_race, runs),
	STAT_FIELD_SUB(epoll_nest_race, ctl_calls),
	STAT_FIELD_SUB(epoll_nest_race, racer_laps),
	STAT_FIELD_SUB(epoll_nest_race, failed),
};

const struct stat_category epoll_nest_race_category =
	STAT_CATEGORY("epoll_nest_race",
	              epoll_nest_race_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tcp_md5_listener_race_fields[] = {
	STAT_FIELD_SUB(tcp_md5_listener_race, runs),
	STAT_FIELD_SUB(tcp_md5_listener_race, setup_failed),
	STAT_FIELD_SUB(tcp_md5_listener_race, md5_set_ok),
	STAT_FIELD_SUB(tcp_md5_listener_race, md5_set_failed),
	STAT_FIELD_SUB(tcp_md5_listener_race, connect_ok),
	STAT_FIELD_SUB(tcp_md5_listener_race, rst_sent_ok),
	STAT_FIELD_SUB(tcp_md5_listener_race, completed_ok),
};

const struct stat_category tcp_md5_listener_race_category =
	STAT_CATEGORY("tcp_md5_listener_race",
	              tcp_md5_listener_race.runs,
	              tcp_md5_listener_race_fields);

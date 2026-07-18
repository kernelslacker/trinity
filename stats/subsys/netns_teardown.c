#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field netns_teardown_fields[] = {
	STAT_FIELD_SUB(netns_teardown, runs),
	STAT_FIELD_SUB(netns_teardown, setup_failed),
	STAT_FIELD_SUB(netns_teardown, unshare_ok),
	STAT_FIELD_SUB(netns_teardown, socket_pair_ok),
	STAT_FIELD_SUB(netns_teardown, fork_ok),
	STAT_FIELD_SUB(netns_teardown, setns_ok),
	STAT_FIELD_SUB(netns_teardown, kill_ok),
	STAT_FIELD_SUB(netns_teardown, completed_ok),
};

const struct stat_category netns_teardown_category =
	STAT_CATEGORY("netns_teardown",
	              netns_teardown.runs,
	              netns_teardown_fields);

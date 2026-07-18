#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field netns_mountns_setup_fields[] = {
	STAT_FIELD_SUB(netns_mountns_setup, runs),
	STAT_FIELD_SUB(netns_mountns_setup, setup_failed),
	STAT_FIELD_SUB(netns_mountns_setup, unshare_ok),
	STAT_FIELD_SUB(netns_mountns_setup, mount_private_ok),
	STAT_FIELD_SUB(netns_mountns_setup, loopback_ok),
	STAT_FIELD_SUB(netns_mountns_setup, socket_ok),
	STAT_FIELD_SUB(netns_mountns_setup, completed_ok),
};

const struct stat_category netns_mountns_setup_category =
	STAT_CATEGORY("netns_mountns_setup",
	              netns_mountns_setup.runs,
	              netns_mountns_setup_fields);

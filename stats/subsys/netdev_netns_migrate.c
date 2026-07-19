#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field netdev_netns_migrate_fields[] = {
	STAT_FIELD_SUB(netdev_netns_migrate, iters),
	STAT_FIELD_SUB(netdev_netns_migrate, eperm),
	STAT_FIELD_SUB(netdev_netns_migrate, unsupported),
	STAT_FIELD_SUB(netdev_netns_migrate, pin_sock_ok),
	STAT_FIELD_SUB(netdev_netns_migrate, link_create_ok),
	STAT_FIELD_SUB(netdev_netns_migrate, migrate_ok),
	STAT_FIELD_SUB(netdev_netns_migrate, migrate_rejected),
	STAT_FIELD_SUB(netdev_netns_migrate, up_ok),
	STAT_FIELD_SUB(netdev_netns_migrate, addr_ok),
	STAT_FIELD_SUB(netdev_netns_migrate, unsupported_observed),
	STAT_FIELD_SUB(netdev_netns_migrate, drive_unsupported_observed),
};

const struct stat_category netdev_netns_migrate_category =
	STAT_CATEGORY("netdev_netns_migrate",
	              netdev_netns_migrate.iters,
	              netdev_netns_migrate_fields);

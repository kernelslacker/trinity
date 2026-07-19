#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ip6erspan_netns_migrate_fields[] = {
	STAT_FIELD_SUB(ip6erspan_netns_migrate, iters),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, eperm),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, unsupported),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, link_create_ok),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, netns_migrate_ok),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, changelink_ok),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, ip6erspan_unsupported_observed),
	STAT_FIELD_SUB(ip6erspan_netns_migrate, changelink_unsupported_observed),
};

const struct stat_category ip6erspan_netns_migrate_category =
	STAT_CATEGORY("ip6erspan_netns_migrate",
	              ip6erspan_netns_migrate.iters,
	              ip6erspan_netns_migrate_fields);

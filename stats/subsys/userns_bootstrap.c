#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field userns_bootstrap_fields[] = {
	STAT_FIELD_SUB(userns_bootstrap, runs),
	STAT_FIELD_SUB(userns_bootstrap, ran),
	STAT_FIELD_SUB(userns_bootstrap, eperm),
	STAT_FIELD_SUB(userns_bootstrap, userns_other),
	STAT_FIELD_SUB(userns_bootstrap, map_write_fail),
	STAT_FIELD_SUB(userns_bootstrap, map_write_fail_eperm),
	STAT_FIELD_SUB(userns_bootstrap, map_write_fail_einval),
	STAT_FIELD_SUB(userns_bootstrap, map_write_fail_other),
	STAT_FIELD_SUB(userns_bootstrap, target_unshare),
	STAT_FIELD_SUB(userns_bootstrap, fork_fail),
	STAT_FIELD_SUB(userns_bootstrap, signalled),
};

const struct stat_category userns_bootstrap_category =
	STAT_CATEGORY("userns_bootstrap",
	              userns_bootstrap.runs,
	              userns_bootstrap_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field statmount_idmap_fields[] = {
	STAT_FIELD_SUB(statmount_idmap, runs),
	STAT_FIELD_SUB(statmount_idmap, setup_failed),
	STAT_FIELD_SUB(statmount_idmap, iter),
	STAT_FIELD_SUB(statmount_idmap, fork_failed),
	STAT_FIELD_SUB(statmount_idmap, carrier_ok),
	STAT_FIELD_SUB(statmount_idmap, carrier_fail),
	STAT_FIELD_SUB(statmount_idmap, setattr_ok),
	STAT_FIELD_SUB(statmount_idmap, setattr_fail),
	STAT_FIELD_SUB(statmount_idmap, statmount_call),
	STAT_FIELD_SUB(statmount_idmap, statmount_ok),
	STAT_FIELD_SUB(statmount_idmap, statmount_overflow),
};

const struct stat_category statmount_idmap_category =
	STAT_CATEGORY("statmount_idmap",
	              statmount_idmap.runs,
	              statmount_idmap_fields);

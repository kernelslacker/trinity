#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field af_unix_scm_rights_gc_fields[] = {
	STAT_FIELD_SUB(af_unix_scm_rights_gc, runs),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, setup_failed),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, cycle_built_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, close_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, trigger_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, recv_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, peek_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, iouring_variant_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, sibling_spawn_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, sibling_spawn_failed),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, sibling_reaped_ok),
	STAT_FIELD_SUB(af_unix_scm_rights_gc, sibling_crashed),
};

const struct stat_category af_unix_scm_rights_gc_category =
	STAT_CATEGORY("af_unix_scm_rights_gc",
	              af_unix_scm_rights_gc.runs,
	              af_unix_scm_rights_gc_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ct_expect_realloc_fields[] = {
	STAT_FIELD_SUB(ct_expect_realloc, runs),
	STAT_FIELD_SUB(ct_expect_realloc, ns_setup_failed),
	STAT_FIELD_SUB(ct_expect_realloc, ns_unsupported),
	STAT_FIELD_SUB(ct_expect_realloc, ct_setup_failed),
	STAT_FIELD_SUB(ct_expect_realloc, helper_missing),
	STAT_FIELD_SUB(ct_expect_realloc, master_ok),
	STAT_FIELD_SUB(ct_expect_realloc, expect_ok),
	STAT_FIELD_SUB(ct_expect_realloc, realloc_ok),
	STAT_FIELD_SUB(ct_expect_realloc, unlink_ok),
	STAT_FIELD_SUB(ct_expect_realloc, full_cycle),
};

const struct stat_category ct_expect_realloc_category =
	STAT_CATEGORY("ct_expect_realloc",
	              ct_expect_realloc.runs,
	              ct_expect_realloc_fields);

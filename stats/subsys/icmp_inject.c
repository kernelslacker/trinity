#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field icmp_inject_fields[] = {
	STAT_FIELD_SUB(icmp_inject, errors_injected),
	STAT_FIELD_SUB(icmp_inject, inject_failed),
	STAT_FIELD_SUB(icmp_inject, selftest_runs),
	STAT_FIELD_SUB(icmp_inject, selftest_ok),
	STAT_FIELD_SUB(icmp_inject, selftest_fail),
	STAT_FIELD_SUB(icmp_inject, init_failed),
};

const struct stat_category icmp_inject_category =
	STAT_CATEGORY("icmp_inject",
	              icmp_inject.errors_injected,
	              icmp_inject_fields);

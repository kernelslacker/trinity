#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field userns_fuzzer_fields[] = {
	STAT_FIELD_SUB(userns_fuzzer, runs),
	STAT_FIELD_SUB(userns_fuzzer, inner_crashed),
	STAT_FIELD_SUB(userns_fuzzer, unsupported),
	STAT_FIELD_SUB(userns_fuzzer, root_private_failed),
};

const struct stat_category userns_fuzzer_category =
	STAT_CATEGORY("userns_fuzzer",
	              userns_fuzzer.runs,
	              userns_fuzzer_fields);

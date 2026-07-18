#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field setsockopt_pairing_fields[] = {
	STAT_FIELD_SUB(setsockopt_pairing, paired_emitted),
};

const struct stat_category setsockopt_pairing_category =
	STAT_CATEGORY("setsockopt_pairing",
	              setsockopt_pairing.paired_emitted,
	              setsockopt_pairing_fields);

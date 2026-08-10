#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field prctl_futex_hash_fields[] = {
	STAT_FIELD_SUB(prctl_futex_hash, set_slots_ebusy),
};

const struct stat_category prctl_futex_hash_category =
	STAT_CATEGORY("prctl_futex_hash",
	              prctl_futex_hash.set_slots_ebusy,
	              prctl_futex_hash_fields);

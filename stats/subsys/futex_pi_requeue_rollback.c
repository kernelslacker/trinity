#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field futex_pi_requeue_rollback_fields[] = {
	STAT_FIELD_SUB(futex_pi_requeue_rollback, runs),
	STAT_FIELD_SUB(futex_pi_requeue_rollback, setup_failed),
	STAT_FIELD_SUB(futex_pi_requeue_rollback, requeue_ok),
	STAT_FIELD_SUB(futex_pi_requeue_rollback, requeue_failed),
};

const struct stat_category futex_pi_requeue_rollback_category =
	STAT_CATEGORY("futex_pi_requeue_rollback",
	              futex_pi_requeue_rollback.runs,
	              futex_pi_requeue_rollback_fields);

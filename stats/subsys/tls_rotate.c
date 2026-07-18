#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tls_rotate_fields[] = {
	STAT_FIELD_SUB(tls_rotate, runs),
	STAT_FIELD_SUB(tls_rotate, setup_failed),
	STAT_FIELD_SUB(tls_rotate, ulp_failed),
	STAT_FIELD_SUB(tls_rotate, ulp_asymmetric),
	STAT_FIELD_SUB(tls_rotate, installs),
	STAT_FIELD_SUB(tls_rotate, rekeys_ok),
	STAT_FIELD_SUB(tls_rotate, rekeys_rejected),
};

const struct stat_category tls_rotate_category =
	STAT_CATEGORY("tls_rotate",
	              tls_rotate.runs,
	              tls_rotate_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field cred_transition_fields[] = {
	STAT_FIELD_SUB(cred_transition, runs),
	STAT_FIELD_SUB(cred_transition, setup_failed),
	STAT_FIELD_SUB(cred_transition, capset_ok),
	STAT_FIELD_SUB(cred_transition, capset_failed),
	STAT_FIELD_SUB(cred_transition, op_ok),
	STAT_FIELD_SUB(cred_transition, op_failed),
	STAT_FIELD_SUB(cred_transition, keyctl_ok),
	STAT_FIELD_SUB(cred_transition, keyctl_failed),
};

const struct stat_category cred_transition_category =
	STAT_CATEGORY("cred_transition",
	              cred_transition.runs,
	              cred_transition_fields);

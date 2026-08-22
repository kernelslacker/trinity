#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field xfrm_grammar_fields[] = {
	STAT_FIELD_SUB(xfrm_grammar, msg_kind_draws),
	STAT_FIELD_SUB(xfrm_grammar, migrate_state_arm_entered),
};

const struct stat_category xfrm_grammar_category =
	STAT_CATEGORY("xfrm_grammar",
	              xfrm_grammar_fields);

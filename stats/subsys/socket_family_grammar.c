#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field socket_family_grammar_fields[] = {
	STAT_FIELD_SUB(socket_family_grammar, runs),
	STAT_FIELD_SUB(socket_family_grammar, completed),
	STAT_FIELD_SUB(socket_family_grammar, distinct_seq),
	STAT_FIELD_SUB(socket_family_grammar, reward),
	STAT_FIELD_SUB(socket_family_grammar, feedback_picks),
};

const struct stat_category socket_family_grammar_category =
	STAT_CATEGORY("socket_family_grammar",
	              socket_family_grammar.runs,
	              socket_family_grammar_fields);

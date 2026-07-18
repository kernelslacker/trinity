#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field socket_family_chain_fields[] = {
	STAT_FIELD_SUB(socket_family_chain, runs),
	STAT_FIELD_SUB(socket_family_chain, completed),
	STAT_FIELD_SUB(socket_family_chain, failed),
	STAT_FIELD_SUB(socket_family_chain, authencesn_attempts),
	STAT_FIELD_SUB(socket_family_chain, splice_attempts),
};

const struct stat_category socket_family_chain_category =
	STAT_CATEGORY("socket_family_chain",
	              socket_family_chain.runs,
	              socket_family_chain_fields);

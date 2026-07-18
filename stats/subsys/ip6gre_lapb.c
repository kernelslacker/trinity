#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ip6gre_bond_lapb_stack_fields[] = {
	STAT_FIELD_SUB(ip6gre_lapb, runs),
	STAT_FIELD_SUB(ip6gre_lapb, setup_failed),
	STAT_FIELD_SUB(ip6gre_lapb, flag_toggles),
};

const struct stat_category ip6gre_bond_lapb_stack_category =
	STAT_CATEGORY("ip6gre_bond_lapb_stack",
	              ip6gre_lapb.runs,
	              ip6gre_bond_lapb_stack_fields);

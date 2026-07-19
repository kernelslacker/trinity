#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_ip6_refrag_fraggap_fields[] = {
	STAT_FIELD_SUB(bridge_ip6_refrag_fraggap, runs),
	STAT_FIELD_SUB(bridge_ip6_refrag_fraggap, brnf_enabled),
	STAT_FIELD_SUB(bridge_ip6_refrag_fraggap, bursts),
	STAT_FIELD_SUB(bridge_ip6_refrag_fraggap, frags_sent),
};

const struct stat_category bridge_ip6_refrag_fraggap_category =
	STAT_CATEGORY("bridge_ip6_refrag_fraggap",
	              bridge_ip6_refrag_fraggap.runs,
	              bridge_ip6_refrag_fraggap_fields);

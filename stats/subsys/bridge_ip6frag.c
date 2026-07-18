#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bridge_ip6frag_refrag_fields[] = {
	STAT_FIELD_SUB(bridge_ip6frag, runs),
	STAT_FIELD_SUB(bridge_ip6frag, pairs_sent),
	STAT_FIELD_SUB(bridge_ip6frag, frames_sent),
};

const struct stat_category bridge_ip6frag_refrag_category =
	STAT_CATEGORY("bridge_ip6frag_refrag",
	              bridge_ip6frag.runs,
	              bridge_ip6frag_refrag_fields);

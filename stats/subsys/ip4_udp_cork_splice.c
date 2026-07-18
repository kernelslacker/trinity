#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ip4_udp_cork_splice_fields[] = {
	STAT_FIELD_SUB(ip4_udp_cork_splice, runs),
	STAT_FIELD_SUB(ip4_udp_cork_splice, setup_failed),
	STAT_FIELD_SUB(ip4_udp_cork_splice, mtu_set),
	STAT_FIELD_SUB(ip4_udp_cork_splice, p1_ok),
	STAT_FIELD_SUB(ip4_udp_cork_splice, p1_rejected),
	STAT_FIELD_SUB(ip4_udp_cork_splice, p2_ok),
};

const struct stat_category ip4_udp_cork_splice_category =
	STAT_CATEGORY("ip4_udp_cork_splice",
		      ip4_udp_cork_splice.runs,
		      ip4_udp_cork_splice_fields);

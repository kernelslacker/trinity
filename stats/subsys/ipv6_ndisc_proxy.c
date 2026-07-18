#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field ipv6_ndisc_proxy_fields[] = {
	STAT_FIELD_SUB(ipv6_ndisc_proxy, runs),
	STAT_FIELD_SUB(ipv6_ndisc_proxy, ns_sent_ok),
	STAT_FIELD_SUB(ipv6_ndisc_proxy, setup_failed),
	STAT_FIELD_SUB(ipv6_ndisc_proxy, proxy_enable_ok),
};

const struct stat_category ipv6_ndisc_proxy_category =
	STAT_CATEGORY("ipv6_ndisc_proxy",
	              ipv6_ndisc_proxy.runs,
	              ipv6_ndisc_proxy_fields);

#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sock_ulp_sockmap_layering_fields[] = {
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, runs),
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, setup_failed),
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, map_failed),
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, prog_failed),
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, attach_failed),
	STAT_FIELD_SUB(sock_ulp_sockmap_layering, layered_ok),
};

const struct stat_category sock_ulp_sockmap_layering_category =
	STAT_CATEGORY("sock_ulp_sockmap_layering",
	              sock_ulp_sockmap_layering.runs,
	              sock_ulp_sockmap_layering_fields);

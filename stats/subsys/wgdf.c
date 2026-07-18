#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field wireguard_decrypt_flood_fields[] = {
	STAT_FIELD_SUB(wgdf, runs),
	STAT_FIELD_SUB(wgdf, setup_failed),
	STAT_FIELD_SUB(wgdf, packets_sent),
	STAT_FIELD_SUB(wgdf, unsupported_latched),
};

const struct stat_category wireguard_decrypt_flood_category =
	STAT_CATEGORY("wireguard_decrypt_flood",
	              wgdf.runs,
	              wireguard_decrypt_flood_fields);

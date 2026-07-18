#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field rxrpc_key_install_fields[] = {
	STAT_FIELD_SUB(rxrpc_key_install, runs),
	STAT_FIELD_SUB(rxrpc_key_install, calls),
	STAT_FIELD_SUB(rxrpc_key_install, revokes),
	STAT_FIELD_SUB(rxrpc_key_install, quota_hits),
	STAT_FIELD_SUB(rxrpc_key_install, unsupported),
	STAT_FIELD_SUB(rxrpc_key_install, xrxgk_accepted),
};

const struct stat_category rxrpc_key_install_category =
	STAT_CATEGORY("rxrpc_key_install",
	              rxrpc_key_install.runs,
	              rxrpc_key_install_fields);

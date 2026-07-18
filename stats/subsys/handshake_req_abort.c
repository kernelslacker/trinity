#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field handshake_req_abort_fields[] = {
	STAT_FIELD_SUB(handshake_req_abort, runs),
	STAT_FIELD_SUB(handshake_req_abort, setup_failed),
	STAT_FIELD_SUB(handshake_req_abort, accept_ok),
	STAT_FIELD_SUB(handshake_req_abort, done_ok),
	STAT_FIELD_SUB(handshake_req_abort, abort_ok),
	STAT_FIELD_SUB(handshake_req_abort, orphan_close),
};

const struct stat_category handshake_req_abort_category =
	STAT_CATEGORY("handshake_req_abort",
	              handshake_req_abort.runs,
	              handshake_req_abort_fields);

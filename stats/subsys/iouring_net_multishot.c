#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_net_multishot_fields[] = {
	STAT_FIELD_SUB(iouring_net_multishot, runs),
	STAT_FIELD_SUB(iouring_net_multishot, setup_failed),
	STAT_FIELD_SUB(iouring_net_multishot, pbuf_ring_ok),
	STAT_FIELD_SUB(iouring_net_multishot, pbuf_legacy_ok),
	STAT_FIELD_SUB(iouring_net_multishot, armed),
	STAT_FIELD_SUB(iouring_net_multishot, packets_sent),
	STAT_FIELD_SUB(iouring_net_multishot, completions),
	STAT_FIELD_SUB(iouring_net_multishot, cancel_submitted),
	STAT_FIELD_JSON_SUB(iouring_net_multishot, napi_register_ok, "napi_register_ok"),
	STAT_FIELD_JSON_SUB(iouring_net_multishot, napi_register_fail, "napi_register_fail"),
	STAT_FIELD_JSON_SUB(iouring_net_multishot, napi_unregister_ok, "napi_unregister_ok"),
	STAT_FIELD_JSON_SUB(iouring_net_multishot, napi_unregister_fail, "napi_unregister_fail"),
};

const struct stat_category iouring_net_multishot_category =
	STAT_CATEGORY("iouring_net_multishot",
	              iouring_net_multishot.runs,
	              iouring_net_multishot_fields);

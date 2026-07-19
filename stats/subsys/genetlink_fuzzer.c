#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field genetlink_fuzzer_fields[] = {
	STAT_FIELD_SUB(genetlink_fuzzer, families_discovered),
	STAT_FIELD_SUB(genetlink_fuzzer, discovery_cycles),
	STAT_FIELD_SUB(genetlink_fuzzer, msgs_sent),
	STAT_FIELD_SUB(genetlink_fuzzer, eperm),
	STAT_FIELD_SUB(genetlink_fuzzer, stale_seq_drops),
	STAT_FIELD_SUB(genetlink_fuzzer, missing_producer),
	STAT_FIELD_SUB(genetlink_fuzzer, discovery_io_err),
	STAT_FIELD_SUB(genetlink_fuzzer, discovery_nlerr),
	STAT_FIELD_SUB(genetlink_fuzzer, userns_run_fail),
	STAT_FIELD_SUB(genetlink_fuzzer, in_ns_open_fail),
	STAT_FIELD_SUB(genetlink_fuzzer, send_drain_fail),
};

const struct stat_category genetlink_fuzzer_category =
	STAT_CATEGORY("genetlink_fuzzer",
	              genetlink_fuzzer.families_discovered,
	              genetlink_fuzzer_fields);

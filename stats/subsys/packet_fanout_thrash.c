#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD_SUB(packet_fanout_thrash, runs),
	STAT_FIELD_SUB(packet_fanout_thrash, setup_failed),
	STAT_FIELD_SUB(packet_fanout_thrash, ring_failed),
	STAT_FIELD_SUB(packet_fanout_thrash, rings_installed),
	STAT_FIELD_SUB(packet_fanout_thrash, mmap_failed),
	STAT_FIELD_SUB(packet_fanout_thrash, joins),
	STAT_FIELD_SUB(packet_fanout_thrash, rejoins_ok),
	STAT_FIELD_SUB(packet_fanout_thrash, rejoins_rejected),
};

const struct stat_category packet_fanout_thrash_category =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_thrash.runs,
	              packet_fanout_thrash_fields);

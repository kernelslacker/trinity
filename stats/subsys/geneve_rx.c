#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field geneve_rx_fields[] = {
	STAT_FIELD_SUB(geneve_rx, runs),
	STAT_FIELD_SUB(geneve_rx, setup_failed),
	STAT_FIELD_SUB(geneve_rx, link_create_ok),
	STAT_FIELD_SUB(geneve_rx, link_create_failed),
	STAT_FIELD_SUB(geneve_rx, link_up_ok),
	STAT_FIELD_SUB(geneve_rx, packet_sent_ok),
	STAT_FIELD_SUB(geneve_rx, link_del_ok),
};

const struct stat_category geneve_rx_category =
	STAT_CATEGORY("geneve_rx",
	              geneve_rx.runs,
	              geneve_rx_fields);

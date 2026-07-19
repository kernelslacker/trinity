#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bareudp_rx_fields[] = {
	STAT_FIELD_SUB(bareudp_rx, runs),
	STAT_FIELD_SUB(bareudp_rx, setup_failed),
	STAT_FIELD_SUB(bareudp_rx, link_create_ok),
	STAT_FIELD_SUB(bareudp_rx, link_create_failed),
	STAT_FIELD_SUB(bareudp_rx, link_up_ok),
	STAT_FIELD_SUB(bareudp_rx, packet_sent_ok),
	STAT_FIELD_SUB(bareudp_rx, link_del_ok),
};

const struct stat_category bareudp_rx_category =
	STAT_CATEGORY("bareudp_rx",
	              bareudp_rx.runs,
	              bareudp_rx_fields);

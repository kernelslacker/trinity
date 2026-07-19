#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sctp_chunk_rx_fields[] = {
	STAT_FIELD_SUB(sctp_chunk_rx, runs),
	STAT_FIELD_SUB(sctp_chunk_rx, setup_failed),
	STAT_FIELD_SUB(sctp_chunk_rx, listener_ok),
	STAT_FIELD_SUB(sctp_chunk_rx, packet_sent_ok),
};

const struct stat_category sctp_chunk_rx_category =
	STAT_CATEGORY("sctp_chunk_rx",
	              sctp_chunk_rx.runs,
	              sctp_chunk_rx_fields);

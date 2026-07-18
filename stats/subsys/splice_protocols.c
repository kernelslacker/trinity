#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field splice_protocols_fields[] = {
	STAT_FIELD_SUB(splice_protocols, runs),
	STAT_FIELD_SUB(splice_protocols, setup_failed),
	STAT_FIELD_SUB(splice_protocols, chain_ok),
	STAT_FIELD_SUB(splice_protocols, in_bytes),
	STAT_FIELD_SUB(splice_protocols, out_bytes),
	STAT_FIELD_SUB(splice_protocols, udp_encap_attempted),
	STAT_FIELD_SUB(splice_protocols, tcp_repair_attempted),
	STAT_FIELD_SUB(splice_protocols, packet_ring_attempted),
	STAT_FIELD_SUB(splice_protocols, alg_attempted),
	STAT_FIELD_SUB(splice_protocols, rxrpc_attempted),
	STAT_FIELD_SUB(splice_protocols, msg_splice_pages_attempted),
	STAT_FIELD_SUB(splice_protocols, msg_splice_pages_path_taken_inferred),
};

const struct stat_category splice_protocols_category =
	STAT_CATEGORY("splice_protocols",
	              splice_protocols.runs,
	              splice_protocols_fields);

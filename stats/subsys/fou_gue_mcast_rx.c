#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field fou_gue_mcast_rx_fields[] = {
	STAT_FIELD_SUB(fou_gue_mcast_rx, runs),
	STAT_FIELD_SUB(fou_gue_mcast_rx, setup_failed),
	STAT_FIELD_SUB(fou_gue_mcast_rx, port_install_ok),
	STAT_FIELD_SUB(fou_gue_mcast_rx, port_install_failed),
	STAT_FIELD_SUB(fou_gue_mcast_rx, packet_sent_ok),
	STAT_FIELD_SUB(fou_gue_mcast_rx, port_delete_ok),
	STAT_FIELD_SUB(fou_gue_mcast_rx, port_nopartial_ok),
	STAT_FIELD_SUB(fou_gue_mcast_rx, gue_flags_uniform),
	STAT_FIELD_SUB(fou_gue_mcast_rx, gue_priv_emitted),
	STAT_FIELD_SUB(fou_gue_mcast_rx, gue_remcsum_emitted),
	STAT_FIELD_SUB(fou_gue_mcast_rx, gue_remcsum_underflow),
};

const struct stat_category fou_gue_mcast_rx_category =
	STAT_CATEGORY("fou_gue_mcast_rx",
	              fou_gue_mcast_rx_fields);

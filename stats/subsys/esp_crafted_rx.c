#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field esp_crafted_rx_fields[] = {
	STAT_FIELD_SUB(esp_crafted_rx, runs),
	STAT_FIELD_SUB(esp_crafted_rx, setup_failed),
	STAT_FIELD_SUB(esp_crafted_rx, sa_install_ok),
	STAT_FIELD_SUB(esp_crafted_rx, sa_install_failed),
	STAT_FIELD_SUB(esp_crafted_rx, packet_sent_ok),
	STAT_FIELD_SUB(esp_crafted_rx, sa_delete_ok),
	STAT_FIELD_SUB(esp_crafted_rx, stacked_sa_install_ok),
	STAT_FIELD_SUB(esp_crafted_rx, stacked_sent_ok),
};

const struct stat_category esp_crafted_rx_category =
	STAT_CATEGORY("esp_crafted_rx",
	              esp_crafted_rx.runs,
	              esp_crafted_rx_fields);

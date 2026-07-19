#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field mpls_label_stack_rx_fields[] = {
	STAT_FIELD_SUB(mpls_label_stack_rx, runs),
	STAT_FIELD_SUB(mpls_label_stack_rx, setup_failed),
	STAT_FIELD_SUB(mpls_label_stack_rx, config_ok),
	STAT_FIELD_SUB(mpls_label_stack_rx, config_failed),
	STAT_FIELD_SUB(mpls_label_stack_rx, link_up_ok),
	STAT_FIELD_SUB(mpls_label_stack_rx, packet_sent_ok),
};

const struct stat_category mpls_label_stack_rx_category =
	STAT_CATEGORY("mpls_label_stack_rx",
	              mpls_label_stack_rx.runs,
	              mpls_label_stack_rx_fields);

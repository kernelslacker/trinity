#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field vsock_transport_churn_fields[] = {
	STAT_FIELD_SUB(vsock_transport_churn, runs),
	STAT_FIELD_SUB(vsock_transport_churn, setup_failed),
	STAT_FIELD_SUB(vsock_transport_churn, bind_ok),
	STAT_FIELD_SUB(vsock_transport_churn, connect_ok),
	STAT_FIELD_SUB(vsock_transport_churn, send_ok),
	STAT_FIELD_SUB(vsock_transport_churn, buffer_size_ok),
	STAT_FIELD_SUB(vsock_transport_churn, timeout_ok),
	STAT_FIELD_SUB(vsock_transport_churn, get_cid_ok),
	STAT_FIELD_SUB(vsock_transport_churn, seq_eom_runs),
	STAT_FIELD_SUB(vsock_transport_churn, seq_eom_sends_ok),
	STAT_FIELD_SUB(vsock_transport_churn, seq_eom_sends_failed),
	STAT_FIELD_SUB(vsock_transport_churn, seq_eom_skipped),
};

const struct stat_category vsock_transport_churn_category =
	STAT_CATEGORY("vsock_transport_churn",
	              vsock_transport_churn.runs,
	              vsock_transport_churn_fields);

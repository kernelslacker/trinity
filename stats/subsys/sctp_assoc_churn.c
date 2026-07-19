#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field sctp_assoc_churn_fields[] = {
	STAT_FIELD_SUB(sctp_assoc_churn, runs),
	STAT_FIELD_SUB(sctp_assoc_churn, setup_failed),
	STAT_FIELD_SUB(sctp_assoc_churn, bindx_added),
	STAT_FIELD_SUB(sctp_assoc_churn, bindx_removed),
	STAT_FIELD_SUB(sctp_assoc_churn, bindx_rejected),
	STAT_FIELD_SUB(sctp_assoc_churn, connect_failed),
	STAT_FIELD_SUB(sctp_assoc_churn, connected),
	STAT_FIELD_SUB(sctp_assoc_churn, accepted),
	STAT_FIELD_SUB(sctp_assoc_churn, packets_sent),
	STAT_FIELD_SUB(sctp_assoc_churn, peeled_off),
	STAT_FIELD_SUB(sctp_assoc_churn, peeloff_rejected),
	STAT_FIELD_SUB(sctp_assoc_churn, cycles),
};

const struct stat_category sctp_assoc_churn_category =
	STAT_CATEGORY("sctp_assoc_churn",
	              sctp_assoc_churn.runs,
	              sctp_assoc_churn_fields);

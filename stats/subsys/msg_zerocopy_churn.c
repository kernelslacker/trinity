#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field msg_zerocopy_churn_fields[] = {
	STAT_FIELD_SUB(msg_zerocopy_churn, runs),
	STAT_FIELD_SUB(msg_zerocopy_churn, setup_failed),
	STAT_FIELD_SUB(msg_zerocopy_churn, sends_ok),
	STAT_FIELD_SUB(msg_zerocopy_churn, sends_efault),
	STAT_FIELD_SUB(msg_zerocopy_churn, sends_eagain),
	STAT_FIELD_SUB(msg_zerocopy_churn, errqueue_drained),
	STAT_FIELD_SUB(msg_zerocopy_churn, errqueue_empty),
	STAT_FIELD_SUB(msg_zerocopy_churn, munmap_ok),
	STAT_FIELD_SUB(msg_zerocopy_churn, send_after_munmap_caught),
	STAT_FIELD_SUB(msg_zerocopy_churn, sndzc_disable_ok),
};

const struct stat_category msg_zerocopy_churn_category =
	STAT_CATEGORY("msg_zerocopy_churn",
	              msg_zerocopy_churn.runs,
	              msg_zerocopy_churn_fields);

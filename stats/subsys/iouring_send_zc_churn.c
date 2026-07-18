#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_send_zc_churn_fields[] = {
	STAT_FIELD_SUB(iouring_send_zc_churn, runs),
	STAT_FIELD_SUB(iouring_send_zc_churn, setup_failed),
	STAT_FIELD_SUB(iouring_send_zc_churn, register_bufs_ok),
	STAT_FIELD_SUB(iouring_send_zc_churn, send_zc_ok),
	STAT_FIELD_SUB(iouring_send_zc_churn, sendmsg_zc_ok),
	STAT_FIELD_SUB(iouring_send_zc_churn, unregister_race_ok),
	STAT_FIELD_SUB(iouring_send_zc_churn, update_race_ok),
	STAT_FIELD_SUB(iouring_send_zc_churn, cqe_drained),
};

const struct stat_category iouring_send_zc_churn_category =
	STAT_CATEGORY("iouring_send_zc_churn",
	              iouring_send_zc_churn.runs,
	              iouring_send_zc_churn_fields);

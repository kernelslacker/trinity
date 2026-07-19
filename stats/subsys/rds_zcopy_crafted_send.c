#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field rds_zcopy_crafted_send_fields[] = {
	STAT_FIELD_SUB(rds_zcopy_crafted_send, runs),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, setup_failed),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, bind_ok),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, zc_enable_ok),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, hole_ok),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, sends_ok),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, sends_efault),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, sends_failed),
	STAT_FIELD_SUB(rds_zcopy_crafted_send, errqueue_drained),
};

const struct stat_category rds_zcopy_crafted_send_category =
	STAT_CATEGORY("rds_zcopy_crafted_send",
	              rds_zcopy_crafted_send.runs,
	              rds_zcopy_crafted_send_fields);

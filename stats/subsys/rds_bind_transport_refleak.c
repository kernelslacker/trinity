#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field rds_bind_transport_refleak_fields[] = {
	STAT_FIELD_SUB(rds_bind_transport_refleak, runs),
	STAT_FIELD_SUB(rds_bind_transport_refleak, setup_failed),
	STAT_FIELD_SUB(rds_bind_transport_refleak, binds_tried),
	STAT_FIELD_SUB(rds_bind_transport_refleak, binds_einval),
	STAT_FIELD_SUB(rds_bind_transport_refleak, binds_eaddrinuse),
	STAT_FIELD_SUB(rds_bind_transport_refleak, leaked_refs),
	STAT_FIELD_SUB(rds_bind_transport_refleak, ref_read_failed),
	STAT_FIELD_SUB(rds_bind_transport_refleak, ref_delta_nonpositive),
	STAT_FIELD_SUB(rds_bind_transport_refleak, rds_tcp_refcount_hwm),
	STAT_FIELD_SUB(rds_bind_transport_refleak, leaked_refs_hwm_growth),
	STAT_FIELD_SUB(rds_bind_transport_refleak, port_collision_skips),
};

const struct stat_category rds_bind_transport_refleak_category =
	STAT_CATEGORY("rds_bind_transport_refleak",
	              rds_bind_transport_refleak.runs,
	              rds_bind_transport_refleak_fields);

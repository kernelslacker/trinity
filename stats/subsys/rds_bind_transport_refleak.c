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
	STAT_FIELD_SUB(rds_bind_transport_refleak, ref_delta_undercount),
	STAT_FIELD_SUB(rds_bind_transport_refleak, baseline_refcount),
	STAT_FIELD_SUB(rds_bind_transport_refleak, pre_refcount_floor),
	STAT_FIELD_SUB(rds_bind_transport_refleak, baseline_floor_revised),
	STAT_FIELD_SUB(rds_bind_transport_refleak, rds_tcp_refcount_hwm),
	STAT_FIELD_SUB(rds_bind_transport_refleak, leaked_refs_hwm_growth),
	STAT_FIELD_SUB(rds_bind_transport_refleak, port_collision_skips),
	STAT_FIELD_SUB(rds_bind_transport_refleak, holder_bind_other_errno),
	STAT_FIELD_SUB(rds_bind_transport_refleak, eaddrinuse_wall_cap_skip),
	STAT_FIELD_SUB(rds_bind_transport_refleak, eaddrinuse_loopfd_setsockopt_fail),
};

const struct stat_category rds_bind_transport_refleak_category =
	STAT_CATEGORY("rds_bind_transport_refleak",
	              rds_bind_transport_refleak_fields);

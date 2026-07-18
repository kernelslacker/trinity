#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iscsi_login_walker_fields[] = {
	STAT_FIELD_SUB(iscsi_walker, runs),
	STAT_FIELD_SUB(iscsi_walker, setup_failed),
	STAT_FIELD_SUB(iscsi_walker, no_target),
	STAT_FIELD_SUB(iscsi_walker, connected),
	STAT_FIELD_SUB(iscsi_walker, state_security_sent),
	STAT_FIELD_SUB(iscsi_walker, state_op_neg_sent),
	STAT_FIELD_SUB(iscsi_walker, login_response_ok),
	STAT_FIELD_SUB(iscsi_walker, login_rejected),
	STAT_FIELD_SUB(iscsi_walker, ffp_reached),
	STAT_FIELD_SUB(iscsi_walker, ffp_iters),
	STAT_FIELD_SUB(iscsi_walker, ffp_pdus),
	STAT_FIELD_SUB(iscsi_walker, chaos_runs),
	STAT_FIELD_SUB(iscsi_walker, chaos_pdus),
	STAT_FIELD_SUB(iscsi_walker, bytes_out),
	STAT_FIELD_SUB(iscsi_walker, bytes_in),
};

const struct stat_category iscsi_login_walker_category =
	STAT_CATEGORY("iscsi_login_walker",
	              iscsi_walker.runs,
	              iscsi_login_walker_fields);

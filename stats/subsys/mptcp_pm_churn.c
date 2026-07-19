#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field mptcp_pm_churn_fields[] = {
	STAT_FIELD_SUB(mptcp_pm_churn, runs),
	STAT_FIELD_SUB(mptcp_pm_churn, setup_failed),
	STAT_FIELD_SUB(mptcp_pm_churn, sock_mptcp_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, addr_added_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, addr_removed_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, send_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, setsockopt_unsupported),
	STAT_FIELD_SUB(mptcp_pm_churn, setsockopt_master_set),
	STAT_FIELD_SUB(mptcp_pm_churn, setsockopt_master_fail),
	STAT_FIELD_SUB(mptcp_pm_churn, getsockopt_verify_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, getsockopt_verify_drift),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_sweep_runs),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_set_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_set_failed),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_subflow_added),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_readback_ok),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_inherit_mismatch),
	STAT_FIELD_SUB(mptcp_pm_churn, sockopt_unsupported_latched),
};

const struct stat_category mptcp_pm_churn_category =
	STAT_CATEGORY("mptcp_pm_churn",
	              mptcp_pm_churn.runs,
	              mptcp_pm_churn_fields);

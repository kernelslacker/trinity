#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tcp_ulp_swap_churn_fields[] = {
	STAT_FIELD_SUB(tcp_ulp_swap_churn, runs),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, setup_failed),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, install_tls_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, tx_install_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, send_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, swap_rejected_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, ifname_probe_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, uninstall_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, reinstall_ok),
	STAT_FIELD_SUB(tcp_ulp_swap_churn, install_failed),
};

const struct stat_category tcp_ulp_swap_churn_category =
	STAT_CATEGORY("tcp_ulp_swap_churn",
	              tcp_ulp_swap_churn.runs,
	              tcp_ulp_swap_churn_fields);

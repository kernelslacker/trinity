#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field mpls_route_churn_fields[] = {
	STAT_FIELD_SUB(mpls_route_churn, runs),
	STAT_FIELD_SUB(mpls_route_churn, label_install_ok),
	STAT_FIELD_SUB(mpls_route_churn, iptunnel_install_ok),
	STAT_FIELD_SUB(mpls_route_churn, delete_ok),
	STAT_FIELD_SUB(mpls_route_churn, ns_unsupported),
};

const struct stat_category mpls_route_churn_category =
	STAT_CATEGORY("mpls_route_churn",
	              mpls_route_churn.runs,
	              mpls_route_churn_fields);

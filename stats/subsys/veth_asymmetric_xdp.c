#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field veth_asymmetric_xdp_fields[] = {
	STAT_FIELD_SUB(veth_asymmetric_xdp, iters),
	STAT_FIELD_SUB(veth_asymmetric_xdp, eperm),
	STAT_FIELD_SUB(veth_asymmetric_xdp, unsupported),
	STAT_FIELD_SUB(veth_asymmetric_xdp, pair_ok),
	STAT_FIELD_SUB(veth_asymmetric_xdp, xdp_attach_ok),
	STAT_FIELD_SUB(veth_asymmetric_xdp, send_ok),
};

const struct stat_category veth_asymmetric_xdp_category =
	STAT_CATEGORY("veth_asymmetric_xdp",
	              veth_asymmetric_xdp.iters,
	              veth_asymmetric_xdp_fields);

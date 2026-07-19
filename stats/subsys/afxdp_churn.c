#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field afxdp_churn_fields[] = {
	STAT_FIELD_SUB(afxdp_churn, runs),
	STAT_FIELD_SUB(afxdp_churn, setup_failed),
	STAT_FIELD_SUB(afxdp_churn, umem_reg_ok),
	STAT_FIELD_SUB(afxdp_churn, rings_setup_ok),
	STAT_FIELD_SUB(afxdp_churn, prog_load_ok),
	STAT_FIELD_SUB(afxdp_churn, map_create_ok),
	STAT_FIELD_SUB(afxdp_churn, map_update_ok),
	STAT_FIELD_SUB(afxdp_churn, bind_ok),
	STAT_FIELD_SUB(afxdp_churn, link_attach_ok),
	STAT_FIELD_SUB(afxdp_churn, netlink_attach_ok),
	STAT_FIELD_SUB(afxdp_churn, attach_failed),
	STAT_FIELD_SUB(afxdp_churn, send_ok),
	STAT_FIELD_SUB(afxdp_churn, recv_ok),
	STAT_FIELD_SUB(afxdp_churn, map_delete_ok),
	STAT_FIELD_SUB(afxdp_churn, munmap_race_ok),
	STAT_FIELD_SUB(afxdp_churn, xsg_iters),
	STAT_FIELD_SUB(afxdp_churn, tx_metadata_iters),
	STAT_FIELD_SUB(afxdp_churn, tun_bind_iters),
	STAT_FIELD_SUB(afxdp_churn, xsg_bind_failed),
	STAT_FIELD_SUB(afxdp_churn, tx_md_bind_failed),
};

const struct stat_category afxdp_churn_category =
	STAT_CATEGORY("afxdp_churn",
	              afxdp_churn.runs,
	              afxdp_churn_fields);

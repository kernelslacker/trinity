/*
 * Network / iouring-network JSON section emitters for --stats-json:
 * the three long category-compose helpers (net-churn + early storms,
 * pidfd + fs + container, and iouring + iSCSI + net tail).
 */

#include <stddef.h>
#include <stdio.h>
#include "stats-internal.h"
#include "stats/json/internal.h"

void json_emit_net_churn_and_early_storms_section(void)
{




	json_stats_sep();
	stat_category_emit_json(&blob_mutator_category);

	json_stats_sep();
	stat_category_emit_json(&blob_ab_mode_category);


	json_stats_sep();
	stat_category_emit_json(&setsockopt_pairing_category);




	json_stats_sep();
	stat_category_emit_json(&userns_bootstrap_category);






}

void json_emit_pidfd_fs_and_container_section(void)
{







	json_stats_sep();
	stat_category_emit_json(&xattr_thrash_category);

	json_stats_sep();
	stat_category_emit_json(&epoll_volatility_category);







}

void json_emit_iouring_iscsi_and_net_tail_section(void)
{
	json_stats_sep();
	stat_category_emit_json(&rxrpc_key_install_category);















}

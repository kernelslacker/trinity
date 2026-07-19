#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tcp_ulp_swap_churn_fields[] = {
	STAT_FIELD(tcp_ulp_swap_churn, runs),
	STAT_FIELD(tcp_ulp_swap_churn, setup_failed),
	STAT_FIELD(tcp_ulp_swap_churn, install_tls_ok),
	STAT_FIELD(tcp_ulp_swap_churn, tx_install_ok),
	STAT_FIELD(tcp_ulp_swap_churn, send_ok),
	STAT_FIELD(tcp_ulp_swap_churn, swap_rejected_ok),
	STAT_FIELD(tcp_ulp_swap_churn, ifname_probe_ok),
	STAT_FIELD(tcp_ulp_swap_churn, uninstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, reinstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, install_failed),
};

const struct stat_category tcp_ulp_swap_churn_category =
	STAT_CATEGORY("tcp_ulp_swap_churn",
	              tcp_ulp_swap_churn_runs,
	              tcp_ulp_swap_churn_fields);

static const struct stat_field tcp_md5_listener_race_fields[] = {
	STAT_FIELD(tcp_md5_listener_race, runs),
	STAT_FIELD(tcp_md5_listener_race, setup_failed),
	STAT_FIELD(tcp_md5_listener_race, md5_set_ok),
	STAT_FIELD(tcp_md5_listener_race, md5_set_failed),
	STAT_FIELD(tcp_md5_listener_race, connect_ok),
	STAT_FIELD(tcp_md5_listener_race, rst_sent_ok),
	STAT_FIELD(tcp_md5_listener_race, completed_ok),
};

const struct stat_category tcp_md5_listener_race_category =
	STAT_CATEGORY("tcp_md5_listener_race",
	              tcp_md5_listener_race_runs,
	              tcp_md5_listener_race_fields);




static const struct stat_field pkt_builder_fields[] = {
	STAT_FIELD(pkt_builder, runs),
	STAT_FIELD(pkt_builder, setup_failed),
	STAT_FIELD(pkt_builder, built_ok),
	STAT_FIELD(pkt_builder, build_failed),
	STAT_FIELD(pkt_builder, mutated),
	STAT_FIELD(pkt_builder, truncated),
	STAT_FIELD(pkt_builder, delivered_ok),
	STAT_FIELD(pkt_builder, delivery_failed),
	STAT_FIELD(pkt_builder, delivery_disabled),
	{ .name = "recipe_vxlan_eth_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[0]) },
	{ .name = "recipe_gretap_eth_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[1]) },
	{ .name = "recipe_raw_ip4_gretap_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[2]) },
	{ .name = "recipe_qinq_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[3]) },
	{ .name = "recipe_geneve_v6_eth_ip6",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[4]) },
	{ .name = "recipe_mpls_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[5]) },
};

const struct stat_category pkt_builder_category =
	STAT_CATEGORY("pkt_builder",
	              pkt_builder_runs,
	              pkt_builder_fields);

static const struct stat_field veth_asymmetric_xdp_fields[] = {
	STAT_FIELD(veth_asym, iters),
	STAT_FIELD(veth_asym, eperm),
	STAT_FIELD(veth_asym, unsupported),
	STAT_FIELD(veth_asym, pair_ok),
	STAT_FIELD(veth_asym, xdp_attach_ok),
	STAT_FIELD(veth_asym, send_ok),
};

const struct stat_category veth_asymmetric_xdp_category =
	STAT_CATEGORY("veth_asymmetric_xdp",
	              veth_asym_iters,
	              veth_asymmetric_xdp_fields);

static const struct stat_field ip6erspan_netns_migrate_fields[] = {
	STAT_FIELD(inm, iters),
	STAT_FIELD(inm, eperm),
	STAT_FIELD(inm, unsupported),
	STAT_FIELD(inm, link_create_ok),
	STAT_FIELD(inm, netns_migrate_ok),
	STAT_FIELD(inm, changelink_ok),
	STAT_FIELD(inm, ip6erspan_unsupported_observed),
	STAT_FIELD(inm, changelink_unsupported_observed),
};

const struct stat_category ip6erspan_netns_migrate_category =
	STAT_CATEGORY("ip6erspan_netns_migrate",
	              inm_iters,
	              ip6erspan_netns_migrate_fields);

static const struct stat_field netdev_netns_migrate_fields[] = {
	STAT_FIELD(nnm, iters),
	STAT_FIELD(nnm, eperm),
	STAT_FIELD(nnm, unsupported),
	STAT_FIELD(nnm, pin_sock_ok),
	STAT_FIELD(nnm, link_create_ok),
	STAT_FIELD(nnm, migrate_ok),
	STAT_FIELD(nnm, migrate_rejected),
	STAT_FIELD(nnm, up_ok),
	STAT_FIELD(nnm, addr_ok),
	STAT_FIELD(nnm, unsupported_observed),
	STAT_FIELD(nnm, drive_unsupported_observed),
};

const struct stat_category netdev_netns_migrate_category =
	STAT_CATEGORY("netdev_netns_migrate",
		      nnm_iters,
		      netdev_netns_migrate_fields);


static const struct stat_field qrtr_bind_race_fields[] = {
	STAT_FIELD(qrtr_bind_race, runs),
	STAT_FIELD(qrtr_bind_race, setup_failed),
	STAT_FIELD(qrtr_bind_race, iter),
	STAT_FIELD(qrtr_bind_race, fork_failed),
	STAT_FIELD(qrtr_bind_race, spawn_pair_ok),
	STAT_FIELD(qrtr_bind_race, sibling_reaped_ok),
	STAT_FIELD(qrtr_bind_race, sibling_crashed),
	STAT_FIELD(qrtr_bind, setup_fail),
};

const struct stat_category qrtr_bind_race_category =
	STAT_CATEGORY("qrtr_bind_race",
		qrtr_bind_race_runs,
		qrtr_bind_race_fields);

static const struct stat_field pfkey_spd_walk_fields[] = {
	STAT_FIELD(pfkey_spd_walk, runs),
	STAT_FIELD(pfkey_spd_walk, setup_failed),
	STAT_FIELD(pfkey_spd_walk, iter),
	STAT_FIELD(pfkey_spd_walk, fork_failed),
	STAT_FIELD(pfkey_spd_walk, spawn_pair_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_reaped_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_crashed),
	STAT_FIELD(pfkey, spdget_resolved),
	STAT_FIELD(pfkey, spdget_missed),
};

const struct stat_category pfkey_spd_walk_category =
	STAT_CATEGORY("pfkey_spd_walk",
		pfkey_spd_walk_runs,
		pfkey_spd_walk_fields);


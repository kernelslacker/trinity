#include <stddef.h>
#include "stats-internal.h"






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








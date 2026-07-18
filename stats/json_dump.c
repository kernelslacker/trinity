/*
 * --stats-json emitters.
 *
 * Carved verbatim out of stats.c.  Contains the JSON string / syscall
 * / kcov / minicorpus / cmp_hints emitters, the descriptor-driven
 * stat_category_emit_json helper, the interleaved stat_field /
 * stat_category tables the JSON walker owns, and the top-level
 * dump_stats_json() that stitches them together for --stats-json.
 *
 * The category tables here are already declared extern in
 * stats-internal.h so the text-side dump in stats.c and stats/dump.c
 * still sees them; the definition site is what moves.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils-proc.h"
#include "utils.h"
#include "version.h"




static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD(packet_fanout, runs),
	STAT_FIELD(packet_fanout, setup_failed),
	STAT_FIELD(packet_fanout, ring_failed),
	STAT_FIELD(packet_fanout, rings_installed),
	STAT_FIELD(packet_fanout, mmap_failed),
	STAT_FIELD(packet_fanout, joins),
	STAT_FIELD(packet_fanout, rejoins_ok),
	STAT_FIELD(packet_fanout, rejoins_rejected),
};

static const struct stat_category packet_fanout_thrash_category =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_runs,
	              packet_fanout_thrash_fields);

/*
 * eth_emitter's five per-template counters live in an array
 * (eth_emitter_per_tmpl[NR_TEMPLATES]); the JSON schema emits one
 * flat key per slot ("tmpl_arp" .. "tmpl_bad_ethertype"), so raw
 * offsetof() entries pin each key to its array index.
 */
static const struct stat_field eth_emitter_fields[] = {
	STAT_FIELD(eth_emitter, runs),
	STAT_FIELD(eth_emitter, setup_failed),
	STAT_FIELD(eth_emitter, short),
	STAT_FIELD(eth_emitter, sends_ok),
	STAT_FIELD(eth_emitter, sends_failed),
	{ .name = "tmpl_arp",
	  .offset = offsetof(struct stats_s, eth_emitter_per_tmpl[0]) },
	{ .name = "tmpl_ipv4_frag_zero",
	  .offset = offsetof(struct stats_s, eth_emitter_per_tmpl[1]) },
	{ .name = "tmpl_ipv6_na",
	  .offset = offsetof(struct stats_s, eth_emitter_per_tmpl[2]) },
	{ .name = "tmpl_vlan_qinq",
	  .offset = offsetof(struct stats_s, eth_emitter_per_tmpl[3]) },
	{ .name = "tmpl_bad_ethertype",
	  .offset = offsetof(struct stats_s, eth_emitter_per_tmpl[4]) },
};

static const struct stat_category eth_emitter_category =
	STAT_CATEGORY("eth_emitter",
	              eth_emitter_runs,
	              eth_emitter_fields);

static const struct stat_field iouring_net_multishot_fields[] = {
	STAT_FIELD(iouring_multishot, runs),
	STAT_FIELD(iouring_multishot, setup_failed),
	STAT_FIELD(iouring_multishot, pbuf_ring_ok),
	STAT_FIELD(iouring_multishot, pbuf_legacy_ok),
	STAT_FIELD(iouring_multishot, armed),
	STAT_FIELD(iouring_multishot, packets_sent),
	STAT_FIELD(iouring_multishot, completions),
	STAT_FIELD(iouring_multishot, cancel_submitted),
	STAT_FIELD_JSON(iouring_napi, register_ok, "napi_register_ok"),
	STAT_FIELD_JSON(iouring_napi, register_fail, "napi_register_fail"),
	STAT_FIELD_JSON(iouring_napi, unregister_ok, "napi_unregister_ok"),
	STAT_FIELD_JSON(iouring_napi, unregister_fail, "napi_unregister_fail"),
};

static const struct stat_category iouring_net_multishot_category =
	STAT_CATEGORY("iouring_net_multishot",
	              iouring_multishot_runs,
	              iouring_net_multishot_fields);

static const struct stat_field bridge_fdb_stp_fields[] = {
	STAT_FIELD(bridge_fdb_stp, runs),
	STAT_FIELD(bridge_fdb_stp, setup_failed),
	STAT_FIELD(bridge_fdb_stp, bridge_create_ok),
	STAT_FIELD(bridge_fdb_stp, veth_create_ok),
	STAT_FIELD(bridge_fdb_stp, raw_send_ok),
	STAT_FIELD(bridge_fdb_stp, stp_toggle_ok),
	STAT_FIELD(bridge_fdb_stp, fdb_del_ok),
	STAT_FIELD(bridge_fdb_stp, link_del_ok),
	STAT_FIELD_JSON(bridge_vlan_mass, runs, "vlan_mass_runs"),
	STAT_FIELD_JSON(bridge_vlan_mass, max_n, "vlan_mass_max_n"),
	STAT_FIELD_JSON(bridge_vlan_mass, enotbufs, "vlan_mass_enotbufs"),
};

static const struct stat_category bridge_fdb_stp_category =
	STAT_CATEGORY("bridge_fdb_stp",
	              bridge_fdb_stp_runs,
	              bridge_fdb_stp_fields);

static void dump_stats_json_socket_family_and_tls(void)
{
	stat_category_emit_json(&packet_fanout_thrash_category);
	putchar(',');
	stat_category_emit_json(&eth_emitter_category);
	putchar(',');
	stat_category_emit_json(&iouring_net_multishot_category);
	putchar(',');
	stat_category_emit_json(&bridge_fdb_stp_category);
	putchar(',');
}

/*
 * Descriptor tables for dump_stats_json_netfilter_and_xfrm().
 *
 * Six categories that the previous hand-written printf emitted with one
 * %lu slot per field and a parallel shm->stats.<field> va-list; adding a
 * counter required three correlated edits.  STAT_FIELD picks whichever
 * struct prefix matches the actual member (nftables_churn_/nft_,
 * tc_qdisc_churn_/tc_qdisc_, xfrm_churn_/xfrm_ah_esn_,
 * mptcp_pm_churn_/mptcp_setsockopt_/mptcp_getsockopt_/mptcp_sockopt_);
 * .name doubles as the (currently unused) text-side key.  STAT_FIELD_JSON
 * pins the JSON key for the xt_ct_* members pulled into nftables_churn,
 * whose struct suffix (e.g. "ct_iters") doesn't carry the "xt_ct_"
 * qualifier the schema emits.
 *
 * The text emitter for these subsystems stays hand-coded for now, so the
 * gate_offset choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field nftables_churn_fields[] = {
	STAT_FIELD(nftables_churn, runs),
	STAT_FIELD(nftables_churn, setup_failed),
	STAT_FIELD(nftables_churn, table_create_ok),
	STAT_FIELD(nftables_churn, set_create_ok),
	STAT_FIELD(nftables_churn, chain_create_ok),
	STAT_FIELD(nftables_churn, rule_create_ok),
	STAT_FIELD(nftables_churn, packet_sent_ok),
	STAT_FIELD(nftables_churn, rule_insert_ok),
	STAT_FIELD(nftables_churn, rule_del_ok),
	STAT_FIELD(nftables_churn, table_del_ok),
	STAT_FIELD(nftables_churn, payload_expr_emit),
	STAT_FIELD(nftables_churn, objref_expr_emit),
	STAT_FIELD(nft, compat_validate_install_ok),
	STAT_FIELD(nft, compat_validate_install_fail),
	STAT_FIELD(nft, compat_validate_unsupported),
	STAT_FIELD(nft, compat_validate_per_hook_pairs),
	STAT_FIELD(nft, dormant_abort_iters),
	STAT_FIELD(nft, dormant_abort_eperm),
	STAT_FIELD(nft, dormant_abort_emsg),
	STAT_FIELD(nft, dormant_abort_ok),
	STAT_FIELD_JSON(xt, ct_iters, "xt_ct_iters"),
	STAT_FIELD_JSON(xt, ct_eperm, "xt_ct_eperm"),
	STAT_FIELD_JSON(xt, ct_unsupported, "xt_ct_unsupported"),
	STAT_FIELD_JSON(xt, ct_set_ok, "xt_ct_set_ok"),
	STAT_FIELD_JSON(xt, ct_get_ok, "xt_ct_get_ok"),
	STAT_FIELD_JSON(xt, ct_v2_seen, "xt_ct_v2_seen"),
	STAT_FIELD(nft, fwd_loop_runs),
	STAT_FIELD(nft, fwd_loop_ns_setup_failed),
	STAT_FIELD(nft, fwd_loop_probe_sent_ok),
	STAT_FIELD(nft, fwd_loop_completed_ok),
	STAT_FIELD(nft, l4frag_iters),
	STAT_FIELD(nft, l4frag_install_ok),
	STAT_FIELD(nft, l4frag_rule_ok),
	STAT_FIELD(nft, l4frag_send_ok),
	STAT_FIELD(nft, l4frag_send_failed),
};

const struct stat_category nftables_churn_category =
	STAT_CATEGORY("nftables_churn",
	              nftables_churn_runs,
	              nftables_churn_fields);

static const struct stat_field tc_qdisc_churn_fields[] = {
	STAT_FIELD(tc_qdisc_churn, runs),
	STAT_FIELD(tc_qdisc_churn, setup_failed),
	STAT_FIELD(tc_qdisc_churn, link_create_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_create_ok),
	STAT_FIELD(tc_qdisc_churn, tclass_create_ok),
	STAT_FIELD(tc_qdisc_churn, tfilter_create_ok),
	STAT_FIELD(tc_qdisc_churn, packet_sent_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_replace_ok),
	STAT_FIELD(tc_qdisc_churn, tfilter_del_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_del_ok),
	STAT_FIELD(tc_qdisc_churn, link_del_ok),
	STAT_FIELD(tc_qdisc, peek_stack_runs),
	STAT_FIELD(tc_qdisc, peek_stack_install_ok),
	STAT_FIELD(tc_qdisc, peek_stack_install_fail),
	STAT_FIELD(tc_qdisc, peek_stack_burst_ok),
	STAT_FIELD(tc_qdisc_churn, bridge_parent_runs),
	STAT_FIELD(tc_qdisc_churn, bridge_dellink_race_ok),
	STAT_FIELD(tc_qdisc_churn, gso_burst_ok),
};

const struct stat_category tc_qdisc_churn_category =
	STAT_CATEGORY("tc_qdisc_churn",
	              tc_qdisc_churn_runs,
	              tc_qdisc_churn_fields);

static const struct stat_field tc_mirred_blockcast_fields[] = {
	STAT_FIELD(tc_mirred_blockcast, runs),
	STAT_FIELD(tc_mirred_blockcast, setup_failed),
	STAT_FIELD(tc_mirred_blockcast, qdisc_ok),
	STAT_FIELD(tc_mirred_blockcast, qdisc_fail),
	STAT_FIELD(tc_mirred_blockcast, filter_ok),
	STAT_FIELD(tc_mirred_blockcast, filter_fail),
	STAT_FIELD(tc_mirred_blockcast, packet_sent_ok),
};

const struct stat_category tc_mirred_blockcast_category =
	STAT_CATEGORY("tc_mirred_blockcast",
		tc_mirred_blockcast_runs,
		tc_mirred_blockcast_fields);

static const struct stat_field tc_live_traffic_fields[] = {
	STAT_FIELD(tc_live_traffic, runs),
	STAT_FIELD(tc_live_traffic, setup_failed),
	STAT_FIELD(tc_live_traffic, qdisc_ok),
	STAT_FIELD(tc_live_traffic, qdisc_fail),
	STAT_FIELD(tc_live_traffic, filter_ok),
	STAT_FIELD(tc_live_traffic, filter_fail),
	STAT_FIELD(tc_live_traffic, filter_del_ok),
	STAT_FIELD(tc_live_traffic, filter_replace_ok),
	STAT_FIELD(tc_live_traffic, packet_sent_ok),
	STAT_FIELD(tc_live_traffic, link_del_ok),
	STAT_FIELD(tc_live_traffic, bpf_load_ok),
	STAT_FIELD(tc_live_traffic, xdp_load_ok),
	STAT_FIELD(tc_live_traffic, xdp_attach_ok),
};

const struct stat_category tc_live_traffic_category =
	STAT_CATEGORY("tc_live_traffic",
		tc_live_traffic_runs,
		tc_live_traffic_fields);

static const struct stat_field xfrm_churn_fields[] = {
	STAT_FIELD(xfrm_churn, runs),
	STAT_FIELD(xfrm_churn, setup_failed),
	STAT_FIELD(xfrm_churn, sa_added),
	STAT_FIELD(xfrm_churn, tunnel_sa_added),
	STAT_FIELD(xfrm_churn, iptfs_sa_added),
	STAT_FIELD(xfrm_churn, sa_updated),
	STAT_FIELD(xfrm_churn, sa_deleted),
	STAT_FIELD(xfrm_churn, pol_added),
	STAT_FIELD(xfrm_churn, pol_deleted),
	STAT_FIELD(xfrm_churn, esp_sent),
	STAT_FIELD(xfrm_churn, zc_sent),
	STAT_FIELD(xfrm_churn, zc_errq_drained),
	STAT_FIELD(xfrm_churn, pfkey_send_ok),
	STAT_FIELD(xfrm_churn, burn_runs),
	STAT_FIELD(xfrm_churn, burn_throttled),
	STAT_FIELD(xfrm_churn, burn_completed),
};

const struct stat_category xfrm_churn_category =
	STAT_CATEGORY("xfrm_churn",
	              xfrm_churn_runs,
	              xfrm_churn_fields);

static const struct stat_field xfrm_ah_esn_fields[] = {
	STAT_FIELD(xfrm_ah_esn, setup_ok),
	STAT_FIELD(xfrm_ah_esn, setup_fail),
	STAT_FIELD(xfrm_ah_esn, async_runs),
	STAT_FIELD(xfrm_ah_esn, delsa_races),
};

const struct stat_category xfrm_ah_esn_category =
	STAT_CATEGORY("xfrm_ah_esn",
	              xfrm_ah_esn_async_runs,
	              xfrm_ah_esn_fields);

static const struct stat_field xfrm_compat_fields[] = {
	STAT_FIELD(xfrm_compat, sweep_runs),
	STAT_FIELD(xfrm_compat, sends_ok),
	STAT_FIELD(xfrm_compat, sends_failed),
	STAT_FIELD(xfrm_compat, replies_seen),
};

const struct stat_category xfrm_compat_category =
	STAT_CATEGORY("xfrm_compat",
	              xfrm_compat_sweep_runs,
	              xfrm_compat_fields);

static const struct stat_field sysfs_string_race_fields[] = {
	STAT_FIELD(sysfs_string_race, runs),
	STAT_FIELD(sysfs_string_race, setup_failed),
	STAT_FIELD(sysfs_string_race, target_missing),
	STAT_FIELD(sysfs_string_race, target_used),
	STAT_FIELD(sysfs_string_race, fork_failed),
	STAT_FIELD(sysfs_string_race, writes_ok),
	STAT_FIELD(sysfs_string_race, writes_failed),
};

const struct stat_category sysfs_string_race_category =
	STAT_CATEGORY("sysfs_string_race",
	              sysfs_string_race_runs,
	              sysfs_string_race_fields);

static const struct stat_field atm_vcc_churn_fields[] = {
	STAT_FIELD(atm_vcc_churn, runs),
	STAT_FIELD(atm_vcc_churn, unsupported),
	STAT_FIELD(atm_vcc_churn, socket_ok),
	STAT_FIELD(atm_vcc_churn, ioctls_sent),
	STAT_FIELD(atm_vcc_churn, kernel_rejected),
};

const struct stat_category atm_vcc_churn_category =
	STAT_CATEGORY("atm_vcc_churn",
	              atm_vcc_churn_runs,
	              atm_vcc_churn_fields);

static const struct stat_field sock_ulp_sockmap_layering_fields[] = {
	STAT_FIELD(sock_ulp_sockmap_layering, runs),
	STAT_FIELD(sock_ulp_sockmap_layering, setup_failed),
	STAT_FIELD(sock_ulp_sockmap_layering, map_failed),
	STAT_FIELD(sock_ulp_sockmap_layering, prog_failed),
	STAT_FIELD(sock_ulp_sockmap_layering, attach_failed),
	STAT_FIELD(sock_ulp_sockmap_layering, layered_ok),
};

const struct stat_category sock_ulp_sockmap_layering_category =
	STAT_CATEGORY("sock_ulp_sockmap_layering",
	              sock_ulp_sockmap_layering_runs,
	              sock_ulp_sockmap_layering_fields);

static const struct stat_field sock_diag_walker_fields[] = {
	STAT_FIELD(sock_diag_walker, runs),
	STAT_FIELD(sock_diag_walker, setup_failed),
	STAT_FIELD(sock_diag_walker, inet),
	STAT_FIELD(sock_diag_walker, unix),
	STAT_FIELD(sock_diag_walker, netlink),
	STAT_FIELD(sock_diag_walker, packet),
	STAT_FIELD(sock_diag_walker, vsock),
};

const struct stat_category sock_diag_walker_category =
	STAT_CATEGORY("sock_diag_walker",
	              sock_diag_walker_runs,
	              sock_diag_walker_fields);

static const struct stat_field altname_thrash_fields[] = {
	STAT_FIELD(altname_thrash, invocations),
	STAT_FIELD(altname_thrash, unshare_failed),
	STAT_FIELD(altname_thrash, addprop_done),
	STAT_FIELD(altname_thrash, delprop_done),
	STAT_FIELD(altname_thrash, getlink_done),
};

const struct stat_category altname_thrash_category =
	STAT_CATEGORY("altname_thrash",
	              altname_thrash_invocations,
	              altname_thrash_fields);

static const struct stat_field sctp_assoc_churn_fields[] = {
	STAT_FIELD(sctp_assoc_churn, runs),
	STAT_FIELD(sctp_assoc_churn, setup_failed),
	STAT_FIELD(sctp_assoc_churn, bindx_added),
	STAT_FIELD(sctp_assoc_churn, bindx_removed),
	STAT_FIELD(sctp_assoc_churn, bindx_rejected),
	STAT_FIELD(sctp_assoc_churn, connect_failed),
	STAT_FIELD(sctp_assoc_churn, connected),
	STAT_FIELD(sctp_assoc_churn, accepted),
	STAT_FIELD(sctp_assoc_churn, packets_sent),
	STAT_FIELD(sctp_assoc_churn, peeled_off),
	STAT_FIELD(sctp_assoc_churn, peeloff_rejected),
	STAT_FIELD(sctp_assoc_churn, cycles),
};

const struct stat_category sctp_assoc_churn_category =
	STAT_CATEGORY("sctp_assoc_churn",
	              sctp_assoc_churn_runs,
	              sctp_assoc_churn_fields);

static const struct stat_field sctp_chunk_rx_fields[] = {
	STAT_FIELD(sctp_chunk_rx, runs),
	STAT_FIELD(sctp_chunk_rx, setup_failed),
	STAT_FIELD(sctp_chunk_rx, listener_ok),
	STAT_FIELD(sctp_chunk_rx, packet_sent_ok),
};

const struct stat_category sctp_chunk_rx_category =
	STAT_CATEGORY("sctp_chunk_rx",
	              sctp_chunk_rx_runs,
	              sctp_chunk_rx_fields);

static const struct stat_field esp_crafted_rx_fields[] = {
	STAT_FIELD(esp_crafted_rx, runs),
	STAT_FIELD(esp_crafted_rx, setup_failed),
	STAT_FIELD(esp_crafted_rx, sa_install_ok),
	STAT_FIELD(esp_crafted_rx, sa_install_failed),
	STAT_FIELD(esp_crafted_rx, packet_sent_ok),
	STAT_FIELD(esp_crafted_rx, sa_delete_ok),
	STAT_FIELD(esp_crafted_rx, stacked_sa_install_ok),
	STAT_FIELD(esp_crafted_rx, stacked_sent_ok),
};

const struct stat_category esp_crafted_rx_category =
	STAT_CATEGORY("esp_crafted_rx",
	              esp_crafted_rx_runs,
	              esp_crafted_rx_fields);

static const struct stat_field fou_gue_mcast_rx_fields[] = {
	STAT_FIELD(fou_gue_mcast_rx, runs),
	STAT_FIELD(fou_gue_mcast_rx, setup_failed),
	STAT_FIELD(fou_gue_mcast_rx, port_install_ok),
	STAT_FIELD(fou_gue_mcast_rx, port_install_failed),
	STAT_FIELD(fou_gue_mcast_rx, packet_sent_ok),
	STAT_FIELD(fou_gue_mcast_rx, port_delete_ok),
};

const struct stat_category fou_gue_mcast_rx_category =
	STAT_CATEGORY("fou_gue_mcast_rx",
	              fou_gue_mcast_rx_runs,
	              fou_gue_mcast_rx_fields);

static const struct stat_field geneve_rx_fields[] = {
	STAT_FIELD(geneve_rx, runs),
	STAT_FIELD(geneve_rx, setup_failed),
	STAT_FIELD(geneve_rx, link_create_ok),
	STAT_FIELD(geneve_rx, link_create_failed),
	STAT_FIELD(geneve_rx, link_up_ok),
	STAT_FIELD(geneve_rx, packet_sent_ok),
	STAT_FIELD(geneve_rx, link_del_ok),
};

const struct stat_category geneve_rx_category =
	STAT_CATEGORY("geneve_rx",
	              geneve_rx_runs,
	              geneve_rx_fields);

static const struct stat_field bareudp_rx_fields[] = {
	STAT_FIELD(bareudp_rx, runs),
	STAT_FIELD(bareudp_rx, setup_failed),
	STAT_FIELD(bareudp_rx, link_create_ok),
	STAT_FIELD(bareudp_rx, link_create_failed),
	STAT_FIELD(bareudp_rx, link_up_ok),
	STAT_FIELD(bareudp_rx, packet_sent_ok),
	STAT_FIELD(bareudp_rx, link_del_ok),
};

const struct stat_category bareudp_rx_category =
	STAT_CATEGORY("bareudp_rx",
	              bareudp_rx_runs,
	              bareudp_rx_fields);

static const struct stat_field mpls_label_stack_rx_fields[] = {
	STAT_FIELD(mpls_label_stack_rx, runs),
	STAT_FIELD(mpls_label_stack_rx, setup_failed),
	STAT_FIELD(mpls_label_stack_rx, config_ok),
	STAT_FIELD(mpls_label_stack_rx, config_failed),
	STAT_FIELD(mpls_label_stack_rx, link_up_ok),
	STAT_FIELD(mpls_label_stack_rx, packet_sent_ok),
};

const struct stat_category mpls_label_stack_rx_category =
	STAT_CATEGORY("mpls_label_stack_rx",
	              mpls_label_stack_rx_runs,
	              mpls_label_stack_rx_fields);

static const struct stat_field rds_zcopy_crafted_send_fields[] = {
	STAT_FIELD(rds_zcopy_crafted_send, runs),
	STAT_FIELD(rds_zcopy_crafted_send, setup_failed),
	STAT_FIELD(rds_zcopy_crafted_send, bind_ok),
	STAT_FIELD(rds_zcopy_crafted_send, zc_enable_ok),
	STAT_FIELD(rds_zcopy_crafted_send, hole_ok),
	STAT_FIELD(rds_zcopy_crafted_send, sends_ok),
	STAT_FIELD(rds_zcopy_crafted_send, sends_efault),
	STAT_FIELD(rds_zcopy_crafted_send, sends_failed),
	STAT_FIELD(rds_zcopy_crafted_send, errqueue_drained),
};

const struct stat_category rds_zcopy_crafted_send_category =
	STAT_CATEGORY("rds_zcopy_crafted_send",
		      rds_zcopy_crafted_send_runs,
		      rds_zcopy_crafted_send_fields);

static const struct stat_field bridge_ip6_refrag_fraggap_fields[] = {
	STAT_FIELD(bridge_ip6_refrag_fraggap, runs),
	STAT_FIELD(bridge_ip6_refrag_fraggap, brnf_enabled),
	STAT_FIELD(bridge_ip6_refrag_fraggap, bursts),
	STAT_FIELD(bridge_ip6_refrag_fraggap, frags_sent),
};

const struct stat_category bridge_ip6_refrag_fraggap_category =
	STAT_CATEGORY("bridge_ip6_refrag_fraggap",
		      bridge_ip6_refrag_fraggap_runs,
		      bridge_ip6_refrag_fraggap_fields);

static const struct stat_field mptcp_pm_churn_fields[] = {
	STAT_FIELD(mptcp_pm_churn, runs),
	STAT_FIELD(mptcp_pm_churn, setup_failed),
	STAT_FIELD(mptcp_pm_churn, sock_mptcp_ok),
	STAT_FIELD(mptcp_pm_churn, addr_added_ok),
	STAT_FIELD(mptcp_pm_churn, addr_removed_ok),
	STAT_FIELD(mptcp_pm_churn, send_ok),
	STAT_FIELD(mptcp, setsockopt_unsupported),
	STAT_FIELD(mptcp, setsockopt_master_set),
	STAT_FIELD(mptcp, setsockopt_master_fail),
	STAT_FIELD(mptcp, getsockopt_verify_ok),
	STAT_FIELD(mptcp, getsockopt_verify_drift),
	STAT_FIELD(mptcp, sockopt_sweep_runs),
	STAT_FIELD(mptcp, sockopt_set_ok),
	STAT_FIELD(mptcp, sockopt_set_failed),
	STAT_FIELD(mptcp, sockopt_subflow_added),
	STAT_FIELD(mptcp, sockopt_readback_ok),
	STAT_FIELD(mptcp, sockopt_inherit_mismatch),
	STAT_FIELD(mptcp, sockopt_unsupported_latched),
};

const struct stat_category mptcp_pm_churn_category =
	STAT_CATEGORY("mptcp_pm_churn",
	              mptcp_pm_churn_runs,
	              mptcp_pm_churn_fields);

static const struct stat_field devlink_port_churn_fields[] = {
	STAT_FIELD(devlink_port_churn, iterations),
	STAT_FIELD(devlink_port_churn, split_ok),
	STAT_FIELD(devlink_port_churn, split_fail),
	STAT_FIELD(devlink_port_churn, reload_ok),
	STAT_FIELD(devlink_port_churn, reload_fail),
	STAT_FIELD(devlink_port_churn, create_skipped),
};

const struct stat_category devlink_port_churn_category =
	STAT_CATEGORY("devlink_port_churn",
	              devlink_port_churn_iterations,
	              devlink_port_churn_fields);

static const struct stat_field ipmr_cache_report_fields[] = {
	STAT_FIELD(ipmr_cache_report, iters),
	STAT_FIELD(ipmr_cache_report, eperm),
	STAT_FIELD(ipmr_cache_report, emit_ok),
};

const struct stat_category ipmr_cache_report_category =
	STAT_CATEGORY("ipmr_cache_report",
	              ipmr_cache_report_iters,
	              ipmr_cache_report_fields);

static const struct stat_field fdstress_fields[] = {
	STAT_FIELD(fdstress, close_reopen),
	STAT_FIELD(fdstress, dup2_replace),
	STAT_FIELD(fdstress, type_confusion),
	STAT_FIELD(fdstress, cloexec_toggle),
};

const struct stat_category fdstress_category =
	STAT_CATEGORY("fdstress",
	              fdstress_close_reopen,
	              fdstress_fields);

static void dump_stats_json_netfilter_and_xfrm(void)
{
	stat_category_emit_json(&nftables_churn_category);
	putchar(',');
	stat_category_emit_json(&tc_qdisc_churn_category);
	putchar(',');
	stat_category_emit_json(&tc_mirred_blockcast_category);
	putchar(',');
	stat_category_emit_json(&tc_live_traffic_category);
	putchar(',');
	stat_category_emit_json(&xfrm_churn_category);
	putchar(',');
	stat_category_emit_json(&xfrm_ah_esn_category);
	putchar(',');
	stat_category_emit_json(&xfrm_compat_category);
	putchar(',');
	stat_category_emit_json(&sysfs_string_race_category);
	putchar(',');
	stat_category_emit_json(&atm_vcc_churn_category);
	putchar(',');
	stat_category_emit_json(&sock_ulp_sockmap_layering_category);
	putchar(',');
	stat_category_emit_json(&sock_diag_walker_category);
	putchar(',');
	stat_category_emit_json(&altname_thrash_category);
	putchar(',');
	stat_category_emit_json(&sctp_assoc_churn_category);
	putchar(',');
	stat_category_emit_json(&sctp_chunk_rx_category);
	putchar(',');
	stat_category_emit_json(&esp_crafted_rx_category);
	putchar(',');
	stat_category_emit_json(&fou_gue_mcast_rx_category);
	putchar(',');
	stat_category_emit_json(&geneve_rx_category);
	putchar(',');
	stat_category_emit_json(&bareudp_rx_category);
	putchar(',');
	stat_category_emit_json(&mpls_label_stack_rx_category);
	putchar(',');
	stat_category_emit_json(&rds_zcopy_crafted_send_category);
	putchar(',');
	stat_category_emit_json(&bridge_ip6_refrag_fraggap_category);
	putchar(',');
	stat_category_emit_json(&mptcp_pm_churn_category);
	putchar(',');
	stat_category_emit_json(&devlink_port_churn_category);
	putchar(',');
	stat_category_emit_json(&ipmr_cache_report_category);
}

static const struct stat_field vsock_transport_churn_fields[] = {
	STAT_FIELD(vsock_transport_churn, runs),
	STAT_FIELD(vsock_transport_churn, setup_failed),
	STAT_FIELD(vsock_transport_churn, bind_ok),
	STAT_FIELD(vsock_transport_churn, connect_ok),
	STAT_FIELD(vsock_transport_churn, send_ok),
	STAT_FIELD(vsock_transport_churn, buffer_size_ok),
	STAT_FIELD(vsock_transport_churn, timeout_ok),
	STAT_FIELD(vsock_transport_churn, get_cid_ok),
	STAT_FIELD(vsock, seq_eom_runs),
	STAT_FIELD(vsock, seq_eom_sends_ok),
	STAT_FIELD(vsock, seq_eom_sends_failed),
	STAT_FIELD(vsock, seq_eom_skipped),
};

static const struct stat_category vsock_transport_churn_category =
	STAT_CATEGORY("vsock_transport_churn",
	              vsock_transport_churn_runs,
	              vsock_transport_churn_fields);

static const struct stat_field psp_key_rotate_fields[] = {
	STAT_FIELD(psp_key_rotate, runs),
	STAT_FIELD(psp_key_rotate, setup_failed),
	STAT_FIELD(psp_key_rotate, netdev_create_ok),
	STAT_FIELD(psp_key_rotate, family_resolve_ok),
	STAT_FIELD(psp_key_rotate, dev_get_ok),
	STAT_FIELD(psp_key_rotate, key_install_ok),
	STAT_FIELD(psp_key_rotate, spi_set_ok),
	STAT_FIELD(psp_key_rotate, send_ok),
	STAT_FIELD(psp_key_rotate, rotate_ok),
	STAT_FIELD(psp_key_rotate, spi_switch_ok),
	STAT_FIELD(psp_key_rotate, shutdown_ok),
	STAT_FIELD(psp, devlink_port_churn_runs),
	STAT_FIELD(psp, devlink_port_churn_port_add_ok),
	STAT_FIELD(psp, devlink_port_churn_port_del_ok),
	STAT_FIELD(psp, devlink_port_churn_vf_spawn_ok),
	STAT_FIELD(psp, devlink_port_churn_unsupported_latched),
};

static const struct stat_category psp_key_rotate_category =
	STAT_CATEGORY("psp_key_rotate",
	              psp_key_rotate_runs,
	              psp_key_rotate_fields);

static const struct stat_field afxdp_churn_fields[] = {
	STAT_FIELD(afxdp_churn, runs),
	STAT_FIELD(afxdp_churn, setup_failed),
	STAT_FIELD(afxdp_churn, umem_reg_ok),
	STAT_FIELD(afxdp_churn, rings_setup_ok),
	STAT_FIELD(afxdp_churn, prog_load_ok),
	STAT_FIELD(afxdp_churn, map_create_ok),
	STAT_FIELD(afxdp_churn, map_update_ok),
	STAT_FIELD(afxdp_churn, bind_ok),
	STAT_FIELD(afxdp_churn, link_attach_ok),
	STAT_FIELD(afxdp_churn, netlink_attach_ok),
	STAT_FIELD(afxdp_churn, attach_failed),
	STAT_FIELD(afxdp_churn, send_ok),
	STAT_FIELD(afxdp_churn, recv_ok),
	STAT_FIELD(afxdp_churn, map_delete_ok),
	STAT_FIELD(afxdp_churn, munmap_race_ok),
	STAT_FIELD(afxdp, xsg_iters),
	STAT_FIELD(afxdp, tx_metadata_iters),
	STAT_FIELD(afxdp, tun_bind_iters),
	STAT_FIELD(afxdp, xsg_bind_failed),
	STAT_FIELD(afxdp, tx_md_bind_failed),
};

static const struct stat_category afxdp_churn_category =
	STAT_CATEGORY("afxdp_churn",
	              afxdp_churn_runs,
	              afxdp_churn_fields);

static const struct stat_field kvm_fields[] = {
	STAT_FIELD(kvm, vcpu_ioctls_dispatched),
	STAT_FIELD(kvm, vm_ioctls_dispatched),
};

static const struct stat_category kvm_category =
	STAT_CATEGORY("kvm",
	              kvm_vcpu_ioctls_dispatched,
	              kvm_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD(kvm_run, invocations),
	STAT_FIELD(kvm_run, exit_io),
	STAT_FIELD(kvm_run, exit_mmio),
	STAT_FIELD(kvm_run, exit_hlt),
	STAT_FIELD(kvm_run, exit_shutdown),
	STAT_FIELD(kvm_run, exit_fail_entry),
	STAT_FIELD(kvm_run, exit_internal_error),
	STAT_FIELD(kvm_run, exit_intr),
	STAT_FIELD(kvm_run, exit_other),
	STAT_FIELD(kvm_run, errors),
	STAT_FIELD(kvm, gpc_memslot_race_runs),
	STAT_FIELD(kvm, gpc_memslot_race_deletes),
	STAT_FIELD(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category =
	STAT_CATEGORY("kvm_run_churn",
	              kvm_run_invocations,
	              kvm_run_churn_fields);

static const struct stat_field nl80211_fields[] = {
	STAT_FIELD(nl80211, runs),
	STAT_FIELD(nl80211, setup_failed),
	STAT_FIELD(nl80211, scan_triggered),
	STAT_FIELD(nl80211, connect_attempted),
	STAT_FIELD(nl80211, connect_succeeded),
	STAT_FIELD(nl80211, disconnect_attempted),
	STAT_FIELD(nl80211, regdom_changed),
	STAT_FIELD(nl80211, iface_created),
	STAT_FIELD(nl80211, iface_destroyed),
	STAT_FIELD(nl80211, bursts_sent),
	STAT_FIELD(nl80211, pmsr_runs),
	STAT_FIELD(nl80211, pmsr_ok),
	STAT_FIELD(nl80211, admin_gate_runs),
	STAT_FIELD(nl80211, admin_gate_eperm_ok),
	STAT_FIELD(nl80211, admin_gate_unexpected),
};

static const struct stat_category nl80211_category =
	STAT_CATEGORY("nl80211",
	              nl80211_runs,
	              nl80211_fields);

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD(nat_t_churn, runs),
	STAT_FIELD(nat_t_churn, setup_failed),
	STAT_FIELD(nat_t_churn, sa_added),
	STAT_FIELD(nat_t_churn, sa_deleted),
	STAT_FIELD(nat_t_churn, frames_sent),
	STAT_FIELD(nat_t, xfrm6_setup_ok),
	STAT_FIELD(nat_t, xfrm6_setup_fail),
	STAT_FIELD(nat_t, xfrm6_sendto_runs),
	STAT_FIELD(nat_t, xfrm6_delsa_races),
};

static const struct stat_category nat_t_churn_category =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn_runs,
	              nat_t_churn_fields);

static void dump_stats_json_iouring_zc_and_kvm(void)
{
	putchar(',');
	stat_category_emit_json(&vsock_transport_churn_category);
	putchar(',');
	stat_category_emit_json(&psp_key_rotate_category);
	putchar(',');
	stat_category_emit_json(&afxdp_churn_category);
	putchar(',');
	stat_category_emit_json(&kvm_category);
	putchar(',');
	stat_category_emit_json(&kvm_run_churn_category);
	putchar(',');
	stat_category_emit_json(&nl80211_category);
	putchar(',');
	stat_category_emit_json(&nat_t_churn_category);
	putchar(',');
}

static const struct stat_field af_alg_probe_fields[] = {
	STAT_FIELD(af_alg_probe, runs),
	STAT_FIELD(af_alg_probe, unsupported),
	STAT_FIELD(af_alg_probe, accept_total),
	STAT_FIELD(af_alg_probe, reject_total),
};

static const struct stat_category af_alg_probe_category =
	STAT_CATEGORY("af_alg_probe",
	              af_alg_probe_runs,
	              af_alg_probe_fields);

static const struct stat_field af_alg_recvmsg_fields[] = {
	STAT_FIELD(af_alg_recvmsg, runs),
	STAT_FIELD(af_alg_recvmsg, setkey_sent),
	STAT_FIELD(af_alg_recvmsg, iv_sent),
	STAT_FIELD(af_alg_recvmsg, oob_iov),
	STAT_FIELD(af_alg_recvmsg, zerolen),
	STAT_FIELD(af_alg_recvmsg, oversize),
	STAT_FIELD(af_alg_recvmsg, empty_cmsg_no_more),
	STAT_FIELD(af_alg_recvmsg, unsupported),
};

static const struct stat_category af_alg_recvmsg_category =
	STAT_CATEGORY("af_alg_recvmsg",
	              af_alg_recvmsg_runs,
	              af_alg_recvmsg_fields);

static void dump_stats_json_rxrpc_alg_ublk_block(void)
{
	stat_category_emit_json(&af_alg_probe_category);
	putchar(',');
	stat_category_emit_json(&af_alg_recvmsg_category);
	putchar(',');
}

static void dump_stats_json_probes_misuse_and_tail(void)
{
	printf("\"ipvs_sysctl_writer\":{\"runs\":%lu,\"writes_ok\":%lu,\"writes_failed\":%lu,\"unsupported_latched\":%lu,\"burn_iters\":%lu},"
		"\"ipfrag_source_churn\":{\"runs\":%lu,\"packets_sent_ok\":%lu,\"send_failed\":%lu,\"unique_srcs\":%lu},"
		"\"obscure_af_churn\":{\"runs\":%lu,\"no_viable_pf\":%lu,"
			"\"sendmsg_no_bind\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"bind_then_sendmsg\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"connect_no_listen\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"ioctl_rotation\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"setsockopt_zero_len\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"close_via_dup\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu}},"
		"\"rxrpc_sendmsg_cmsg_churn\":{\"runs\":%lu,\"socket_failed\":%lu,\"sendmsg_ok\":%lu,\"sendmsg_fail\":%lu,"
			"\"user_call_id\":%lu,\"abort\":%lu,\"accept\":%lu,\"exclusive_call\":%lu,"
			"\"upgrade_service\":%lu,\"tx_length\":%lu,\"set_call_timeout\":%lu,\"charge_accept\":%lu},"
		"\"tty_ldisc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"ldisc_set_ok\":%lu,\"ldisc_set_failed\":%lu,"
			"\"write_ok\":%lu,\"read_ok\":%lu,"
			"\"per_disc\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu]}"
		"}",
		shm->stats.ipvs_sysctl_writer_runs,
		shm->stats.ipvs_sysctl_writer_writes_ok,
		shm->stats.ipvs_sysctl_writer_writes_failed,
		shm->stats.ipvs_sysctl_writer_unsupported_latched,
		shm->stats.ipvs_sysctl_writer_burn_iters,
		shm->stats.ipfrag_source_runs,
		shm->stats.ipfrag_packets_sent_ok,
		shm->stats.ipfrag_send_failed,
		shm->stats.ipfrag_unique_srcs,
		shm->stats.obscure_af_churn_runs,
		shm->stats.obscure_af_churn_no_viable_pf,
		shm->stats.obscure_af_churn_pattern_runs[0],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[0],
		shm->stats.obscure_af_churn_pattern_unexpected_success[0],
		shm->stats.obscure_af_churn_pattern_runs[1],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[1],
		shm->stats.obscure_af_churn_pattern_unexpected_success[1],
		shm->stats.obscure_af_churn_pattern_runs[2],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[2],
		shm->stats.obscure_af_churn_pattern_unexpected_success[2],
		shm->stats.obscure_af_churn_pattern_runs[3],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[3],
		shm->stats.obscure_af_churn_pattern_unexpected_success[3],
		shm->stats.obscure_af_churn_pattern_runs[4],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[4],
		shm->stats.obscure_af_churn_pattern_unexpected_success[4],
		shm->stats.obscure_af_churn_pattern_runs[5],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[5],
		shm->stats.obscure_af_churn_pattern_unexpected_success[5],
		shm->stats.rxrpc_sendmsg_cmsg_runs,
		shm->stats.rxrpc_sendmsg_cmsg_socket_failed,
		shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok,
		shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail,
		shm->stats.rxrpc_sendmsg_cmsg_sent[0],
		shm->stats.rxrpc_sendmsg_cmsg_sent[1],
		shm->stats.rxrpc_sendmsg_cmsg_sent[2],
		shm->stats.rxrpc_sendmsg_cmsg_sent[3],
		shm->stats.rxrpc_sendmsg_cmsg_sent[4],
		shm->stats.rxrpc_sendmsg_cmsg_sent[5],
		shm->stats.rxrpc_sendmsg_cmsg_sent[6],
		shm->stats.rxrpc_sendmsg_cmsg_sent[7],
		shm->stats.tty_ldisc_churn_runs,
		shm->stats.tty_ldisc_churn_setup_failed,
		shm->stats.tty_ldisc_churn_ldisc_set_ok,
		shm->stats.tty_ldisc_churn_ldisc_set_failed,
		shm->stats.tty_ldisc_churn_write_ok,
		shm->stats.tty_ldisc_churn_read_ok,
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[0],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[1],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[2],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[3],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[4],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[5],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[6],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[7],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[8],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[9],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[10],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[11],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[12],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[13],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[14],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[15],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[16],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[17],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[18],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[19],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[20],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[21],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[22],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[23],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[24]);
}

static void json_emit_socket_family_grammar_section(void)
{
	stat_category_emit_json(&socket_family_grammar_category);
}

static void json_emit_net_churn_and_early_storms_section(void)
{
	printf(",");
	stat_category_emit_json(&nf_conntrack_helper_churn_category);

	printf(",");
	stat_category_emit_json(&ipset_churn_category);

	printf(",");
	stat_category_emit_json(&tcp_ulp_swap_churn_category);

	printf(",");
	stat_category_emit_json(&blob_mutator_category);

	printf(",");
	stat_category_emit_json(&blob_ab_mode_category);

	printf(",");
	stat_category_emit_json(&msg_zerocopy_churn_category);

	printf(",");
	stat_category_emit_json(&setsockopt_pairing_category);

	printf(",");
	stat_category_emit_json(&sched_cycler_category);

	printf(",");
	stat_category_emit_json(&userns_fuzzer_category);

	printf(",");
	stat_category_emit_json(&userns_bootstrap_category);

	printf(",");
	stat_category_emit_json(&barrier_racer_category);

	printf(",");
	stat_category_emit_json(&perf_event_chains_category);

	printf(",");
	stat_category_emit_json(&bpf_lifecycle_category);

	printf(",");
	stat_category_emit_json(&signal_storm_category);

	printf(",");
	stat_category_emit_json(&pipe_thrash_category);

	printf(",");
	stat_category_emit_json(&fork_storm_category);
}

static void json_emit_pidfd_fs_and_container_section(void)
{
	printf(",");
	stat_category_emit_json(&cpu_hotplug_rider_category);

	printf(",");
	stat_category_emit_json(&pidfd_storm_category);

	printf(",");
	stat_category_emit_json(&madvise_cycler_category);

	printf(",");
	stat_category_emit_json(&keyring_spam_category);

	printf(",");
	stat_category_emit_json(&vdso_mremap_race_category);

	printf(",");
	stat_category_emit_json(&flock_thrash_category);

	printf(",");
	stat_category_emit_json(&xattr_thrash_category);

	printf(",");
	stat_category_emit_json(&epoll_volatility_category);

	printf(",");
	stat_category_emit_json(&cgroup_churn_category);

	printf(",");
	stat_category_emit_json(&mount_churn_category);

	printf(",");
	stat_category_emit_json(&umount_race_category);

	printf(",");
	stat_category_emit_json(&statmount_idmap_category);

	printf(",");
	stat_category_emit_json(&uffd_churn_category);

	printf(",");
	stat_category_emit_json(&tls_rotate_category);
}

static void json_emit_tcp_ipv6_and_tunnels_section(void)
{
	printf(",");
	stat_category_emit_json(&netns_teardown_category);

	printf(",");
	stat_category_emit_json(&cred_transition_category);

	printf(",");
	stat_category_emit_json(&deep_path_nesting_category);

	printf(",");
	stat_category_emit_json(&espintcp_coalesce_category);

	printf(",");
	stat_category_emit_json(&netns_mountns_setup_category);

	printf(",");
	stat_category_emit_json(&socket_family_chain_category);

	printf(",");
	stat_category_emit_json(&tcp_ao_rotate_category);

	printf(",");
	stat_category_emit_json(&tcp_md5_listener_race_category);

	printf(",");
	stat_category_emit_json(&ipv6_pmtu_race_category);

	printf(",");
	stat_category_emit_json(&vrf_fib_churn_category);

	printf(",");
	stat_category_emit_json(&ip6_udp_cork_splice_category);

	printf(",");
	stat_category_emit_json(&ip4_udp_cork_splice_category);

	printf(",");
	stat_category_emit_json(&mpls_route_churn_category);

	printf(",");
	stat_category_emit_json(&tls_ulp_churn_category);

	printf(",");
	stat_category_emit_json(&ip6gre_bond_lapb_stack_category);

	printf(",");
	stat_category_emit_json(&vxlan_encap_churn_category);

	printf(",");
	stat_category_emit_json(&ip_gre_churn_category);

	printf(",");
	stat_category_emit_json(&ovs_tunnel_vport_churn_category);

	printf(",");
	stat_category_emit_json(&netlink_monitor_race_category);

	printf(",");
	stat_category_emit_json(&tipc_link_churn_category);

	printf(",");
	stat_category_emit_json(&igmp_mld_source_churn_category);
}

static void json_emit_bridge_pci_unix_and_iouring_section(void)
{
	printf(",");
	stat_category_emit_json(&bridge_vlan_churn_category);

	printf(",");
	stat_category_emit_json(&vlan_filter_churn_category);

	printf(",");
	stat_category_emit_json(&pkt_builder_category);

	printf(",");
	stat_category_emit_json(&pci_bind_category);

	printf(",");
	stat_category_emit_json(&ublk_lifecycle_category);

	printf(",");
	stat_category_emit_json(&handshake_req_abort_category);

	printf(",");
	stat_category_emit_json(&af_unix_scm_rights_gc_category);

	printf(",");
	stat_category_emit_json(&af_unix_peek_race_category);

	printf(",");
	stat_category_emit_json(&sysv_shm_orphan_race_category);

	printf(",");
	stat_category_emit_json(&map_shared_stress_category);

	printf(",");
	stat_category_emit_json(&qrtr_bind_race_category);

	printf(",");
	stat_category_emit_json(&pfkey_spd_walk_category);

	printf(",");
	stat_category_emit_json(&l2tp_ifname_race_category);

	printf(",");
	stat_category_emit_json(&bpf_cgroup_attach_category);

	printf(",");
	stat_category_emit_json(&iouring_flood_category);

	printf(",");
	stat_category_emit_json(&close_racer_category);

	printf(",");
	stat_category_emit_json(&refcount_audit_category);
}

static void json_emit_iouring_iscsi_and_net_tail_section(void)
{
	printf(",");
	stat_category_emit_json(&iouring_send_zc_churn_category);

	printf(",");
	stat_category_emit_json(&iscsi_target_probe_category);

	printf(",");
	stat_category_emit_json(&iscsi_login_walker_category);

	printf(",");
	stat_category_emit_json(&ipv6_ndisc_proxy_category);

	printf(",");
	stat_category_emit_json(&rxrpc_key_install_category);

	printf(",");
	stat_category_emit_json(&af_alg_weak_cipher_probe_category);

	printf(",");
	stat_category_emit_json(&bridge_conntrack_churn_category);

	printf(",");
	stat_category_emit_json(&bridge_ip6frag_refrag_category);

	printf(",");
	stat_category_emit_json(&blkdev_lifecycle_race_category);

	printf(",");
	stat_category_emit_json(&hfs_mount_fuzz_category);

	printf(",");
	stat_category_emit_json(&veth_asymmetric_xdp_category);

	printf(",");
	stat_category_emit_json(&ip6erspan_netns_migrate_category);

	printf(",");
	stat_category_emit_json(&netdev_netns_migrate_category);

	printf(",");
	stat_category_emit_json(&flowtable_encap_vlan_category);

	printf(",");
	stat_category_emit_json(&splice_protocols_category);

	printf(",");
	stat_category_emit_json(&wireguard_decrypt_flood_category);

	printf(",");
	stat_category_emit_json(&rtnl_vf_broadcast_getlink_category);

	printf(",");
	stat_category_emit_json(&fdstress_category);
}

void __cold dump_stats_json(void)
{
	putchar('{');

	json_emit_syscalls_array();

	fputs(",\"stats\":{", stdout);
	dump_stats_json_fault_and_fd_lifecycle();
	dump_stats_json_oracle();
	dump_stats_json_basic_subsystems();
	dump_stats_json_iouring_and_zombies();
	dump_stats_json_corruption_and_audit();
	dump_stats_json_lifecycle_and_storms();
	json_emit_socket_family_grammar_section();
	printf(",");
	dump_stats_json_socket_family_and_tls();
	dump_stats_json_netfilter_and_xfrm();

	json_emit_net_churn_and_early_storms_section();
	json_emit_pidfd_fs_and_container_section();
	json_emit_tcp_ipv6_and_tunnels_section();
	json_emit_bridge_pci_unix_and_iouring_section();
	json_emit_iouring_iscsi_and_net_tail_section();

	dump_stats_json_iouring_zc_and_kvm();
	dump_stats_json_rxrpc_alg_ublk_block();
	dump_stats_json_probes_misuse_and_tail();

	/*
	 * Per-childop arrays in struct stats_s indexed by NR_CHILD_OP_TYPES
	 * (taint_transitions[], pool_race_aborted[],
	 * childop_edges_discovered[], childop_calls_with_edges[]) are
	 * intentionally not emitted here.
	 * The JSON schema in this function is a flat per-key mapping;
	 * expanding any of these arrays as a nested object or array would
	 * change the schema shape and inflate the JSON for consumers that
	 * only care about scalar counters.  These arrays remain visible in
	 * the human-readable dump_stats() output, which iterates them as
	 * one row per non-zero entry under the matching group name.
	 */

	json_emit_kcov_section();
	json_emit_minicorpus_section();
	json_emit_cmp_hints_section();

	fputs("}\n", stdout);
	fflush(stdout);
}

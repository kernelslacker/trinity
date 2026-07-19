/*
 * Network / netfilter / xfrm / socket-family / iouring-network
 * JSON section emitters for --stats-json.
 *
 * Owns three groups of section helpers plus the JSON-local
 * descriptor tables they walk: the socket-family + TLS block,
 * the netfilter + xfrm block, and the six long
 * category-compose helpers (socket-family grammar, net-churn +
 * early storms, pidfd + fs + container, TCP + IPv6 + tunnels,
 * bridge + PCI + unix + iouring, and iouring + iSCSI + net
 * tail).  Descriptor tables that already carry extern
 * declarations in include/stats-internal.h retain their
 * external linkage; tables used only by this file stay
 * file-static.
 */

#include <stddef.h>
#include <stdio.h>
#include "stats.h"
#include "stats-internal.h"
#include "stats/json/internal.h"

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

void dump_stats_json_socket_family_and_tls(void)
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


static const struct stat_field ipmr_cache_report_fields[] = {
	STAT_FIELD(ipmr_cache_report, iters),
	STAT_FIELD(ipmr_cache_report, eperm),
	STAT_FIELD(ipmr_cache_report, emit_ok),
};

const struct stat_category ipmr_cache_report_category =
	STAT_CATEGORY("ipmr_cache_report",
	              ipmr_cache_report_iters,
	              ipmr_cache_report_fields);

void dump_stats_json_netfilter_and_xfrm(void)
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

void json_emit_socket_family_grammar_section(void)
{
	stat_category_emit_json(&socket_family_grammar_category);
}

void json_emit_net_churn_and_early_storms_section(void)
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

void json_emit_pidfd_fs_and_container_section(void)
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

void json_emit_tcp_ipv6_and_tunnels_section(void)
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

void json_emit_bridge_pci_unix_and_iouring_section(void)
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

void json_emit_iouring_iscsi_and_net_tail_section(void)
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

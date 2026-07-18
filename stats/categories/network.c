#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field msg_zerocopy_churn_fields[] = {
	STAT_FIELD(msg_zerocopy_churn, runs),
	STAT_FIELD(msg_zerocopy_churn, setup_failed),
	STAT_FIELD(msg_zerocopy_churn, sends_ok),
	STAT_FIELD(msg_zerocopy_churn, sends_efault),
	STAT_FIELD(msg_zerocopy_churn, sends_eagain),
	STAT_FIELD(msg_zerocopy_churn, errqueue_drained),
	STAT_FIELD(msg_zerocopy_churn, errqueue_empty),
	STAT_FIELD(msg_zerocopy_churn, munmap_ok),
	STAT_FIELD(msg_zerocopy_churn, send_after_munmap_caught),
	STAT_FIELD(msg_zerocopy_churn, sndzc_disable_ok),
};

const struct stat_category msg_zerocopy_churn_category =
	STAT_CATEGORY("msg_zerocopy_churn",
	              msg_zerocopy_churn_runs,
	              msg_zerocopy_churn_fields);

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

static const struct stat_field tls_rotate_fields[] = {
	STAT_FIELD(tls_rotate, runs),
	STAT_FIELD(tls_rotate, setup_failed),
	STAT_FIELD(tls_rotate, ulp_failed),
	STAT_FIELD(tls_rotate, ulp_asymmetric),
	STAT_FIELD(tls_rotate, installs),
	STAT_FIELD(tls_rotate, rekeys_ok),
	STAT_FIELD(tls_rotate, rekeys_rejected),
};

const struct stat_category tls_rotate_category =
	STAT_CATEGORY("tls_rotate",
	              tls_rotate_runs,
	              tls_rotate_fields);

static const struct stat_field netns_teardown_fields[] = {
	STAT_FIELD(netns_teardown, runs),
	STAT_FIELD(netns_teardown, setup_failed),
	STAT_FIELD(netns_teardown, unshare_ok),
	STAT_FIELD(netns_teardown, socket_pair_ok),
	STAT_FIELD(netns_teardown, fork_ok),
	STAT_FIELD(netns_teardown, setns_ok),
	STAT_FIELD(netns_teardown, kill_ok),
	STAT_FIELD(netns_teardown, completed_ok),
};

const struct stat_category netns_teardown_category =
	STAT_CATEGORY("netns_teardown",
	              netns_teardown_runs,
	              netns_teardown_fields);

static const struct stat_field netns_mountns_setup_fields[] = {
	STAT_FIELD(netns_mountns_setup, runs),
	STAT_FIELD(netns_mountns_setup, setup_failed),
	STAT_FIELD(netns_mountns_setup, unshare_ok),
	STAT_FIELD(netns_mountns_setup, mount_private_ok),
	STAT_FIELD(netns_mountns_setup, loopback_ok),
	STAT_FIELD(netns_mountns_setup, socket_ok),
	STAT_FIELD(netns_mountns_setup, completed_ok),
};

const struct stat_category netns_mountns_setup_category =
	STAT_CATEGORY("netns_mountns_setup",
	              netns_mountns_setup_runs,
	              netns_mountns_setup_fields);

static const struct stat_field tcp_ao_rotate_fields[] = {
	STAT_FIELD(tcp_ao_rotate, runs),
	STAT_FIELD(tcp_ao_rotate, setup_failed),
	STAT_FIELD(tcp_ao_rotate, addkey_rejected),
	STAT_FIELD(tcp_ao_rotate, keys_added),
	STAT_FIELD(tcp_ao_rotate, connect_failed),
	STAT_FIELD(tcp_ao_rotate, connected),
	STAT_FIELD(tcp_ao_rotate, packets_sent),
	STAT_FIELD(tcp_ao_rotate, key_rotations),
	STAT_FIELD(tcp_ao_rotate, info_rejected),
	STAT_FIELD(tcp_ao_rotate, key_dels),
	STAT_FIELD(tcp_ao_rotate, delkey_rejected),
	STAT_FIELD(tcp_ao_rotate, cycles),
};

const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate_runs,
	              tcp_ao_rotate_fields);

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

static const struct stat_field vrf_fib_churn_fields[] = {
	STAT_FIELD(vrf_fib_churn, runs),
	STAT_FIELD(vrf_fib_churn, setup_failed),
	STAT_FIELD(vrf_fib_churn, link_ok),
	STAT_FIELD(vrf_fib_churn, addr_ok),
	STAT_FIELD(vrf_fib_churn, up_ok),
	STAT_FIELD(vrf_fib_churn, rule_added),
	STAT_FIELD(vrf_fib_churn, bound),
	STAT_FIELD(vrf_fib_churn, sendto_ok),
	STAT_FIELD(vrf_fib_churn, rule2_added),
	STAT_FIELD(vrf_fib_churn, rule_removed),
	STAT_FIELD(vrf_fib_churn, link_removed),
};

const struct stat_category vrf_fib_churn_category =
	STAT_CATEGORY("vrf_fib_churn",
	              vrf_fib_churn_runs,
	              vrf_fib_churn_fields);

static const struct stat_field ip6_udp_cork_splice_fields[] = {
	STAT_FIELD(ip6_udp_cork_splice, runs),
	STAT_FIELD(ip6_udp_cork_splice, setup_failed),
	STAT_FIELD(ip6_udp_cork_splice, mtu_set),
	STAT_FIELD(ip6_udp_cork_splice, p1_ok),
	STAT_FIELD(ip6_udp_cork_splice, p1_rejected),
	STAT_FIELD(ip6_udp_cork_splice, p2_ok),
};

const struct stat_category ip6_udp_cork_splice_category =
	STAT_CATEGORY("ip6_udp_cork_splice",
	              ip6_udp_cork_splice_runs,
	              ip6_udp_cork_splice_fields);

static const struct stat_field ip4_udp_cork_splice_fields[] = {
	STAT_FIELD(ip4_udp_cork_splice, runs),
	STAT_FIELD(ip4_udp_cork_splice, setup_failed),
	STAT_FIELD(ip4_udp_cork_splice, mtu_set),
	STAT_FIELD(ip4_udp_cork_splice, p1_ok),
	STAT_FIELD(ip4_udp_cork_splice, p1_rejected),
	STAT_FIELD(ip4_udp_cork_splice, p2_ok),
};

const struct stat_category ip4_udp_cork_splice_category =
	STAT_CATEGORY("ip4_udp_cork_splice",
		      ip4_udp_cork_splice_runs,
		      ip4_udp_cork_splice_fields);

static const struct stat_field tls_ulp_churn_fields[] = {
	STAT_FIELD(tls_ulp_churn, runs),
	STAT_FIELD(tls_ulp_churn, setup_failed),
	STAT_FIELD(tls_ulp_churn, ulp_install_ok),
	STAT_FIELD(tls_ulp_churn, tx_install_ok),
	STAT_FIELD(tls_ulp_churn, send_ok),
	STAT_FIELD(tls_ulp_churn, splice_ok),
	STAT_FIELD(tls_ulp_churn, rekey_ok),
	STAT_FIELD(tls_ulp_churn, recv_ok),
};

const struct stat_category tls_ulp_churn_category =
	STAT_CATEGORY("tls_ulp_churn",
	              tls_ulp_churn_runs,
	              tls_ulp_churn_fields);

static const struct stat_field vxlan_encap_churn_fields[] = {
	STAT_FIELD(vxlan_encap_churn, runs),
	STAT_FIELD(vxlan_encap_churn, setup_failed),
	STAT_FIELD(vxlan_encap_churn, link_create_ok),
	STAT_FIELD(vxlan_encap_churn, fdb_add_ok),
	STAT_FIELD(vxlan_encap_churn, link_up_ok),
	STAT_FIELD(vxlan_encap_churn, packet_sent_ok),
	STAT_FIELD(vxlan_encap_churn, link_del_ok),
};

const struct stat_category vxlan_encap_churn_category =
	STAT_CATEGORY("vxlan_encap_churn",
	              vxlan_encap_churn_runs,
	              vxlan_encap_churn_fields);

static const struct stat_field ip_gre_churn_fields[] = {
	STAT_FIELD(ip_gre_churn, runs),
	STAT_FIELD(ip_gre_churn, setup_failed),
	STAT_FIELD(ip_gre_churn, link_create_ok),
	STAT_FIELD(ip_gre_churn, link_up_ok),
	STAT_FIELD(ip_gre_churn, packet_sent_ok),
	STAT_FIELD(ip_gre_churn, link_del_ok),
};

const struct stat_category ip_gre_churn_category =
	STAT_CATEGORY("ip_gre_churn",
	              ip_gre_churn_runs,
	              ip_gre_churn_fields);

static const struct stat_field netlink_monitor_race_fields[] = {
	STAT_FIELD(netlink_monitor_race, runs),
	STAT_FIELD(netlink_monitor_race, setup_failed),
	STAT_FIELD(netlink_monitor_race, mon_open),
	STAT_FIELD(netlink_monitor_race, mut_open),
	STAT_FIELD(netlink_monitor_race, mut_op_ok),
	STAT_FIELD(netlink_monitor_race, recv_drained),
	STAT_FIELD(netlink_monitor_race, group_drop),
	STAT_FIELD(netlink_monitor_race, group_add),
};

const struct stat_category netlink_monitor_race_category =
	STAT_CATEGORY("netlink_monitor_race",
	              netlink_monitor_race_runs,
	              netlink_monitor_race_fields);

static const struct stat_field tipc_link_churn_fields[] = {
	STAT_FIELD(tipc_link_churn, runs),
	STAT_FIELD(tipc_link_churn, setup_failed),
	STAT_FIELD(tipc_link_churn, bearer_enable_ok),
	STAT_FIELD(tipc_link_churn, sock_rdm_ok),
	STAT_FIELD(tipc_link_churn, topsrv_connect_ok),
	STAT_FIELD(tipc_link_churn, sub_ports_sent),
	STAT_FIELD(tipc_link_churn, publish_ok),
	STAT_FIELD(tipc_link_churn, bearer_disable_ok),
};

const struct stat_category tipc_link_churn_category =
	STAT_CATEGORY("tipc_link_churn",
	              tipc_link_churn_runs,
	              tipc_link_churn_fields);

static const struct stat_field igmp_mld_source_churn_fields[] = {
	STAT_FIELD(igmp_mld_source_churn, runs),
	STAT_FIELD(igmp_mld_source_churn, setup_failed),
	STAT_FIELD(igmp_mld_source_churn, join_ok),
	STAT_FIELD(igmp_mld_source_churn, leave_ok),
	STAT_FIELD(igmp_mld_source_churn, block_ok),
	STAT_FIELD(igmp_mld_source_churn, msfilter_ok),
	STAT_FIELD(igmp_mld_source_churn, drop_ok),
	STAT_FIELD(igmp_mld_source_churn, send_ok),
};

const struct stat_category igmp_mld_source_churn_category =
	STAT_CATEGORY("igmp_mld_source_churn",
	              igmp_mld_source_churn_runs,
	              igmp_mld_source_churn_fields);

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

static const struct stat_field iscsi_login_walker_fields[] = {
	STAT_FIELD(iscsi_walker, runs),
	STAT_FIELD(iscsi_walker, setup_failed),
	STAT_FIELD(iscsi_walker, no_target),
	STAT_FIELD(iscsi_walker, connected),
	STAT_FIELD(iscsi_walker, state_security_sent),
	STAT_FIELD(iscsi_walker, state_op_neg_sent),
	STAT_FIELD(iscsi_walker, login_response_ok),
	STAT_FIELD(iscsi_walker, login_rejected),
	STAT_FIELD(iscsi_walker, ffp_reached),
	STAT_FIELD(iscsi_walker, ffp_iters),
	STAT_FIELD(iscsi_walker, ffp_pdus),
	STAT_FIELD(iscsi_walker, chaos_runs),
	STAT_FIELD(iscsi_walker, chaos_pdus),
	STAT_FIELD(iscsi_walker, bytes_out),
	STAT_FIELD(iscsi_walker, bytes_in),
};

const struct stat_category iscsi_login_walker_category =
	STAT_CATEGORY("iscsi_login_walker",
	              iscsi_walker_runs,
	              iscsi_login_walker_fields);

static const struct stat_field rxrpc_key_install_fields[] = {
	STAT_FIELD(rxrpc_key_install, runs),
	STAT_FIELD(rxrpc_key_install, calls),
	STAT_FIELD(rxrpc_key_install, revokes),
	STAT_FIELD(rxrpc_key_install, quota_hits),
	STAT_FIELD(rxrpc_key_install, unsupported),
	STAT_FIELD(rxrpc_key_install, xrxgk_accepted),
};

const struct stat_category rxrpc_key_install_category =
	STAT_CATEGORY("rxrpc_key_install",
	              rxrpc_key_install_runs,
	              rxrpc_key_install_fields);

static const struct stat_field hfs_mount_fuzz_fields[] = {
	STAT_FIELD(hfs_mount_fuzz, runs),
	STAT_FIELD(hfs_mount_fuzz, setup_failed),
	STAT_FIELD(hfs_mount_fuzz, set_fd_ok),
	STAT_FIELD(hfs_mount_fuzz, set_fd_busy),
	STAT_FIELD(hfs_mount_fuzz, mount_ok),
	STAT_FIELD(hfs_mount_fuzz, mount_failed),
	STAT_FIELD(hfs_mount_fuzz, ns_unsupported),
	STAT_FIELD(hfs_mount_fuzz, hfs_unsupported),
};

const struct stat_category hfs_mount_fuzz_category =
	STAT_CATEGORY("hfs_mount_fuzz",
		      hfs_mount_fuzz_runs,
		      hfs_mount_fuzz_fields);

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

static const struct stat_field flowtable_encap_vlan_fields[] = {
	STAT_FIELD(flowtable_vlan, runs),
	STAT_FIELD(flowtable_vlan, setup_ok),
	STAT_FIELD(flowtable_vlan, setup_failed),
	STAT_FIELD(flowtable_vlan, offloaded_pkts),
	STAT_FIELD(flowtable_vlan, gso_sends),
	STAT_FIELD(flowtable_vlan, vlan_teardown_races),
	STAT_FIELD(flowtable_vlan, unsupported_latched),
};

const struct stat_category flowtable_encap_vlan_category =
	STAT_CATEGORY("flowtable_encap_vlan",
	              flowtable_vlan_runs,
	              flowtable_encap_vlan_fields);

static const struct stat_field splice_protocols_fields[] = {
	STAT_FIELD(splice_protocols, runs),
	STAT_FIELD(splice_protocols, setup_failed),
	STAT_FIELD(splice_protocols, chain_ok),
	STAT_FIELD(splice_protocols, in_bytes),
	STAT_FIELD(splice_protocols, out_bytes),
	STAT_FIELD(splice_protocols, udp_encap_attempted),
	STAT_FIELD(splice_protocols, tcp_repair_attempted),
	STAT_FIELD(splice_protocols, packet_ring_attempted),
	STAT_FIELD(splice_protocols, alg_attempted),
	STAT_FIELD(splice_protocols, rxrpc_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_path_taken_inferred),
};

const struct stat_category splice_protocols_category =
	STAT_CATEGORY("splice_protocols",
	              splice_protocols_runs,
	              splice_protocols_fields);

static const struct stat_field pci_bind_fields[] = {
	STAT_FIELD(pci_bind, runs),
	STAT_FIELD(pci_bind, drivers_available),
	STAT_FIELD(pci_bind, no_devices),
	STAT_FIELD(pci_bind, unbind_ok),
	STAT_FIELD(pci_bind, unbind_enodev),
	STAT_FIELD(pci_bind, unbind_failed),
	STAT_FIELD(pci_bind, bind_ok),
	STAT_FIELD(pci_bind, bind_enodev),
	STAT_FIELD(pci_bind, bind_failed),
};

const struct stat_category pci_bind_category =
	STAT_CATEGORY("pci_bind",
	              pci_bind_runs,
	              pci_bind_fields);

static const struct stat_field ublk_lifecycle_fields[] = {
	STAT_FIELD(ublk_lifecycle, iters),
	STAT_FIELD(ublk_lifecycle, eperm),
	STAT_FIELD(ublk_lifecycle, add_ok),
	STAT_FIELD(ublk_lifecycle, fetch_ok),
	STAT_FIELD(ublk_lifecycle, del_ok),
	STAT_FIELD(ublk_lifecycle, race_observed),
};

const struct stat_category ublk_lifecycle_category =
	STAT_CATEGORY("ublk_lifecycle",
	              ublk_lifecycle_iters,
	              ublk_lifecycle_fields);

static const struct stat_field handshake_req_abort_fields[] = {
	STAT_FIELD(handshake_req_abort, runs),
	STAT_FIELD(handshake_req_abort, setup_failed),
	STAT_FIELD(handshake_req_abort, accept_ok),
	STAT_FIELD(handshake_req_abort, done_ok),
	STAT_FIELD(handshake_req_abort, abort_ok),
	STAT_FIELD(handshake_req_abort, orphan_close),
};

const struct stat_category handshake_req_abort_category =
	STAT_CATEGORY("handshake_req_abort",
	              handshake_req_abort_runs,
	              handshake_req_abort_fields);

static const struct stat_field nf_conntrack_helper_churn_fields[] = {
	STAT_FIELD(nf_conntrack_helper_churn, runs),
	STAT_FIELD(nf_conntrack_helper_churn, setup_failed),
	STAT_FIELD(nf_conntrack_helper_churn, no_helper),
	STAT_FIELD(nf_conntrack_helper_churn, attach_ok),
	STAT_FIELD(nf_conntrack_helper_churn, attach_fail),
	STAT_FIELD(nf_conntrack_helper_churn, exp_ok),
	STAT_FIELD(nf_conntrack_helper_churn, packet_sent),
	STAT_FIELD(nf_conntrack_helper_churn, delete_ok),
	STAT_FIELD(nf_conntrack_helper_churn, zone_swap),
	STAT_FIELD(nf_conntrack_helper_churn, detach_ok),
};

const struct stat_category nf_conntrack_helper_churn_category =
	STAT_CATEGORY("nf_conntrack_helper_churn",
	              nf_conntrack_helper_churn_runs,
	              nf_conntrack_helper_churn_fields);

static const struct stat_field ipset_churn_fields[] = {
	STAT_FIELD(ipset_churn, runs),
	STAT_FIELD(ipset_churn, setup_failed),
	STAT_FIELD(ipset_churn, create_ok),
	STAT_FIELD(ipset_churn, create_fail),
	STAT_FIELD(ipset_churn, add_ok),
	STAT_FIELD(ipset_churn, test_ok),
	STAT_FIELD(ipset_churn, del_ok),
	STAT_FIELD(ipset_churn, header_ok),
	STAT_FIELD(ipset_churn, list_ok),
	STAT_FIELD(ipset_churn, swap_ok),
	STAT_FIELD(ipset_churn, flush_ok),
	STAT_FIELD(ipset_churn, destroy_ok),
};

const struct stat_category ipset_churn_category =
	STAT_CATEGORY("ipset_churn",
	              ipset_churn_runs,
	              ipset_churn_fields);

static const struct stat_field sysv_shm_orphan_race_fields[] = {
	STAT_FIELD(sysv_shm_orphan_race, runs),
	STAT_FIELD(sysv_shm_orphan_race, setup_failed),
	STAT_FIELD(sysv_shm_orphan_race, shmget_ok),
	STAT_FIELD(sysv_shm_orphan_race, shmget_failed),
	STAT_FIELD(sysv_shm_orphan_race, attach_ok),
	STAT_FIELD(sysv_shm_orphan_race, attach_failed),
	STAT_FIELD(sysv_shm_orphan_race, rmid_ok),
	STAT_FIELD(sysv_shm_orphan_race, rmid_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_reaped_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_crashed),
};

const struct stat_category sysv_shm_orphan_race_category =
	STAT_CATEGORY("sysv_shm_orphan_race",
		sysv_shm_orphan_race_runs,
		sysv_shm_orphan_race_fields);

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

static const struct stat_field l2tp_ifname_race_fields[] = {
	STAT_FIELD(l2tp_ifname_race, runs),
	STAT_FIELD(l2tp_ifname_race, setup_failed),
	STAT_FIELD(l2tp_ifname_race, iter),
	STAT_FIELD(l2tp_ifname_race, tunnel_ok),
	STAT_FIELD(l2tp_ifname_race, tunnel_fail),
	STAT_FIELD(l2tp_ifname_race, fork_failed),
	STAT_FIELD(l2tp_ifname_race, spawn_pair_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_reaped_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_crashed),
};

const struct stat_category l2tp_ifname_race_category =
	STAT_CATEGORY("l2tp_ifname_race",
		l2tp_ifname_race_runs,
		l2tp_ifname_race_fields);


#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

/* Per-group shadow of blob_fills.  Sum-suppressed so an OFF /
 * no-blob-fill run emits nothing (render-gap-aware); per-row zero-
 * suppressed so a partially-covered run only shows the groups that
 * actually ran a blob_fill().  Group name table mirrors
 * check_fd_leaks() in child/child.c. */
static void dump_stats_render_blob_fills_by_group(void)
{
	static const char * const group_names[NR_GROUPS] = {
		[GROUP_NONE]     = "none",
		[GROUP_VM]       = "vm",
		[GROUP_VFS]      = "vfs",
		[GROUP_NET]      = "net",
		[GROUP_IPC]      = "ipc",
		[GROUP_PROCESS]  = "process",
		[GROUP_SIGNAL]   = "signal",
		[GROUP_IO_URING] = "io_uring",
		[GROUP_BPF]      = "bpf",
		[GROUP_SCHED]    = "sched",
		[GROUP_TIME]     = "time",
		[GROUP_XATTR]    = "xattr",
	};
	unsigned long total = 0;
	unsigned int i;

	for (i = 0; i < NR_GROUPS; i++)
		total += shm->stats.blob_fills_by_group[i];
	if (total == 0)
		return;

	for (i = 0; i < NR_GROUPS; i++) {
		if (shm->stats.blob_fills_by_group[i] == 0)
			continue;
		stat_row("blob_fills_by_group", group_names[i],
			 shm->stats.blob_fills_by_group[i]);
	}
}

static void dump_stats_render_packet_fanout_thrash(void)
{
	if (shm->stats.packet_fanout_runs) {
		stat_row("packet_fanout_thrash", "runs",             shm->stats.packet_fanout_runs);
		stat_row("packet_fanout_thrash", "setup_failed",     shm->stats.packet_fanout_setup_failed);
		stat_row("packet_fanout_thrash", "ring_failed",      shm->stats.packet_fanout_ring_failed);
		stat_row("packet_fanout_thrash", "rings_installed",  shm->stats.packet_fanout_rings_installed);
		stat_row("packet_fanout_thrash", "mmap_failed",      shm->stats.packet_fanout_mmap_failed);
		stat_row("packet_fanout_thrash", "joins",            shm->stats.packet_fanout_joins);
		stat_row("packet_fanout_thrash", "rejoins_ok",       shm->stats.packet_fanout_rejoins_ok);
		stat_row("packet_fanout_thrash", "rejoins_rejected", shm->stats.packet_fanout_rejoins_rejected);
	}
}

static void dump_stats_render_eth_emitter(void)
{
	if (shm->stats.eth_emitter_runs) {
		stat_row("eth_emitter", "runs",               shm->stats.eth_emitter_runs);
		stat_row("eth_emitter", "setup_failed",       shm->stats.eth_emitter_setup_failed);
		stat_row("eth_emitter", "short",              shm->stats.eth_emitter_short);
		stat_row("eth_emitter", "sends_ok",           shm->stats.eth_emitter_sends_ok);
		stat_row("eth_emitter", "sends_failed",       shm->stats.eth_emitter_sends_failed);
		stat_row("eth_emitter", "tmpl_arp",           shm->stats.eth_emitter_per_tmpl[0]);
		stat_row("eth_emitter", "tmpl_ipv4_frag_zero", shm->stats.eth_emitter_per_tmpl[1]);
		stat_row("eth_emitter", "tmpl_ipv6_na",       shm->stats.eth_emitter_per_tmpl[2]);
		stat_row("eth_emitter", "tmpl_vlan_qinq",     shm->stats.eth_emitter_per_tmpl[3]);
		stat_row("eth_emitter", "tmpl_bad_ethertype", shm->stats.eth_emitter_per_tmpl[4]);
	}
}

static void dump_stats_render_iouring_multishot(void)
{
	if (shm->stats.iouring_multishot_runs) {
		stat_row("iouring_net_multishot", "runs",             shm->stats.iouring_multishot_runs);
		stat_row("iouring_net_multishot", "setup_failed",     shm->stats.iouring_multishot_setup_failed);
		stat_row("iouring_net_multishot", "pbuf_ring_ok",     shm->stats.iouring_multishot_pbuf_ring_ok);
		stat_row("iouring_net_multishot", "pbuf_legacy_ok",   shm->stats.iouring_multishot_pbuf_legacy_ok);
		stat_row("iouring_net_multishot", "armed",            shm->stats.iouring_multishot_armed);
		stat_row("iouring_net_multishot", "packets_sent",     shm->stats.iouring_multishot_packets_sent);
		stat_row("iouring_net_multishot", "completions",      shm->stats.iouring_multishot_completions);
		stat_row("iouring_net_multishot", "cancel_submitted", shm->stats.iouring_multishot_cancel_submitted);
		stat_row("iouring_net_multishot", "napi_register_ok",   shm->stats.iouring_napi_register_ok);
		stat_row("iouring_net_multishot", "napi_register_fail", shm->stats.iouring_napi_register_fail);
		stat_row("iouring_net_multishot", "napi_unregister_ok", shm->stats.iouring_napi_unregister_ok);
		stat_row("iouring_net_multishot", "napi_unregister_fail", shm->stats.iouring_napi_unregister_fail);
	}
}

static void dump_stats_render_bridge_fdb_stp(void)
{
	if (shm->stats.bridge_fdb_stp_runs) {
		stat_row("bridge_fdb_stp", "runs",            shm->stats.bridge_fdb_stp_runs);
		stat_row("bridge_fdb_stp", "setup_failed",    shm->stats.bridge_fdb_stp_setup_failed);
		stat_row("bridge_fdb_stp", "bridge_create_ok", shm->stats.bridge_fdb_stp_bridge_create_ok);
		stat_row("bridge_fdb_stp", "veth_create_ok",  shm->stats.bridge_fdb_stp_veth_create_ok);
		stat_row("bridge_fdb_stp", "raw_send_ok",     shm->stats.bridge_fdb_stp_raw_send_ok);
		stat_row("bridge_fdb_stp", "stp_toggle_ok",   shm->stats.bridge_fdb_stp_stp_toggle_ok);
		stat_row("bridge_fdb_stp", "fdb_del_ok",      shm->stats.bridge_fdb_stp_fdb_del_ok);
		stat_row("bridge_fdb_stp", "link_del_ok",     shm->stats.bridge_fdb_stp_link_del_ok);
		stat_row("bridge_fdb_stp", "vlan_mass_runs",  shm->stats.bridge_vlan_mass_runs);
		stat_row("bridge_fdb_stp", "vlan_mass_max_n", shm->stats.bridge_vlan_mass_max_n);
		stat_row("bridge_fdb_stp", "vlan_mass_enotbufs", shm->stats.bridge_vlan_mass_enotbufs);
	}
}

static void dump_stats_render_nftables_churn(void)
{
	if (shm->stats.nftables_churn_runs) {
		stat_row("nftables_churn", "runs",             shm->stats.nftables_churn_runs);
		stat_row("nftables_churn", "setup_failed",     shm->stats.nftables_churn_setup_failed);
		stat_row("nftables_churn", "table_create_ok",  shm->stats.nftables_churn_table_create_ok);
		stat_row("nftables_churn", "set_create_ok",    shm->stats.nftables_churn_set_create_ok);
		stat_row("nftables_churn", "chain_create_ok",  shm->stats.nftables_churn_chain_create_ok);
		stat_row("nftables_churn", "rule_create_ok",   shm->stats.nftables_churn_rule_create_ok);
		stat_row("nftables_churn", "packet_sent_ok",   shm->stats.nftables_churn_packet_sent_ok);
		stat_row("nftables_churn", "rule_insert_ok",   shm->stats.nftables_churn_rule_insert_ok);
		stat_row("nftables_churn", "rule_del_ok",      shm->stats.nftables_churn_rule_del_ok);
		stat_row("nftables_churn", "table_del_ok",     shm->stats.nftables_churn_table_del_ok);
		stat_row("nftables_churn", "payload_expr_emit",shm->stats.nftables_churn_payload_expr_emit);
		stat_row("nftables_churn", "objref_expr_emit", shm->stats.nftables_churn_objref_expr_emit);
		stat_row("nftables_churn", "compat_validate_install_ok",     shm->stats.nft_compat_validate_install_ok);
		stat_row("nftables_churn", "compat_validate_install_fail",   shm->stats.nft_compat_validate_install_fail);
		stat_row("nftables_churn", "compat_validate_unsupported",    shm->stats.nft_compat_validate_unsupported);
		stat_row("nftables_churn", "compat_validate_per_hook_pairs", shm->stats.nft_compat_validate_per_hook_pairs);
		stat_row("nftables_churn", "dormant_abort_iters", shm->stats.nft_dormant_abort_iters);
		stat_row("nftables_churn", "dormant_abort_eperm", shm->stats.nft_dormant_abort_eperm);
		stat_row("nftables_churn", "dormant_abort_emsg",  shm->stats.nft_dormant_abort_emsg);
		stat_row("nftables_churn", "dormant_abort_ok",    shm->stats.nft_dormant_abort_ok);
		stat_row("nftables_churn", "xt_ct_iters",         shm->stats.xt_ct_iters);
		stat_row("nftables_churn", "xt_ct_eperm",         shm->stats.xt_ct_eperm);
		stat_row("nftables_churn", "xt_ct_unsupported",   shm->stats.xt_ct_unsupported);
		stat_row("nftables_churn", "xt_ct_set_ok",        shm->stats.xt_ct_set_ok);
		stat_row("nftables_churn", "xt_ct_get_ok",        shm->stats.xt_ct_get_ok);
		stat_row("nftables_churn", "xt_ct_v2_seen",       shm->stats.xt_ct_v2_seen);
		stat_row("nftables_churn", "fwd_loop_runs",             shm->stats.nft_fwd_loop_runs);
		stat_row("nftables_churn", "fwd_loop_ns_setup_failed",  shm->stats.nft_fwd_loop_ns_setup_failed);
		stat_row("nftables_churn", "fwd_loop_probe_sent_ok",    shm->stats.nft_fwd_loop_probe_sent_ok);
		stat_row("nftables_churn", "fwd_loop_completed_ok",     shm->stats.nft_fwd_loop_completed_ok);
		stat_row("nftables_churn", "l4frag_iters",              shm->stats.nft_l4frag_iters);
		stat_row("nftables_churn", "l4frag_install_ok",         shm->stats.nft_l4frag_install_ok);
		stat_row("nftables_churn", "l4frag_rule_ok",            shm->stats.nft_l4frag_rule_ok);
		stat_row("nftables_churn", "l4frag_send_ok",            shm->stats.nft_l4frag_send_ok);
		stat_row("nftables_churn", "l4frag_send_failed",        shm->stats.nft_l4frag_send_failed);
	}
}

static void dump_stats_render_tc_qdisc_churn(void)
{
	if (shm->stats.tc_qdisc_churn_runs) {
		stat_row("tc_qdisc_churn", "runs",              shm->stats.tc_qdisc_churn_runs);
		stat_row("tc_qdisc_churn", "setup_failed",      shm->stats.tc_qdisc_churn_setup_failed);
		stat_row("tc_qdisc_churn", "link_create_ok",    shm->stats.tc_qdisc_churn_link_create_ok);
		stat_row("tc_qdisc_churn", "qdisc_create_ok",   shm->stats.tc_qdisc_churn_qdisc_create_ok);
		stat_row("tc_qdisc_churn", "tclass_create_ok",  shm->stats.tc_qdisc_churn_tclass_create_ok);
		stat_row("tc_qdisc_churn", "tfilter_create_ok", shm->stats.tc_qdisc_churn_tfilter_create_ok);
		stat_row("tc_qdisc_churn", "packet_sent_ok",    shm->stats.tc_qdisc_churn_packet_sent_ok);
		stat_row("tc_qdisc_churn", "qdisc_replace_ok",  shm->stats.tc_qdisc_churn_qdisc_replace_ok);
		stat_row("tc_qdisc_churn", "tfilter_del_ok",    shm->stats.tc_qdisc_churn_tfilter_del_ok);
		stat_row("tc_qdisc_churn", "qdisc_del_ok",      shm->stats.tc_qdisc_churn_qdisc_del_ok);
		stat_row("tc_qdisc_churn", "link_del_ok",       shm->stats.tc_qdisc_churn_link_del_ok);
		stat_row("tc_qdisc_churn", "peek_stack_runs",         shm->stats.tc_qdisc_peek_stack_runs);
		stat_row("tc_qdisc_churn", "peek_stack_install_ok",   shm->stats.tc_qdisc_peek_stack_install_ok);
		stat_row("tc_qdisc_churn", "peek_stack_install_fail", shm->stats.tc_qdisc_peek_stack_install_fail);
		stat_row("tc_qdisc_churn", "peek_stack_burst_ok",     shm->stats.tc_qdisc_peek_stack_burst_ok);
		stat_row("tc_qdisc_churn", "bridge_parent_runs",      shm->stats.tc_qdisc_churn_bridge_parent_runs);
		stat_row("tc_qdisc_churn", "bridge_dellink_race_ok",  shm->stats.tc_qdisc_churn_bridge_dellink_race_ok);
	}
}

static void dump_stats_render_tc_mirred_blockcast(void)
{
	if (shm->stats.tc_mirred_blockcast_runs) {
		stat_row("tc_mirred_blockcast", "runs",            shm->stats.tc_mirred_blockcast_runs);
		stat_row("tc_mirred_blockcast", "setup_failed",    shm->stats.tc_mirred_blockcast_setup_failed);
		stat_row("tc_mirred_blockcast", "qdisc_ok",        shm->stats.tc_mirred_blockcast_qdisc_ok);
		stat_row("tc_mirred_blockcast", "qdisc_fail",      shm->stats.tc_mirred_blockcast_qdisc_fail);
		stat_row("tc_mirred_blockcast", "filter_ok",       shm->stats.tc_mirred_blockcast_filter_ok);
		stat_row("tc_mirred_blockcast", "filter_fail",     shm->stats.tc_mirred_blockcast_filter_fail);
		stat_row("tc_mirred_blockcast", "packet_sent_ok",  shm->stats.tc_mirred_blockcast_packet_sent_ok);
	}
}

static void dump_stats_render_xfrm_churn(void)
{
	if (shm->stats.xfrm_churn_runs) {
		stat_row("xfrm_churn", "runs",          shm->stats.xfrm_churn_runs);
		stat_row("xfrm_churn", "setup_failed",  shm->stats.xfrm_churn_setup_failed);
		stat_row("xfrm_churn", "sa_added",      shm->stats.xfrm_churn_sa_added);
		stat_row("xfrm_churn", "sa_updated",    shm->stats.xfrm_churn_sa_updated);
		stat_row("xfrm_churn", "sa_deleted",    shm->stats.xfrm_churn_sa_deleted);
		stat_row("xfrm_churn", "pol_added",     shm->stats.xfrm_churn_pol_added);
		stat_row("xfrm_churn", "pol_deleted",   shm->stats.xfrm_churn_pol_deleted);
		stat_row("xfrm_churn", "esp_sent",      shm->stats.xfrm_churn_esp_sent);
		stat_row("xfrm_churn", "pfkey_send_ok", shm->stats.xfrm_churn_pfkey_send_ok);
		stat_row("xfrm_churn", "ah_esn_setup_ok",    shm->stats.xfrm_ah_esn_setup_ok);
		stat_row("xfrm_churn", "ah_esn_setup_fail",  shm->stats.xfrm_ah_esn_setup_fail);
		stat_row("xfrm_churn", "ah_esn_async_runs",  shm->stats.xfrm_ah_esn_async_runs);
		stat_row("xfrm_churn", "ah_esn_delsa_races", shm->stats.xfrm_ah_esn_delsa_races);
		stat_row("xfrm_churn", "compat_sweep_runs",  shm->stats.xfrm_compat_sweep_runs);
		stat_row("xfrm_churn", "compat_sends_ok",    shm->stats.xfrm_compat_sends_ok);
		stat_row("xfrm_churn", "compat_sends_failed", shm->stats.xfrm_compat_sends_failed);
		stat_row("xfrm_churn", "compat_replies_seen", shm->stats.xfrm_compat_replies_seen);
	}
}

static void dump_stats_render_accept_unblocker(void)
{
	if (shm->stats.accept_unblocker_connects_fired ||
	    shm->stats.accept_unblocker_loopback_only_skipped ||
	    shm->stats.accept_unblocker_probe_failed) {
		stat_row("accept_unblocker", "connects_fired",
			 shm->stats.accept_unblocker_connects_fired);
		stat_row("accept_unblocker", "loopback_only_skipped",
			 shm->stats.accept_unblocker_loopback_only_skipped);
		stat_row("accept_unblocker", "probe_failed",
			 shm->stats.accept_unblocker_probe_failed);
	}
}

static void dump_stats_render_pipe_waker(void)
{
	if (shm->stats.pipe_waker_bytes_written ||
	    shm->stats.pipe_waker_no_target ||
	    shm->stats.pipe_waker_write_failed) {
		stat_row("pipe_waker", "bytes_written",
			 shm->stats.pipe_waker_bytes_written);
		stat_row("pipe_waker", "no_target",
			 shm->stats.pipe_waker_no_target);
		stat_row("pipe_waker", "write_failed",
			 shm->stats.pipe_waker_write_failed);
	}
}

static void dump_stats_render_nat_t_churn(void)
{
	if (shm->stats.nat_t_churn_runs) {
		stat_row("nat_t_churn", "runs",              shm->stats.nat_t_churn_runs);
		stat_row("nat_t_churn", "setup_failed",      shm->stats.nat_t_churn_setup_failed);
		stat_row("nat_t_churn", "sa_added",          shm->stats.nat_t_churn_sa_added);
		stat_row("nat_t_churn", "sa_deleted",        shm->stats.nat_t_churn_sa_deleted);
		stat_row("nat_t_churn", "frames_sent",       shm->stats.nat_t_churn_frames_sent);
		stat_row("nat_t_churn", "xfrm6_setup_ok",    shm->stats.nat_t_xfrm6_setup_ok);
		stat_row("nat_t_churn", "xfrm6_setup_fail",  shm->stats.nat_t_xfrm6_setup_fail);
		stat_row("nat_t_churn", "xfrm6_sendto_runs", shm->stats.nat_t_xfrm6_sendto_runs);
		stat_row("nat_t_churn", "xfrm6_delsa_races", shm->stats.nat_t_xfrm6_delsa_races);
	}
}

static void dump_stats_render_mptcp_pm_churn(void)
{
	if (shm->stats.mptcp_pm_churn_runs) {
		stat_row("mptcp_pm_churn", "runs",            shm->stats.mptcp_pm_churn_runs);
		stat_row("mptcp_pm_churn", "setup_failed",    shm->stats.mptcp_pm_churn_setup_failed);
		stat_row("mptcp_pm_churn", "sock_mptcp_ok",   shm->stats.mptcp_pm_churn_sock_mptcp_ok);
		stat_row("mptcp_pm_churn", "addr_added_ok",   shm->stats.mptcp_pm_churn_addr_added_ok);
		stat_row("mptcp_pm_churn", "addr_removed_ok", shm->stats.mptcp_pm_churn_addr_removed_ok);
		stat_row("mptcp_pm_churn", "send_ok",         shm->stats.mptcp_pm_churn_send_ok);
		stat_row("mptcp_pm_churn", "setsockopt_unsupported",   shm->stats.mptcp_setsockopt_unsupported);
		stat_row("mptcp_pm_churn", "setsockopt_master_set",    shm->stats.mptcp_setsockopt_master_set);
		stat_row("mptcp_pm_churn", "setsockopt_master_fail",   shm->stats.mptcp_setsockopt_master_fail);
		stat_row("mptcp_pm_churn", "getsockopt_verify_ok",     shm->stats.mptcp_getsockopt_verify_ok);
		stat_row("mptcp_pm_churn", "getsockopt_verify_drift",  shm->stats.mptcp_getsockopt_verify_drift);
		stat_row("mptcp_pm_churn", "sockopt_sweep_runs",       shm->stats.mptcp_sockopt_sweep_runs);
		stat_row("mptcp_pm_churn", "sockopt_set_ok",           shm->stats.mptcp_sockopt_set_ok);
		stat_row("mptcp_pm_churn", "sockopt_set_failed",       shm->stats.mptcp_sockopt_set_failed);
		stat_row("mptcp_pm_churn", "sockopt_subflow_added",    shm->stats.mptcp_sockopt_subflow_added);
		stat_row("mptcp_pm_churn", "sockopt_readback_ok",      shm->stats.mptcp_sockopt_readback_ok);
		stat_row("mptcp_pm_churn", "sockopt_inherit_mismatch", shm->stats.mptcp_sockopt_inherit_mismatch);
		stat_row("mptcp_pm_churn", "sockopt_unsupported_latched", shm->stats.mptcp_sockopt_unsupported_latched);
	}
}

static void dump_stats_render_devlink_port_churn(void)
{
	if (shm->stats.devlink_port_churn.iterations ||
	    shm->stats.devlink_port_churn.create_skipped) {
		stat_row("devlink_port_churn", "iterations",     shm->stats.devlink_port_churn.iterations);
		stat_row("devlink_port_churn", "split_ok",       shm->stats.devlink_port_churn.split_ok);
		stat_row("devlink_port_churn", "split_fail",     shm->stats.devlink_port_churn.split_fail);
		stat_row("devlink_port_churn", "reload_ok",      shm->stats.devlink_port_churn.reload_ok);
		stat_row("devlink_port_churn", "reload_fail",    shm->stats.devlink_port_churn.reload_fail);
		stat_row("devlink_port_churn", "create_skipped", shm->stats.devlink_port_churn.create_skipped);
	}
}

static void dump_stats_render_vsock_transport_churn(void)
{
	if (shm->stats.vsock_transport_churn_runs) {
		stat_row("vsock_transport_churn", "runs",           shm->stats.vsock_transport_churn_runs);
		stat_row("vsock_transport_churn", "setup_failed",   shm->stats.vsock_transport_churn_setup_failed);
		stat_row("vsock_transport_churn", "bind_ok",        shm->stats.vsock_transport_churn_bind_ok);
		stat_row("vsock_transport_churn", "connect_ok",     shm->stats.vsock_transport_churn_connect_ok);
		stat_row("vsock_transport_churn", "send_ok",        shm->stats.vsock_transport_churn_send_ok);
		stat_row("vsock_transport_churn", "buffer_size_ok", shm->stats.vsock_transport_churn_buffer_size_ok);
		stat_row("vsock_transport_churn", "timeout_ok",     shm->stats.vsock_transport_churn_timeout_ok);
		stat_row("vsock_transport_churn", "get_cid_ok",     shm->stats.vsock_transport_churn_get_cid_ok);
		stat_row("vsock_transport_churn", "seq_eom_runs",         shm->stats.vsock_seq_eom_runs);
		stat_row("vsock_transport_churn", "seq_eom_sends_ok",     shm->stats.vsock_seq_eom_sends_ok);
		stat_row("vsock_transport_churn", "seq_eom_sends_failed", shm->stats.vsock_seq_eom_sends_failed);
		stat_row("vsock_transport_churn", "seq_eom_skipped",      shm->stats.vsock_seq_eom_skipped);
	}
}

static void dump_stats_render_psp_key_rotate(void)
{
	if (shm->stats.psp_key_rotate_runs) {
		stat_row("psp_key_rotate", "runs",              shm->stats.psp_key_rotate_runs);
		stat_row("psp_key_rotate", "setup_failed",      shm->stats.psp_key_rotate_setup_failed);
		stat_row("psp_key_rotate", "netdev_create_ok",  shm->stats.psp_key_rotate_netdev_create_ok);
		stat_row("psp_key_rotate", "family_resolve_ok", shm->stats.psp_key_rotate_family_resolve_ok);
		stat_row("psp_key_rotate", "dev_get_ok",        shm->stats.psp_key_rotate_dev_get_ok);
		stat_row("psp_key_rotate", "key_install_ok",    shm->stats.psp_key_rotate_key_install_ok);
		stat_row("psp_key_rotate", "spi_set_ok",        shm->stats.psp_key_rotate_spi_set_ok);
		stat_row("psp_key_rotate", "send_ok",           shm->stats.psp_key_rotate_send_ok);
		stat_row("psp_key_rotate", "rotate_ok",         shm->stats.psp_key_rotate_rotate_ok);
		stat_row("psp_key_rotate", "spi_switch_ok",     shm->stats.psp_key_rotate_spi_switch_ok);
		stat_row("psp_key_rotate", "shutdown_ok",       shm->stats.psp_key_rotate_shutdown_ok);
	}
}

static void dump_stats_render_psp_devlink_port_churn(void)
{
	if (shm->stats.psp_devlink_port_churn_runs) {
		stat_row("psp_devlink_port_churn", "runs",                 shm->stats.psp_devlink_port_churn_runs);
		stat_row("psp_devlink_port_churn", "port_add_ok",          shm->stats.psp_devlink_port_churn_port_add_ok);
		stat_row("psp_devlink_port_churn", "port_del_ok",          shm->stats.psp_devlink_port_churn_port_del_ok);
		stat_row("psp_devlink_port_churn", "vf_spawn_ok",          shm->stats.psp_devlink_port_churn_vf_spawn_ok);
		stat_row("psp_devlink_port_churn", "unsupported_latched",  shm->stats.psp_devlink_port_churn_unsupported_latched);
	}
}

static void dump_stats_render_ipvs_sysctl_writer(void)
{
	if (shm->stats.ipvs_sysctl_writer.runs) {
		stat_row("ipvs_sysctl_writer", "runs",                shm->stats.ipvs_sysctl_writer.runs);
		stat_row("ipvs_sysctl_writer", "writes_ok",           shm->stats.ipvs_sysctl_writer.writes_ok);
		stat_row("ipvs_sysctl_writer", "writes_failed",       shm->stats.ipvs_sysctl_writer.writes_failed);
		stat_row("ipvs_sysctl_writer", "unsupported_latched", shm->stats.ipvs_sysctl_writer.unsupported_latched);
	}
}

static void dump_stats_render_ipfrag_source(void)
{
	if (shm->stats.ipfrag_source_runs) {
		stat_row("ipfrag_source_churn", "runs",            shm->stats.ipfrag_source_runs);
		stat_row("ipfrag_source_churn", "packets_sent_ok", shm->stats.ipfrag_packets_sent_ok);
		stat_row("ipfrag_source_churn", "send_failed",     shm->stats.ipfrag_send_failed);
		stat_row("ipfrag_source_churn", "unique_srcs",     shm->stats.ipfrag_unique_srcs);
	}
}

static void dump_stats_render_obscure_af_churn(void)
{
	if (shm->stats.obscure_af_churn_runs) {
		static const char * const ap_names[] = {
			"sendmsg_no_bind",
			"bind_then_sendmsg",
			"connect_no_listen",
			"ioctl_rotation",
			"setsockopt_zero_len",
			"close_via_dup",
		};
		char key[64];
		unsigned int ap;

		stat_row("obscure_af_churn", "runs",         shm->stats.obscure_af_churn_runs);
		stat_row("obscure_af_churn", "no_viable_pf", shm->stats.obscure_af_churn_no_viable_pf);

		for (ap = 0; ap < ARRAY_SIZE(ap_names); ap++) {
			snprintf(key, sizeof(key), "%s_runs", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_runs[ap]);
			snprintf(key, sizeof(key), "%s_kernel_rejected", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_kernel_rejected[ap]);
			snprintf(key, sizeof(key), "%s_unexpected_success", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_unexpected_success[ap]);
		}
	}
}

static void dump_stats_render_rxrpc_sendmsg_cmsg(void)
{
	if (shm->stats.rxrpc_sendmsg_cmsg_runs) {
		static const char * const rxrpc_cmsg_slot_names[8] = {
			"user_call_id",
			"abort",
			"accept",
			"exclusive_call",
			"upgrade_service",
			"tx_length",
			"set_call_timeout",
			"charge_accept",
		};
		char key[64];
		unsigned int slot;

		stat_row("rxrpc_sendmsg_cmsg_churn", "runs",          shm->stats.rxrpc_sendmsg_cmsg_runs);
		stat_row("rxrpc_sendmsg_cmsg_churn", "socket_failed", shm->stats.rxrpc_sendmsg_cmsg_socket_failed);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_ok",    shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_fail",  shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail);
		for (slot = 0; slot < 8U; slot++) {
			snprintf(key, sizeof(key), "cmsg_sent_%s",
				 rxrpc_cmsg_slot_names[slot]);
			stat_row("rxrpc_sendmsg_cmsg_churn", key,
				 shm->stats.rxrpc_sendmsg_cmsg_sent[slot]);
		}
	}
}

static void dump_stats_render_tty_ldisc_churn(void)
{
	if (shm->stats.tty_ldisc_churn_runs) {
		char key[64];
		unsigned int slot;

		stat_row("tty_ldisc_churn", "runs",             shm->stats.tty_ldisc_churn_runs);
		stat_row("tty_ldisc_churn", "setup_failed",     shm->stats.tty_ldisc_churn_setup_failed);
		stat_row("tty_ldisc_churn", "ldisc_set_ok",     shm->stats.tty_ldisc_churn_ldisc_set_ok);
		stat_row("tty_ldisc_churn", "ldisc_set_failed", shm->stats.tty_ldisc_churn_ldisc_set_failed);
		stat_row("tty_ldisc_churn", "write_ok",         shm->stats.tty_ldisc_churn_write_ok);
		stat_row("tty_ldisc_churn", "read_ok",          shm->stats.tty_ldisc_churn_read_ok);
		for (slot = 0; slot < 25U; slot++) {
			if (shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot] == 0)
				continue;
			snprintf(key, sizeof(key), "ldisc_set_ok_n%u", slot);
			stat_row("tty_ldisc_churn", key,
				 shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot]);
		}
	}
}

static void dump_stats_render_afxdp_churn(void)
{
	if (shm->stats.afxdp_churn_runs) {
		stat_row("afxdp_churn", "runs",            shm->stats.afxdp_churn_runs);
		stat_row("afxdp_churn", "setup_failed",    shm->stats.afxdp_churn_setup_failed);
		stat_row("afxdp_churn", "umem_reg_ok",     shm->stats.afxdp_churn_umem_reg_ok);
		stat_row("afxdp_churn", "rings_setup_ok",  shm->stats.afxdp_churn_rings_setup_ok);
		stat_row("afxdp_churn", "prog_load_ok",    shm->stats.afxdp_churn_prog_load_ok);
		stat_row("afxdp_churn", "map_create_ok",   shm->stats.afxdp_churn_map_create_ok);
		stat_row("afxdp_churn", "map_update_ok",   shm->stats.afxdp_churn_map_update_ok);
		stat_row("afxdp_churn", "bind_ok",         shm->stats.afxdp_churn_bind_ok);
		stat_row("afxdp_churn", "link_attach_ok",  shm->stats.afxdp_churn_link_attach_ok);
		stat_row("afxdp_churn", "netlink_attach_ok", shm->stats.afxdp_churn_netlink_attach_ok);
		stat_row("afxdp_churn", "attach_failed",   shm->stats.afxdp_churn_attach_failed);
		stat_row("afxdp_churn", "send_ok",         shm->stats.afxdp_churn_send_ok);
		stat_row("afxdp_churn", "recv_ok",         shm->stats.afxdp_churn_recv_ok);
		stat_row("afxdp_churn", "map_delete_ok",   shm->stats.afxdp_churn_map_delete_ok);
		stat_row("afxdp_churn", "munmap_race_ok",  shm->stats.afxdp_churn_munmap_race_ok);
		stat_row("afxdp_churn", "xsg_iters",         shm->stats.afxdp_xsg_iters);
		stat_row("afxdp_churn", "tx_metadata_iters", shm->stats.afxdp_tx_metadata_iters);
		stat_row("afxdp_churn", "tun_bind_iters",    shm->stats.afxdp_tun_bind_iters);
		stat_row("afxdp_churn", "xsg_bind_failed",   shm->stats.afxdp_xsg_bind_failed);
		stat_row("afxdp_churn", "tx_md_bind_failed", shm->stats.afxdp_tx_md_bind_failed);
	}
}

static void dump_stats_render_kvm_run_churn(void)
{
	if (shm->stats.kvm_run_invocations) {
		stat_row("kvm_run_churn", "invocations",        shm->stats.kvm_run_invocations);
		stat_row("kvm_run_churn", "exit_io",            shm->stats.kvm_run_exit_io);
		stat_row("kvm_run_churn", "exit_mmio",          shm->stats.kvm_run_exit_mmio);
		stat_row("kvm_run_churn", "exit_hlt",           shm->stats.kvm_run_exit_hlt);
		stat_row("kvm_run_churn", "exit_shutdown",      shm->stats.kvm_run_exit_shutdown);
		stat_row("kvm_run_churn", "exit_fail_entry",    shm->stats.kvm_run_exit_fail_entry);
		stat_row("kvm_run_churn", "exit_internal_error", shm->stats.kvm_run_exit_internal_error);
		stat_row("kvm_run_churn", "exit_intr",          shm->stats.kvm_run_exit_intr);
		stat_row("kvm_run_churn", "exit_other",         shm->stats.kvm_run_exit_other);
		stat_row("kvm_run_churn", "errors",             shm->stats.kvm_run_errors);
		stat_row("kvm_run_churn", "gpc_memslot_race_runs",         shm->stats.kvm_gpc_memslot_race_runs);
		stat_row("kvm_run_churn", "gpc_memslot_race_deletes",      shm->stats.kvm_gpc_memslot_race_deletes);
		stat_row("kvm_run_churn", "gpc_memslot_race_unsupported",  shm->stats.kvm_gpc_memslot_race_unsupported);
	}
}

static void dump_stats_render_nl80211_churn(void)
{
	if (shm->stats.nl80211_runs) {
		stat_row("nl80211_churn", "runs",                  shm->stats.nl80211_runs);
		stat_row("nl80211_churn", "setup_failed",          shm->stats.nl80211_setup_failed);
		stat_row("nl80211_churn", "scan_triggered",        shm->stats.nl80211_scan_triggered);
		stat_row("nl80211_churn", "connect_attempted",     shm->stats.nl80211_connect_attempted);
		stat_row("nl80211_churn", "connect_succeeded",     shm->stats.nl80211_connect_succeeded);
		stat_row("nl80211_churn", "disconnect_attempted",  shm->stats.nl80211_disconnect_attempted);
		stat_row("nl80211_churn", "regdom_changed",        shm->stats.nl80211_regdom_changed);
		stat_row("nl80211_churn", "iface_created",         shm->stats.nl80211_iface_created);
		stat_row("nl80211_churn", "iface_destroyed",       shm->stats.nl80211_iface_destroyed);
		stat_row("nl80211_churn", "bursts_sent",           shm->stats.nl80211_bursts_sent);
		stat_row("nl80211_churn", "pmsr_runs",             shm->stats.nl80211_pmsr_runs);
		stat_row("nl80211_churn", "pmsr_ok",               shm->stats.nl80211_pmsr_ok);
		stat_row("nl80211_churn", "admin_gate_runs",       shm->stats.nl80211_admin_gate_runs);
		stat_row("nl80211_churn", "admin_gate_eperm_ok",   shm->stats.nl80211_admin_gate_eperm_ok);
		stat_row("nl80211_churn", "admin_gate_unexpected", shm->stats.nl80211_admin_gate_unexpected);
	}
}

static void dump_stats_render_af_alg_probe(void)
{
	if (shm->stats.af_alg_probe_runs || shm->stats.af_alg_probe_unsupported) {
		unsigned int tmpl;

		stat_row("af_alg_probe", "runs",         shm->stats.af_alg_probe_runs);
		stat_row("af_alg_probe", "unsupported",  shm->stats.af_alg_probe_unsupported);
		stat_row("af_alg_probe", "accept_total", shm->stats.af_alg_probe_accept_total);
		stat_row("af_alg_probe", "reject_total", shm->stats.af_alg_probe_reject_total);
		for (tmpl = 0; tmpl < NR_AF_ALG_PROBE_TEMPLATES; tmpl++) {
			char metric[64];
			const char *label = af_alg_probe_template_label(tmpl);

			snprintf(metric, sizeof(metric), "%s.accept", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_accept[tmpl]);
			snprintf(metric, sizeof(metric), "%s.reject", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_reject[tmpl]);
		}
	}
}

static void dump_stats_render_af_alg_recvmsg_churn(void)
{
	if (shm->stats.af_alg_recvmsg_runs) {
		stat_row("af_alg_recvmsg_churn", "runs",               shm->stats.af_alg_recvmsg_runs);
		stat_row("af_alg_recvmsg_churn", "setkey_sent",        shm->stats.af_alg_recvmsg_setkey_sent);
		stat_row("af_alg_recvmsg_churn", "iv_sent",            shm->stats.af_alg_recvmsg_iv_sent);
		stat_row("af_alg_recvmsg_churn", "oob_iov",            shm->stats.af_alg_recvmsg_oob_iov);
		stat_row("af_alg_recvmsg_churn", "zerolen",            shm->stats.af_alg_recvmsg_zerolen);
		stat_row("af_alg_recvmsg_churn", "oversize",           shm->stats.af_alg_recvmsg_oversize);
		stat_row("af_alg_recvmsg_churn", "empty_cmsg_no_more", shm->stats.af_alg_recvmsg_empty_cmsg_no_more);
		stat_row("af_alg_recvmsg_churn", "unsupported",        shm->stats.af_alg_recvmsg_unsupported);
	}
}
void __cold dump_stats_childop_runs_network(void)
{
	stat_category_emit_text(&socket_family_chain_category);

	stat_category_emit_text(&socket_family_grammar_category);

	stat_category_emit_text(&tls_rotate_category);

	dump_stats_render_packet_fanout_thrash();

	dump_stats_render_eth_emitter();

	dump_stats_render_iouring_multishot();

	stat_category_emit_text(&tcp_ao_rotate_category);

	stat_category_emit_text(&tcp_md5_listener_race_category);

	stat_category_emit_text(&ipv6_pmtu_race_category);

	stat_category_emit_text(&vrf_fib_churn_category);

	stat_category_emit_text(&ip6_udp_cork_splice_category);

	stat_category_emit_text(&ip4_udp_cork_splice_category);

	stat_category_emit_text(&mpls_route_churn_category);

	stat_category_emit_text(&netlink_monitor_race_category);

	stat_category_emit_text(&tipc_link_churn_category);

	stat_category_emit_text(&tls_ulp_churn_category);

	stat_category_emit_text(&vxlan_encap_churn_category);

	stat_category_emit_text(&ip_gre_churn_category);

	stat_category_emit_text(&ovs_tunnel_vport_churn_category);

	stat_category_emit_text(&esp_crafted_rx_category);

	stat_category_emit_text(&fou_gue_mcast_rx_category);

	stat_category_emit_text(&geneve_rx_category);

	stat_category_emit_text(&bareudp_rx_category);

	stat_category_emit_text(&sctp_chunk_rx_category);

	stat_category_emit_text(&mpls_label_stack_rx_category);

	stat_category_emit_text(&tc_live_traffic_category);

	dump_stats_render_bridge_fdb_stp();

	stat_category_emit_text(&bridge_conntrack_churn_category);

	dump_stats_render_nftables_churn();

	dump_stats_render_tc_qdisc_churn();

	dump_stats_render_tc_mirred_blockcast();

	dump_stats_render_xfrm_churn();

	stat_category_emit_text(&altname_thrash_category);

	stat_category_emit_text(&ublk_lifecycle_category);

	stat_category_emit_text(&pci_bind_category);

	dump_stats_render_accept_unblocker();

	dump_stats_render_pipe_waker();

	dump_stats_render_nat_t_churn();

	stat_category_emit_text(&bpf_cgroup_attach_category);

	dump_stats_render_mptcp_pm_churn();

	dump_stats_render_devlink_port_churn();

	stat_category_emit_text(&handshake_req_abort_category);

	stat_category_emit_text(&nf_conntrack_helper_churn_category);

	stat_category_emit_text(&ipset_churn_category);

	stat_category_emit_text(&af_unix_scm_rights_gc_category);

	stat_category_emit_text(&af_unix_peek_race_category);

	stat_category_emit_text(&sysv_shm_orphan_race_category);

	stat_category_emit_text(&map_shared_stress_category);

	stat_category_emit_text(&qrtr_bind_race_category);

	stat_category_emit_text(&pfkey_spd_walk_category);

	stat_category_emit_text(&l2tp_ifname_race_category);

	stat_category_emit_text(&netns_teardown_category);

	stat_category_emit_text(&cred_transition_category);

	stat_category_emit_text(&deep_path_nesting_category);

	stat_category_emit_text(&espintcp_coalesce_category);

	stat_category_emit_text(&netns_mountns_setup_category);

	stat_category_emit_text(&tcp_ulp_swap_churn_category);

	stat_category_emit_text(&blob_mutator_category);

	stat_category_emit_text(&blob_ab_mode_category);

	dump_stats_render_blob_fills_by_group();

	stat_category_emit_text(&msg_zerocopy_churn_category);

	stat_category_emit_text(&rds_zcopy_crafted_send_category);

	stat_category_emit_text(&setsockopt_pairing_category);

	stat_category_emit_text(&iouring_send_zc_churn_category);

	dump_stats_render_vsock_transport_churn();

	stat_category_emit_text(&bridge_vlan_churn_category);

	stat_category_emit_text(&vlan_filter_churn_category);

	stat_category_emit_text(&pkt_builder_category);

	stat_category_emit_text(&igmp_mld_source_churn_category);

	dump_stats_render_psp_key_rotate();

	dump_stats_render_psp_devlink_port_churn();

	stat_category_emit_text(&veth_asymmetric_xdp_category);

	stat_category_emit_text(&ip6erspan_netns_migrate_category);

	stat_category_emit_text(&netdev_netns_migrate_category);

	stat_category_emit_text(&ip6gre_bond_lapb_stack_category);

	stat_category_emit_text(&wireguard_decrypt_flood_category);

	stat_category_emit_text(&blkdev_lifecycle_race_category);

	stat_category_emit_text(&hfs_mount_fuzz_category);

	stat_category_emit_text(&iscsi_target_probe_category);

	stat_category_emit_text(&iscsi_login_walker_category);

	dump_stats_render_ipvs_sysctl_writer();

	stat_category_emit_text(&ipv6_ndisc_proxy_category);

	dump_stats_render_ipfrag_source();

	stat_category_emit_text(&rtnl_vf_broadcast_getlink_category);

	dump_stats_render_obscure_af_churn();

	stat_category_emit_text(&flowtable_encap_vlan_category);

	dump_stats_render_rxrpc_sendmsg_cmsg();

	dump_stats_render_tty_ldisc_churn();

	dump_stats_render_afxdp_churn();

	dump_stats_render_kvm_run_churn();

	dump_stats_render_nl80211_churn();

	stat_category_emit_text(&splice_protocols_category);

	stat_category_emit_text(&rxrpc_key_install_category);

	stat_category_emit_text(&af_alg_weak_cipher_probe_category);

	stat_category_emit_text(&sysfs_string_race_category);

	stat_category_emit_text(&fdstress_category);

	dump_stats_render_af_alg_probe();

	dump_stats_render_af_alg_recvmsg_churn();
}

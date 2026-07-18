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

/*
 * Tail-of-schema JSON emitters for --stats-json: iouring-zc /
 * KVM / nl80211 / NAT-T (dump_stats_json_iouring_zc_and_kvm),
 * AF_ALG probes (dump_stats_json_rxrpc_alg_ublk_block), and the
 * hand-written probes-misuse tail
 * (dump_stats_json_probes_misuse_and_tail).
 *
 * These sections carry their own JSON-local descriptor tables
 * -- vsock_transport_churn, psp_key_rotate, afxdp_churn, kvm,
 * kvm_run_churn, nl80211, nat_t_churn, af_alg_probe, and
 * af_alg_recvmsg -- so the emitters and tables move as a
 * cluster.
 */

#include <stdio.h>
#include "shm.h"
#include "stats-internal.h"
#include "stats/json/internal.h"




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

void dump_stats_json_iouring_zc_and_kvm(void)
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

void dump_stats_json_rxrpc_alg_ublk_block(void)
{
	stat_category_emit_json(&af_alg_probe_category);
	putchar(',');
	stat_category_emit_json(&af_alg_recvmsg_category);
	putchar(',');
}

void dump_stats_json_probes_misuse_and_tail(void)
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
		shm->stats.ipvs_sysctl_writer.runs,
		shm->stats.ipvs_sysctl_writer.writes_ok,
		shm->stats.ipvs_sysctl_writer.writes_failed,
		shm->stats.ipvs_sysctl_writer.unsupported_latched,
		shm->stats.ipvs_sysctl_writer.burn_iters,
		shm->stats.ipfrag_source_churn.runs,
		shm->stats.ipfrag_source_churn.packets_sent_ok,
		shm->stats.ipfrag_source_churn.send_failed,
		shm->stats.ipfrag_source_churn.unique_srcs,
		shm->stats.obscure_af_churn.runs,
		shm->stats.obscure_af_churn.no_viable_pf,
		shm->stats.obscure_af_churn.pattern_runs[0],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[0],
		shm->stats.obscure_af_churn.pattern_unexpected_success[0],
		shm->stats.obscure_af_churn.pattern_runs[1],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[1],
		shm->stats.obscure_af_churn.pattern_unexpected_success[1],
		shm->stats.obscure_af_churn.pattern_runs[2],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[2],
		shm->stats.obscure_af_churn.pattern_unexpected_success[2],
		shm->stats.obscure_af_churn.pattern_runs[3],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[3],
		shm->stats.obscure_af_churn.pattern_unexpected_success[3],
		shm->stats.obscure_af_churn.pattern_runs[4],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[4],
		shm->stats.obscure_af_churn.pattern_unexpected_success[4],
		shm->stats.obscure_af_churn.pattern_runs[5],
		shm->stats.obscure_af_churn.pattern_kernel_rejected[5],
		shm->stats.obscure_af_churn.pattern_unexpected_success[5],
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
		shm->stats.tty_ldisc_churn.runs,
		shm->stats.tty_ldisc_churn.setup_failed,
		shm->stats.tty_ldisc_churn.ldisc_set_ok,
		shm->stats.tty_ldisc_churn.ldisc_set_failed,
		shm->stats.tty_ldisc_churn.write_ok,
		shm->stats.tty_ldisc_churn.read_ok,
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[0],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[1],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[2],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[3],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[4],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[5],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[6],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[7],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[8],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[9],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[10],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[11],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[12],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[13],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[14],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[15],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[16],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[17],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[18],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[19],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[20],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[21],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[22],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[23],
		shm->stats.tty_ldisc_churn.ldisc_set_ok_per_disc[24]);
}

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

#include <stdbool.h>
#include <stdio.h>
#include "shm.h"
#include "stats-internal.h"
#include "stats/json/internal.h"




static const struct stat_field kvm_fields[] = {
	STAT_FIELD_SUB(kvm, vcpu_ioctls_dispatched),
	STAT_FIELD_SUB(kvm, vm_ioctls_dispatched),
};

static const struct stat_category kvm_category =
	STAT_CATEGORY("kvm",
	              kvm.vcpu_ioctls_dispatched,
	              kvm_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD_SUB(kvm, invocations),
	STAT_FIELD_SUB(kvm, exit_io),
	STAT_FIELD_SUB(kvm, exit_mmio),
	STAT_FIELD_SUB(kvm, exit_hlt),
	STAT_FIELD_SUB(kvm, exit_shutdown),
	STAT_FIELD_SUB(kvm, exit_fail_entry),
	STAT_FIELD_SUB(kvm, exit_internal_error),
	STAT_FIELD_SUB(kvm, exit_intr),
	STAT_FIELD_SUB(kvm, exit_other),
	STAT_FIELD_SUB(kvm, errors),
	STAT_FIELD_SUB(kvm, gpc_memslot_race_runs),
	STAT_FIELD_SUB(kvm, gpc_memslot_race_deletes),
	STAT_FIELD_SUB(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category =
	STAT_CATEGORY("kvm_run_churn",
	              kvm.invocations,
	              kvm_run_churn_fields);

static const struct stat_field kvm_reclaim_race_fields[] = {
	STAT_FIELD_SUB(kvm, reclaim_prefault_ok),
	STAT_FIELD_SUB(kvm, reclaim_prefault_eopnotsupp),
	STAT_FIELD_SUB(kvm, reclaim_prefault_err),
	STAT_FIELD_SUB(kvm, reclaim_set_nr_mmu_ok),
	STAT_FIELD_SUB(kvm, reclaim_set_nr_mmu_err),
	STAT_FIELD_SUB(kvm, reclaim_memslot_ok),
};

static const struct stat_category kvm_reclaim_race_category =
	STAT_CATEGORY("kvm_reclaim_race",
	              kvm.reclaim_prefault_ok,
	              kvm_reclaim_race_fields);

static const struct stat_field nl80211_fields[] = {
	STAT_FIELD_SUB(nl80211, runs),
	STAT_FIELD_SUB(nl80211, setup_failed),
	STAT_FIELD_SUB(nl80211, scan_triggered),
	STAT_FIELD_SUB(nl80211, connect_attempted),
	STAT_FIELD_SUB(nl80211, connect_succeeded),
	STAT_FIELD_SUB(nl80211, disconnect_attempted),
	STAT_FIELD_SUB(nl80211, regdom_changed),
	STAT_FIELD_SUB(nl80211, iface_created),
	STAT_FIELD_SUB(nl80211, iface_destroyed),
	STAT_FIELD_SUB(nl80211, bursts_sent),
	STAT_FIELD_SUB(nl80211, pmsr_runs),
	STAT_FIELD_SUB(nl80211, pmsr_ok),
	STAT_FIELD_SUB(nl80211, admin_gate_runs),
	STAT_FIELD_SUB(nl80211, admin_gate_eperm_ok),
	STAT_FIELD_SUB(nl80211, admin_gate_unexpected),
};

static const struct stat_category nl80211_category =
	STAT_CATEGORY("nl80211",
	              nl80211.runs,
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
	stat_category_emit_json(&kvm_reclaim_race_category);
	putchar(',');
	stat_category_emit_json(&nl80211_category);
	putchar(',');
	stat_category_emit_json(&nat_t_churn_category);
	putchar(',');
}

static const struct stat_field af_alg_probe_fields[] = {
	STAT_FIELD_SUB(af_alg_probe, runs),
	STAT_FIELD_SUB(af_alg_probe, unsupported),
	STAT_FIELD_SUB(af_alg_probe, accept_total),
	STAT_FIELD_SUB(af_alg_probe, reject_total),
};

static const struct stat_category af_alg_probe_category =
	STAT_CATEGORY("af_alg_probe",
	              af_alg_probe.runs,
	              af_alg_probe_fields);

static const struct stat_field af_alg_recvmsg_fields[] = {
	STAT_FIELD_SUB(af_alg_recvmsg, runs),
	STAT_FIELD_SUB(af_alg_recvmsg, setkey_sent),
	STAT_FIELD_SUB(af_alg_recvmsg, iv_sent),
	STAT_FIELD_SUB(af_alg_recvmsg, oob_iov),
	STAT_FIELD_SUB(af_alg_recvmsg, zerolen),
	STAT_FIELD_SUB(af_alg_recvmsg, oversize),
	STAT_FIELD_SUB(af_alg_recvmsg, empty_cmsg_no_more),
	STAT_FIELD_SUB(af_alg_recvmsg, unsupported),
};

static const struct stat_category af_alg_recvmsg_category =
	STAT_CATEGORY("af_alg_recvmsg",
	              af_alg_recvmsg.runs,
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
		shm->stats.rxrpc_sendmsg_cmsg.runs,
		shm->stats.rxrpc_sendmsg_cmsg.socket_failed,
		shm->stats.rxrpc_sendmsg_cmsg.sendmsg_ok,
		shm->stats.rxrpc_sendmsg_cmsg.sendmsg_fail,
		shm->stats.rxrpc_sendmsg_cmsg.sent[0],
		shm->stats.rxrpc_sendmsg_cmsg.sent[1],
		shm->stats.rxrpc_sendmsg_cmsg.sent[2],
		shm->stats.rxrpc_sendmsg_cmsg.sent[3],
		shm->stats.rxrpc_sendmsg_cmsg.sent[4],
		shm->stats.rxrpc_sendmsg_cmsg.sent[5],
		shm->stats.rxrpc_sendmsg_cmsg.sent[6],
		shm->stats.rxrpc_sendmsg_cmsg.sent[7],
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

/*
 * Single-element printer for json_emit_dead_arms_section().  Named with
 * the json_emit_ prefix so the stats-json-schema checker follows it when
 * resolving the dead_arms array element shape.
 *
 * All five fields are always emitted so the array element schema is
 * uniform regardless of which entry type (dead vs insufficient_samples)
 * appears first in the output.
 *
 * status values:
 *   "dead"                 -- arm_entered==0, sampling floor met
 *   "insufficient_samples" -- too few draws to distinguish dead from live
 */
static void json_emit_dead_arms_element(bool *first, const char *group,
					const char *arm,
					unsigned long arm_entered,
					unsigned long parent_runs,
					const char *status)
{
	printf("%s{\"group\":\"%s\",\"arm\":\"%s\","
	       "\"arm_entered\":%lu,\"parent_runs\":%lu,\"status\":\"%s\"}",
	       *first ? "" : ",",
	       group, arm, arm_entered, parent_runs, status);
	*first = false;
}

/*
 * Emit the dead-arm verdict as a top-level "dead_arms" JSON array,
 * parallel to "kcov" / "minicorpus" / "cmp_hints" / "type_graph".
 *
 * Applies the same sampling-floor logic as dump_stats_dead_arm_check()
 * on the text path but produces structured objects so the run-analysis
 * fleet tooling (e.g. extractors/strategy.py) can ingest the verdict
 * without re-implementing the floor logic itself.
 *
 * An empty array ("dead_arms":[]) is emitted when no instrumented
 * subsystem ran during this invocation.
 *
 * NOTE: do NOT merge this with dump_stats_dead_arm_check() -- the text
 * and JSON paths are intentionally independent and evolve separately.
 */
void json_emit_dead_arms_section(void)
{
	bool first = true;

	fputs(",\"dead_arms\":[", stdout);

	/* igmp-mld-source-churn: five v4 arms (race_v4_a through race_v4_e)
	 * and four v6 arms (race_v6_a through race_v6_d).
	 * Floors: v4 requires 5*5=25 total draws; v6 requires 5*4=20. */
	if (shm->stats.igmp_mld_source_churn.runs > 0) {
		const unsigned long pr = shm->stats.igmp_mld_source_churn.runs;
		unsigned long v4_draws =
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_a +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_b +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_c +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_d +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_e;

		if (v4_draws >= 5 * 5) {
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_a)
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "race_v4_a",
					0, pr, "dead");
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_b)
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "race_v4_b",
					0, pr, "dead");
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_c)
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "race_v4_c",
					0, pr, "dead");
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_d)
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "race_v4_d",
					0, pr, "dead");
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_e)
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "race_v4_e",
					0, pr, "dead");
		} else {
			json_emit_dead_arms_element(&first,
				"igmp-mld-source-churn", "v4",
				v4_draws, pr, "insufficient_samples");
		}

		{
			unsigned long v6_draws =
				shm->stats.igmp_mld_source_churn.arm_entered_race_v6_a +
				shm->stats.igmp_mld_source_churn.arm_entered_race_v6_b +
				shm->stats.igmp_mld_source_churn.arm_entered_race_v6_c +
				shm->stats.igmp_mld_source_churn.arm_entered_race_v6_d;

			if (v6_draws >= 5 * 4) {
				if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_a)
					json_emit_dead_arms_element(&first,
						"igmp-mld-source-churn", "race_v6_a",
						0, pr, "dead");
				if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_b)
					json_emit_dead_arms_element(&first,
						"igmp-mld-source-churn", "race_v6_b",
						0, pr, "dead");
				if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_c)
					json_emit_dead_arms_element(&first,
						"igmp-mld-source-churn", "race_v6_c",
						0, pr, "dead");
				if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_d)
					json_emit_dead_arms_element(&first,
						"igmp-mld-source-churn", "race_v6_d",
						0, pr, "dead");
			} else {
				json_emit_dead_arms_element(&first,
					"igmp-mld-source-churn", "v6",
					v6_draws, pr, "insufficient_samples");
			}
		}
	}

	/* afxdp-churn: single XDP_COPY bind arm, floor = 5*1 = 5 draws.
	 * Floor gates on runs (group opportunity count), not arm_entered_bind --
	 * for a single-arm group arm_entered_bind==0 IS the dead state, so
	 * gating on it is a tautology (always insufficient_samples, never dead).
	 * ran_no_effect: arm_entered_bind > 0 but arm_effective_bind == 0 --
	 * the bind arm was reached but never produced detectable output. */
	if (shm->stats.afxdp_churn.runs > 0) {
		unsigned long runs = shm->stats.afxdp_churn.runs;
		unsigned long ae = shm->stats.afxdp_churn.arm_entered_bind;

		if (runs < 5 * 1)
			json_emit_dead_arms_element(&first, "afxdp-churn", "bind",
						    ae, runs, "insufficient_samples");
		else if (!ae)
			json_emit_dead_arms_element(&first, "afxdp-churn", "bind",
						    ae, runs, "dead");
		else if (!shm->stats.afxdp_churn.arm_effective_bind)
			json_emit_dead_arms_element(&first, "afxdp-churn", "bind",
						    ae, runs, "ran_no_effect");
		/* else: ae >= 1, arm_effective_bind >= 1: fully live */
	}

	/* xfrm-churn: XFRM_MSG_MIGRATE_STATE arm.
	 * Gate on msg_kind_draws (grammar pick_msg_kind() call count) to match
	 * the text emitter in stats/dump/subsystems.c. Floor: 300 draws.
	 * No zero-guard: draws==0 falls into draws<300 and emits
	 * insufficient_samples, matching the text emitter behaviour. */
	{
		unsigned long draws = shm->stats.xfrm_churn.msg_kind_draws;
		unsigned long ae = shm->stats.xfrm_churn.arm_entered_migrate_state;

		if (draws < 300)
			json_emit_dead_arms_element(&first, "xfrm-churn", "migrate_state",
						    ae, draws, "insufficient_samples");
		else if (!ae)
			json_emit_dead_arms_element(&first, "xfrm-churn", "migrate_state",
						    ae, draws, "dead");
		/* else: ae >= 1, arm is live -- emit nothing */
	}

	fputs("]", stdout);
}

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
#include "stats-internal.h"
#include "stats/json/internal.h"

/*
 * eth_emitter's five per-template counters live in an array
 * (eth_emitter.per_tmpl[NR_TEMPLATES]); the JSON schema emits one
 * flat key per slot ("tmpl_arp" .. "tmpl_bad_ethertype"), so raw
 * offsetof() entries pin each key to its array index.
 */



void dump_stats_json_socket_family_and_tls(void)
{
}

/*
 * Descriptor tables for dump_stats_json_netfilter_and_xfrm().
 *
 * Six categories that the previous hand-written printf emitted with one
 * %lu slot per field and a parallel shm->stats.<field> va-list; adding a
 * counter required three correlated edits.  STAT_FIELD_SUB names the
 * per-subsystem struct member and the field within it; .name doubles as
 * the (currently unused) text-side key.  For the xt_ct_* / nft_*
 * sub-groups nested inside struct nftables_churn_stats, .name preserves
 * the full member identifier so the JSON key stays "xt_ct_iters" etc.
 *
 * The text emitter for these subsystems stays hand-coded for now; if a
 * future change wires stat_category_emit_text() onto these tables it will
 * emit when any field is non-zero, so the gate_field choices below are
 * documentation only.
 */





static const struct stat_field xfrm_ah_esn_fields[] = {
	STAT_FIELD_SUB(xfrm_ah_esn, setup_ok),
	STAT_FIELD_SUB(xfrm_ah_esn, setup_fail),
	STAT_FIELD_SUB(xfrm_ah_esn, async_runs),
	STAT_FIELD_SUB(xfrm_ah_esn, delsa_races),
};

const struct stat_category xfrm_ah_esn_category =
	STAT_CATEGORY("xfrm_ah_esn",
	              xfrm_ah_esn_fields);

static const struct stat_field xfrm_compat_fields[] = {
	STAT_FIELD_SUB(xfrm_compat, sweep_runs),
	STAT_FIELD_SUB(xfrm_compat, sends_ok),
	STAT_FIELD_SUB(xfrm_compat, sends_failed),
	STAT_FIELD_SUB(xfrm_compat, replies_seen),
	STAT_FIELD_SUB(xfrm_compat, allocspi_runs),
	STAT_FIELD_SUB(xfrm_compat, allocspi_sends_ok),
	STAT_FIELD_SUB(xfrm_compat, allocspi_sends_failed),
	STAT_FIELD_SUB(xfrm_compat, allocspi_replies_seen),
	STAT_FIELD_SUB(xfrm_compat, allocspi_unsupported),
};

const struct stat_category xfrm_compat_category =
	STAT_CATEGORY("xfrm_compat",
	              xfrm_compat_fields);

void dump_stats_json_netfilter_and_xfrm(void)
{
	json_stats_sep();
	stat_category_emit_json(&xfrm_ah_esn_category);
	json_stats_sep();
	stat_category_emit_json(&xfrm_compat_category);
}

void json_emit_socket_family_grammar_section(void)
{
	json_stats_sep();
	stat_category_emit_json(&socket_family_grammar_category);
	json_stats_sep();
	stat_category_emit_json(&xfrm_grammar_category);
}

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





	json_stats_sep();
	stat_category_emit_json(&statmount_idmap_category);


}

void json_emit_tcp_ipv6_and_tunnels_section(void)
{
	json_stats_sep();
	stat_category_emit_json(&netns_teardown_category);

	json_stats_sep();
	stat_category_emit_json(&cred_transition_category);


	json_stats_sep();
	stat_category_emit_json(&espintcp_coalesce_category);

	json_stats_sep();
	stat_category_emit_json(&netns_mountns_setup_category);





	json_stats_sep();
	stat_category_emit_json(&ipv6_pmtu_race_category);















}

void json_emit_bridge_pci_unix_and_iouring_section(void)
{


	json_stats_sep();
	stat_category_emit_json(&pkt_builder_category);




	json_stats_sep();
	stat_category_emit_json(&af_unix_scm_rights_gc_category);










	json_stats_sep();
	stat_category_emit_json(&refcount_audit_category);
}

void json_emit_iouring_iscsi_and_net_tail_section(void)
{
	json_stats_sep();
	stat_category_emit_json(&iouring_send_zc_churn_category);




	json_stats_sep();
	stat_category_emit_json(&rxrpc_key_install_category);






	json_stats_sep();
	stat_category_emit_json(&icmp_inject_category);









	json_stats_sep();
	stat_category_emit_json(&fdstress_category);
}

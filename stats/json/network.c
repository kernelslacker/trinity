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





void dump_stats_json_netfilter_and_xfrm(void)
{
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







}

void json_emit_tcp_ipv6_and_tunnels_section(void)
{
























}

void json_emit_bridge_pci_unix_and_iouring_section(void)
{
















}

void json_emit_iouring_iscsi_and_net_tail_section(void)
{
	json_stats_sep();
	stat_category_emit_json(&iouring_send_zc_churn_category);




	json_stats_sep();
	stat_category_emit_json(&rxrpc_key_install_category);















}

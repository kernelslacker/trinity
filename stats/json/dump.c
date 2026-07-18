/*
 * Top-level orchestration for --stats-json.  dump_stats_json()
 * stitches together the section-emitter helpers under stats/json/
 * into a single JSON document on stdout.  This file owns the
 * root object braces, the "stats":{...} wrapper, and the section
 * order; individual sections live in their own files (common,
 * syscalls, kcov, minicorpus, cmp-hints, core, network, tail).
 */

#include <stdio.h>
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "trinity.h"

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

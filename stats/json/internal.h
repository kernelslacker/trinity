#pragma once

/*
 * Private cross-file interface for the stats/json/ cluster.
 *
 * The only symbol the rest of the tree needs from this cluster is
 * dump_stats_json(), which stays declared in include/stats-internal.h.
 * Everything here is JSON-cluster local: helpers shared across the
 * files under stats/json/ so each section can stay in a small file
 * of its own without having to expose its internals to callers
 * outside the cluster.
 */

#include "stats-internal.h"

/* stats/json/common.c */
void json_emit_string(const char *s);
void stat_category_emit_json(const struct stat_category *cat);

/* stats/json/syscalls.c */
void json_emit_syscalls_array(void);

/* stats/json/kcov.c */
void json_emit_kcov_section(void);

/* stats/json/minicorpus.c */
void json_emit_minicorpus_section(void);

/* stats/json/cmp-hints.c */
void json_emit_cmp_hints_section(void);

/* stats/json/core.c */
void dump_stats_json_fault_and_fd_lifecycle(void);
void dump_stats_json_oracle(void);
void dump_stats_json_basic_subsystems(void);
void dump_stats_json_iouring_and_zombies(void);
void dump_stats_json_corruption_and_audit(void);
void dump_stats_json_lifecycle_and_storms(void);

/* stats/json/network.c */
void dump_stats_json_socket_family_and_tls(void);
void dump_stats_json_netfilter_and_xfrm(void);
void json_emit_socket_family_grammar_section(void);
void json_emit_net_churn_and_early_storms_section(void);
void json_emit_pidfd_fs_and_container_section(void);
void json_emit_tcp_ipv6_and_tunnels_section(void);
void json_emit_bridge_pci_unix_and_iouring_section(void);
void json_emit_iouring_iscsi_and_net_tail_section(void);

/* stats/json/tail.c */
void dump_stats_json_iouring_zc_and_kvm(void);
void dump_stats_json_rxrpc_alg_ublk_block(void);
void dump_stats_json_probes_misuse_and_tail(void);

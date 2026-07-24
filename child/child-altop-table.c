/*
 * Alt-op string names, external-linkage lookup, the outer-bracket
 * eligibility gate, and the op_dispatch[] indirect-call table.  Pure
 * static metadata carved out of child-altop.c so make -j can compile
 * each half of the split in parallel.
 *
 * Function declarations for the many child-op entry points threaded
 * into op_dispatch[] arrive via child.h; the include set matches
 * child-altop.c's so the dispatch initialiser sees the same set of
 * prototypes it always did.
 */


#include <string.h>
#include "child.h"
#include "child-internal.h"
#include "params.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mount.h"
#include "kernel/if_packet.h"

/*
 * KCOV bracketing opt-in.  Read by the childop dispatcher.
 * Defaults to true for every op.
 * CHILD_OP_SYSCALL falls through to run_sequence_chain
 * which brackets per-syscall internally.  CHILD_OP_SCHED_CYCLER
 * (childops/misc/sched-cycler.c) calls random_syscall(child) in
 * a tight loop; an outer bracket would double-call
 * ioctl(KCOV_ENABLE) and the kernel returns -EBUSY which
 * kcov_enable_trace currently treats as fatal.
 *
 * Expressed as an accessor so new enum members default to
 * eligible without per-table maintenance and without the
 * [0 ... N-1] = true designated-init override idiom, which
 * trips -Woverride-init on this codebase's -Wextra build.
 * Compiler folds the switch into a constant-time check at
 * the future call site.
 */
bool op_uses_outer_bracket(enum child_op_type op)
{
	switch (op) {
	case CHILD_OP_SYSCALL:
	case CHILD_OP_SCHED_CYCLER:
		return false;
	default:
		return true;
	}
}

const char *alt_op_name(enum child_op_type op)
{
	switch (op) {
	case CHILD_OP_SYSCALL:		return "syscall";
	case CHILD_OP_MMAP_LIFECYCLE:	return "mmap_lifecycle";
	case CHILD_OP_MPROTECT_SPLIT:	return "mprotect_split";
	case CHILD_OP_MLOCK_PRESSURE:	return "mlock_pressure";
	case CHILD_OP_INODE_SPEWER:	return "inode_spewer";
	case CHILD_OP_PROCFS_WRITER:	return "procfs_writer";
	case CHILD_OP_MEMORY_PRESSURE:	return "memory_pressure";
	case CHILD_OP_USERNS_FUZZER:	return "userns_fuzzer";
	case CHILD_OP_SCHED_CYCLER:	return "sched_cycler";
	case CHILD_OP_BARRIER_RACER:	return "barrier_racer";
	case CHILD_OP_GENETLINK_FUZZER:	return "genetlink_fuzzer";
	case CHILD_OP_PERF_CHAINS:	return "perf_chains";
	case CHILD_OP_TRACEFS_FUZZER:	return "tracefs_fuzzer";
	case CHILD_OP_BPF_LIFECYCLE:	return "bpf_lifecycle";
	case CHILD_OP_FAULT_INJECTOR:	return "fault_injector";
	case CHILD_OP_RECIPE_RUNNER:	return "recipe_runner";
	case CHILD_OP_IOURING_RECIPES:	return "iouring_recipes";
	case CHILD_OP_FD_STRESS:	return "fd_stress";
	case CHILD_OP_REFCOUNT_AUDITOR:	return "refcount_auditor";
	case CHILD_OP_FS_LIFECYCLE:	return "fs_lifecycle";
	case CHILD_OP_SIGNAL_STORM:	return "signal_storm";
	case CHILD_OP_FUTEX_STORM:	return "futex_storm";
	case CHILD_OP_PIPE_THRASH:	return "pipe_thrash";
	case CHILD_OP_FORK_STORM:	return "fork_storm";
	case CHILD_OP_FLOCK_THRASH:	return "flock_thrash";
	case CHILD_OP_CGROUP_CHURN:	return "cgroup_churn";
	case CHILD_OP_MOUNT_CHURN:	return "mount_churn";
	case CHILD_OP_UFFD_CHURN:	return "uffd_churn";
	case CHILD_OP_IOURING_FLOOD:	return "iouring_flood";
	case CHILD_OP_CLOSE_RACER:	return "close_racer";
	case CHILD_OP_SOCKET_FAMILY_CHAIN:	return "socket_family_chain";
	case CHILD_OP_XATTR_THRASH:	return "xattr_thrash";
	case CHILD_OP_PIDFD_STORM:	return "pidfd_storm";
	case CHILD_OP_MADVISE_CYCLER:	return "madvise_cycler";
	case CHILD_OP_EPOLL_VOLATILITY:	return "epoll_volatility";
	case CHILD_OP_KEYRING_SPAM:	return "keyring_spam";
	case CHILD_OP_VDSO_MREMAP_RACE:	return "vdso_mremap_race";
	case CHILD_OP_NUMA_MIGRATION:	return "numa_migration";
	case CHILD_OP_CPU_HOTPLUG_RIDER: return "cpu_hotplug_rider";
	case CHILD_OP_SLAB_CACHE_THRASH: return "slab_cache_thrash";
	case CHILD_OP_TLS_ROTATE:	return "tls_rotate";
	case CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING:	return "sock_ulp_sockmap_layering";
	case CHILD_OP_PACKET_FANOUT_THRASH:	return "packet_fanout_thrash";
	case CHILD_OP_IOURING_NET_MULTISHOT:	return "iouring_net_multishot";
	case CHILD_OP_TCP_AO_ROTATE:	return "tcp_ao_rotate";
	case CHILD_OP_VRF_FIB_CHURN:	return "vrf_fib_churn";
	case CHILD_OP_NETLINK_MONITOR_RACE:	return "netlink_monitor_race";
	case CHILD_OP_TIPC_LINK_CHURN:	return "tipc_link_churn";
	case CHILD_OP_TLS_ULP_CHURN:	return "tls_ulp_churn";
	case CHILD_OP_VXLAN_ENCAP_CHURN:	return "vxlan_encap_churn";
	case CHILD_OP_IP_GRE_CHURN:	return "ip_gre_churn";
	case CHILD_OP_BRIDGE_FDB_STP:	return "bridge_fdb_stp";
	case CHILD_OP_NFTABLES_CHURN:	return "nftables_churn";
	case CHILD_OP_TC_QDISC_CHURN:	return "tc_qdisc_churn";
	case CHILD_OP_XFRM_CHURN:	return "xfrm_churn";
	case CHILD_OP_BPF_CGROUP_ATTACH:	return "bpf_cgroup_attach";
	case CHILD_OP_SCTP_ASSOC_CHURN:	return "sctp_assoc_churn";
	case CHILD_OP_MPTCP_PM_CHURN:	return "mptcp_pm_churn";
	case CHILD_OP_DEVLINK_PORT_CHURN:	return "devlink_port_churn";
	case CHILD_OP_HANDSHAKE_REQ_ABORT:	return "handshake_req_abort";
	case CHILD_OP_NF_CONNTRACK_HELPER:	return "nf_conntrack_helper_churn";
	case CHILD_OP_AF_UNIX_SCM_RIGHTS_GC:	return "af_unix_scm_rights_gc_churn";
	case CHILD_OP_NETNS_TEARDOWN_CHURN:	return "netns_teardown_churn";
	case CHILD_OP_TCP_ULP_SWAP_CHURN:	return "tcp_ulp_swap_churn";
	case CHILD_OP_MSG_ZEROCOPY_CHURN:	return "msg_zerocopy_churn";
	case CHILD_OP_IOURING_SEND_ZC_CHURN:	return "iouring_send_zc_churn";
	case CHILD_OP_VSOCK_TRANSPORT_CHURN:	return "vsock_transport_churn";
	case CHILD_OP_BRIDGE_VLAN_CHURN:	return "bridge_vlan_churn";
	case CHILD_OP_IGMP_MLD_SOURCE_CHURN:	return "igmp_mld_source_churn";
	case CHILD_OP_PSP_KEY_ROTATE:	return "psp_key_rotate";
	case CHILD_OP_AFXDP_CHURN:	return "afxdp_churn";
	case CHILD_OP_KVM_RUN_CHURN:	return "kvm_run_churn";
	case CHILD_OP_NL80211_CHURN:	return "nl80211_churn";
	case CHILD_OP_NAT_T_CHURN:	return "nat_t_churn";
	case CHILD_OP_SPLICE_PROTOCOLS:	return "splice_protocols";
	case CHILD_OP_RXRPC_KEY_INSTALL:	return "rxrpc_key_install";
	case CHILD_OP_INPLACE_CRYPTO_ORACLE:	return "inplace_crypto_oracle";
	case CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE:	return "af_alg_weak_cipher_probe";
	case CHILD_OP_AF_ALG_TEMPLATE_PROBE:	return "af_alg_template_probe";
	case CHILD_OP_AF_ALG_RECVMSG_CHURN:	return "af_alg_recvmsg_churn";
	case CHILD_OP_IOURING_CMD_PASSTHROUGH:	return "iouring_cmd_passthrough";
	case CHILD_OP_PAGECACHE_CANARY_CHECK:	return "pagecache_canary_check";
	case CHILD_OP_MPLS_ROUTE_CHURN:	return "mpls_route_churn";
	case CHILD_OP_SOCK_DIAG_WALKER:	return "sock_diag_walker";
	case CHILD_OP_ALTNAME_THRASH:	return "altname_thrash";
	case CHILD_OP_IPMR_CACHE_REPORT:	return "ipmr_cache_report";
	case CHILD_OP_UBLK_LIFECYCLE:	return "ublk_lifecycle";
	case CHILD_OP_VETH_ASYMMETRIC_XDP:	return "veth_asymmetric_xdp";
	case CHILD_OP_IP6ERSPAN_NETNS_MIGRATE:	return "ip6erspan_netns_migrate";
	case CHILD_OP_IPVS_SYSCTL_WRITER:	return "ipvs_sysctl_writer";
	case CHILD_OP_TCP_MD5_LISTENER_RACE:	return "tcp_md5_listener_race";
	case CHILD_OP_IPV6_NDISC_PROXY:	return "ipv6_ndisc_proxy";
	case CHILD_OP_IPFRAG_SOURCE_CHURN:	return "ipfrag_source_churn";
	case CHILD_OP_RTNL_VF_BROADCAST_GETLINK:	return "rtnl_vf_broadcast_getlink";
	case CHILD_OP_OBSCURE_AF_CHURN:	return "obscure_af_churn";
	case CHILD_OP_BRIDGE_CT_CHURN:	return "bridge_conntrack_churn";
	case CHILD_OP_ATM_VCC_CHURN:	return "atm_vcc_churn";
	case CHILD_OP_IP6GRE_BOND_LAPB_STACK:	return "ip6gre_bond_lapb_stack";
	case CHILD_OP_FLOWTABLE_ENCAP_VLAN:	return "flowtable_encap_vlan";
	case CHILD_OP_IPV6_PMTU_TEARDOWN_RACE:	return "ipv6_pmtu_teardown_race";
	case CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN:	return "rxrpc_sendmsg_cmsg_churn";
	case CHILD_OP_OVS_TUNNEL_VPORT_CHURN:	return "ovs_tunnel_vport_churn";
	case CHILD_OP_TTY_LDISC_CHURN:	return "tty_ldisc_churn";
	case CHILD_OP_WIREGUARD_DECRYPT_FLOOD:	return "wireguard_decrypt_flood";
	case CHILD_OP_BLKDEV_LIFECYCLE_RACE:	return "blkdev_lifecycle_race";
	case CHILD_OP_ISCSI_TARGET_PROBE:	return "iscsi_target_probe";
	case CHILD_OP_ISCSI_LOGIN_WALKER:	return "iscsi_login_walker";
	case CHILD_OP_ETH_EMITTER:	return "eth_emitter";
	case CHILD_OP_VMA_SPLIT_STORM:	return "vma_split_storm";
	case CHILD_OP_SYSFS_STRING_RACE:	return "sysfs_string_race";
	case CHILD_OP_PCI_BIND:		return "pci_bind";
	case CHILD_OP_AF_UNIX_PEEK_RACE:	return "af_unix_peek_race";
	case CHILD_OP_SYSV_SHM_ORPHAN_RACE:	return "sysv_shm_orphan_race";
	case CHILD_OP_QRTR_BIND_RACE:	return "qrtr_bind_race";
	case CHILD_OP_TC_MIRRED_BLOCKCAST:	return "tc_mirred_blockcast";
	case CHILD_OP_PFKEY_SPD_WALK:	return "pfkey_spd_walk";
	case CHILD_OP_L2TP_IFNAME_RACE:	return "l2tp_ifname_race";
	case CHILD_OP_STATMOUNT_IDMAP_OVERFLOW:	return "statmount_idmap_overflow";
	case CHILD_OP_UMOUNT_RACE:	return "umount_race";
	case CHILD_OP_IP6_UDP_CORK_SPLICE:	return "ip6_udp_cork_splice";
	case CHILD_OP_IP4_UDP_CORK_SPLICE:	return "ip4_udp_cork_splice";
	case CHILD_OP_FUTEX_PI_REQUEUE_ROLLBACK:	return "futex_pi_requeue_rollback";
	case CHILD_OP_VLAN_FILTER_CHURN:	return "vlan_filter_churn";
	case CHILD_OP_SCTP_CHUNK_RX:	return "sctp_chunk_rx";
	case CHILD_OP_PKT_BUILDER_PROBE:	return "pkt_builder_probe";
	case CHILD_OP_ESP_CRAFTED_RX:	return "esp_crafted_rx";
	case CHILD_OP_FOU_GUE_MCAST_RX:	return "fou_gue_mcast_rx";
	case CHILD_OP_GENEVE_RX:	return "geneve_rx";
	case CHILD_OP_NETNS_MOUNTNS_SETUP_PROBE:	return "netns_mountns_setup_probe";
	case CHILD_OP_BAREUDP_RX:	return "bareudp_rx";
	case CHILD_OP_MPLS_LABEL_STACK_RX:	return "mpls_label_stack_rx";
	case CHILD_OP_DEEP_PATH_NESTING:	return "deep_path_nesting";
	case CHILD_OP_ESPINTCP_COALESCE_CHURN:	return "espintcp_coalesce_churn";
	case CHILD_OP_CRED_TRANSITION_CHURN:	return "cred_transition_churn";
	case CHILD_OP_NETDEV_NETNS_MIGRATE:	return "netdev_netns_migrate";
	case CHILD_OP_MAP_SHARED_STRESS:	return "map_shared_stress";
	case CHILD_OP_TC_LIVE_TRAFFIC:	return "tc_live_traffic";
	case CHILD_OP_HFS_MOUNT_FUZZ:	return "hfs_mount_fuzz";
	case CHILD_OP_RDS_ZCOPY_CRAFTED_SEND:	return "rds_zcopy_crafted_send";
	case CHILD_OP_BRIDGE_IP6FRAG_REFRAG:	return "bridge_ip6frag_refrag";
	case CHILD_OP_BRIDGE_IP6_REFRAG_FRAGGAP:	return "bridge_ip6_refrag_fraggap";
	case CHILD_OP_IPSET_CHURN:	return "ipset_churn";
	case NR_CHILD_OP_TYPES:		break;
	}
	return "unknown";
}

/*
 * Reverse of alt_op_name(): looks up an op by its string form (as
 * emitted by alt_op_name) and returns the matching enum value.  Used
 * by the --canary-seed CLI flag parser to translate operator-supplied
 * op names into an override seed list.  Linear scan over
 * NR_CHILD_OP_TYPES; called at most a few times at startup, never on
 * the hot path.  Returns NR_CHILD_OP_TYPES when no match is found so
 * the caller can distinguish "unknown name" from any real enum value.
 */
enum child_op_type alt_op_lookup_by_name(const char *name)
{
	unsigned int i;

	if (name == NULL || *name == '\0')
		return NR_CHILD_OP_TYPES;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		const char *n = alt_op_name((enum child_op_type)i);
		if (n != NULL && strcmp(n, name) == 0)
			return (enum child_op_type)i;
	}
	return NR_CHILD_OP_TYPES;
}

/*
 * Dispatch table for the per-iteration childop call.  Indexed by
 * enum child_op_type; a NULL slot means "fall through to the
 * sequence-chain path" (CHILD_OP_SYSCALL is handled by the 95% fast
 * path in pick_op_type and reaches the dispatcher only when it ends
 * up running random_syscall via run_sequence_chain).
 *
 * A dense table replaces what was a 38-case switch in the dispatch
 * site: a single indirect call out of a cache-friendly array,
 * instead of the jump-table the compiler emits per branch site.
 */
bool (*const op_dispatch[NR_CHILD_OP_TYPES])(struct childdata *) = {
	[CHILD_OP_SYSCALL]		= NULL,
	[CHILD_OP_MMAP_LIFECYCLE]	= mmap_lifecycle,
	[CHILD_OP_MPROTECT_SPLIT]	= mprotect_split,
	[CHILD_OP_MLOCK_PRESSURE]	= mlock_pressure,
	[CHILD_OP_INODE_SPEWER]		= inode_spewer,
	[CHILD_OP_PROCFS_WRITER]	= procfs_writer,
	[CHILD_OP_MEMORY_PRESSURE]	= memory_pressure,
	[CHILD_OP_USERNS_FUZZER]	= userns_fuzzer,
	[CHILD_OP_SCHED_CYCLER]		= sched_cycler,
	[CHILD_OP_BARRIER_RACER]	= barrier_racer,
	[CHILD_OP_GENETLINK_FUZZER]	= genetlink_fuzzer,
	[CHILD_OP_PERF_CHAINS]		= perf_event_chains,
	[CHILD_OP_TRACEFS_FUZZER]	= tracefs_fuzzer,
	[CHILD_OP_BPF_LIFECYCLE]	= bpf_lifecycle,
	[CHILD_OP_FAULT_INJECTOR]	= fault_injector,
	[CHILD_OP_RECIPE_RUNNER]	= recipe_runner,
	[CHILD_OP_IOURING_RECIPES]	= iouring_recipes,
	[CHILD_OP_FD_STRESS]		= fd_stress,
	[CHILD_OP_REFCOUNT_AUDITOR]	= refcount_auditor,
	[CHILD_OP_FS_LIFECYCLE]		= fs_lifecycle,
	[CHILD_OP_SIGNAL_STORM]		= signal_storm,
	[CHILD_OP_FUTEX_STORM]		= futex_storm,
	[CHILD_OP_PIPE_THRASH]		= pipe_thrash,
	[CHILD_OP_FORK_STORM]		= fork_storm,
	[CHILD_OP_FLOCK_THRASH]		= flock_thrash,
	[CHILD_OP_CGROUP_CHURN]		= cgroup_churn,
	[CHILD_OP_MOUNT_CHURN]		= mount_churn,
	[CHILD_OP_UFFD_CHURN]		= uffd_churn,
	[CHILD_OP_IOURING_FLOOD]	= iouring_flood,
	[CHILD_OP_CLOSE_RACER]		= close_racer,
	[CHILD_OP_SOCKET_FAMILY_CHAIN]	= socket_family_chain,
	[CHILD_OP_XATTR_THRASH]		= xattr_thrash,
	[CHILD_OP_PIDFD_STORM]		= pidfd_storm,
	[CHILD_OP_MADVISE_CYCLER]	= madvise_cycler,
	[CHILD_OP_EPOLL_VOLATILITY]	= epoll_volatility,
	[CHILD_OP_KEYRING_SPAM]		= keyring_spam,
	[CHILD_OP_VDSO_MREMAP_RACE]	= vdso_mremap_race,
	[CHILD_OP_NUMA_MIGRATION]	= numa_migration_churn,
	[CHILD_OP_CPU_HOTPLUG_RIDER]	= cpu_hotplug_rider,
	[CHILD_OP_SLAB_CACHE_THRASH]	= slab_cache_thrash,
	[CHILD_OP_TLS_ROTATE]		= tls_rotate,
	[CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING]	= sock_ulp_sockmap_layering,
	[CHILD_OP_PACKET_FANOUT_THRASH]	= packet_fanout_thrash,
	[CHILD_OP_IOURING_NET_MULTISHOT] = iouring_net_multishot,
	[CHILD_OP_TCP_AO_ROTATE]	= tcp_ao_rotate,
	[CHILD_OP_VRF_FIB_CHURN]	= vrf_fib_churn,
	[CHILD_OP_NETLINK_MONITOR_RACE]	= netlink_monitor_race,
	[CHILD_OP_TIPC_LINK_CHURN]	= tipc_link_churn,
	[CHILD_OP_TLS_ULP_CHURN]	= tls_ulp_churn,
	[CHILD_OP_VXLAN_ENCAP_CHURN]	= vxlan_encap_churn,
	[CHILD_OP_BRIDGE_FDB_STP]	= bridge_fdb_stp,
	[CHILD_OP_NFTABLES_CHURN]	= nftables_churn,
	[CHILD_OP_TC_QDISC_CHURN]	= tc_qdisc_churn,
	[CHILD_OP_XFRM_CHURN]		= xfrm_churn,
	[CHILD_OP_BPF_CGROUP_ATTACH]	= bpf_cgroup_attach,
	[CHILD_OP_SCTP_ASSOC_CHURN]	= sctp_assoc_churn,
	[CHILD_OP_MPTCP_PM_CHURN]	= mptcp_pm_churn,
	[CHILD_OP_DEVLINK_PORT_CHURN]	= devlink_port_churn,
	[CHILD_OP_HANDSHAKE_REQ_ABORT]	= handshake_req_abort,
	[CHILD_OP_NF_CONNTRACK_HELPER]	= nf_conntrack_helper_churn,
	[CHILD_OP_AF_UNIX_SCM_RIGHTS_GC]	= af_unix_scm_rights_gc_churn,
	[CHILD_OP_NETNS_TEARDOWN_CHURN]	= netns_teardown_churn,
	[CHILD_OP_TCP_ULP_SWAP_CHURN]	= tcp_ulp_swap_churn,
	[CHILD_OP_MSG_ZEROCOPY_CHURN]	= msg_zerocopy_churn,
	[CHILD_OP_IOURING_SEND_ZC_CHURN]	= iouring_send_zc_churn,
	[CHILD_OP_VSOCK_TRANSPORT_CHURN]	= vsock_transport_churn,
	[CHILD_OP_BRIDGE_VLAN_CHURN]	= bridge_vlan_churn,
	[CHILD_OP_IGMP_MLD_SOURCE_CHURN]	= igmp_mld_source_churn,
	[CHILD_OP_PSP_KEY_ROTATE]	= psp_key_rotate,
	[CHILD_OP_AFXDP_CHURN]		= afxdp_churn,
	[CHILD_OP_KVM_RUN_CHURN]	= kvm_run_churn,
	[CHILD_OP_NL80211_CHURN]	= nl80211_churn,
	[CHILD_OP_NAT_T_CHURN]		= nat_t_churn,
	[CHILD_OP_SPLICE_PROTOCOLS]	= splice_protocols,
	[CHILD_OP_RXRPC_KEY_INSTALL]	= rxrpc_key_install,
	[CHILD_OP_INPLACE_CRYPTO_ORACLE]	= inplace_crypto_oracle,
	[CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE]	= af_alg_weak_cipher_probe,
	[CHILD_OP_AF_ALG_TEMPLATE_PROBE]	= af_alg_template_probe,
	[CHILD_OP_AF_ALG_RECVMSG_CHURN]		= af_alg_recvmsg_churn,
	[CHILD_OP_IOURING_CMD_PASSTHROUGH]	= iouring_cmd_passthrough,
	[CHILD_OP_PAGECACHE_CANARY_CHECK]	= pagecache_canary_check,
	[CHILD_OP_MPLS_ROUTE_CHURN]	= mpls_route_churn,
	[CHILD_OP_SOCK_DIAG_WALKER]	= sock_diag_walker,
	[CHILD_OP_ALTNAME_THRASH]	= altname_thrash,
	[CHILD_OP_IPMR_CACHE_REPORT]	= ipmr_cache_report,
	[CHILD_OP_UBLK_LIFECYCLE]	= ublk_lifecycle,
	[CHILD_OP_VETH_ASYMMETRIC_XDP]	= veth_asymmetric_xdp,
	[CHILD_OP_IP6ERSPAN_NETNS_MIGRATE]	= ip6erspan_netns_migrate,
	[CHILD_OP_IPVS_SYSCTL_WRITER]	= ipvs_sysctl_writer,
	[CHILD_OP_TCP_MD5_LISTENER_RACE]	= tcp_md5_listener_race,
	[CHILD_OP_IPV6_NDISC_PROXY]	= ipv6_ndisc_proxy,
	[CHILD_OP_IPFRAG_SOURCE_CHURN]	= ipfrag_source_churn,
	[CHILD_OP_RTNL_VF_BROADCAST_GETLINK]	= rtnl_vf_broadcast_getlink,
	[CHILD_OP_OBSCURE_AF_CHURN]	= obscure_af_churn,
	[CHILD_OP_BRIDGE_CT_CHURN]	= bridge_conntrack_churn,
	[CHILD_OP_ATM_VCC_CHURN]	= atm_vcc_churn,
	[CHILD_OP_IP6GRE_BOND_LAPB_STACK]	= ip6gre_bond_lapb_stack,
	[CHILD_OP_FLOWTABLE_ENCAP_VLAN]	= flowtable_encap_vlan,
	[CHILD_OP_IPV6_PMTU_TEARDOWN_RACE]	= ipv6_pmtu_teardown_race,
	[CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN]	= rxrpc_sendmsg_cmsg_churn,
	[CHILD_OP_OVS_TUNNEL_VPORT_CHURN]	= ovs_tunnel_vport_churn,
	[CHILD_OP_TTY_LDISC_CHURN]	= tty_ldisc_churn,
	[CHILD_OP_WIREGUARD_DECRYPT_FLOOD]	= wireguard_decrypt_flood,
	[CHILD_OP_BLKDEV_LIFECYCLE_RACE]	= blkdev_lifecycle_race,
	[CHILD_OP_ISCSI_TARGET_PROBE]	= iscsi_target_probe,
	[CHILD_OP_ISCSI_LOGIN_WALKER]	= iscsi_login_walker,
	[CHILD_OP_ETH_EMITTER]		= eth_emitter,
	[CHILD_OP_VMA_SPLIT_STORM]	= vma_split_storm,
	[CHILD_OP_SYSFS_STRING_RACE]	= sysfs_string_race,
	[CHILD_OP_PCI_BIND]		= pci_bind,
	[CHILD_OP_AF_UNIX_PEEK_RACE]	= af_unix_peek_race,
	[CHILD_OP_SYSV_SHM_ORPHAN_RACE]	= sysv_shm_orphan_race,
	[CHILD_OP_QRTR_BIND_RACE]	= qrtr_bind_race,
	[CHILD_OP_TC_MIRRED_BLOCKCAST]	= tc_mirred_blockcast,
	[CHILD_OP_PFKEY_SPD_WALK]	= pfkey_spd_walk,
	[CHILD_OP_L2TP_IFNAME_RACE]	= l2tp_ifname_race,
	[CHILD_OP_STATMOUNT_IDMAP_OVERFLOW] = statmount_idmap_overflow,
	[CHILD_OP_UMOUNT_RACE]		= umount_race,
	[CHILD_OP_IP6_UDP_CORK_SPLICE]	= ip6_udp_cork_splice,
	[CHILD_OP_IP_GRE_CHURN]		= ip_gre_churn,
	[CHILD_OP_FUTEX_PI_REQUEUE_ROLLBACK]	= futex_pi_requeue_rollback,
	[CHILD_OP_VLAN_FILTER_CHURN]	= vlan_filter_churn,
	[CHILD_OP_SCTP_CHUNK_RX]	= sctp_chunk_rx,
	[CHILD_OP_PKT_BUILDER_PROBE]	= pkt_builder_probe,
	[CHILD_OP_ESP_CRAFTED_RX]	= esp_crafted_rx,
	[CHILD_OP_FOU_GUE_MCAST_RX]	= fou_gue_mcast_rx,
	[CHILD_OP_GENEVE_RX]		= geneve_rx,
	[CHILD_OP_NETNS_MOUNTNS_SETUP_PROBE]	= netns_mountns_setup_probe,
	[CHILD_OP_BAREUDP_RX]		= bareudp_rx,
	[CHILD_OP_MPLS_LABEL_STACK_RX]	= mpls_label_stack_rx,
	[CHILD_OP_DEEP_PATH_NESTING]	= deep_path_nesting,
	[CHILD_OP_ESPINTCP_COALESCE_CHURN]	= espintcp_coalesce_churn,
	[CHILD_OP_CRED_TRANSITION_CHURN]	= cred_transition_churn,
	[CHILD_OP_NETDEV_NETNS_MIGRATE]	= netdev_netns_migrate,
	[CHILD_OP_MAP_SHARED_STRESS]	= map_shared_stress,
	[CHILD_OP_TC_LIVE_TRAFFIC]	= tc_live_traffic,
	[CHILD_OP_HFS_MOUNT_FUZZ]	= hfs_mount_fuzz,
	[CHILD_OP_RDS_ZCOPY_CRAFTED_SEND]	= rds_zcopy_crafted_send,
	[CHILD_OP_BRIDGE_IP6FRAG_REFRAG]	= bridge_ip6frag_refrag,
	[CHILD_OP_BRIDGE_IP6_REFRAG_FRAGGAP]	= bridge_ip6_refrag_fraggap,
	[CHILD_OP_IPSET_CHURN]		= ipset_churn,
	[CHILD_OP_IP4_UDP_CORK_SPLICE]	= ip4_udp_cork_splice,
};

_Static_assert(ARRAY_SIZE(op_dispatch) == NR_CHILD_OP_TYPES,
	"op_dispatch must have one slot per enum child_op_type");

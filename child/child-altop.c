/*
 * Alt-op picker, dispatch table, and the scoring / dormancy
 * machinery that drives the canary queue's observability.  Split
 * out of child.c so make -j can compile this concurrently with the
 * per-child setup and the main loop.
 *
 * pick_op_type, adapt_budget, and the op_dispatch[] table shed
 * their `static` linkage at the TU split -- child_process() in
 * child.c calls all three on the hot per-iteration path.  See
 * include/child-internal.h for the extern declarations.
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
 * Startup snapshot of the dormant-op gate consulted by init_altop_dispatch()
 * to build the dense enabled_altops[] vector.  Mutated at runtime by the
 * parent's queue transition path (enter_canarying / close_window_and_decide);
 * to check what's CURRENTLY active, read the periodic `canary queue:` log
 * lines and see canary_queue_init() in child-canary.c, not this table.
 *
 * Slot ordering matches pick_op_type_table[]; the _Static_assert below
 * pins ARRAY_SIZE equality between the two.
 */
static int dormant_op_disabled[141] = {
	0, 0, 0, 0, 0,
	0, 1, 1, 1, 1,
	1, 1, 1, 0, 1,
	1, 0, 0, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 0, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 0,
	1, 1,
	1, 1, 1, 1, 1, 1,
	0,	/* pagecache_canary_check stays active: it's an in-tree verifier, not a fuzz target the queue should ever demote. */
	1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1,
	0,	/* eth_emitter is lightweight (one socket per child, fixed-size sendto) — promote at startup. */
	1,	/* sysfs_string_race: dormant until canary-queue load-tests the .store() race burst. */
	1,	/* pci_bind: dormant until canary-queue load-tests the driver attach/detach path on the conservative allowlist. */
	1,	/* iscsi_login_walker: dormant until canary-queue load-tests the LIO Login state-machine walk. */
	1,	/* vma_split_storm: dormant until canary-queue load-tests the heavy VMA-split mm pressure burst. */
	1,	/* af_unix_peek_race: dormant until canary-queue load-tests the SO_PEEK_OFF + MSG_PEEK/recv/shutdown race burst. */
	1,	/* sysv_shm_orphan_race: dormant until canary-queue load-tests the SysV SHM orphan-destroy attach/RMID race burst. */
	1,	/* qrtr_bind_race: dormant until canary-queue load-tests the AF_QRTR same-port bind/close race burst. */
	1,	/* tc_mirred_blockcast: dormant until canary-queue load-tests the clsact + shared egress block + mirred blockcast recursion burst. */
	1,	/* pfkey_spd_walk: dormant until canary-queue load-tests the PF_KEYv2 SPDDUMP-vs-SPDADD walk-race burst. */
	1,	/* l2tp_ifname_race: dormant until canary-queue load-tests the L2TP SESSION_CREATE same-ifname race burst. */
	1,	/* statmount_idmap_overflow: dormant until canary-queue load-tests the statmount() idmap seq-buffer overflow sweep. */
	1,	/* sock_ulp_sockmap_layering: dormant until canary-queue load-tests the TCP_ULP "tls" + sockmap STREAM_VERDICT layering burst. */
	1,	/* umount_race: dormant until canary-queue load-tests the umount2(MNT_DETACH)-vs-accessor race against scratch_block-published mounts. */
	1,	/* ip6_udp_cork_splice: dormant until canary-queue load-tests the ip6 __ip6_append_data continuation-skb length-accounting stress path. */
	1,	/* ip_gre_churn: dormant until canary-queue load-tests the v4 gretap/ip_gre RX decap burst (userns_run_in_ns + IPPROTO_RAW hand-rolled outer IPv4/GRE/TEB frames). */
	1,	/* futex_pi_requeue_rollback: default-off; only for a targeted debugging run behind the canary queue. */
	1,	/* vlan_filter_churn: dormant until canary-queue load-tests the RTM_NEWLINK type=vlan add/del burst against a private-netns veth base (vlan_vid_add / vlan_vid_del pair). */
	1,	/* sctp_chunk_rx: dormant until canary-queue load-tests the SCTP chunk-parse RX-path burst (userns_run_in_ns + IPPROTO_RAW hand-rolled outer IPv4/SCTP frames with fuzzed INIT/INIT_ACK/COOKIE_ECHO chunk + parameter TLV lengths). */
	0,	/* pkt_builder_probe: lightweight infra prover — one raw/AF_PACKET/UDP socket per child, fixed 6-recipe stack; promote at startup so the composable layer stack keeps compiling and delivering across kernels. */
	1,	/* esp_crafted_rx: dormant until canary-queue load-tests the crafted ESP RX-decap burst (userns_run_in_ns + NETLINK_XFRM inbound null-cipher/null-auth SA install + IPPROTO_RAW hand-rolled outer IPv4/IPv6 + ESP + truncated inner frames). */
	1,	/* fou_gue_mcast_rx: dormant until canary-queue load-tests the FOU/GUE multicast crafted-RX burst (userns_run_in_ns + genl "fou" FOU_CMD_ADD install + IPPROTO_RAW hand-rolled outer IPv4/IPv6 + UDP-encap + optional GUE + truncated inner frames at mcast dst). */
	1,	/* geneve_rx: dormant until canary-queue load-tests the geneve UDP/6081 RX-decap burst (userns_run_in_ns + RTM_NEWLINK kind=geneve install + IPPROTO_RAW hand-rolled outer IPv4/UDP/GENEVE + variable-length options + truncated inner frames). */
	1,	/* netns_mountns_setup_probe: dormant until canary-queue load-tests the fresh-namespace SETUP-path burst (userns_run_in_ns + repeated CLONE_NEWNET|CLONE_NEWNS unshare + MS_PRIVATE remount + loopback rtnl bring-up + first-socket alloc). */
	1,	/* bareudp_rx: dormant until canary-queue load-tests the bareudp UDP RX-decap burst (userns_run_in_ns + RTM_NEWLINK kind=bareudp install with picked port+ethertype+multiproto + IPPROTO_RAW hand-rolled outer IPv4/UDP/inner-L3 frames against 127.0.0.1). */
	1,	/* mpls_label_stack_rx: dormant until canary-queue load-tests the MPLS label-stack crafted-RX burst (userns_run_in_ns + net.mpls.conf.lo.input=1 + AF_PACKET SOCK_RAW hand-rolled Ethernet(0x8847)/label-stack/inner-IPv4 frames at lo). */
	1,	/* deep_path_nesting: dormant until canary-queue load-tests the deeply-nested chdir/mkdir tree + proc mountinfo/maps + getcwd/readlink/statx + leaf unlink/rename readers at extreme cwd depth. */
	1,	/* espintcp_coalesce_churn: dormant until canary-queue load-tests the espintcp TCP-coalesce/page-cache reassembly RX-path burst (userns_run_in_ns + loopback TCP pair + setsockopt(TCP_ULP,"espintcp") both ends + crafted length-prefixed frames with TCP_CORK/TCP_NODELAY toggling to force skb coalescing). */
	1,	/* cred_transition_churn: dormant until canary-queue load-tests the userns_run_in_ns capset()-into-a-churned-effective-cap-subset + immediate cred-checked op (raw socket / in-ns unshare / session-keyring keyctl) + interleaved JOIN_SESSION_KEYRING / add_key / READ / REVOKE churn. */
	1,	/* netdev_netns_migrate: dormant until canary-queue load-tests the userns_run_in_ns + private-netns RTM_NEWLINK (veth/vxlan/gretap) + RTM_SETLINK IFLA_NET_NS_FD migration into a sibling userns-owned netns + in-target-ns bring-up + RTM_NEWADDR drive, with a source-ns AF_INET socket pinned as ref across the move. */
	1,	/* map_shared_stress: dormant until canary-queue load-tests the file-backed MAP_SHARED writeback / MADV_DONTFORK fork / O_APPEND-vs-mmap coherence burst. */
	1,	/* tc_live_traffic: dormant until canary-queue load-tests the private-veth clsact matchall+mirred chain with live UDP burst + mid-burst RTM_DELTFILTER/RTM_NEWTFILTER race + opportunistic XDP-pass attach. */
	1,	/* hfs_mount_fuzz: dormant until canary-queue load-tests the crafted-image HFS mount fuzzer over a scratch_block loop inside a userns_run_in_ns grandchild (image-mount lifecycle race; not safe for steady rotation). */
	1,	/* rds_zcopy_crafted_send: dormant until canary-queue load-tests the AF_RDS SO_ZEROCOPY sendmsg with a partially-mapped iovec that faults mid pin-walk (rds_message_zcopy_from_user + rds_message_purge page-refcount edge). */
	1,	/* bridge_ip6frag_refrag: dormant until canary-queue load-tests the bridge IPv6 defrag / refrag burst (userns_run_in_ns + private-netns bridge + veth + nft bridge-family ct rule + AF_PACKET IPv6-fragment injection with pre-frag extension headers and small egress MTU forcing br_ip6_fragment on the reassembled skb). */
	1,	/* bridge_ip6_refrag_fraggap: dormant until canary-queue load-tests the bridge IPv6 refrag path (userns_run_in_ns + bridge + veth + bridge-nf + nft ct + AF_PACKET hand-rolled fragmented IPv6 frames with churned HbH/DstOpt chain + short-prevhdr arm). */
	1,	/* ipset_churn: dormant until canary-queue load-tests the NFNL_SUBSYS_IPSET CREATE/ADD/DEL/TEST/SWAP/FLUSH/DESTROY cycle across hash: and bitmap: set types with TIMEOUT/COUNTERS/COMMENT extensions. */
	1,	/* ip4_udp_cork_splice: dormant until canary-queue load-tests the ip4 __ip_append_data continuation-skb length-accounting stress path. */
};

/*
 * Round-robin rotation for dedicated alt-op children.  The slow,
 * pressure-style ops are listed first (mmap_lifecycle, mprotect_split,
 * mlock_pressure, inode_spewer) because those are the paths the design
 * brief explicitly calls out as too expensive to mix into the syscall
 * hot loop even at 1%.  fork/futex/signal/pipe/flock storms come next,
 * then the cgroup/mount/uffd/io_uring churners, and finally the heavier
 * subsystem fuzzers (perf, tracefs, bpf, fault-injector, recipes).  The
 * dispatch in child_process() already has cases for every entry below,
 * so a dedicated child stamped with any of these op types runs straight
 * through the existing per-op function on every iteration.
 *
 * Bypasses the dormant_op_disabled[] gate by design: random pickers stay
 * gated until each op has been load-tested, but a child reserved for a
 * specific op runs it deliberately.
 */
static const enum child_op_type alt_op_rotation[] = {
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_VMA_SPLIT_STORM,
	CHILD_OP_MADVISE_CYCLER,
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_FORK_STORM,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_FUTEX_STORM,
	CHILD_OP_SIGNAL_STORM,
	CHILD_OP_PIPE_THRASH,
	CHILD_OP_FLOCK_THRASH,
	CHILD_OP_XATTR_THRASH,
	CHILD_OP_CGROUP_CHURN,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_IOURING_FLOOD,
	CHILD_OP_CLOSE_RACER,
	CHILD_OP_EPOLL_VOLATILITY,
	CHILD_OP_KEYRING_SPAM,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_SLAB_CACHE_THRASH,
	CHILD_OP_TLS_ROTATE,
	CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	CHILD_OP_PACKET_FANOUT_THRASH,
	CHILD_OP_ETH_EMITTER,
	CHILD_OP_PKT_BUILDER_PROBE,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SCHED_CYCLER,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_FAULT_INJECTOR,
	CHILD_OP_RECIPE_RUNNER,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_FD_STRESS,
	CHILD_OP_REFCOUNT_AUDITOR,
	CHILD_OP_FS_LIFECYCLE,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_SOCKET_FAMILY_CHAIN,
	CHILD_OP_IOURING_NET_MULTISHOT,
	CHILD_OP_TCP_AO_ROTATE,
	CHILD_OP_VRF_FIB_CHURN,
	CHILD_OP_NETLINK_MONITOR_RACE,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_TLS_ULP_CHURN,
	CHILD_OP_VXLAN_ENCAP_CHURN,
	CHILD_OP_IP_GRE_CHURN,
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_NFTABLES_CHURN,
	CHILD_OP_TC_QDISC_CHURN,
	CHILD_OP_XFRM_CHURN,
	CHILD_OP_ESP_CRAFTED_RX,
	CHILD_OP_BPF_CGROUP_ATTACH,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_SCTP_CHUNK_RX,
	CHILD_OP_MPTCP_PM_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_NAT_T_CHURN,
	CHILD_OP_SOCK_DIAG_WALKER,
	CHILD_OP_ALTNAME_THRASH,
	CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	CHILD_OP_TTY_LDISC_CHURN,
	CHILD_OP_UMOUNT_RACE,
};
#define NR_ALT_OP_ROTATION	ARRAY_SIZE(alt_op_rotation)

void assign_dedicated_alt_op(struct childdata *child, int childno)
{
	if (alt_op_children == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= alt_op_children)
		return;

	/* Canary slots are carved from the FRONT of the alt-op pool: the
	 * first canary_slots slots get the canary queue's currently-
	 * canarying op stamped here at spawn time, instead of the
	 * alt_op_rotation[] entry they would otherwise use.  The
	 * remaining alt-op slots continue with the rotation, shifted past
	 * the canary carve so the rotation walk stays stable.  When the
	 * queue is disabled (--no-canary-queue or canary_slots=0), or
	 * before the first canarying op has been selected,
	 * canary_slot_active() returns false and the rotation handles
	 * every slot from index 0 as it did pre-queue. */
	if (canary_slot_active(childno)) {
		child->op_type = canary_active_op();
		return;
	}

	unsigned int rotation_idx = (unsigned int)childno;
	if (canary_slots > 0 && rotation_idx >= canary_slots)
		rotation_idx -= canary_slots;
	child->op_type = alt_op_rotation[rotation_idx % NR_ALT_OP_ROTATION];
}

void log_alt_op_config(void)
{
	char buf[512];
	size_t off = 0;
	unsigned int i;
	unsigned int show;

	if (alt_op_children == 0)
		return;

	/* Show the head of the rotation at -v so the assignment for the
	 * first few slots is eyeballable.  Cap at 5 (or fewer if
	 * alt_op_children itself is smaller) and append an ellipsis when
	 * there are more rotation entries left. */
	show = alt_op_children < 5 ? alt_op_children : 5;
	if (show > NR_ALT_OP_ROTATION)
		show = NR_ALT_OP_ROTATION;

	for (i = 0; i < show; i++) {
		int n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
				 off ? ", " : "",
				 alt_op_name(alt_op_rotation[i]));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off)
			break;
		off += (size_t)n;
	}
	if (show < NR_ALT_OP_ROTATION && off < sizeof(buf) - 1)
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");

	output(1, "alt-op children: %u reserved, rotation = %s\n",
		alt_op_children, buf);
}

/*
 * Slot -> alt-op mapping.  Same indexing as dormant_op_disabled[]: slot N
 * is enabled iff dormant_op_disabled[N] == 0.  Slot 53 was previously a hole
 * left by a removed op; it now holds CHILD_OP_MPLS_ROUTE_CHURN.  The
 * CHILD_OP_SYSCALL sentinel filter in init_altop_dispatch() stays as
 * defensive coding for any future hole.
 */
static const enum child_op_type pick_op_type_table[141] = {
	[0]  = CHILD_OP_MMAP_LIFECYCLE,
	[1]  = CHILD_OP_MPROTECT_SPLIT,
	[2]  = CHILD_OP_MLOCK_PRESSURE,
	[3]  = CHILD_OP_INODE_SPEWER,
	[4]  = CHILD_OP_PROCFS_WRITER,
	[5]  = CHILD_OP_MEMORY_PRESSURE,
	[6]  = CHILD_OP_USERNS_FUZZER,
	[7]  = CHILD_OP_SCHED_CYCLER,
	[8]  = CHILD_OP_BARRIER_RACER,
	[9]  = CHILD_OP_GENETLINK_FUZZER,
	[10] = CHILD_OP_PERF_CHAINS,
	[11] = CHILD_OP_TRACEFS_FUZZER,
	[12] = CHILD_OP_BPF_LIFECYCLE,
	[13] = CHILD_OP_FAULT_INJECTOR,
	[14] = CHILD_OP_RECIPE_RUNNER,
	[15] = CHILD_OP_IOURING_RECIPES,
	[16] = CHILD_OP_FD_STRESS,
	[17] = CHILD_OP_REFCOUNT_AUDITOR,
	[18] = CHILD_OP_FS_LIFECYCLE,
	[19] = CHILD_OP_SIGNAL_STORM,
	[20] = CHILD_OP_FUTEX_STORM,
	[21] = CHILD_OP_PIPE_THRASH,
	[22] = CHILD_OP_FORK_STORM,
	[23] = CHILD_OP_FLOCK_THRASH,
	[24] = CHILD_OP_CGROUP_CHURN,
	[25] = CHILD_OP_MOUNT_CHURN,
	[26] = CHILD_OP_UFFD_CHURN,
	[27] = CHILD_OP_IOURING_FLOOD,
	[28] = CHILD_OP_CLOSE_RACER,
	[29] = CHILD_OP_SOCKET_FAMILY_CHAIN,
	[30] = CHILD_OP_XATTR_THRASH,
	[31] = CHILD_OP_PIDFD_STORM,
	[32] = CHILD_OP_MADVISE_CYCLER,
	[33] = CHILD_OP_EPOLL_VOLATILITY,
	[34] = CHILD_OP_KEYRING_SPAM,
	[35] = CHILD_OP_VDSO_MREMAP_RACE,
	[36] = CHILD_OP_NUMA_MIGRATION,
	[37] = CHILD_OP_CPU_HOTPLUG_RIDER,
	[38] = CHILD_OP_SLAB_CACHE_THRASH,
	[39] = CHILD_OP_TLS_ROTATE,
	[40] = CHILD_OP_PACKET_FANOUT_THRASH,
	[41] = CHILD_OP_IOURING_NET_MULTISHOT,
	[42] = CHILD_OP_TCP_AO_ROTATE,
	[43] = CHILD_OP_VRF_FIB_CHURN,
	[44] = CHILD_OP_NETLINK_MONITOR_RACE,
	[45] = CHILD_OP_TIPC_LINK_CHURN,
	[46] = CHILD_OP_TLS_ULP_CHURN,
	[47] = CHILD_OP_VXLAN_ENCAP_CHURN,
	[48] = CHILD_OP_BRIDGE_FDB_STP,
	[49] = CHILD_OP_NFTABLES_CHURN,
	[50] = CHILD_OP_TC_QDISC_CHURN,
	[51] = CHILD_OP_XFRM_CHURN,
	[52] = CHILD_OP_BPF_CGROUP_ATTACH,
	[53] = CHILD_OP_MPLS_ROUTE_CHURN,
	[54] = CHILD_OP_SCTP_ASSOC_CHURN,
	[55] = CHILD_OP_MPTCP_PM_CHURN,
	[56] = CHILD_OP_DEVLINK_PORT_CHURN,
	[57] = CHILD_OP_HANDSHAKE_REQ_ABORT,
	[58] = CHILD_OP_NF_CONNTRACK_HELPER,
	[59] = CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
	[60] = CHILD_OP_NETNS_TEARDOWN_CHURN,
	[61] = CHILD_OP_TCP_ULP_SWAP_CHURN,
	[62] = CHILD_OP_MSG_ZEROCOPY_CHURN,
	[63] = CHILD_OP_IOURING_SEND_ZC_CHURN,
	[64] = CHILD_OP_VSOCK_TRANSPORT_CHURN,
	[65] = CHILD_OP_BRIDGE_VLAN_CHURN,
	[66] = CHILD_OP_IGMP_MLD_SOURCE_CHURN,
	[67] = CHILD_OP_PSP_KEY_ROTATE,
	[68] = CHILD_OP_AFXDP_CHURN,
	[69] = CHILD_OP_KVM_RUN_CHURN,
	[70] = CHILD_OP_NL80211_CHURN,
	[71] = CHILD_OP_NAT_T_CHURN,
	[72] = CHILD_OP_SPLICE_PROTOCOLS,
	[73] = CHILD_OP_RXRPC_KEY_INSTALL,
	[74] = CHILD_OP_INPLACE_CRYPTO_ORACLE,
	[75] = CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE,
	[76] = CHILD_OP_AF_ALG_TEMPLATE_PROBE,
	[77] = CHILD_OP_IOURING_CMD_PASSTHROUGH,
	[78] = CHILD_OP_PAGECACHE_CANARY_CHECK,
	[79] = CHILD_OP_SOCK_DIAG_WALKER,
	[80] = CHILD_OP_ALTNAME_THRASH,
	[81] = CHILD_OP_IPMR_CACHE_REPORT,
	[82] = CHILD_OP_UBLK_LIFECYCLE,
	[83] = CHILD_OP_VETH_ASYMMETRIC_XDP,
	[84] = CHILD_OP_IP6ERSPAN_NETNS_MIGRATE,
	[85] = CHILD_OP_IPVS_SYSCTL_WRITER,
	[86] = CHILD_OP_TCP_MD5_LISTENER_RACE,
	[87] = CHILD_OP_IPV6_NDISC_PROXY,
	[88] = CHILD_OP_IPFRAG_SOURCE_CHURN,
	[89] = CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
	[90] = CHILD_OP_OBSCURE_AF_CHURN,
	[91] = CHILD_OP_AF_ALG_RECVMSG_CHURN,
	[92] = CHILD_OP_BRIDGE_CT_CHURN,
	[93] = CHILD_OP_ATM_VCC_CHURN,
	[94] = CHILD_OP_IP6GRE_BOND_LAPB_STACK,
	[95] = CHILD_OP_FLOWTABLE_ENCAP_VLAN,
	[96] = CHILD_OP_IPV6_PMTU_TEARDOWN_RACE,
	[97] = CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN,
	[98] = CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	[99] = CHILD_OP_TTY_LDISC_CHURN,
	[100] = CHILD_OP_WIREGUARD_DECRYPT_FLOOD,
	[101] = CHILD_OP_BLKDEV_LIFECYCLE_RACE,
	[102] = CHILD_OP_ISCSI_TARGET_PROBE,
	[103] = CHILD_OP_ETH_EMITTER,
	[104] = CHILD_OP_SYSFS_STRING_RACE,
	[105] = CHILD_OP_PCI_BIND,
	[106] = CHILD_OP_ISCSI_LOGIN_WALKER,
	[107] = CHILD_OP_VMA_SPLIT_STORM,
	[108] = CHILD_OP_AF_UNIX_PEEK_RACE,
	[109] = CHILD_OP_SYSV_SHM_ORPHAN_RACE,
	[110] = CHILD_OP_QRTR_BIND_RACE,
	[111] = CHILD_OP_TC_MIRRED_BLOCKCAST,
	[112] = CHILD_OP_PFKEY_SPD_WALK,
	[113] = CHILD_OP_L2TP_IFNAME_RACE,
	[114] = CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
	[115] = CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	[116] = CHILD_OP_UMOUNT_RACE,
	[117] = CHILD_OP_IP6_UDP_CORK_SPLICE,
	[118] = CHILD_OP_IP_GRE_CHURN,
	[119] = CHILD_OP_FUTEX_PI_REQUEUE_ROLLBACK,
	[120] = CHILD_OP_VLAN_FILTER_CHURN,
	[121] = CHILD_OP_SCTP_CHUNK_RX,
	[122] = CHILD_OP_PKT_BUILDER_PROBE,
	[123] = CHILD_OP_ESP_CRAFTED_RX,
	[124] = CHILD_OP_FOU_GUE_MCAST_RX,
	[125] = CHILD_OP_GENEVE_RX,
	[126] = CHILD_OP_NETNS_MOUNTNS_SETUP_PROBE,
	[127] = CHILD_OP_BAREUDP_RX,
	[128] = CHILD_OP_MPLS_LABEL_STACK_RX,
	[129] = CHILD_OP_DEEP_PATH_NESTING,
	[130] = CHILD_OP_ESPINTCP_COALESCE_CHURN,
	[131] = CHILD_OP_CRED_TRANSITION_CHURN,
	[132] = CHILD_OP_NETDEV_NETNS_MIGRATE,
	[133] = CHILD_OP_MAP_SHARED_STRESS,
	[134] = CHILD_OP_TC_LIVE_TRAFFIC,
	[135] = CHILD_OP_HFS_MOUNT_FUZZ,
	[136] = CHILD_OP_RDS_ZCOPY_CRAFTED_SEND,
	[137] = CHILD_OP_BRIDGE_IP6FRAG_REFRAG,
	[138] = CHILD_OP_BRIDGE_IP6_REFRAG_FRAGGAP,
	[139] = CHILD_OP_IPSET_CHURN,
	[140] = CHILD_OP_IP4_UDP_CORK_SPLICE,
};
_Static_assert(ARRAY_SIZE(pick_op_type_table) == ARRAY_SIZE(dormant_op_disabled),
	"pick_op_type_table and dormant_op_disabled must have matching slot counts");
/* One slot per non-sentinel child_op_type.  Adding a new CHILD_OP_* without
 * also adding its slot to pick_op_type_table[] (and dormant_op_disabled[])
 * leaves the op invisible to the random picker + canary queue; fail the
 * build instead of silently dropping coverage. */
_Static_assert(ARRAY_SIZE(pick_op_type_table) == NR_CHILD_OP_TYPES - 1,
	"pick_op_type_table missing a slot for a CHILD_OP_* enum value");

/*
 * Reverse of pick_op_type_table[]: given a child_op_type, find the
 * slot index in dormant_op_disabled[] whose pick_op_type_table[]
 * entry points to that op.  Returns -1 if no slot matches (slot-53
 * sentinel for CHILD_OP_SYSCALL would return -1 in current builds;
 * the canary queue never asks for that mapping).  Linear scan over
 * ~100 entries; called once per state transition, never on the hot
 * path.
 *
 * Exists so child-canary.c can flip the gate for a specific op
 * without taking a direct reference to pick_op_type_table[] / the
 * dormant_op_disabled[] storage.  Keeps both arrays file-static.
 */
int dormant_op_slot_for(enum child_op_type op)
{
	unsigned int i;

	if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
		return -1;
	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		if (pick_op_type_table[i] == op)
			return (int)i;
	}
	return -1;
}

/*
 * Mutate the dormant-op gate for `op` and rebuild the dense vector.
 * Called from the canary queue's promote / demote transitions.
 * Single store on the parent path (the parent is the sole writer);
 * children re-read the rebuilt enabled_altops[] on their next pick.
 * See the design note in init_altop_dispatch() about the deliberately
 * non-atomic rebuild -- both gate states are safe to dispatch on.
 *
 * Phase 1 propagation contract: both dormant_op_disabled[] and
 * enabled_altops[] are parent-private after fork() (COW), so the
 * "children re-read" above means children spawned AFTER this call,
 * not children already running.  Already-forked random children
 * continue to consult their fork-time snapshot until the slot turns
 * over.  Dedicated canary slots are re-stamped on respawn and so see
 * the new state immediately on the next spawn cycle.  See the header
 * block in child-canary.c for the full scope statement; the shm-
 * published variant is Phase 2 work.
 */
void dormant_op_set(enum child_op_type op, bool dormant)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return;
	dormant_op_disabled[slot] = dormant ? 1 : 0;
	init_altop_dispatch();
}

/*
 * Read-only view used by the canary queue's startup pass: it walks
 * the dormant gate to figure out which ops are already promoted
 * (gate == 0) at startup so the queue's PROMOTED state matches what
 * the dispatcher will actually pick from t=0.
 */
bool dormant_op_is_active(enum child_op_type op)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return false;
	return dormant_op_disabled[slot] == 0;
}

/*
 * Dense vector of currently-enabled alt-ops, derived from
 * dormant_op_disabled[] + pick_op_type_table[] by init_altop_dispatch().
 *
 * The previous implementation re-rolled into the full 71-slot space and
 * rejected dormant slots inline, which collapsed the EFFECTIVE altop rate
 * well below the nominal 5% (effective ≈ 5% × enabled/71).  Picking from
 * the dense vector keeps effective ≈ nominal regardless of how many slots
 * are gated off, while keeping dormant_op_disabled[] as the source of truth.
 *
 * Sized at NR_CHILD_OP_TYPES (one slot per enum value, more than enough to
 * hold every non-sentinel slot in pick_op_type_table[]).
 */
static enum child_op_type enabled_altops[NR_CHILD_OP_TYPES];
static unsigned int enabled_altop_count;

/*
 * Walk dormant_op_disabled[] + pick_op_type_table[] in parallel and
 * populate enabled_altops[] / enabled_altop_count.  Skips dormant slots
 * and the slot-53 sentinel hole.  Logs the resulting dispatch config so
 * the operator can see at -v what the effective altop mix actually is.
 *
 * Called once from main_loop before fork_children; the dormant gates
 * are compile-time constants so a single startup pass suffices.
 * dormant_op_set() re-invokes this so runtime flips stay accurate.
 */
void init_altop_dispatch(void)
{
	char buf[1024];
	size_t off = 0;
	unsigned int i;
	unsigned int count = 0;
	bool truncated = false;

	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		enum child_op_type op = pick_op_type_table[i];
		int n;

		if (dormant_op_disabled[i])
			continue;
		if (op == CHILD_OP_SYSCALL)	/* slot-53 sentinel */
			continue;

		enabled_altops[count++] = op;

		if (truncated)
			continue;

		n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
			off ? ", " : "", alt_op_name(op));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off) {
			/* Drop the partial write and stop appending --
			 * keep walking the table so enabled_altops[]
			 * still gets every non-dormant op. */
			buf[off] = '\0';
			truncated = true;
			continue;
		}
		off += (size_t)n;
	}
	if (truncated && off + sizeof(", ...") <= sizeof(buf))
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");
	enabled_altop_count = count;

	if (count == 0) {
		output(1, "altop dispatch: nominal=5%% effective=0%% (all altops dormant, falling back to syscall)\n");
		return;
	}

	output(1, "altop dispatch: nominal=5%% effective=5%% (%u enabled altops: %s)\n",
		count, buf);
}

enum child_op_type pick_op_type(void)
{
	unsigned int threshold = 95;
	unsigned int r;

	/* Phase 2 plateau intervention: when the classifier has the
	 * fleet in the childop_dominant regime (alt-op-driven edges
	 * out-running generic-syscall edges by PHC_CHILDOP_DOMINANT_
	 * RATIO), raise the non-dedicated-child alt-op share from 5%
	 * to 25% for the plateau duration.  Leans into the channel
	 * that's actually discovering edges instead of letting the
	 * 95% generic-syscall mass dilute its yield.
	 *
	 * Dedicated alt-op children (alt_op_children + canary slots)
	 * skip this picker entirely via the use_dedicated_op hoist in
	 * child_process(), so the canary queue's measurement window is
	 * untouched -- the burst only retargets the non-dedicated
	 * child pool.
	 *
	 * Gate is a derived predicate over shm->plateau_current_
	 * hypothesis (NOT a latched flag); deactivates automatically
	 * when the tick driver writes NONE on plateau clear or when
	 * the classifier transitions to a different hypothesis.
	 *
	 * The counter bump tracks predicate-active picker invocations
	 * (not picks that resolved to an alt-op).  We want to validate
	 * "did the burst predicate fire while childop_dominant was
	 * live?"; the realised alt-op yield can be cross-checked via
	 * the existing childop_invocations[] delta during plateau
	 * windows.
	 */
	if (__atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT) {
		threshold = 75;
		__atomic_fetch_add(
			&shm->stats.childop.burst_alt_picks_window,
			1UL, __ATOMIC_RELAXED);
	}

	r = rnd_modulo_u32(100);

	if (r < threshold || enabled_altop_count == 0)
		return CHILD_OP_SYSCALL;

	return enabled_altops[rnd_modulo_u32(enabled_altop_count)];
}

/*
 * Aggregated per-childop outcome record (see struct childop_outcome in
 * include/child.h for the field contract).  Snapshots existing shm
 * counters into one coherent view so downstream policy units (clean /
 * noisy scores, WOULD-DEMOTE recommendations) consume a single record
 * instead of scraping a dozen parallel arrays.
 *
 * Telemetry-only: no scheduler decision currently reads this snapshot.
 * Fields whose producer is not yet wired stay at 0 / false; the
 * subtraction-derived slots clamp at zero because the source counters
 * race under multi-producer RELAXED updates and a few childops bump
 * setup_accepted more than once per dispatch (the existing setup-yield
 * permille dump in dump_stats() clamps for the same reason).
 */
void childop_outcome_snapshot(enum child_op_type op,
			      struct childop_outcome *out)
{
	unsigned long invocations, setup_accepted, discovered, clean;

	memset(out, 0, sizeof(*out));
	out->op = op;

	if (op >= NR_CHILD_OP_TYPES)
		return;

	invocations = __atomic_load_n(&shm->stats.childop.invocations[op],
				      __ATOMIC_RELAXED);
	setup_accepted = __atomic_load_n(&shm->stats.childop.setup_accepted[op],
					 __ATOMIC_RELAXED);
	discovered = __atomic_load_n(&shm->stats.childop.edges_discovered[op],
				     __ATOMIC_RELAXED);
	clean = __atomic_load_n(&shm->stats.childop.edges_clean[op],
				__ATOMIC_RELAXED);

	out->clean_edges = clean;
	out->noisy_edges = sat_sub_ul(discovered, clean);
	out->wall_ns = __atomic_load_n(&shm->stats.childop.wall_ns[op],
				       __ATOMIC_RELAXED);
	out->wedges = (uint32_t)__atomic_load_n(
			&shm->stats.childop.wedge_count[op], __ATOMIC_RELAXED);
	out->timeout_observed = (uint32_t)__atomic_load_n(
			&shm->stats.childop.timeout_observed[op], __ATOMIC_RELAXED);
	out->timeout_missed = (uint32_t)__atomic_load_n(
			&shm->stats.childop.timeout_missed[op], __ATOMIC_RELAXED);
	out->setup_failures = (invocations > setup_accepted)
		? (uint32_t)(invocations - setup_accepted) : 0;
	out->taint_transition = __atomic_load_n(
			&shm->stats.childop.taint_transitions[op], __ATOMIC_RELAXED) > 0;
}

void childop_outcome_window_dump(void)
{
	enum child_op_type op;

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		struct childop_outcome rec;
		unsigned long invocations, latch;

		invocations = __atomic_load_n(
				&shm->stats.childop.invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		childop_outcome_snapshot(op, &rec);
		latch = __atomic_load_n(
				&shm->stats.childop.latch_reason[op],
				__ATOMIC_RELAXED);

		output(1,
		       "childop_window %s: invocations=%lu wall_ns=%lu clean_edges=%lu noisy_edges=%lu wedges=%u crashes=%u setup_failures=%u timeout_observed=%u timeout_missed=%u latch=%lu\n",
		       alt_op_name(op), invocations,
		       (unsigned long)rec.wall_ns,
		       (unsigned long)rec.clean_edges,
		       (unsigned long)rec.noisy_edges,
		       rec.wedges, rec.crashes, rec.setup_failures,
		       rec.timeout_observed, rec.timeout_missed, latch);
	}
}

/*
 * Derived utility + penalty scores from struct childop_outcome (see
 * include/child.h for the field contract), surfaced as two ranked
 * tables.  The score derivation is shadow-only: no scheduler / canary
 * picker / promotion / demotion path reads these numbers; the function
 * snapshots shm, computes, and emits via output(1, ...) -- nothing
 * else.
 *
 * clean_score = clean_edges * SCALE / wall_ns -- good-utility, i.e.
 * canary-path edges per nanosecond of wall time, scaled up by SCALE so
 * the ratio fits in an integer (edges-per-second when SCALE=1e9 and
 * wall_ns is in nanoseconds).  noisy_score is the same shape over
 * noisy_edges.  Both clamp to 0 when wall_ns is 0 (an op that has
 * never run yet).
 *
 * bad_score sums the wedge / dstate / crash / setup-failure /
 * asan-failure accumulators.  These have producers today, so the
 * bad-utility table surfaces immediately.
 *
 * Under __SANITIZE_ADDRESS__ a third "asan" table is emitted that
 * re-weights bad_score against the failure classes whose runtime cost
 * is several times higher in an ASAN build, and pairs each row with a
 * one-third wall-time budget hint (ASAN runs typically take 2-3x the
 * walltime per syscall).  Class detection reads only existing
 * childop_outcome fields, so no hardcoded childop list is needed and
 * the weighting tracks observed behaviour rather than a hand-curated
 * deny-list:
 *
 *   asan_runtime_failure         -> poisoning CHECK abort (weight x8)
 *   setup_failures > 0           -> allocator / mmap reservation fail
 *                                   against the shadow steal (x3)
 *   wedges && clean_edges == 0   -> no-return-from-sigaltstack, the
 *                                   child wedged without producing
 *                                   any canary edge (per-wedge x4)
 *
 * The non-ASAN weights for wedge / dstate / crash / setup-failure are
 * 1 / 1 / 1 / 1 (matching bad_score); the ASAN profile is strictly an
 * additive re-weight on top.  Under a non-ASAN build this entire
 * compute-and-emit block is omitted, the bad_score table is unchanged,
 * and there is no behavioural difference from before this commit.
 */
#define CHILDOP_SCORE_SCALE	1000000000ULL
#define CHILDOP_SCORE_TOPN	10

/*
 * Wall-normalized utility kill-list thresholds.  An op is flagged
 * "would_demote_utility" when its clean_score (clean_edges * SCALE /
 * wall_ns -- i.e. clean edges per wall second) sits below FLOOR and it
 * has consumed at least WALL_MIN nanoseconds of cumulative child time.
 * The two halves are needed together: the floor on its own would flag
 * ops that have barely run (a few hundred ns, no edges yet), and the
 * wall-min on its own would flag the most productive long-running ops.
 *
 * Start conservative.  FLOOR=100 captures only ops producing fewer
 * than ~100 clean edges per wall second -- well below typical altop
 * yields, so a healthy op won't appear.  WALL_MIN=5s of accumulated
 * wall time keeps newly-unblocked ops off the list until they've had
 * a fair sample.  Telemetry-only: nothing reads either macro at
 * runtime, the score dump is the sole consumer.
 */
#define CHILDOP_UTIL_FLOOR	100UL
#define CHILDOP_UTIL_WALL_MIN	5000000000ULL

#ifdef __SANITIZE_ADDRESS__
#define CHILDOP_ASAN_W_WEDGE_NOEDGE	4UL
#define CHILDOP_ASAN_W_CRASH		2UL
#define CHILDOP_ASAN_W_SETUP_FAIL	3UL
#define CHILDOP_ASAN_W_RUNTIME_FAIL	8UL
#define CHILDOP_ASAN_WALL_BUDGET_DIV	3ULL
#endif

/*
 * Row descriptor populated by score_row_compute() and consumed by
 * score_sort_desc() / score_render_top() when childop_score_dump()
 * emits its per-op ranking tables.
 */
struct score_row {
	enum child_op_type op;
	uint64_t clean_score;
	uint64_t noisy_score;
	uint64_t good_score;
	unsigned long bad_score;
	uint64_t clean_edges;
	uint64_t noisy_edges;
	uint64_t wall_ns;
	uint64_t wall_per_clean_edge;
	unsigned long long wedge_wall_us;
	unsigned int wedges;
	unsigned int dstate_wedges;
	unsigned int crashes;
	unsigned int setup_failures;
	bool asan_runtime_failure;
	bool would_demote_utility;
#ifdef __SANITIZE_ADDRESS__
	unsigned long asan_bad_score;
	uint64_t asan_wall_budget_ns;
#endif
};

static uint64_t score_key_good(const struct score_row *r) { return r->good_score; }
static uint64_t score_key_bad(const struct score_row *r) { return r->bad_score; }
static uint64_t score_key_util(const struct score_row *r) { return r->wall_per_clean_edge; }
#ifdef __SANITIZE_ADDRESS__
static uint64_t score_key_asan(const struct score_row *r) { return r->asan_bad_score; }
#endif

static void score_emit_good(const struct score_row *r)
{
	output(1,
	       "childop_score_good %s: clean_score=%lu noisy_score=%lu clean_edges=%lu noisy_edges=%lu wall_ns=%lu\n",
	       alt_op_name(r->op),
	       (unsigned long)r->clean_score,
	       (unsigned long)r->noisy_score,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->noisy_edges,
	       (unsigned long)r->wall_ns);
}

static void score_emit_bad(const struct score_row *r)
{
	output(1,
	       "childop_score_bad %s: wedges=%u dstate_wedges=%u crashes=%u setup_failures=%u asan_runtime_failure=%d total=%lu\n",
	       alt_op_name(r->op),
	       r->wedges, r->dstate_wedges,
	       r->crashes, r->setup_failures,
	       r->asan_runtime_failure ? 1 : 0,
	       r->bad_score);
}

static void score_emit_util(const struct score_row *r)
{
	output(1,
	       "childop_score_util %s: clean_score=%lu wall_per_clean_edge=%lu wedge_wall_us=%llu clean_edges=%lu wall_ns=%lu would_demote_utility=%d\n",
	       alt_op_name(r->op),
	       (unsigned long)r->clean_score,
	       (unsigned long)r->wall_per_clean_edge,
	       r->wedge_wall_us,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->wall_ns,
	       r->would_demote_utility ? 1 : 0);
}

#ifdef __SANITIZE_ADDRESS__
static void score_emit_asan(const struct score_row *r)
{
	output(1,
	       "childop_score_asan %s: wedges=%u dstate_wedges=%u crashes=%u setup_failures=%u asan_runtime_failure=%d clean_edges=%lu wall_budget_ns=%lu total=%lu\n",
	       alt_op_name(r->op),
	       r->wedges, r->dstate_wedges,
	       r->crashes, r->setup_failures,
	       r->asan_runtime_failure ? 1 : 0,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->asan_wall_budget_ns,
	       r->asan_bad_score);
}
#endif

/*
 * Snapshot one op and derive its scoring row.  Returns false when the
 * op had no invocations and the caller should skip it entirely.
 */
static bool score_row_compute(enum child_op_type op, struct score_row *r)
{
	struct childop_outcome rec;
	unsigned long invocations;

	invocations = __atomic_load_n(
			&shm->stats.childop.invocations[op],
			__ATOMIC_RELAXED);
	if (invocations == 0)
		return false;

	childop_outcome_snapshot(op, &rec);

	r->op = op;
	/* __uint128_t intermediate so a long-running op whose
	 * cumulative edge count approaches UINT64_MAX / SCALE
	 * does not overflow the multiply before the divide. */
	r->clean_score = rec.wall_ns ?
		(uint64_t)(((__uint128_t)rec.clean_edges *
			    CHILDOP_SCORE_SCALE) / rec.wall_ns) : 0;
	r->noisy_score = rec.wall_ns ?
		(uint64_t)(((__uint128_t)rec.noisy_edges *
			    CHILDOP_SCORE_SCALE) / rec.wall_ns) : 0;
	r->good_score = r->clean_score + r->noisy_score;
	r->bad_score = (unsigned long)rec.wedges + rec.dstate_wedges +
		       rec.crashes + rec.setup_failures +
		       (rec.asan_runtime_failure ? 1UL : 0UL);
	r->clean_edges = rec.clean_edges;
	r->noisy_edges = rec.noisy_edges;
	r->wall_ns = rec.wall_ns;
	/* Wall-normalized utility view.  When clean_edges == 0 the
	 * ratio is undefined, so surface the raw wall_ns instead --
	 * a "spent N ns, produced no edges at all" signal is the
	 * worst-case utility outcome and should sort to the top
	 * rather than being silently zeroed. */
	r->wall_per_clean_edge = rec.clean_edges ?
		(rec.wall_ns / rec.clean_edges) : rec.wall_ns;
	r->wedge_wall_us = __atomic_load_n(
			&shm->stats.childop.wedge_total_us[op],
			__ATOMIC_RELAXED);
	r->would_demote_utility =
		(r->clean_score < CHILDOP_UTIL_FLOOR) &&
		(rec.wall_ns >= CHILDOP_UTIL_WALL_MIN);
	r->wedges = rec.wedges;
	r->dstate_wedges = rec.dstate_wedges;
	r->crashes = rec.crashes;
	r->setup_failures = rec.setup_failures;
	r->asan_runtime_failure = rec.asan_runtime_failure;

#ifdef __SANITIZE_ADDRESS__
	{
		unsigned long wedge_w = (rec.clean_edges == 0)
			? CHILDOP_ASAN_W_WEDGE_NOEDGE : 1UL;
		r->asan_bad_score =
			(unsigned long)rec.wedges * wedge_w +
			rec.dstate_wedges +
			(unsigned long)rec.crashes *
				CHILDOP_ASAN_W_CRASH +
			(unsigned long)rec.setup_failures *
				CHILDOP_ASAN_W_SETUP_FAIL +
			(rec.asan_runtime_failure
				? CHILDOP_ASAN_W_RUNTIME_FAIL : 0UL);
		r->asan_wall_budget_ns =
			rec.wall_ns / CHILDOP_ASAN_WALL_BUDGET_DIV;
	}
#endif

	return true;
}

/*
 * Insertion sort descending by the caller-supplied key.  nrows is
 * bounded by NR_CHILD_OP_TYPES (~60), so O(n^2) is fine.
 */
static void score_sort_desc(struct score_row *rows, unsigned int nrows,
			    uint64_t (*key)(const struct score_row *))
{
	unsigned int i, j;

	for (i = 1; i < nrows; i++) {
		struct score_row tmp = rows[i];
		for (j = i; j > 0 && key(&rows[j - 1]) < key(&tmp); j--)
			rows[j] = rows[j - 1];
		rows[j] = tmp;
	}
}

/*
 * Emit up to CHILDOP_SCORE_TOPN rows via the caller-supplied emitter,
 * stopping once the key value drops to zero.  Assumes the caller has
 * already sorted rows[] descending by the same key.
 */
static void score_render_top(const struct score_row *rows, unsigned int nrows,
			     uint64_t (*key)(const struct score_row *),
			     void (*emit)(const struct score_row *))
{
	unsigned int i, n;

	n = nrows < CHILDOP_SCORE_TOPN ? nrows : CHILDOP_SCORE_TOPN;
	for (i = 0; i < n && key(&rows[i]) > 0; i++)
		emit(&rows[i]);
}

void childop_score_dump(void)
{
	struct score_row rows[NR_CHILD_OP_TYPES];
	unsigned int nrows = 0;
	enum child_op_type op;
	bool any_good = false, any_bad = false, any_util = false;
#ifdef __SANITIZE_ADDRESS__
	bool any_asan = false;
#endif

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		struct score_row *r = &rows[nrows];

		if (!score_row_compute(op, r))
			continue;
		nrows++;

		if (r->good_score > 0)
			any_good = true;
		if (r->bad_score > 0)
			any_bad = true;
		if (r->wall_per_clean_edge > 0)
			any_util = true;
#ifdef __SANITIZE_ADDRESS__
		if (r->asan_bad_score > 0)
			any_asan = true;
#endif
	}

	if (nrows == 0)
		return;

	if (any_good) {
		score_sort_desc(rows, nrows, score_key_good);
		score_render_top(rows, nrows, score_key_good, score_emit_good);
	}

	if (any_bad) {
		score_sort_desc(rows, nrows, score_key_bad);
		score_render_top(rows, nrows, score_key_bad, score_emit_bad);
	}

	/*
	 * Wall-normalized utility table.  Ranks ops by ns spent per
	 * clean edge produced (descending) so the least-productive
	 * consumers of child wall time -- typically the wedge-prone
	 * stress ops -- surface at the top.  would_demote_utility flags
	 * the rows that meet both the floor and wall-min thresholds; it
	 * is informational, no demote actually fires.
	 */
	if (any_util) {
		score_sort_desc(rows, nrows, score_key_util);
		score_render_top(rows, nrows, score_key_util, score_emit_util);
	}

#ifdef __SANITIZE_ADDRESS__
	if (any_asan) {
		score_sort_desc(rows, nrows, score_key_asan);
		score_render_top(rows, nrows, score_key_asan, score_emit_asan);
	}
#endif
}

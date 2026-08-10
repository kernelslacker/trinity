#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "child-api.h"	/* NR_CHILD_OP_TYPES */
#include "compiler.h"	/* __cold */
#include "cred_throttle.h"	/* CRED_CLASS_NR */
#include "reach-band.h"	/* REACH_BAND_NR */
#include "sequence.h"	/* CHAIN_RESTYPE_NR */
#include "strategy.h"	/* NR_STRATEGIES */
#include "syscall.h"	/* MAX_NR_SYSCALL */

#include "kernel/mman.h"
#include "kernel/netlink.h"
#include "kernel/socket.h"
#include "kernel/in.h"
#include "kernel/sctp.h"
#include "kernel/mptcp.h"
#include "kernel/udp.h"
#include "kernel/if_packet.h"
#include "kernel/mount.h"
#include "stats/subsys/accept_unblocker.h"
#include "stats/subsys/af_alg_probe.h"
#include "stats/subsys/af_alg_recvmsg.h"
#include "stats/subsys/af_alg_weak_cipher_probe.h"
#include "stats/subsys/af_unix_peek_race.h"
#include "stats/subsys/af_unix_scm_rights_gc.h"
#include "stats/subsys/afxdp_churn.h"
#include "stats/subsys/aio.h"
#include "stats/subsys/altname_thrash.h"
#include "stats/subsys/arg.h"
#include "stats/subsys/atm_vcc_churn.h"
#include "stats/subsys/bareudp_rx.h"
#include "stats/subsys/barrier_racer.h"
#include "stats/subsys/blkdev_lifecycle.h"
#include "stats/subsys/blob.h"
#include "stats/subsys/blob_ab.h"
#include "stats/subsys/bpf_cgroup_attach.h"
#include "stats/subsys/bpf_lifecycle.h"
#include "stats/subsys/bridge_ct.h"
#include "stats/subsys/bridge_fdb_stp.h"
#include "stats/subsys/bridge_ip6_refrag_fraggap.h"
#include "stats/subsys/bridge_ip6frag.h"
#include "stats/subsys/bridge_vlan_churn.h"
#include "stats/subsys/cgroup_churn.h"
#include "stats/subsys/chain_corpus.h"
#include "stats/subsys/chain_restype.h"
#include "stats/subsys/childop.h"
#include "stats/subsys/close_racer.h"
#include "stats/subsys/cmp_frontier.h"
#include "stats/subsys/context_suppress.h"
#include "stats/subsys/cost_pool_selector.h"
#include "stats/subsys/cold_overflow.h"
#include "stats/subsys/corrupt_ptr.h"
#include "stats/subsys/cpu_hotplug.h"
#include "stats/subsys/cred_class.h"
#include "stats/subsys/cred_transition.h"
#include "stats/subsys/deep_path.h"
#include "stats/subsys/deferred_free.h"
#include "stats/subsys/diag.h"
#include "stats/subsys/devlink_port_churn.h"
#include "stats/subsys/divergence_sentinel.h"
#include "stats/subsys/epoll_volatility.h"
#include "stats/subsys/epoll_nest_race.h"
#include "stats/subsys/errno_gradient.h"
#include "stats/subsys/esp_crafted_rx.h"
#include "stats/subsys/espintcp_coalesce.h"
#include "stats/subsys/eth_emitter.h"
#include "stats/subsys/ebpf_gen.h"
#include "stats/subsys/expensive_adaptive.h"
#include "stats/subsys/fd.h"
#include "stats/subsys/fd_runtime.h"
#include "stats/subsys/fdstress.h"
#include "stats/subsys/flock_thrash.h"
#include "stats/subsys/flowtable_vlan.h"
#include "stats/subsys/fnhe_pmtu_mtu_race.h"
#include "stats/subsys/fork_storm.h"
#include "stats/subsys/fou_gue_mcast_rx.h"
#include "stats/subsys/frontier.h"
#include "stats/subsys/fs_lifecycle.h"
#include "stats/subsys/futex_pi_requeue_rollback.h"
#include "stats/subsys/futex_storm.h"
#include "stats/subsys/genetlink_fuzzer.h"
#include "stats/subsys/geneve_rx.h"
#include "stats/subsys/handshake_req_abort.h"
#include "stats/subsys/hfs_mount_fuzz.h"
#include "stats/subsys/icmp_inject.h"
#include "stats/subsys/igmp_mld_source_churn.h"
#include "stats/subsys/inet_listener_rehash_race.h"
#include "stats/subsys/inplace_crypto.h"
#include "stats/subsys/iouring.h"
#include "stats/subsys/iouring_eventfd.h"
#include "stats/subsys/iouring_net_multishot.h"
#include "stats/subsys/iouring_recipes.h"
#include "stats/subsys/iouring_send_zc_churn.h"
#include "stats/subsys/kvm.h"
#include "stats/subsys/ipfrag_source_churn.h"
#include "stats/subsys/ipmr_cache_report.h"
#include "stats/subsys/ipmr_getroute_pktinfo.h"
#include "stats/subsys/ip6mr_churn.h"
#include "stats/subsys/ip4_udp_cork_splice.h"
#include "stats/subsys/ip6_udp_cork_splice.h"
#include "stats/subsys/ip6erspan_netns_migrate.h"
#include "stats/subsys/ip6gre_lapb.h"
#include "stats/subsys/ip_gre_churn.h"
#include "stats/subsys/ipset_churn.h"
#include "stats/subsys/ipv6_ndisc_proxy.h"
#include "stats/subsys/ipv6_pmtu_race.h"
#include "stats/subsys/ipvs_sysctl_writer.h"
#include "stats/subsys/iscsi_target_probe.h"
#include "stats/subsys/iscsi_walker.h"
#include "stats/subsys/keyring_spam.h"
#include "stats/subsys/l2tp_ifname_race.h"
#include "stats/subsys/madvise_cycler.h"
#include "stats/subsys/map_shared_stress.h"
#include "stats/subsys/maps.h"
#include "stats/subsys/memory_pressure.h"
#include "stats/subsys/minicorpus.h"
#include "stats/subsys/mount_churn.h"
#include "stats/subsys/memfd_secret_lifecycle.h"
#include "stats/subsys/mremap_merge_matrix.h"
#include "stats/subsys/nat_t_churn.h"
#include "stats/subsys/mpls_label_stack_rx.h"
#include "stats/subsys/mpls_route_churn.h"
#include "stats/subsys/mptcp_pm_churn.h"
#include "stats/subsys/msg_zerocopy_churn.h"
#include "stats/subsys/netdev_netns_migrate.h"
#include "stats/subsys/nexthop_replace_churn.h"
#include "stats/subsys/netlink_monitor_race.h"
#include "stats/subsys/netns_mountns_setup.h"
#include "stats/subsys/netns_teardown.h"
#include "stats/subsys/ct_expect_realloc.h"
#include "stats/subsys/nf_conntrack_helper_churn.h"
#include "stats/subsys/nl80211.h"
#include "stats/subsys/nftables_churn.h"
#include "stats/subsys/no_domains.h"
#include "stats/subsys/numa_migration.h"
#include "stats/subsys/obscure_af_churn.h"
#include "stats/subsys/oracle.h"
#include "stats/subsys/packet_fanout_thrash.h"
#include "stats/subsys/packet_qdisc_bypass_unanchored_l2.h"
#include "stats/subsys/ovs_tunnel_vport_churn.h"
#include "stats/subsys/pci_bind.h"
#include "stats/subsys/pc_edge_source.h"
#include "stats/subsys/perf_chains.h"
#include "stats/subsys/pfkey_spd_walk.h"
#include "stats/subsys/pidfd_storm.h"
#include "stats/subsys/process_mrelease_race.h"
#include "stats/subsys/pipe_thrash.h"
#include "stats/subsys/picker_bandit.h"
#include "stats/subsys/pipe_waker.h"
#include "stats/subsys/plateau.h"
#include "stats/subsys/pkt_builder.h"
#include "stats/subsys/procfs_writer.h"
#include "stats/subsys/psp_key_rotate.h"
#include "stats/subsys/qrtr_bind_race.h"
#include "stats/subsys/rds_bind_transport_refleak.h"
#include "stats/subsys/rds_zcopy_crafted_send.h"
#include "stats/subsys/recipe.h"
#include "stats/subsys/remote_adaptive.h"
#include "stats/subsys/refcount_audit.h"
#include "stats/subsys/rpl_clone_fidelity.h"
#include "stats/subsys/rtnl-ack-oracle.h"
#include "stats/subsys/rtnl_vf_broadcast.h"
#include "stats/subsys/netconf_inetdev_race.h"
#include "stats/subsys/rxrpc_key_install.h"
#include "stats/subsys/rxrpc_sendmsg_cmsg.h"
#include "stats/subsys/sched_cycler.h"
#include "stats/subsys/sctp_assoc_churn.h"
#include "stats/subsys/sctp_chunk_rx.h"
#include "stats/subsys/setsockopt_pairing.h"
#include "stats/subsys/signal_storm.h"
#include "stats/subsys/slab_cache_thrash.h"
#include "stats/subsys/sock_diag_walker.h"
#include "stats/subsys/sock_ulp_sockmap_layering.h"
#include "stats/subsys/socket_family_chain.h"
#include "stats/subsys/socket_family_grammar.h"
#include "stats/subsys/sockmap_cork_race.h"
#include "stats/subsys/splice_protocols.h"
#include "stats/subsys/statmount_idmap.h"
#include "stats/subsys/syscall_wedge.h"
#include "stats/subsys/sysfs_string_race.h"
#include "stats/subsys/syscall_dispatch.h"
#include "stats/subsys/sysv_shm_orphan_race.h"
#include "stats/subsys/tc_live_traffic.h"
#include "stats/subsys/tc_mirred_blockcast.h"
#include "stats/subsys/tc_qdisc_churn.h"
#include "stats/subsys/tcp_ao_rotate.h"
#include "stats/subsys/tcp_md5_listener_race.h"
#include "stats/subsys/tcp_ulp_swap_churn.h"
#include "stats/subsys/tipc_link_churn.h"
#include "stats/subsys/tls_rotate.h"
#include "stats/subsys/tls_ulp_churn.h"
#include "stats/subsys/topo_pair.h"
#include "stats/subsys/tracefs_fuzzer.h"
#include "stats/subsys/transition_edge.h"
#include "stats/subsys/tty_ldisc_churn.h"
#include "stats/subsys/ublk_lifecycle.h"
#include "stats/subsys/uffd.h"
#include "stats/subsys/thp_split_ref_race.h"
#include "stats/subsys/uffd_fault_move.h"
#include "stats/subsys/uid_change.h"
#include "stats/subsys/umount_race.h"
#include "stats/subsys/userns_bootstrap.h"
#include "stats/subsys/userns_fuzzer.h"
#include "stats/subsys/ipcns_ucount_exhaustion.h"
#include "stats/subsys/vdso_race.h"
#include "stats/subsys/veth_asymmetric_xdp.h"
#include "stats/subsys/vlan_filter_churn.h"
#include "stats/subsys/vrf_fib_churn.h"
#include "stats/subsys/vsock_transport_churn.h"
#include "stats/subsys/vxlan_encap_churn.h"
#include "stats/subsys/watchdog_signal.h"
#include "stats/subsys/wgdf.h"
#include "stats/subsys/xattr_thrash.h"
#include "stats/subsys/xfrm_ah_esn.h"
#include "stats/subsys/xfrm_churn.h"
#include "stats/subsys/xfrm_compat.h"
#include "stats/subsys/zombie_reaper.h"
/*
 * Adaptive-budget tunables for childop_budget_mult[] / adapt_budget().
 * Q8.8 fixed point: 256 == 1.0x.  Floor and ceiling cap how far the
 * runtime feedback loop can shift any one op away from its hard-coded
 * MAX_ITERATIONS / BUDGET_NS — at the floor a 64-iter op still runs 16
 * iters per invocation, at the ceiling it runs 256.
 */
#define ADAPT_BUDGET_UNITY	256	/* 1.0x */
#define ADAPT_BUDGET_MIN	64	/* 0.25x */
#define ADAPT_BUDGET_MAX	1024	/* 4.0x */

/*
 * SHADOW-ONLY topology-pair packed-entry helpers.  Ring sizing +
 * layout live in stats/subsys/topo_pair.h; the packed-entry field
 * semantics are documented on struct topo_pair_stats::ring[].
 *
 * TOPO_PAIR_REASON_PC / _TRANSITION are the two values written by the
 * frontier_record_new_edge() / _transition_edge() producers; 0 is
 * reserved for the uninitialised slot state so a half-populated ring
 * can be distinguished from a recorded zero.
 *
 * TOPO_PAIR_AGE_MAX is the saturating upper bound on the
 * age_in_syscalls field -- any older setup is clamped at this value so
 * the 20-bit width is never overflowed.  At ~1k syscalls/sec/child this
 * caps the visible age window at ~17 minutes per child, which is well
 * past the point where a setup's effect is interesting.
 */

#define TOPO_PAIR_REASON_PC		1u
#define TOPO_PAIR_REASON_TRANSITION	2u

#define TOPO_PAIR_AGE_MAX		((1u << 20) - 1u)

/*
 * Packed-entry storage is uint64_t, not unsigned long, so 32-bit
 * trinity builds (where unsigned long is 32 bits) still carry the full
 * setup_op / reason / syscall_nr / age / valid layout below.  All
 * single-store / single-load atomic accesses to the ring slot operate
 * on uint64_t for the same reason -- a 32-bit __atomic_store_n on
 * unsigned long would truncate everything above bit 31.
 */
static inline uint64_t topo_pair_pack(unsigned int setup_op,
				      unsigned int reason,
				      unsigned int syscall_nr,
				      unsigned int age)
{
	uint64_t e = 0;

	if (age > TOPO_PAIR_AGE_MAX)
		age = TOPO_PAIR_AGE_MAX;
	if (syscall_nr > 0xffffu)
		syscall_nr = 0xffffu;
	e |= (uint64_t)(setup_op & 0xffu);
	e |= (uint64_t)(reason & 0x3u) << 8;
	e |= (uint64_t)(syscall_nr & 0xffffu) << 10;
	e |= (uint64_t)(age & TOPO_PAIR_AGE_MAX) << 26;
	e |= (uint64_t)1 << 46;
	return e;
}

static inline bool topo_pair_unpack(uint64_t e,
				    unsigned int *setup_op,
				    unsigned int *reason,
				    unsigned int *syscall_nr,
				    unsigned int *age)
{
	if (((e >> 46) & (uint64_t)1) == 0)
		return false;
	*setup_op = (unsigned int)(e & (uint64_t)0xff);
	*reason = (unsigned int)((e >> 8) & (uint64_t)0x3);
	*syscall_nr = (unsigned int)((e >> 10) & (uint64_t)0xffff);
	*age = (unsigned int)((e >> 26) & (uint64_t)TOPO_PAIR_AGE_MAX);
	return true;
}

/*
 * Edge-delta floor that classifies an invocation as productive.  Reads
 * the GLOBAL kcov_shm->coverage.edges_found counter, so a fleet running with N
 * children adds baseline noise on every dispatch — the threshold has to
 * sit clear of the noise floor or every op gets boosted just by being
 * invoked while siblings are productive.  16 is calibrated for the
 * default fleet size; for very large fleets the noise floor may rise
 * above this value and the boost ratchet effectively stalls (which is
 * the safer failure mode — multipliers stay near 1.0x and behaviour
 * matches the fixed budgets used before adaptive budget multipliers).
 */
#define ADAPT_BUDGET_THRESHOLD	16

/*
 * Consecutive sub-threshold invocations required before the shrink
 * ratchet fires.  Hysteresis: a single noisy zero-delta invocation in
 * the middle of a productive streak should not halve the budget.
 */
#define ADAPT_BUDGET_ZERO_STREAK	4

/* MAX_RECIPES lives in stats/subsys/recipe.h (used by struct
 * recipe_stats::completed_per[]).
 * MAX_IOURING_RECIPES lives in stats/subsys/iouring_recipes.h (used by
 * struct iouring_recipes_stats::completed_per[]). */

/* Coarse syscall categories used by the dispatch-time histogram.  Order
 * is also the dump order; SYSCAT_OTHER is the catch-all for anything not
 * matched by the prefix table in stats/dump/syscall.c. */
enum syscall_category {
	SYSCAT_READ = 0,
	SYSCAT_WRITE,
	SYSCAT_OPEN,
	SYSCAT_MMAP,
	SYSCAT_SOCKET,
	SYSCAT_PROCESS,
	SYSCAT_FILE,
	SYSCAT_IPC,
	SYSCAT_OTHER,
	NR_SYSCAT,
};

/* Various statistics.
 *
 * Fields are grouped by access pattern with cacheline padding between
 * groups so that one child's writes to a low-frequency counter do not
 * invalidate the cacheline a sibling is bumping for op_count on every
 * syscall.  At 32 children all incrementing different fields packed
 * into the same cacheline the resulting MESI traffic absorbs a large
 * fraction of fleet syscall throughput; reshaping into the four groups
 * below isolates the hot fast path from the rare-condition counters
 * and the per-childop / parent-side bookkeeping.
 *
 * Group A (hot per-syscall): bumped on every syscall by every child.
 *   Kept first so it lands on the cacheline shm_s already aligns
 *   stats to.  Deliberately small — successive counters a child
 *   touches in a single dispatch_step() should ideally hit the same
 *   line on that child's L1 even if siblings invalidate it.
 *
 * Group B (per-syscall but rare-condition): on the syscall path but
 *   only bumped when an oracle anomaly fires or a corrupted pointer
 *   is detected — most syscalls touch nothing in this group.
 *
 * Group C (per-childop): bumped per childop invocation, which is
 *   orders of magnitude less frequent than per-syscall.
 *
 * Group D (diagnostic / startup / parent-side / one-shot): mostly
 *   parent-bumped or written rarely; kept apart so child writes in
 *   groups A-C never invalidate the parent's line and vice versa.
 */

struct stats_s {
	/* ---- Group B: per-syscall, rare-condition ---- */

	/* post-syscall oracle anomaly counts.  See stats/subsys/oracle.h. */
	struct oracle_stats oracle __attribute__((aligned(64)));

	/* check_output_struct() in a post handler saw the ARG_STRUCT_PTR_OUT
	 * buffer still byte-for-byte equal to the poison pattern that
	 * poison_output_struct() stamped at sanitise time, on a syscall that
	 * returned success.  Means the kernel claimed the call worked without
	 * copying any output into the user buffer.  Distinct from the
	 * per-syscall oracle anomaly counters: those re-issue the syscall
	 * and compare field by field, this catches the strict "zero bytes
	 * written" subset cheaply without a re-entry into the kernel.
	 * Wired into newfstat for now; treewide rollout to the other
	 * ARG_STRUCT_PTR_OUT consumers is a follow-up. */
	unsigned long post_handler_untouched_out_buf;

	/* post_handler_corrupt_ptr / validator_rejected /
	 * deferred_free_reject live in struct stats_aggregate
	 * (parent-private) and are bumped via the per-child stats_ring.
	 * Their per-handler / per-callsite shards live in each child's
	 * struct childdata.  See include/stats_ring.h and include/child.h.
	 * validator_rejected has its own counter separate from
	 * post_handler_corrupt_ptr so the scribble-catch headline counts
	 * only post-dispatch scribbles, not pre-dispatch structural
	 * coupling rejects (DOA (buf,count) shapes the kernel would
	 * EFAULT on). */

	/* uid-change accounting.  See stats/subsys/uid_change.h. */
	struct uid_change_stats uid_change __attribute__((aligned(64)));

	/* corrupt-pointer instrumentation.  See stats/subsys/corrupt_ptr.h. */
	struct corrupt_ptr_stats corrupt_ptr __attribute__((aligned(64)));

	/* snapshot_non_heap_reject / ring_eviction_corrupt /
	 * deferred_free_corrupt_ptr live in struct stats_aggregate
	 * (parent-private) and are bumped via the per-child stats_ring.
	 * See include/stats_ring.h. */

	/* divergence-sentinel per-field accounting.  See stats/subsys/divergence_sentinel.h. */
	struct divergence_sentinel_stats divergence_sentinel __attribute__((aligned(64)));

	/* Per-childop accounting -- edge / call / setup / data-path /
	 * latch / demote-promote / budget / wedge / wall-time /
	 * fd-delta / decay-recency arrays plus scattered scalars and the
	 * taint-transition / pool-race-abort per-op counters.
	 * See stats/subsys/childop.h. */
	struct childop_stats childop __attribute__((aligned(64)));

	/* ---- Group C: per-childop ---- */

	/* procfs_writer accounting.  See stats/subsys/procfs_writer.h. */
	struct procfs_writer_stats procfs_writer __attribute__((aligned(64)));

	/* memory_pressure accounting.  See stats/subsys/memory_pressure.h. */
	struct memory_pressure_stats memory_pressure;

	/* sched_cycler accounting.  See stats/subsys/sched_cycler.h. */
	struct sched_cycler_stats sched_cycler __attribute__((aligned(64)));

	/* userns_fuzzer accounting.  See stats/subsys/userns_fuzzer.h. */
	struct userns_fuzzer_stats userns_fuzzer __attribute__((aligned(64)));

	/* ipcns_ucount_exhaustion accounting.
	 * See stats/subsys/ipcns_ucount_exhaustion.h. */
	struct ipcns_ucount_exhaustion_stats ipcns_ucount_exhaustion __attribute__((aligned(64)));

	/* barrier_racer accounting.  See stats/subsys/barrier_racer.h. */
	struct barrier_racer_stats barrier_racer __attribute__((aligned(64)));

	/* genetlink_fuzzer accounting.  See stats/subsys/genetlink_fuzzer.h. */
	struct genetlink_fuzzer_stats genetlink_fuzzer __attribute__((aligned(64)));

	/* netlink message generator: NLA_F_NESTED containers emitted/accepted.
	 * netlink_nested_attrs_emitted is bumped for every nested-attr
	 * container written into the message buffer, regardless of whether
	 * the kernel accepts the message.  netlink_nested_attrs_accepted is
	 * bumped by the rtnl ACK oracle each time a sampled NETLINK_ROUTE
	 * message returns a positive ACK (err->error == 0).  If accepted <<
	 * emitted the kernel is silently discarding most of the nested-attr
	 * traffic.  See net/netlink/rtnl-ack-oracle.c for oracle details. */
	unsigned long netlink_nested_attrs_emitted;
	unsigned long netlink_nested_attrs_accepted;
	/* build_nested_attrs: exact-width attr skipped because buffer clamp
	 * would have truncated it to fewer bytes than aw->width requires.
	 * A persistent non-zero rate with a low netlink_nested_attr_built_width
	 * rate indicates that the msg buffer is too tight to fit most of the
	 * attr table's widths, shrinking effective nested coverage.
	 * Skip ratio: skipped / (skipped + netlink_nested_attr_built_width). */
	unsigned long netlink_nested_attr_skipped_width;
	/* build_nested_attrs: exact-width pick successfully written (the
	 * denominator paired with netlink_nested_attr_skipped_width).
	 * Bumped only for exact_width==true picks on the offset+=total path,
	 * once per attribute written.  Fault-injection picks (1/32, random
	 * width) are excluded so that both skipped and built draw from the
	 * same exact-width population.
	 * Skip ratio = skipped / (skipped + built); a ratio near 1.0 means
	 * the buffer is too small to accommodate most of the attr table. */
	unsigned long netlink_nested_attr_built_width;
	/* build_nested_attrs: number of calls whose attr loop was reachable
	 * (`offset + NLA_HDRLEN + 1 <= buflen`); calls too small to emit or
	 * truncate an attr are excluded so they do not dilute the ratio.
	 * One count per nested-attr container that entered the loop.
	 * This is the per-container denominator for
	 * netlink_nested_attr_lost_align; skipped_width and built_width are
	 * per-attr and must NOT be used as denominators for lost_align.
	 * Truncation rate (per container) = lost_align / build_calls. */
	unsigned long netlink_nested_attr_build_calls;
	/* build_nested_attrs: attrs whose NLA_ALIGN(NLA_HDRLEN+payload_len)
	 * total exceeded the remaining buffer space after all clamping and
	 * skip-on-clamp logic ran.  The loop breaks here, so this counter
	 * advances at most once per build_nested_attrs() call — it is a
	 * per-container counter, not per-attr; use build_calls as denominator.
	 * Truncation rate (per container) = lost_align / netlink_nested_attr_build_calls. */
	unsigned long netlink_nested_attr_lost_align;

	/* rtnl ACK oracle: per-outcome histogram + per-RTM-group accepted
	 * counters.  See stats/subsys/rtnl-ack-oracle.h for field details.
	 * Populated by rtnl_oracle_drain() on 1-in-32 sampled messages. */
	struct rtnl_ack_oracle_stats rtnl_ack_oracle __attribute__((aligned(64)));

	/* setsockopt pairing accounting.  See stats/subsys/setsockopt_pairing.h. */
	struct setsockopt_pairing_stats setsockopt_pairing __attribute__((aligned(64)));

	/* genetlink registry per-family dispatch counters.  Bumped from
	 * gen_genl_body() each time the spec-driven dispatcher routes a
	 * message to a registered family — distinct from the
	 * genetlink_fuzzer childop counters above (which only see the
	 * dedicated discovery childop).  Diagnostic-only: reading a non-
	 * zero count at run end confirms two things at once -- the
	 * controller dump resolved the family ID, and at least one
	 * NETLINK_GENERIC syscall picked that family during dispatch.  A
	 * zero value when the family is known to be loaded narrows the
	 * miss to either the resolver (no CTRL response) or the picker
	 * (genl_pick_resolved_family never selected this slot during the
	 * run window).  Per family in the registry; ifdef'd ones share
	 * the gate of their family file. */
	unsigned long genl_family_calls_devlink;
	unsigned long genl_family_calls_nl80211;
	unsigned long genl_family_calls_taskstats;
	unsigned long genl_family_calls_ethtool;
	unsigned long genl_family_calls_mptcp_pm;
	unsigned long genl_family_calls_tipc;
	unsigned long genl_family_calls_wireguard;
	unsigned long genl_family_calls_l2tp;
	unsigned long genl_family_calls_gtp;
	unsigned long genl_family_calls_macsec;
	/* Bundled counter for the four NetLabel families (CALIPSO,
	 * CIPSOv4, UNLBL, MGMT) — they all dispatch into the same LSM
	 * hook chain on the kernel side, so a single end-of-run row
	 * captures total NetLabel traffic without splitting four ways. */
	unsigned long genl_family_calls_netlabel;
	unsigned long genl_family_calls_team;
	unsigned long genl_family_calls_hsr;
	unsigned long genl_family_calls_fou;
	unsigned long genl_family_calls_psample;
	unsigned long genl_family_calls_ncsi;
	unsigned long genl_family_calls_tcmu;
	unsigned long genl_family_calls_nfsd;
	unsigned long genl_family_calls_ila;
	unsigned long genl_family_calls_ioam6;
	unsigned long genl_family_calls_seg6;
	unsigned long genl_family_calls_thermal;
	unsigned long genl_family_calls_ipvs;

	/* nfnetlink registry per-subsystem dispatch counters.  Same shape
	 * as the genl_family_calls counters above but for NETLINK_NETFILTER
	 * subsystems.  Bumped from gen_nfnl_body() each time the message
	 * generator routes an nfnetlink message at a registered subsys —
	 * a non-zero count at run end confirms both that the type picker
	 * landed on the subsys and that the body generator routed through
	 * the spec-driven path.  Per subsys in the registry; the
	 * ctnetlink/ctnetlink_exp pair share a CTA_* attr namespace but
	 * each carries its own counter so the EXP traffic split is
	 * visible. */
	unsigned long nfnl_subsys_calls_ctnetlink;
	unsigned long nfnl_subsys_calls_ctnetlink_exp;
	unsigned long nfnl_subsys_calls_nftables;
	unsigned long nfnl_subsys_calls_ipset;

	/* perf_event_chains accounting.  See stats/subsys/perf_chains.h. */
	struct perf_chains_stats perf_chains __attribute__((aligned(64)));

	/* tracefs_fuzzer accounting.  See stats/subsys/tracefs_fuzzer.h. */
	struct tracefs_fuzzer_stats tracefs_fuzzer __attribute__((aligned(64)));

	/* bpf_lifecycle accounting.  See stats/subsys/bpf_lifecycle.h. */
	struct bpf_lifecycle_stats bpf_lifecycle __attribute__((aligned(64)));

	/* recipe_runner accounting.  See stats/subsys/recipe.h. */
	struct recipe_stats recipe __attribute__((aligned(64)));

	/* fdstress accounting.  See stats/subsys/fdstress.h. */
	struct fdstress_stats fdstress __attribute__((aligned(64)));

	/* iouring_recipes accounting.  See stats/subsys/iouring_recipes.h. */
	struct iouring_recipes_stats iouring_recipes __attribute__((aligned(64)));

	/* iouring_eventfd accounting.  See stats/subsys/iouring_eventfd.h. */
	struct iouring_eventfd_stats iouring_eventfd __attribute__((aligned(64)));

	/* aio submission counter.  See stats/subsys/aio.h. */
	struct aio_stats aio __attribute__((aligned(64)));

	/* refcount_audit accounting.  See stats/subsys/refcount_audit.h. */
	struct refcount_audit_stats refcount_audit __attribute__((aligned(64)));

	/* fs_lifecycle accounting.  See stats/subsys/fs_lifecycle.h. */
	struct fs_lifecycle_stats fs_lifecycle __attribute__((aligned(64)));

	/* signal_storm childop counters.  See stats/subsys/signal_storm.h. */
	struct signal_storm_stats signal_storm __attribute__((aligned(64)));

	/* futex_storm childop counters.  See stats/subsys/futex_storm.h. */
	struct futex_storm_stats futex_storm __attribute__((aligned(64)));

	/* futex_pi_requeue_rollback childop counters.
	 * See stats/subsys/futex_pi_requeue_rollback.h. */
	struct futex_pi_requeue_rollback_stats futex_pi_requeue_rollback __attribute__((aligned(64)));

	/* pipe_thrash childop counters.  See stats/subsys/pipe_thrash.h. */
	struct pipe_thrash_stats pipe_thrash __attribute__((aligned(64)));

	/* flock_thrash childop counters.  See stats/subsys/flock_thrash.h. */
	struct flock_thrash_stats flock_thrash __attribute__((aligned(64)));

	/* xattr_thrash childop counters.  See stats/subsys/xattr_thrash.h. */
	struct xattr_thrash_stats xattr_thrash __attribute__((aligned(64)));

	/* epoll_volatility childop counters.  See stats/subsys/epoll_volatility.h. */
	struct epoll_volatility_stats epoll_volatility __attribute__((aligned(64)));

	/* epoll_nest_race childop counters.  See stats/subsys/epoll_nest_race.h. */
	struct epoll_nest_race_stats epoll_nest_race __attribute__((aligned(64)));

	/* cgroup_churn accounting.  See stats/subsys/cgroup_churn.h. */
	struct cgroup_churn_stats cgroup_churn __attribute__((aligned(64)));

	/* mount_churn childop counters.  See stats/subsys/mount_churn.h. */
	struct mount_churn_stats mount_churn __attribute__((aligned(64)));

	/* umount_race accounting.  See stats/subsys/umount_race.h. */
	struct umount_race_stats umount_race __attribute__((aligned(64)));

	/* fork_storm childop counters.  See stats/subsys/fork_storm.h. */
	struct fork_storm_stats fork_storm __attribute__((aligned(64)));

	/* pidfd_storm accounting.  See stats/subsys/pidfd_storm.h. */
	struct pidfd_storm_stats pidfd_storm __attribute__((aligned(64)));

	/* process_mrelease_race accounting.  See stats/subsys/process_mrelease_race.h. */
	struct process_mrelease_race_stats process_mrelease_race __attribute__((aligned(64)));

	/* madvise_cycler childop counters.  See stats/subsys/madvise_cycler.h. */
	struct madvise_cycler_stats madvise_cycler __attribute__((aligned(64)));

	/* keyring_spam childop counters.  See stats/subsys/keyring_spam.h. */
	struct keyring_spam_stats keyring_spam __attribute__((aligned(64)));

	/* vdso_mremap_race accounting.  See stats/subsys/vdso_race.h. */
	struct vdso_race_stats vdso_race __attribute__((aligned(64)));

	/* numa_migration accounting.  See stats/subsys/numa_migration.h. */
	struct numa_migration_stats numa_migration __attribute__((aligned(64)));

	/* cpu_hotplug accounting.  See stats/subsys/cpu_hotplug.h. */
	struct cpu_hotplug_stats cpu_hotplug __attribute__((aligned(64)));

	/* uffd_churn accounting.  See stats/subsys/uffd.h. */
	struct uffd_stats uffd __attribute__((aligned(64)));

	/* iouring_flood accounting.  See stats/subsys/iouring.h. */
	struct iouring_stats iouring __attribute__((aligned(64)));

	/* watchdog signal-handler clobber + reinstall accounting.  See
	 * stats/subsys/watchdog_signal.h. */
	struct watchdog_signal_stats watchdog_signal;

	/* close_racer accounting.  See stats/subsys/close_racer.h. */
	struct close_racer_stats close_racer __attribute__((aligned(64)));

	/* socket_family_chain accounting.  See stats/subsys/socket_family_chain.h. */
	struct socket_family_chain_stats socket_family_chain __attribute__((aligned(64)));

	/* socket_family_grammar accounting.  See stats/subsys/socket_family_grammar.h. */
	struct socket_family_grammar_stats socket_family_grammar __attribute__((aligned(64)));

	/* Auto-skipped socket families.  See stats/subsys/no_domains.h. */
	struct no_domains_stats no_domains __attribute__((aligned(64)));

	/* tls_rotate accounting.  See stats/subsys/tls_rotate.h. */
	struct tls_rotate_stats tls_rotate __attribute__((aligned(64)));

	/* sock_ulp_sockmap_layering accounting.  See stats/subsys/sock_ulp_sockmap_layering.h. */
	struct sock_ulp_sockmap_layering_stats sock_ulp_sockmap_layering __attribute__((aligned(64)));

	/* packet_fanout_thrash accounting.  See stats/subsys/packet_fanout_thrash.h. */
	struct packet_fanout_thrash_stats packet_fanout_thrash __attribute__((aligned(64)));

	/* packet_qdisc_bypass_unanchored_l2 accounting.
	 * See stats/subsys/packet_qdisc_bypass_unanchored_l2.h. */
	struct packet_qdisc_bypass_unanchored_l2_stats packet_qdisc_bypass_unanchored_l2 __attribute__((aligned(64)));

	/* eth_emitter accounting.  See stats/subsys/eth_emitter.h. */
	struct eth_emitter_stats eth_emitter __attribute__((aligned(64)));

	/* pkt_builder accounting.  See stats/subsys/pkt_builder.h. */
	struct pkt_builder_stats pkt_builder __attribute__((aligned(64)));

	/* iouring_net_multishot accounting.  See stats/subsys/iouring_net_multishot.h. */
	struct iouring_net_multishot_stats iouring_net_multishot __attribute__((aligned(64)));

	/* tcp_ao_rotate accounting.  See stats/subsys/tcp_ao_rotate.h. */
	struct tcp_ao_rotate_stats tcp_ao_rotate __attribute__((aligned(64)));

	/* tcp_md5_listener_race accounting.  See stats/subsys/tcp_md5_listener_race.h. */
	struct tcp_md5_listener_race_stats tcp_md5_listener_race __attribute__((aligned(64)));

	/* inet_listener_rehash_race accounting.  See stats/subsys/inet_listener_rehash_race.h. */
	struct inet_listener_rehash_race_stats inet_listener_rehash_race __attribute__((aligned(64)));

	/* ipv6_ndisc_proxy accounting.  See stats/subsys/ipv6_ndisc_proxy.h. */
	struct ipv6_ndisc_proxy_stats ipv6_ndisc_proxy __attribute__((aligned(64)));

	/* ipfrag_source_churn accounting.  See stats/subsys/ipfrag_source_churn.h. */
	struct ipfrag_source_churn_stats ipfrag_source_churn __attribute__((aligned(64)));

	/* rtnl_vf_broadcast_getlink accounting.  See stats/subsys/rtnl_vf_broadcast.h. */
	struct rtnl_vf_broadcast_stats rtnl_vf_broadcast __attribute__((aligned(64)));

	/* netconf_getdevconf_inetdev_teardown_race accounting.
	 * See stats/subsys/netconf_inetdev_race.h. */
	struct netconf_inetdev_race_stats netconf_inetdev_race __attribute__((aligned(64)));

	/* obscure_af_churn accounting.  See stats/subsys/obscure_af_churn.h. */
	struct obscure_af_churn_stats obscure_af_churn __attribute__((aligned(64)));

	/* ipv6_pmtu_race accounting.  See stats/subsys/ipv6_pmtu_race.h. */
	struct ipv6_pmtu_race_stats ipv6_pmtu_race __attribute__((aligned(64)));

	/* vrf_fib_churn accounting.  See stats/subsys/vrf_fib_churn.h. */
	struct vrf_fib_churn_stats vrf_fib_churn __attribute__((aligned(64)));

	/* ip6_udp_cork_splice accounting.  See stats/subsys/ip6_udp_cork_splice.h. */
	struct ip6_udp_cork_splice_stats ip6_udp_cork_splice __attribute__((aligned(64)));

	/* ip4_udp_cork_splice accounting.  See stats/subsys/ip4_udp_cork_splice.h. */
	struct ip4_udp_cork_splice_stats ip4_udp_cork_splice __attribute__((aligned(64)));

	/* nexthop_replace_churn accounting.  See stats/subsys/nexthop_replace_churn.h. */
	struct nexthop_replace_churn_stats nexthop_replace_churn __attribute__((aligned(64)));

	/* mpls_route_churn accounting.  See stats/subsys/mpls_route_churn.h. */
	struct mpls_route_churn_stats mpls_route_churn __attribute__((aligned(64)));

	/* netlink_monitor_race accounting.  See stats/subsys/netlink_monitor_race.h. */
	struct netlink_monitor_race_stats netlink_monitor_race __attribute__((aligned(64)));

	/* tipc_link_churn accounting.  See stats/subsys/tipc_link_churn.h. */
	struct tipc_link_churn_stats tipc_link_churn __attribute__((aligned(64)));

	/* tls_ulp_churn accounting.  See stats/subsys/tls_ulp_churn.h. */
	struct tls_ulp_churn_stats tls_ulp_churn __attribute__((aligned(64)));

	/* vxlan_encap_churn accounting.  See stats/subsys/vxlan_encap_churn.h. */
	struct vxlan_encap_churn_stats vxlan_encap_churn __attribute__((aligned(64)));

	/* ip_gre_churn accounting.  See stats/subsys/ip_gre_churn.h. */
	struct ip_gre_churn_stats ip_gre_churn __attribute__((aligned(64)));

	/* ovs_tunnel_vport_churn accounting.  See stats/subsys/ovs_tunnel_vport_churn.h. */
	struct ovs_tunnel_vport_churn_stats ovs_tunnel_vport_churn __attribute__((aligned(64)));

	/* bridge_fdb_stp accounting.  See stats/subsys/bridge_fdb_stp.h. */
	struct bridge_fdb_stp_stats bridge_fdb_stp __attribute__((aligned(64)));

	/* bridge_conntrack_churn accounting.  See stats/subsys/bridge_ct.h. */
	struct bridge_ct_stats bridge_ct __attribute__((aligned(64)));

	/* bridge_ip6frag_refrag accounting.  See stats/subsys/bridge_ip6frag.h. */
	struct bridge_ip6frag_stats bridge_ip6frag __attribute__((aligned(64)));

	/* atm_vcc_churn accounting.  See stats/subsys/atm_vcc_churn.h. */
	struct atm_vcc_churn_stats atm_vcc_churn __attribute__((aligned(64)));

	/* tty_ldisc_churn accounting.  See stats/subsys/tty_ldisc_churn.h. */
	struct tty_ldisc_churn_stats tty_ldisc_churn __attribute__((aligned(64)));

	/* nftables_churn accounting.  See stats/subsys/nftables_churn.h. */
	struct nftables_churn_stats nftables_churn __attribute__((aligned(64)));

	/* tc_qdisc_churn accounting.  See stats/subsys/tc_qdisc_churn.h. */
	struct tc_qdisc_churn_stats tc_qdisc_churn __attribute__((aligned(64)));

	/* tc_mirred_blockcast accounting.  See stats/subsys/tc_mirred_blockcast.h. */
	struct tc_mirred_blockcast_stats tc_mirred_blockcast __attribute__((aligned(64)));

	/* tc_live_traffic accounting.  See stats/subsys/tc_live_traffic.h. */
	struct tc_live_traffic_stats tc_live_traffic __attribute__((aligned(64)));

	/* xfrm_churn accounting.  See stats/subsys/xfrm_churn.h. */
	struct xfrm_churn_stats xfrm_churn __attribute__((aligned(64)));

	/* xfrm_ah_esn accounting.  See stats/subsys/xfrm_ah_esn.h. */
	struct xfrm_ah_esn_stats xfrm_ah_esn __attribute__((aligned(64)));

	/* xfrm_compat accounting.  See stats/subsys/xfrm_compat.h. */
	struct xfrm_compat_stats xfrm_compat __attribute__((aligned(64)));

	/* nat_t_churn accounting.  See stats/subsys/nat_t_churn.h. */
	struct nat_t_churn_stats nat_t_churn __attribute__((aligned(64)));

	/* bpf_cgroup_attach accounting.  See stats/subsys/bpf_cgroup_attach.h. */
	struct bpf_cgroup_attach_stats bpf_cgroup_attach __attribute__((aligned(64)));

	/* sctp_assoc_churn accounting.  See stats/subsys/sctp_assoc_churn.h. */
	struct sctp_assoc_churn_stats sctp_assoc_churn __attribute__((aligned(64)));

	/* sctp_chunk_rx accounting.  See stats/subsys/sctp_chunk_rx.h. */
	struct sctp_chunk_rx_stats sctp_chunk_rx __attribute__((aligned(64)));

	/* esp_crafted_rx accounting.  See stats/subsys/esp_crafted_rx.h. */
	struct esp_crafted_rx_stats esp_crafted_rx __attribute__((aligned(64)));

	/* fou_gue_mcast_rx accounting.  See stats/subsys/fou_gue_mcast_rx.h. */
	struct fou_gue_mcast_rx_stats fou_gue_mcast_rx __attribute__((aligned(64)));

	/* geneve_rx accounting.  See stats/subsys/geneve_rx.h. */
	struct geneve_rx_stats geneve_rx __attribute__((aligned(64)));

	/* bareudp_rx accounting.  See stats/subsys/bareudp_rx.h. */
	struct bareudp_rx_stats bareudp_rx __attribute__((aligned(64)));

	/* mpls_label_stack_rx accounting.  See stats/subsys/mpls_label_stack_rx.h. */
	struct mpls_label_stack_rx_stats mpls_label_stack_rx __attribute__((aligned(64)));

	/* bridge_ip6_refrag_fraggap accounting.  See stats/subsys/bridge_ip6_refrag_fraggap.h. */
	struct bridge_ip6_refrag_fraggap_stats bridge_ip6_refrag_fraggap __attribute__((aligned(64)));

	/* mptcp_pm_churn accounting.  See stats/subsys/mptcp_pm_churn.h. */
	struct mptcp_pm_churn_stats mptcp_pm_churn __attribute__((aligned(64)));

	/* devlink_port_churn accounting.  See stats/subsys/devlink_port_churn.h. */
	struct devlink_port_churn_stats devlink_port_churn __attribute__((aligned(64)));

	/* handshake_req_abort accounting.  See stats/subsys/handshake_req_abort.h. */
	struct handshake_req_abort_stats handshake_req_abort __attribute__((aligned(64)));

	/* nf_conntrack_helper_churn accounting.  See stats/subsys/nf_conntrack_helper_churn.h. */
	struct nf_conntrack_helper_churn_stats nf_conntrack_helper_churn __attribute__((aligned(64)));

	/* ct_expect_realloc accounting.  See stats/subsys/ct_expect_realloc.h. */
	struct ct_expect_realloc_stats ct_expect_realloc __attribute__((aligned(64)));

	/* ipset_churn accounting.  See stats/subsys/ipset_churn.h. */
	struct ipset_churn_stats ipset_churn __attribute__((aligned(64)));

	/* af_unix_scm_rights_gc accounting.  See stats/subsys/af_unix_scm_rights_gc.h. */
	struct af_unix_scm_rights_gc_stats af_unix_scm_rights_gc __attribute__((aligned(64)));

	/* af_unix_peek_race accounting.  See stats/subsys/af_unix_peek_race.h. */
	struct af_unix_peek_race_stats af_unix_peek_race __attribute__((aligned(64)));

	/* sysv_shm_orphan_race accounting.  See stats/subsys/sysv_shm_orphan_race.h. */
	struct sysv_shm_orphan_race_stats sysv_shm_orphan_race __attribute__((aligned(64)));

	/* map_shared_stress accounting.  See stats/subsys/map_shared_stress.h. */
	struct map_shared_stress_stats map_shared_stress __attribute__((aligned(64)));

	/* qrtr_bind_race accounting.  See stats/subsys/qrtr_bind_race.h. */
	struct qrtr_bind_race_stats qrtr_bind_race __attribute__((aligned(64)));

	/* pfkey_spd_walk accounting.  See stats/subsys/pfkey_spd_walk.h. */
	struct pfkey_spd_walk_stats pfkey_spd_walk __attribute__((aligned(64)));

	/* l2tp_ifname_race accounting.  See stats/subsys/l2tp_ifname_race.h. */
	struct l2tp_ifname_race_stats l2tp_ifname_race __attribute__((aligned(64)));

	/* statmount_idmap accounting.  See stats/subsys/statmount_idmap.h. */
	struct statmount_idmap_stats statmount_idmap __attribute__((aligned(64)));

	/* cred_transition accounting.  See stats/subsys/cred_transition.h. */
	struct cred_transition_stats cred_transition __attribute__((aligned(64)));

	/* netns_teardown accounting.  See stats/subsys/netns_teardown.h. */
	struct netns_teardown_stats netns_teardown __attribute__((aligned(64)));

	/* deep_path_nesting accounting.  See stats/subsys/deep_path.h. */
	struct deep_path_stats deep_path __attribute__((aligned(64)));

	/* espintcp_coalesce accounting.  See stats/subsys/espintcp_coalesce.h. */
	struct espintcp_coalesce_stats espintcp_coalesce __attribute__((aligned(64)));

	/* netns_mountns_setup accounting.  See stats/subsys/netns_mountns_setup.h. */
	struct netns_mountns_setup_stats netns_mountns_setup __attribute__((aligned(64)));

	/* tcp_ulp_swap_churn accounting.  See stats/subsys/tcp_ulp_swap_churn.h. */
	struct tcp_ulp_swap_churn_stats tcp_ulp_swap_churn __attribute__((aligned(64)));

	/* msg_zerocopy_churn accounting.  See stats/subsys/msg_zerocopy_churn.h. */
	struct msg_zerocopy_churn_stats msg_zerocopy_churn __attribute__((aligned(64)));

	/* rds_bind_transport_refleak accounting.  See stats/subsys/rds_bind_transport_refleak.h. */
	struct rds_bind_transport_refleak_stats rds_bind_transport_refleak __attribute__((aligned(64)));

	/* rds_zcopy_crafted_send accounting.  See stats/subsys/rds_zcopy_crafted_send.h. */
	struct rds_zcopy_crafted_send_stats rds_zcopy_crafted_send __attribute__((aligned(64)));

	/* iouring_send_zc_churn accounting.  See stats/subsys/iouring_send_zc_churn.h. */
	struct iouring_send_zc_churn_stats iouring_send_zc_churn __attribute__((aligned(64)));

	/* vsock_transport_churn accounting.  See stats/subsys/vsock_transport_churn.h. */
	struct vsock_transport_churn_stats vsock_transport_churn __attribute__((aligned(64)));

	/* bridge_vlan_churn accounting.  See stats/subsys/bridge_vlan_churn.h. */
	struct bridge_vlan_churn_stats bridge_vlan_churn __attribute__((aligned(64)));

	/* vlan_filter_churn accounting.  See stats/subsys/vlan_filter_churn.h. */
	struct vlan_filter_churn_stats vlan_filter_churn __attribute__((aligned(64)));

	/* igmp_mld_source_churn accounting.  See stats/subsys/igmp_mld_source_churn.h. */
	struct igmp_mld_source_churn_stats igmp_mld_source_churn __attribute__((aligned(64)));

	/* psp_key_rotate accounting.  See stats/subsys/psp_key_rotate.h. */
	struct psp_key_rotate_stats psp_key_rotate __attribute__((aligned(64)));


	/* afxdp_churn accounting.  See stats/subsys/afxdp_churn.h. */
	struct afxdp_churn_stats afxdp_churn __attribute__((aligned(64)));

	/* veth_asymmetric_xdp accounting.  See stats/subsys/veth_asymmetric_xdp.h. */
	struct veth_asymmetric_xdp_stats veth_asymmetric_xdp __attribute__((aligned(64)));

	/* ip6gre_bond_lapb_stack accounting.  See stats/subsys/ip6gre_lapb.h. */
	struct ip6gre_lapb_stats ip6gre_lapb __attribute__((aligned(64)));

	/* wireguard_decrypt_flood accounting.  See stats/subsys/wgdf.h. */
	struct wgdf_stats wgdf __attribute__((aligned(64)));

	/* blkdev_lifecycle_race accounting.  See stats/subsys/blkdev_lifecycle.h. */
	struct blkdev_lifecycle_stats blkdev_lifecycle __attribute__((aligned(64)));

	/* hfs_mount_fuzz accounting.  See stats/subsys/hfs_mount_fuzz.h. */
	struct hfs_mount_fuzz_stats hfs_mount_fuzz __attribute__((aligned(64)));

	/* icmp_inject accounting.  See stats/subsys/icmp_inject.h. */
	struct icmp_inject_stats icmp_inject __attribute__((aligned(64)));

	/* iscsi_target_probe accounting.  See stats/subsys/iscsi_target_probe.h. */
	struct iscsi_target_probe_stats iscsi_target_probe __attribute__((aligned(64)));

	/* iscsi_walker accounting.  See stats/subsys/iscsi_walker.h. */
	struct iscsi_walker_stats iscsi_walker __attribute__((aligned(64)));

	/* ip6erspan_netns_migrate accounting.  See stats/subsys/ip6erspan_netns_migrate.h. */
	struct ip6erspan_netns_migrate_stats ip6erspan_netns_migrate __attribute__((aligned(64)));

	/* netdev_netns_migrate accounting.  See stats/subsys/netdev_netns_migrate.h. */
	struct netdev_netns_migrate_stats netdev_netns_migrate __attribute__((aligned(64)));

	/* ipvs_sysctl_writer accounting.  See stats/subsys/ipvs_sysctl_writer.h. */
	struct ipvs_sysctl_writer_stats ipvs_sysctl_writer __attribute__((aligned(64)));

	/* flowtable_vlan accounting.  See stats/subsys/flowtable_vlan.h. */
	struct flowtable_vlan_stats flowtable_vlan __attribute__((aligned(64)));

	/* fnhe_pmtu_mtu_race accounting.  See stats/subsys/fnhe_pmtu_mtu_race.h. */
	struct fnhe_pmtu_mtu_race_stats fnhe_pmtu_mtu_race __attribute__((aligned(64)));

	/* slab_cache_thrash accounting.  See stats/subsys/slab_cache_thrash.h. */
	struct slab_cache_thrash_stats slab_cache_thrash __attribute__((aligned(64)));

	/* sockmap_cork_race accounting.  See stats/subsys/sockmap_cork_race.h. */
	struct sockmap_cork_race_stats sockmap_cork_race __attribute__((aligned(64)));

	/* ---- Group D: diagnostic / parent-side / one-shot ---- */

	/* fd_runtime bookkeeping (registered + skipped reject arms).
	 * See stats/subsys/fd_runtime.h. */
	struct fd_runtime_stats fd_runtime __attribute__((aligned(64)));

	/* eBPF program-generator counters (fds/bpf provisioning + net/bpf/
	 * ebpf.c generator side-effects).  See stats/subsys/ebpf_gen.h. */
	struct ebpf_gen_stats ebpf_gen;

	/* zombie-reaper accounting.  See stats/subsys/zombie_reaper.h. */
	struct zombie_reaper_stats zombie_reaper;

	/* fd-pool RAW observability -- ring-pointer canary rejections,
	 * event ring-full drop attribution, per-provider outstanding
	 * gauge, live-remove scan histogram, close-range enqueue
	 * accounting.  See stats/subsys/fd.h. */
	struct fd_stats fd __attribute__((aligned(64)));

	/* mmap-pool pick/reject accounting.  See stats/subsys/maps.h. */
	struct maps_stats maps __attribute__((aligned(64)));

	/* deferred-free enqueue rejects, post-state release contract, VMA-pressure
	 * trio, ring-owned/double-admit guards, alloc_track refresh guards.  See
	 * stats/subsys/deferred_free.h. */
	struct deferred_free_stats deferred_free;

	/* Diagnostic / canary / corruption-guard residue counters
	 * (single-signal defense-in-depth signals).  See stats/subsys/diag.h. */
	struct diag_stats diag;

	/* STRATEGY_COVERAGE_FRONTIER picker observability -- pick regimes,
	 * per-syscall distributions, silent-streak decay shadow predicates,
	 * saturation-cooldown / barren-demote / live-cooldown / group-
	 * antilock shadow lanes, errno-plateau decay, cold-weight blend A/B.
	 * See stats/subsys/frontier.h. */
	struct frontier_stats frontier __attribute__((aligned(64)));

	/* Scheduler picker / bandit -- CMP + edge-count reward-term rates,
	 * explorer vs bandit pool discovery + per-syscall attribution,
	 * warm-reserve candidate + wall-lever eligibility + reach-band
	 * shadow lanes.  See stats/subsys/picker_bandit.h. */
	struct picker_bandit_stats picker_bandit;

	/* CMP-weighted frontier picker arm observability.
	 * See stats/subsys/cmp_frontier.h. */
	struct cmp_frontier_stats cmp_frontier;

	/* Adaptive expensive-syscall accept gate observability.
	 * See stats/subsys/expensive_adaptive.h. */
	struct expensive_adaptive_stats expensive_adaptive;

	/* Cost-pool one-shot selector observer counters.
	 * See stats/subsys/cost_pool_selector.h. */
	struct cost_pool_selector_stats cost_pool_selector;

	/* Context-regular suppression classifier telemetry (SHADOW_ONLY).
	 * See stats/subsys/context_suppress.h. */
	struct context_suppress_stats context_suppress;

	/* Adaptive remote-KCOV mode A/B disposition counters.
	 * See stats/subsys/remote_adaptive.h. */
	struct remote_adaptive_stats remote_adaptive;


	/* Coverage-plateau detector counters (transitions, bucket-canary
	 * integrity, mut-attrib inversion catches, forced_windows).
	 * See stats/subsys/plateau.h. */
	struct plateau_stats plateau __attribute__((aligned(64)));

	/* KVM ioctl fuzzing: per-vCPU / per-VM dispatches, KVM_RUN churn,
	 * gpc-memslot-race sub-mode.  See stats/subsys/kvm.h. */
	struct kvm_stats kvm;

	/* btrfs ioctl dispatches into btrfs_grp.  Bumped from btrfs_sanitise()
	 * each time pick_random_ioctl() lands on an ioctl destined for an
	 * OBJ_FD_TESTFILE fd matching btrfs_fd_test().  A non-zero count
	 * confirms the seeded-struct path (TREE_SEARCH / INO_LOOKUP /
	 * GET_SUBVOL_INFO etc.) is reaching the kernel parsers rather than
	 * EFAULTing on a random arg pointer; flat counter with active testfile
	 * fds means find_ioctl_group() arbitration isn't picking btrfs_grp. */
	unsigned long btrfs_ioctls_dispatched;

	/* ioctl group-match rate accounting.  Bumped from sanitise_ioctl()
	 * in syscalls/ioctl.c to surface whether the ~62 registered ioctl
	 * groups (~1864 gen rows) are actually being reached for fd-derived
	 * picks (99% of the time), or if find_ioctl_group() is routinely
	 * falling through to the "make some shit up" a3-junk branch.
	 *  - ioctl_group_match:  fd-derived group found and dispatched.
	 *  - ioctl_group_miss:   fd-derived lookup returned NULL; fell
	 *                        through to the a3-junk fallback switch.
	 *  - ioctl_group_random: the 1% get_random_ioctl_group() branch
	 *                        was taken (independent of match/miss).
	 * A low match/(match+miss) ratio means most fds don't map to any
	 * registered group; a starved random count means the 1% branch is
	 * being under-sampled. */
	unsigned long ioctl_group_match;
	unsigned long ioctl_group_miss;
	unsigned long ioctl_group_random;

	/* nl80211_churn childop counters (cfg80211 state-machine fuzz).
	 * See stats/subsys/nl80211.h. */
	struct nl80211_stats nl80211;

	/* splice_protocols accounting.  See stats/subsys/splice_protocols.h. */
	struct splice_protocols_stats splice_protocols __attribute__((aligned(64)));

	/* rxrpc_key_install accounting.  See stats/subsys/rxrpc_key_install.h. */
	struct rxrpc_key_install_stats rxrpc_key_install __attribute__((aligned(64)));

	/* af_alg_weak_cipher_probe accounting.  See stats/subsys/af_alg_weak_cipher_probe.h. */
	struct af_alg_weak_cipher_probe_stats af_alg_weak_cipher_probe __attribute__((aligned(64)));

	/* af_alg_template_probe accounting.  See stats/subsys/af_alg_probe.h. */
	struct af_alg_probe_stats af_alg_probe;

	/* af_alg_recvmsg_churn childop counters.  See stats/subsys/af_alg_recvmsg.h. */
	struct af_alg_recvmsg_stats af_alg_recvmsg;

	/* inplace_crypto_oracle childop counters.
	 * See stats/subsys/inplace_crypto.h. */
	struct inplace_crypto_stats inplace_crypto __attribute__((aligned(64)));

	/* ipv6_rpl_clone_fidelity oracle childop counters.
	 * See stats/subsys/rpl_clone_fidelity.h. */
	struct rpl_clone_fidelity_stats rpl_clone_fidelity __attribute__((aligned(64)));

	/* memfd_secret_lifecycle oracle and lifecycle counters.
	 * See stats/subsys/memfd_secret_lifecycle.h. */
	struct memfd_secret_lifecycle_stats memfd_secret_lifecycle __attribute__((aligned(64)));

	/* mremap_merge_matrix oracle childop counters.
	 * See stats/subsys/mremap_merge_matrix.h. */
	struct mremap_merge_matrix_stats mremap_merge_matrix __attribute__((aligned(64)));

	/* thp_split_ref_race oracle and race-landing counters.
	 * See stats/subsys/thp_split_ref_race.h. */
	struct thp_split_ref_race_stats thp_split_ref_race __attribute__((aligned(64)));

	/* uffd_fault_move childop counters (fault-resolve matrix, MOVE race,
	 * teardown race).  See stats/subsys/uffd_fault_move.h. */
	struct uffd_fault_move_stats uffd_fault_move __attribute__((aligned(64)));

	/* sock_diag_walker accounting.  See stats/subsys/sock_diag_walker.h. */
	struct sock_diag_walker_stats sock_diag_walker;

	/* altname_thrash accounting.  See stats/subsys/altname_thrash.h. */
	struct altname_thrash_stats altname_thrash;

	/* ipmr_cache_report accounting.  See stats/subsys/ipmr_cache_report.h. */
	struct ipmr_cache_report_stats ipmr_cache_report;

	/* ipmr_getroute_pktinfo accounting.  See stats/subsys/ipmr_getroute_pktinfo.h. */
	struct ipmr_getroute_pktinfo_stats ipmr_getroute_pktinfo;
	/* ip6mr_churn accounting.  See stats/subsys/ip6mr_churn.h. */
	struct ip6mr_churn_stats ip6mr_churn;

	/* ublk_lifecycle accounting.  See stats/subsys/ublk_lifecycle.h. */
	struct ublk_lifecycle_stats ublk_lifecycle __attribute__((aligned(64)));

	/* minicorpus snapshot/ring accounting.  See stats/subsys/minicorpus.h. */
	struct minicorpus_stats minicorpus;

	/* rxrpc_sendmsg_cmsg accounting.  See stats/subsys/rxrpc_sendmsg_cmsg.h. */
	struct rxrpc_sendmsg_cmsg_stats rxrpc_sendmsg_cmsg;

	/* sysfs_string_race accounting.  See stats/subsys/sysfs_string_race.h. */
	struct sysfs_string_race_stats sysfs_string_race;

	/* pci_bind accounting.  See stats/subsys/pci_bind.h. */
	struct pci_bind_stats pci_bind __attribute__((aligned(64)));

	/* accept-unblocker accounting.  See stats/subsys/accept_unblocker.h. */
	struct accept_unblocker_stats accept_unblocker;

	/* pipe-waker accounting.  See stats/subsys/pipe_waker.h. */
	struct pipe_waker_stats pipe_waker;

	/* Chain-corpus duplicate-shape rate.  See stats/subsys/chain_corpus.h. */
	struct chain_corpus_stats chain_corpus;

	/* Resource-type chain-generation telemetry + replay-len corruption
	 * canary.  See stats/subsys/chain_restype.h. */
	struct chain_restype_stats chain_restype;

	/* Aggregate syscall-dispatch accounting -- walltime and per-source
	 * counters.  See stats/subsys/syscall_dispatch.h. */
	struct syscall_dispatch_stats syscall_dispatch;

	/* Credential-syscall observability oracle + throttle counters.
	 * See stats/subsys/cred_class.h. */
	struct cred_class_stats cred_class;

	/* Per-syscall provenance attribution for RedQueen-sourced and
	 * errno-sourced corpus saves and their downstream PC-edge wins.
	 * See stats/subsys/pc_edge_source.h. */
	struct pc_edge_source_stats pc_edge_source __attribute__((aligned(64)));

	/* Per-strategy transition-reward attribution (calls/count arrays +
	 * window-start snapshots).  Gated on !child->kcov.remote_mode and
	 * kcov_transition_reward_mode != KCOV_TRANSITION_REWARD_OFF at the
	 * bump sites; see the kcov_transition_reward_mode enum in
	 * include/kcov.h for the contract.  Members and doc block live in
	 * stats/subsys/transition_edge.h. */
	struct transition_edge_stats transition_edge __attribute__((aligned(64)));

	/* SHADOW-ONLY per-syscall stuck-child accounting (count + total_us
	 * arrays).  See stats/subsys/syscall_wedge.h. */
	struct syscall_wedge_stats syscall_wedge __attribute__((aligned(64)));

	/* SHADOW-ONLY topology-pair sample ring + companion counters.
	 * See stats/subsys/topo_pair.h. */
	struct topo_pair_stats topo_pair __attribute__((aligned(64)));

	/* arg-generation observability (meta sidecar + object-size-relative
	 * ARG_LEN draws + wrong-fd-type substitution + blanket-scrub census).
	 * See stats/subsys/arg.h. */
	struct arg_stats arg __attribute__((aligned(64)));

	/* userns_bootstrap accounting.  See stats/subsys/userns_bootstrap.h. */
	struct userns_bootstrap_stats userns_bootstrap __attribute__((aligned(64)));

	/* Shadow errno-class gradient (measurement only -- no fuzzer
	 * behaviour change).  See stats/subsys/errno_gradient.h for the
	 * predicate contract and per-field semantics. */
	struct errno_gradient_stats errno_gradient __attribute__((aligned(64)));

	/* Shadow cold-overflow would-save accounting (measurement only --
	 * no fuzzer behaviour change).  See stats/subsys/cold_overflow.h
	 * for the predicate composition and per-field semantics. */
	struct cold_overflow_stats cold_overflow __attribute__((aligned(64)));

	/* --blob-mutator content-authoring lane counters.  See
	 * stats/subsys/blob.h for the per-field commentary. */
	struct blob_stats blob __attribute__((aligned(64)));

	/* --blob-ab-mode within-run A/B harness counters.  See
	 * stats/subsys/blob_ab.h for the per-field commentary. */
	struct blob_ab_stats blob_ab;
};

unsigned int stats_syscall_category(const char *name);

void dump_stats(void) __cold;

/* SHADOW: render the per-childop decaying edge+wall recency ring as a
 * "childop_decay:" line per op with non-zero invocations.  Pure reader;
 * walks shm->stats.childop.edge_recent_cached[] / childop_wall_recent_
 * cached[] (maintained in lockstep with the per-slot bumps by the
 * child.c producer sites and aged out by childop_window_advance()).
 * Surfaces the recent-yield horizon the future util-table reader will
 * consume; no scheduler or picker path reads either array. */
void dump_stats_childop_decay_recency(void) __cold;

/* SHADOW-ONLY topology-pair sample writer.
 * Producers call this from a productive-coverage event site -- a new PC
 * bucket bit or a new transition slot -- to record one packed
 * {setup_op, reason, syscall_nr, age_in_syscalls} tuple into
 * shm->stats.topo_pair.ring[].  Reads the firing child's last_setup_op /
 * last_setup_op_nr latch (stamped from child_process() at every is_alt_op
 * dispatch), bumps topo_pair.no_setup_observed instead when no setup has
 * been observed yet on this child, and otherwise claims a slot via
 * __atomic_fetch_add on topo_pair.ring_head + writes the packed entry
 * with a single __atomic_store_n.  Skips silently when called from
 * parent context (this_child() == NULL).  No live decision consumes the
 * resulting ring -- the only reader is dump_stats_topo_pair_shadow()
 * at shutdown.  reason is one of TOPO_PAIR_REASON_PC /
 * TOPO_PAIR_REASON_TRANSITION; any other value still gets written but
 * the aggregator drops the entry on the read side. */
void topo_pair_record_shadow(unsigned int nr, unsigned int reason);

/* SHADOW-ONLY topology-pair aggregator.
 * Walks shm->stats.topo_pair.ring[] (capacity TOPO_PAIR_RING_SIZE; each
 * slot a single packed 64-bit entry produced via topo_pair_record_
 * shadow() from frontier_record_new_edge() in strategy-frontier.c (PC
 * lane) and from the ungated kcov_collect() transition block in kcov.c
 * (transition lane, co-located with per_syscall_transition_edges_real))
 * and prints a per-setup_op summary:
 * sample count, PC vs transition split, and mean age-in-syscalls.  The
 * "no setup observed yet" denominator is rendered as a separate row so
 * an operator can compare the productive-event population against the
 * fraction of events that fired before any setup had run on the firing
 * child.  Self-skips if topo_pair_records is zero (the ring has never
 * been written).  Pure reader; no live decision consumes either the
 * ring or any of the counters this function aggregates. */

/* Run-identity baseline snapshot.  Captured once at parent start, AFTER
 * warm_start_all() has loaded the persisted KCOV bitmap / minicorpus /
 * cmp-hints carriers, so the stored {edges_found, distinct_edges,
 * corpus_entries, monotonic_seconds} are the post-warm-load "where this
 * run picked up from" baseline.  Idempotent: extra calls (e.g. each
 * epoch_loop iteration re-entering main_loop) are silently ignored so
 * the baseline reflects the very first entry only.  No-op when the
 * relevant shm carriers are unmapped (early-exit dump modes). */
void stats_runid_snapshot_start(void) __cold;

/* Print the run-identity block: build/kernel/cache-key provenance, the
 * cohort/knob configuration this run booted with, the cold-vs-warm
 * carrier state, and the start->shutdown deltas for edges_found /
 * distinct_edges / corpus_entries (computed against the baseline
 * captured by stats_runid_snapshot_start above).  Called from
 * dump_stats() so the block leads the shutdown report; safe to call
 * without a prior start snapshot (the deltas are then suppressed and
 * an explanatory line is printed in their place). */
void stats_runid_render(void) __cold;

/* Per-tick scan: emits a WARNING when parent_stats.post_handler_corrupt_ptr
 * advances by a threshold count over a one-minute window. */
void corrupt_ptr_spike_check(void);

/* Per-tick scan: every 10 minutes, emits per-second rates for the defense
 * counters surfaced once-per-run by dump_stats(), so an operator watching
 * a long fuzz run can tell which guards are catching real wild writes vs
 * sitting at noise without waiting for the run to finish. */
void periodic_counter_rates_dump(void) __cold;

/* Per-tick childop reporting entry point: emits the childop-vs-random
 * split summary line and advances the per-childop decaying recency ring
 * used by dump_stats_childop_decay_recency() at shutdown.  Self-rate-
 * limited on the same DEFENSE_DUMP_INTERVAL_SEC cadence as the sibling
 * periodic surfaces; split out from periodic_counter_rates_dump() so the
 * recency-window rotation is not hidden inside a counter-rate function. */
void childop_periodic_dump_and_advance(void) __cold;

/* Per-tick snapshot of the cost-partitioned active-syscall pools maintained
 * beside the flat shm->active_syscalls*[] arrays.  Surfaces cheap / expensive
 * pool counts alongside the flat count so an operator can confirm the
 * partition invariant (cheap + exp == flat) at any time.  Called from
 * run_periodic_surfaces() every tick and from dump_stats() at shutdown. */
void cost_pool_periodic_dump(void) __cold;

/* Per-tick scan paired with periodic_counter_rates_dump: every dump
 * window, emits the top-5 syscalls by new-edge attribution for each
 * strategy pool (bandit vs explorer) so the operator can see which
 * single syscalls are currently driving coverage growth in each pool.
 * Where the two top-5s diverge is the diagnostic value: explorer-top
 * surfacing a syscall the bandit-top has dropped means either the
 * bandit has correctly converged or has over-converged and is missing
 * something. */
void top_syscalls_periodic_dump(void) __cold;

/* Per-tick scan paired with periodic_counter_rates_dump: every dump
 * window, snapshot the parent's /proc/self/maps line count and walk the
 * live child pid slots to sum/max/min the children's per-process VMA
 * counts.  Surfaces VMA-count growth (e.g. a thaw/freeze path that
 * leaks a split VMA per cycle) before a host OOM-kill removes the
 * post-mortem evidence; children_max specifically is the leak-finder. */
void vma_count_periodic_dump(void) __cold;

/* Per-tick scan paired with periodic_counter_rates_dump: every dump
 * window, emit the KCOV CMP counter block (per-window deltas + rates for
 * cmp_records_collected / cmp_trace_truncated /
 * cmp_hints_bloom_skipped / cmp_hints_strip_skipped,
 * cumulative per-mode child population, and first-failure-wins DIAG
 * errnos).  Without this the cmp counters are only visible at run
 * shutdown via dump_stats(), so a long overnight run produces no
 * time-series of cmp_hints effectiveness. */
void kcov_cmp_stats_periodic_dump(void) __cold;

/* --stats-log-file backing.  Open at startup (append, header line on each
 * open), close at shutdown (footer line).  stats_log_write() mirrors its
 * formatted line to stdout via output(0,...) AND, if the log is open, to
 * the file with an immediate fflush so a crash mid-run doesn't truncate
 * the most recent dump. */
void stats_log_open(const char *path);
void stats_log_close(void);
void stats_log_write(const char *fmt, ...);
/* Closes the inherited stats-log fd in a fork()'d child so the syscall
 * fuzzer can't reach it numerically (fchmod / ftruncate / write).  Parent
 * fd is unaffected — different fd-table slots, same kernel struct file. */
void stats_log_drop_in_child(void);

/* Per-syscall timeseries log gated on --stats.  Open writes one JSONL
 * file in the operator's launch CWD (stats-timeseries-<epoch>.jsonl);
 * emit_window appends one record per print_stats() tick carrying the
 * op_count, the distinct-edge and bucket-bit totals + their per-window
 * deltas, warm-loaded baselines and run-owned edge gains, trace /
 * cmp-trace truncation levels + deltas, cmp-hint / cmp-hyp inject
 * and conversion levels + deltas, the current plateau hypothesis and
 * intervention mode names, per-arm bandit pulls / reward levels +
 * deltas, and a per-syscall array carrying edges + kcov/attempted
 * calls plus local_edges / remote_edges (kcov mode split) and
 * cmp_injected / cmp_hint_pc_wins (CMP-hint conversion), each with a
 * _gained per-window delta; close at shutdown; drop_in_child
 * closes the inherited fd so a fuzzed write/fchmod can't smash the
 * operator's file.  No-ops when --stats was not passed. */
void stats_timeseries_open(void);
void stats_timeseries_close(void);
void stats_timeseries_emit_window(unsigned long op_count);
void stats_timeseries_drop_in_child(void);

/*
 * Shadow soft-saturation score (row t371-b).  Parent-side, observation-
 * only: computed each stats-emit window over trailing 10-min and 60-min
 * horizons from parent-visible counters (distinct_edges, op_count,
 * RUSAGE_CHILDREN, stall_count, trace_truncated).  Raises a shadow
 * `soft_saturated` boolean when both horizons' distinct-edge yield sit
 * below configured floors for K consecutive evals; a health veto
 * (D-state wedges / trace_truncated rising / throughput halved)
 * distinguishes the diagnosis from supply-side starvation.  Consumed by
 * NOTHING -- routing/policy is untouched.  tick() samples + recomputes,
 * emit_out_log() prints the one-line human summary, emit_shadow_sat()
 * appends the JSONL block (rates, floors, health inputs, raw per-window
 * edge deltas for offline estimator swap-in).
 */
void stats_shadow_sat_tick(void);
void stats_shadow_sat_emit_out_log(void);
/* stats_ts_emit_shadow_sat(FILE *) is prototyped in stats-internal.h --
 * FILE isn't part of stats.h's public surface, and only stats/log.c
 * calls it. */

/* Implemented in childops/recipe/runner.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void recipe_runner_dump_stats(void) __cold;

/* Implemented in childops/io_uring/recipes.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void iouring_recipes_dump_stats(void) __cold;

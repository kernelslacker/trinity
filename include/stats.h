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
#include "stats/subsys/af_alg_weak_cipher_probe.h"
#include "stats/subsys/af_unix_peek_race.h"
#include "stats/subsys/af_unix_scm_rights_gc.h"
#include "stats/subsys/aio.h"
#include "stats/subsys/arg.h"
#include "stats/subsys/barrier_racer.h"
#include "stats/subsys/blkdev_lifecycle.h"
#include "stats/subsys/blob.h"
#include "stats/subsys/blob_ab.h"
#include "stats/subsys/bpf_cgroup_attach.h"
#include "stats/subsys/bpf_lifecycle.h"
#include "stats/subsys/bridge_ct.h"
#include "stats/subsys/bridge_ip6frag.h"
#include "stats/subsys/bridge_vlan_churn.h"
#include "stats/subsys/childop.h"
#include "stats/subsys/close_racer.h"
#include "stats/subsys/cold_overflow.h"
#include "stats/subsys/corrupt_ptr.h"
#include "stats/subsys/cpu_hotplug.h"
#include "stats/subsys/cred_transition.h"
#include "stats/subsys/deep_path.h"
#include "stats/subsys/epoll_volatility.h"
#include "stats/subsys/errno_gradient.h"
#include "stats/subsys/espintcp_coalesce.h"
#include "stats/subsys/fd.h"
#include "stats/subsys/fd_runtime_skipped.h"
#include "stats/subsys/flock_thrash.h"
#include "stats/subsys/flowtable_vlan.h"
#include "stats/subsys/fork_storm.h"
#include "stats/subsys/frontier.h"
#include "stats/subsys/fs_lifecycle.h"
#include "stats/subsys/futex_pi_requeue_rollback.h"
#include "stats/subsys/futex_storm.h"
#include "stats/subsys/handshake_req_abort.h"
#include "stats/subsys/hfs_mount_fuzz.h"
#include "stats/subsys/igmp_mld_source_churn.h"
#include "stats/subsys/inplace_crypto.h"
#include "stats/subsys/iouring.h"
#include "stats/subsys/iouring_eventfd.h"
#include "stats/subsys/iouring_recipes.h"
#include "stats/subsys/iouring_send_zc_churn.h"
#include "stats/subsys/ip4_udp_cork_splice.h"
#include "stats/subsys/ip6_udp_cork_splice.h"
#include "stats/subsys/ip6gre_lapb.h"
#include "stats/subsys/ip_gre_churn.h"
#include "stats/subsys/ipset_churn.h"
#include "stats/subsys/ipv6_ndisc_proxy.h"
#include "stats/subsys/ipv6_pmtu_race.h"
#include "stats/subsys/iscsi_target_probe.h"
#include "stats/subsys/iscsi_walker.h"
#include "stats/subsys/keyring_spam.h"
#include "stats/subsys/l2tp_ifname_race.h"
#include "stats/subsys/madvise_cycler.h"
#include "stats/subsys/map_shared_stress.h"
#include "stats/subsys/maps.h"
#include "stats/subsys/mount_churn.h"
#include "stats/subsys/mpls_route_churn.h"
#include "stats/subsys/msg_zerocopy_churn.h"
#include "stats/subsys/netlink_monitor_race.h"
#include "stats/subsys/netns_mountns_setup.h"
#include "stats/subsys/netns_teardown.h"
#include "stats/subsys/nf_conntrack_helper_churn.h"
#include "stats/subsys/no_domains.h"
#include "stats/subsys/oracle.h"
#include "stats/subsys/ovs_tunnel_vport_churn.h"
#include "stats/subsys/pci_bind.h"
#include "stats/subsys/perf_chains.h"
#include "stats/subsys/pidfd_storm.h"
#include "stats/subsys/pipe_thrash.h"
#include "stats/subsys/recipe.h"
#include "stats/subsys/refcount_audit.h"
#include "stats/subsys/rtnl_vf_broadcast.h"
#include "stats/subsys/rxrpc_key_install.h"
#include "stats/subsys/sched_cycler.h"
#include "stats/subsys/setsockopt_pairing.h"
#include "stats/subsys/signal_storm.h"
#include "stats/subsys/socket_family_chain.h"
#include "stats/subsys/socket_family_grammar.h"
#include "stats/subsys/splice_protocols.h"
#include "stats/subsys/statmount_idmap.h"
#include "stats/subsys/tcp_ao_rotate.h"
#include "stats/subsys/tls_rotate.h"
#include "stats/subsys/tls_ulp_churn.h"
#include "stats/subsys/topo_pair.h"
#include "stats/subsys/ublk_lifecycle.h"
#include "stats/subsys/uffd.h"
#include "stats/subsys/uid_change.h"
#include "stats/subsys/umount_race.h"
#include "stats/subsys/userns_bootstrap.h"
#include "stats/subsys/vdso_race.h"
#include "stats/subsys/vlan_filter_churn.h"
#include "stats/subsys/wgdf.h"
#include "stats/subsys/xattr_thrash.h"
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
 * the GLOBAL kcov_shm->edges_found counter, so a fleet running with N
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

/* Upper bound on the recipe_runner catalog size.  recipe-runner.c
 * asserts at startup that its table fits.  Sized large enough to
 * accommodate future recipes without reshuffling shared memory. */
#define MAX_RECIPES 36

/* Upper bound on the iouring_recipes catalog.  iouring-recipes.c asserts
 * at build time that its table fits. */
#define MAX_IOURING_RECIPES 64

/* Number of distinct slab classes the slab_cache_thrash childop targets,
 * one entry per enum slab_target in childops/misc/slab-cache-thrash.c.  Sized
 * here (rather than in the childop) so the per-target run counter array
 * can live inside struct stats_s.  A static_assert in slab-cache-thrash.c
 * fails the build if the two ever drift. */
#define NR_SLAB_TARGETS 7

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

/*
 * Divergence-sentinel per-field identifiers.  Lives in stats.h (rather
 * than private to child-sentinel.c) so the per-field anomaly array in
 * struct stats_s can be sized and indexed by SF__MAX, and so the stats dump
 * can name individual shards via offsetof for periodic / end-of-run
 * reporting.
 *
 * Grouped by source syscall so a post-mortem reader can decode
 * "which syscall, which field" from the single id without a side
 * table.  The gaps in the numbering (5..9 and 14..) are intentional --
 * the post-mortem decoder reads these as raw numeric ids, so leaving
 * the original group bases in place keeps old sentinel entries in
 * already-collected logs unambiguous.
 */
enum sentinel_field {
	SF_UNAME_SYSNAME	= 0,
	SF_UNAME_RELEASE	= 2,
	SF_UNAME_VERSION	= 3,
	SF_UNAME_MACHINE	= 4,

	SF_SYSINFO_TOTALRAM	= 10,
	SF_SYSINFO_TOTALSWAP	= 11,
	SF_SYSINFO_TOTALHIGH	= 12,
	SF_SYSINFO_MEM_UNIT	= 13,

	SF__MAX			= 14,	/* array size for shards; keep > max above */
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

	/* post_mmap clamped new->map.size below the requested length because
	 * the underlying file fd was shorter than mapping_sizes[i]+offset.
	 * Without the clamp dirty_mapping (and later get_map() consumers) walk
	 * pages past EOF and SIGBUS with BUS_ADRERR — a trinity self-bug that
	 * burns the child before it can contribute to coverage. */
	unsigned long mmap_size_clamped;

	/* sanitise_statmount() bailed before assigning rec->aN because the
	 * csfu mnt_id_req allocation came back NULL.  Without this counter
	 * a statmount syscall whose setup always failed presents as a
	 * silently-zero op in the dispatch histogram -- the syscall path
	 * has no other place to record a pre-syscall abort.  Bumped from
	 * sanitise_statmount; the post handler stays untouched. */
	unsigned long statmount_setup_fail;

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

	/* get_random_object_versioned() OBJ_LOCAL pick path or add_object()
	 * pre-grow snapshot saw head->num_entries > head->array_capacity and
	 * refused to deref head->array[idx] / proceed with the slot write.
	 * Mirrors the OBJ_GLOBAL wild-stomp defences at objects/registry.c and
	 * 1088.  Non-zero means a wild value-result write has scribbled an
	 * objhead's num_entries; the pick-side bumper converted what would
	 * have been an OOB head->array[] read into a NULL return; the write-
	 * side bumper converted what would have been a doubling loop to
	 * satisfy a stomped target into an early release_obj. */
	unsigned long local_obj_num_entries_corrupted;

	/* handle_syscall_ret() found rec->_canary != REC_CANARY_MAGIC on
	 * entry — the entire syscallrecord was rewritten between BEFORE
	 * and AFTER, including bookkeeping fields the per-arg snapshot
	 * pattern can't shadow.  Distinct from post_handler_corrupt_ptr,
	 * which only catches scribbled rec->aN pointer slots: a wholesale
	 * stomp from a sibling value-result syscall whose buffer aliased
	 * the rec lands here without tripping the snapshot guards.  Bumped
	 * informationally; the child does NOT abort, since the call has
	 * already returned and the mismatched data is past being trusted
	 * anyway.  See pre_crash_ring entry kind PRE_CRASH_KIND_CANARY for
	 * the matching context capture. */
	unsigned long rec_canary_stomped;

	/* unlock() sampled the lock word pre-release and saw
	 * LOCK_RESERVED_DIRTY(state) non-zero -- the reserved bits 1..31
	 * carry a stray write from somewhere in the held window.
	 * Companion to parent_stats.lock_word_scribbled, which only fires
	 * from check_lock()'s periodic walk in main context.  The walker
	 * cannot see scribbles that land + clear inside a single held
	 * window, so without this counter a transient stomp during the
	 * held interval is invisible.  Multi-producer (any child
	 * releasing any lock) so it lives in shm->stats with an atomic
	 * RELAXED add-fetch, not in parent_stats.  unlock() does NOT
	 * refuse the release on a dirty word -- refusing would leave the
	 * lock permanently held and deadlock every waiter; the headline
	 * counter is enough to surface the event. */
	unsigned long lock_held_scribble;

	/* handle_syscall_ret() observed rec->retval outside the {0, -1UL}
	 * contract on a syscall whose per-call rettype was RET_ZERO_SUCCESS.
	 * The dispatcher gate fires once per call and covers every handler
	 * advertising that rettype (whether set statically in syscallentry
	 * or overridden per-cmd by a sanitise hook), so a single chokepoint
	 * substitutes for retval bounds duplicated across the ~85
	 * RET_ZERO_SUCCESS .post handlers.  Non-zero means a torn or
	 * wholesale-stomped retval slipped past the canary check (different
	 * stomp class — the canary catches whole-rec rewrites, this catches
	 * an isolated rec->retval scribble).  Distinct bug class from
	 * post_handler_corrupt_ptr (which counts .post handlers rejecting a
	 * pid-shaped pointer in rec->aN): this is a dispatcher-level
	 * rettype-contract violation, no .post pointer is examined.
	 * rzs_blanket_reject has its own storage, separate from
	 * post_handler_corrupt_ptr, because sharing would inflate the
	 * post_handler_corrupt_ptr headline ~9x at ~2/s steady-state. */
	unsigned long rzs_blanket_reject;

	/* handle_syscall_ret() saw reject_corrupt_retfd() flag a structurally
	 * out-of-bound rec->retval on a RET_FD-class syscall (negative,
	 * >= NR_OPEN, or otherwise outside [0, 1<<20)) BEFORE the
	 * success/failure dispatch.  Distinct from the failures aggregate
	 * counter: the latter aggregates legitimate -1UL returns alongside the coerced
	 * corruption returns, drowning the corruption signal in the noise
	 * of normal failed syscalls (>50% of every fuzz run).  This counter
	 * surfaces only the structurally-corrupt RET_FD subset, so a quiet
	 * window where every failure was a real -ENOENT/-EBADF/etc still
	 * reads as zero corruption -- non-zero here always means a fabricated
	 * fd value reached the dispatcher.  Sub-attribution by syscall (nr,
	 * do32bit) routes through post_handler_corrupt_ptr_bump's
	 * per-handler ring (already invoked from inside
	 * reject_corrupt_retfd()), so this counter is the headline tally and
	 * the per-handler ring carries the breakdown. */
	unsigned long retfd_blanket_reject;

	/* handle_syscall_ret() observed a page-aligned, arena-band-shaped
	 * pointer in either an ARG_ADDRESS / ARG_NON_NULL_ADDRESS slot of
	 * rec->aN (..._arg) or in the rec->post_state tail (..._post_state)
	 * that neither range_in_tracked_shared() nor
	 * addr_in_local_runtime_map() recognised as live.  Distinct bug
	 * class from post_handler_corrupt_ptr, which catches structurally-
	 * broken values (NULL-ish, kernel-VA, misaligned): the values
	 * caught here are structurally valid arena-shaped pointers whose
	 * underlying mapping is gone -- a sibling munmap landed the page
	 * between the syscall returning and the .post handler about to
	 * dereference it, or a sibling scribbled an arena-shaped value
	 * into the slot from outside the live tracker set.  The
	 * is_corrupt_ptr_shape() gate at include/utils.h:200 cannot
	 * distinguish "live arena pointer" from "stale arena pointer",
	 * since the predicate is purely structural; this counter surfaces
	 * the residual STALE class.
	 *
	 * SPLIT into two counters rather than one-with-attribution: the
	 * arg-slot and post_state detection sites have different stomp
	 * vectors (arg slots ride the value-result sibling-write path,
	 * post_state rides the .post handler's snap-stash convention), and
	 * a downstream operator reading the periodic rate dump benefits
	 * from seeing the two rates side by side instead of having to
	 * untangle them from per-PC attribution.
	 *
	 * Both sites are telemetry-only -- the kernel has already observed
	 * the syscall by the time the probe runs, so post-dispatch coercion
	 * of the slot would just scribble shared rec state without changing
	 * the syscall outcome.  Downstream consumers must take their own
	 * explicit skip path on a stale slot. */
	unsigned long arena_ptr_stale_caught_arg;
	unsigned long arena_ptr_stale_caught_post_state;

	/* fill_arg() fired the ONE_IN(WRONG_FD_TYPE_FREQ) branch on a
	 * typed-fd argument and substituted either a different typed-fd
	 * subtype or a generic-pool fd in its place.  Headline counter for
	 * the wrong-fd-type substitution: divided by op_count this is the
	 * realised substitution rate, which should track 1 / WRONG_FD_TYPE_FREQ
	 * weighted by the typed-fd-arg fraction of the syscall mix.  Targets
	 * the wrong-fd-type bug class -- without these substitutions the
	 * typed-fd consumer always hands the kernel the correct subtype and
	 * any type-check guard sitting only on the mismatched-subtype path
	 * is never reached. */
	unsigned long wrong_fd_type_substitutions;

	/* Subset of wrong_fd_type_substitutions where the substitution fell
	 * through to get_random_fd() instead of picking another typed-fd
	 * argtype.  Surfaces the typed-vs-generic split so the ONE_IN(4)
	 * generic branch is observable separately from the dominant
	 * other-typed-fd path. */
	unsigned long wrong_fd_type_subst_generic;

	/* sanitise_execve() refused to let an execve / execveat fire because
	 * the resolved target inode matched trinity's own binary -- the path
	 * argument was rewritten to a known-bad value so the kernel returns
	 * a clean -ENOENT/-ENOTDIR and the post handler's argv/envp free
	 * walk runs unchanged.  Without this guard a fuzzed pathname that
	 * resolves to /proc/self/exe, /proc/<pid>/exe, the original launch
	 * path, or an inherited fd backed by the trinity binary spawns a
	 * full nested trinity that inherits the parent's cmdline, cgroup,
	 * and namespace state and starts its own child fleet -- the nested
	 * fleets eat the process table fast enough to trip the parent's
	 * fork-retry budget and wedge the main loop.  Always-on; no CLI
	 * knob.  See sanitise_execve() for the (dev, ino) compare site. */
	unsigned long execve_self_exec_blocked;

	/* init_child()'s sibling-freeze step issues mprotect(PROT_READ) on
	 * every other child's childdata (and on the shared pids[] array) so
	 * a value-result syscall buffer in one sibling can't scribble over
	 * another sibling's rec->aN.  Each mprotect can fail with -ENOMEM
	 * if the kernel hits a per-mm VMA-count or address-space limit
	 * while splitting the existing mapping.  A non-zero count means at
	 * least one freeze step silently left a sibling's childdata (or
	 * pids[]) writable -- the cross-child scribble vector that the
	 * post-handler / snapshot guards exist to defend against is open
	 * for that sibling pair.  We don't abort the child on a single
	 * failure (best-effort hardening), but the counter lets us tell
	 * whether the failure is rare or a real runtime vector. */
	unsigned long sibling_mprotect_failed;

	/* init_child() bumps shm->sibling_freeze_gen after its for_each_child
	 * mprotect loop completes; each child re-checks the gen at the top of
	 * its child_process loop and, on mismatch, re-runs the mprotect sweep
	 * to pull any newly-spawned sibling into PROT_READ.  This counter
	 * ticks once per refreeze.  Expected pattern: a burst at startup
	 * (max_children-1 refreezes per child as the fleet fills in), then
	 * occasional bumps as replace_child() respawns dead slots.  A
	 * runaway count (e.g. tens of refreezes per second long after
	 * startup) would indicate constant child churn — useful signal when
	 * paired with reaper / SEGV stats. */
	unsigned long sibling_refreeze_count;

	/* periodic_work re-issues a curated set of "should be deterministic
	 * across short windows" syscalls (uname, sysinfo, getrlimit/prlimit64
	 * RLIMIT_NOFILE, sched_getparam(0)) and compares the result against
	 * the previous tick's reading cached in childdata.sentinel_prev.  Any
	 * divergence outside the expected drift fields (loads/uptime/freeram
	 * et al. are excluded) is the fingerprint of a fuzzed value-result
	 * syscall buffer scribbling the cached struct or a kernel-managed
	 * datum: a wild write into the cache surfaces as the live re-read
	 * disagreeing with what we captured previously, and a wild write into
	 * the kernel-managed copy surfaces the same way from the other side.
	 * Bumped per diverging field, so a single sample with multi-field
	 * corruption contributes more than one to the count -- intentional,
	 * to amplify multi-field clobbers above noise from singleton drifts.
	 *
	 * Sharded by enum sentinel_field so an operator can see which
	 * monitored field actually drifted.  pre_crash_ring is only 64 slots
	 * wide (overwrite-on-full) and gives the last few ids at crash time;
	 * the per-field counters give the live histogram.  Gaps in the enum
	 * (5..9) are present in the array as always-zero slots — kept that
	 * way so the index matches the on-the-wire field id in collected
	 * logs.
	 *
	 * SF_UNAME_RELEASE and SF_UNAME_MACHINE are routed to
	 * divergence_sentinel_expected_drift below instead of bumping their
	 * shard here — personality(PER_LINUX32|UNAME26) legitimately
	 * rewrites those strings every time the fuzzer hits it, so leaving
	 * them on the anomaly histogram would drown out the real wild-write
	 * signal. */
	unsigned long divergence_sentinel_anomalies[SF__MAX];

	/* Counter for divergences in fields that are known to be mutated by
	 * operator-driven syscalls trinity itself fuzzes — specifically
	 * SF_UNAME_RELEASE and SF_UNAME_MACHINE, which personality()
	 * rewrites every time the bandit fixates on PER_LINUX32 / UNAME26.
	 * Bumped per diverging field, aggregate only (no per-field shard) —
	 * if a second "expected drift" field is added later this can be
	 * widened.  Mirror of the 2026-05-09 uid_change_logged split:
	 * separating expected mutations from corruption keeps the headline
	 * anomaly array as a real signal rather than a noise floor.
	 *
	 * SF_SYSINFO_TOTALSWAP intentionally stays on the anomaly array —
	 * swapon/swapoff bumps it at a far lower rate than personality()
	 * bumps RELEASE/MACHINE, and calling that "expected" would muddy
	 * the meaning of this counter. */
	unsigned long divergence_sentinel_expected_drift;

	/* Childop taint-watcher: count of times a /proc/sys/kernel/tainted
	 * bit transition was observed across a non-syscall childop dispatch,
	 * indexed by enum child_op_type.  Surfaces soft taints (lockdep WARN,
	 * RCU stall, reckless module load, etc.) tied to a specific childop
	 * even when no oops is raised.  RELAXED add-fetch: the counter is a
	 * coarse anomaly indicator, not a precise event log — the matching
	 * pre_crash_ring entry holds the full per-event context. */
	unsigned long taint_transitions[NR_CHILD_OP_TYPES];

	/* Pool-race aborted counter, indexed by enum child_op_type.
	 * Bumped from inside each pool-consuming childop's SIGSEGV/SIGBUS
	 * sigsetjmp wrap when a sibling unmapped the pool entry between
	 * the get_map_with_prot() draw and the actual user-mode dereference
	 * inside the body.  Closes the race-window residual that the
	 * munmap post-hook pool invalidation cannot catch (live mapping at
	 * draw, gone at use).  Wrapped childops: memory_pressure,
	 * iouring_flood, iouring_recipes, madvise_cycler.  RELAXED add-
	 * fetch: a coarse anomaly indicator, not an event log. */
	unsigned long pool_race_aborted[NR_CHILD_OP_TYPES];

	/* Per-childop accounting -- edge / call / setup / data-path /
	 * latch / demote-promote / budget / wedge / wall-time /
	 * fd-delta / decay-recency arrays plus scattered scalars.
	 * See stats/subsys/childop.h. */
	struct childop_stats childop __attribute__((aligned(64)));

	/* ---- Group C: per-childop ---- */

	/* procfs_writer childop: per-tree write counts, split by outcome.
	 * Discovery happens in the parent under root privileges (access(W_OK)
	 * succeeds), but writes happen in privilege-dropped children, so a
	 * large fraction of open() / write() calls fail.  Counting only
	 * "open succeeded" hides this; split into open-fail / write-fail /
	 * write-ok so the dump shows real reach into each tree. */
	unsigned long procfs_writes_open_fail __attribute__((aligned(64)));
	unsigned long procfs_writes_write_fail;
	unsigned long procfs_writes_write_ok;
	unsigned long sysfs_writes_open_fail;
	unsigned long sysfs_writes_write_fail;
	unsigned long sysfs_writes_write_ok;
	unsigned long debugfs_writes_open_fail;
	unsigned long debugfs_writes_write_fail;
	unsigned long debugfs_writes_write_ok;

	/* memory_pressure childop: MADV_PAGEOUT + refault cycles */
	unsigned long memory_pressure_runs;

	/* sched_cycler accounting.  See stats/subsys/sched_cycler.h. */
	struct sched_cycler_stats sched_cycler __attribute__((aligned(64)));

	/* userns_fuzzer childop counters */
	unsigned long userns_runs;		/* total userns_fuzzer invocations */
	unsigned long userns_inner_crashed;	/* inner child died by signal */
	unsigned long userns_unsupported;	/* CLONE_NEWUSER refused, noop path */

	/* barrier_racer accounting.  See stats/subsys/barrier_racer.h. */
	struct barrier_racer_stats barrier_racer __attribute__((aligned(64)));

	/* genetlink_fuzzer childop counters */
	unsigned long genetlink_families_discovered;	/* cumulative across children */
	unsigned long genetlink_msgs_sent;		/* successful send() to a family */
	unsigned long genetlink_eperm;			/* family rejected with EPERM/EACCES */
	/* NLMSG_ERROR entry whose nlmsg_seq did not match the seq the
	 * caller passed to nl_send_drain_errors() -- a stale ack left
	 * in the socket queue by an earlier request, possibly from a
	 * different family.  Counted so the queue-hygiene rate stays
	 * visible; the drop suppresses the on_err callback so a stale
	 * -EPERM/-EACCES cannot latch the wrong family's needs_priv. */
	unsigned long genetlink_stale_seq_drops;
	/* CTRL_CMD_GETFAMILY/NLM_F_DUMP completed cleanly (NLMSG_DONE)
	 * but produced zero usable family entries.  Bumped at the
	 * empty-catalog bail in the persistent fuzz child so a genuine
	 * "kernel has no registered genetlink families" outcome is
	 * counted explicitly instead of vanishing into a silent return
	 * that only surfaces as derived setup_fail.  Separable from a
	 * transport-side failure (genetlink_discovery_io_err) and a
	 * controller-rejection (genetlink_discovery_nlerr). */
	unsigned long genetlink_missing_producer;
	/* CTRL_CMD_GETFAMILY dump failed with a local I/O error: short
	 * recv, sendmsg failure, recv timeout, or a malformed reply
	 * stream with no DONE/ERROR seen.  Bumped instead of
	 * genetlink_missing_producer when the empty-catalog bail is
	 * caused by transport rather than an empty kernel registry. */
	unsigned long genetlink_discovery_io_err;
	/* CTRL_CMD_GETFAMILY dump terminated with a mid-dump
	 * NLMSG_ERROR (negated errno from the controller family).
	 * Bumped instead of genetlink_missing_producer for that case
	 * so a kernel-side rejection is distinguishable from both a
	 * transport failure and a genuinely empty registry. */
	unsigned long genetlink_discovery_nlerr;
	/* Successful CTRL_CMD_GETFAMILY dumps that produced a
	 * non-empty catalog.  Bumped once per genetlink_fuzzer()
	 * invocation just before the grandchild fork.  Distinct from
	 * genetlink_families_discovered, which sums cat->count across
	 * cycles (entries).  With cycles + entries we can tell a
	 * healthy 50-entry dump repeated N times from a degraded
	 * 2-entry dump repeated many more times, and we can compare
	 * cycles against genetlink_msgs_sent to localise a
	 * discovery-to-send stall (setup_accepted bumps alongside
	 * this counter, so cycles == setup_accepted on the hot
	 * path). */
	unsigned long genetlink_discovery_cycles;
	/* userns_run_in_ns(CLONE_NEWNET, genetlink_fuzzer_in_ns, ...)
	 * returned < 0 for any reason (EPERM policy latch, EAGAIN
	 * transient fork/id-map/target-unshare failure, waitpid
	 * failure).  Bumped alongside the appropriate
	 * userns_bootstrap_* counter so we can attribute a
	 * "setup_accepted grows but msgs_sent stays zero" pattern to
	 * userns/netns bootstrap vs. the in-ns nl_open vs. the send
	 * itself without cross-referencing every other userns caller. */
	unsigned long genetlink_userns_run_fail;
	/* Grandchild-side nl_open(NETLINK_GENERIC) in the fresh
	 * user+net namespace returned < 0.  The pre-existing
	 * outputerr line covers per-event debugging; this counter
	 * gives the rate.  When this is the dominant miss the fix is
	 * in the ns-bootstrap path (missing loopback, missing family
	 * registration, LSM refusal) rather than in the send path. */
	unsigned long genetlink_in_ns_open_fail;
	/* Grandchild-side nl_send_drain_errors() returned < 0
	 * (sendmsg failure, recv returned non-EAGAIN error).
	 * Previously silent — send_fuzzed_msg() bailed without
	 * bumping msgs_sent and without accounting the miss, so a
	 * consistently-failing sendmsg looked identical to a healthy
	 * op that never picked this family.  When this is the
	 * dominant miss the fault is in the send-path envelope, not
	 * in ns bootstrap. */
	unsigned long genetlink_send_drain_fail;

	/* netlink message generator: NLA_F_NESTED containers emitted */
	unsigned long netlink_nested_attrs_emitted;

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

	/* tracefs_fuzzer childop counters, per-ARM, split by outcome into
	 * open-fail (tracefs not mounted, EACCES, ENOENT on a per-event
	 * enable that was unloaded mid-run), write-fail (EINVAL on a
	 * malformed probe spec, EBUSY, ...) and write-OK (the bytes
	 * actually reached the kernel parser), so the dump shows real
	 * reach into each tracefs surface.  write_fail + write_ok sum
	 * to the per-ARM total; open_fail additionally distinguishes
	 * open failures. */
	unsigned long tracefs_kprobe_writes_open_fail;		/* writes to kprobe_events */
	unsigned long tracefs_kprobe_writes_write_fail;
	unsigned long tracefs_kprobe_writes_write_ok;
	unsigned long tracefs_uprobe_writes_open_fail;		/* writes to uprobe_events */
	unsigned long tracefs_uprobe_writes_write_fail;
	unsigned long tracefs_uprobe_writes_write_ok;
	unsigned long tracefs_filter_writes_open_fail;		/* writes to set_ftrace_filter/notrace/graph */
	unsigned long tracefs_filter_writes_write_fail;
	unsigned long tracefs_filter_writes_write_ok;
	unsigned long tracefs_event_enable_writes_open_fail;	/* writes to events subsystem enable files */
	unsigned long tracefs_event_enable_writes_write_fail;
	unsigned long tracefs_event_enable_writes_write_ok;
	unsigned long tracefs_misc_writes_open_fail;		/* trace_options, current_tracer, etc. */
	unsigned long tracefs_misc_writes_write_fail;
	unsigned long tracefs_misc_writes_write_ok;

	/* bpf_lifecycle accounting.  See stats/subsys/bpf_lifecycle.h. */
	struct bpf_lifecycle_stats bpf_lifecycle __attribute__((aligned(64)));

	/* recipe_runner accounting.  See stats/subsys/recipe.h. */
	struct recipe_stats recipe __attribute__((aligned(64)));

	/* fd_stress childop counters, one per stress mode */
	unsigned long fdstress_close_reopen;
	unsigned long fdstress_dup2_replace;
	unsigned long fdstress_type_confusion;
	unsigned long fdstress_cloexec_toggle;

	/* Per-recipe completion counts, indexed by the recipe's slot in the
	 * static catalog inside recipe-runner.c.  Dumped via
	 * recipe_runner_dump_stats() so the stats dump stays decoupled from the
	 * catalog layout. */
	unsigned long recipe_completed_per[MAX_RECIPES];

	/* iouring_recipes accounting.  See stats/subsys/iouring_recipes.h. */
	struct iouring_recipes_stats iouring_recipes __attribute__((aligned(64)));

	/* Per-iouring-recipe completion counts, indexed by the recipe's slot in
	 * the static catalog inside iouring-recipes.c.  Dumped via
	 * iouring_recipes_dump_stats() so the stats dump stays decoupled from the
	 * catalog layout. */
	unsigned long iouring_recipe_completed_per[MAX_IOURING_RECIPES];

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

	/* cgroup_churn childop counters */
	unsigned long cgroup_churn_runs;	/* total cgroup_churn invocations */
	unsigned long cgroup_mkdirs;		/* successful mkdir() under /sys/fs/cgroup/ */
	unsigned long cgroup_rmdirs;		/* successful rmdir() under /sys/fs/cgroup/ */
	unsigned long cgroup_failed;		/* mkdir or rmdir returned -1 */
	unsigned long cgroup_psi_race_runs;	/* PSI pressure_write race sub-mode entries */
	unsigned long cgroup_psi_race_writes;	/* successful pressure-file write() inside race */
	unsigned long cgroup_psi_race_failed;	/* pressure-file open() failed for the whole sub-mode */

	/* mount_churn childop counters.  See stats/subsys/mount_churn.h. */
	struct mount_churn_stats mount_churn __attribute__((aligned(64)));

	/* umount_race accounting.  See stats/subsys/umount_race.h. */
	struct umount_race_stats umount_race __attribute__((aligned(64)));

	/* fork_storm childop counters.  See stats/subsys/fork_storm.h. */
	struct fork_storm_stats fork_storm __attribute__((aligned(64)));

	/* pidfd_storm accounting.  See stats/subsys/pidfd_storm.h. */
	struct pidfd_storm_stats pidfd_storm __attribute__((aligned(64)));

	/* madvise_cycler childop counters.  See stats/subsys/madvise_cycler.h. */
	struct madvise_cycler_stats madvise_cycler __attribute__((aligned(64)));

	/* keyring_spam childop counters.  See stats/subsys/keyring_spam.h. */
	struct keyring_spam_stats keyring_spam __attribute__((aligned(64)));

	/* vdso_mremap_race accounting.  See stats/subsys/vdso_race.h. */
	struct vdso_race_stats vdso_race __attribute__((aligned(64)));

	/* numa_migration_churn childop counters */
	unsigned long numa_migration_runs;	/* total numa_migration_churn invocations */
	unsigned long numa_migration_calls;	/* total mbind/migrate/move/set_mempolicy calls issued */
	unsigned long numa_migration_failed;	/* migration syscall returned -1 */
	unsigned long numa_migration_no_numa;	/* attempted invocations skipped (single-node host) */
	unsigned long numa_migration_sysfs_unreadable;	/* /sys/devices/system/node/online open/read failed */

	/* cpu_hotplug accounting.  See stats/subsys/cpu_hotplug.h. */
	struct cpu_hotplug_stats cpu_hotplug __attribute__((aligned(64)));

	/* uffd_churn accounting.  See stats/subsys/uffd.h. */
	struct uffd_stats uffd __attribute__((aligned(64)));

	/* iouring_flood accounting.  See stats/subsys/iouring.h. */
	struct iouring_stats iouring __attribute__((aligned(64)));

	/* sanitise_io_uring_enter bailed out because the kernel-shared SQ ring
	 * mask read back larger than ring->sq_entries -- a sibling op had
	 * stomped the mask, which would have steered fill_sqe past the SQE
	 * array and faulted on an unmapped page. */
	unsigned long iouring_enter_mask_corrupt;

	/* Bumped immediately before each alarm(1) arm (alt-op dispatch
	 * and NEED_ALARM syscall paths) when a sigaction(SIGALRM, NULL,
	 * &cur) probe reads back sa_handler != sigalrm_handler -- i.e. a
	 * fuzzed rt_sigaction call in this child has overwritten the
	 * internal-watchdog disposition before the watchdog gets armed.
	 * SIGALRM appears in settable_signals[], so a child can disarm
	 * its own 1-second inner watchdog by installing SIG_IGN /
	 * SIG_DFL / an arbitrary dummy; subsequent blocking ops then
	 * ride only the ~30-second outer watchdog, which is the dominant
	 * late-run wedge mechanism.  The arm-site probe now restores the
	 * handler in place before arming (see watchdog_sigalrm_reinstalled
	 * below), so this row measures the incidence and the reinstalled
	 * row measures the repair rate; both bump on every repair.
	 * RELAXED add-fetch: coarse anomaly counter, not an event log. */
	unsigned long watchdog_sigalrm_clobbered;

	/* Mirror of watchdog_sigalrm_clobbered for SIGXCPU.  SIGXCPU
	 * also lives in settable_signals[] and shares the same
	 * disarm-by-fuzzed-rt_sigaction class; the inner-watchdog
	 * SIGXCPU disposition (sigxcpu_handler) is installed once per
	 * child in mask_signals_child() and is now restored by the same
	 * arm-site probe that reinstalls SIGALRM.  Sampled from the same
	 * arm sites as the SIGALRM probe -- the probe is effectively
	 * free (one extra rt_sigaction read) and surfacing SIGXCPU
	 * separately keeps the SIGALRM signal clean.  RELAXED add-fetch;
	 * same caveat as the SIGALRM row above. */
	unsigned long watchdog_sigxcpu_clobbered;

	/* Companion counters to the two _clobbered rows above: bumped
	 * alongside a clobber when the arm-site probe restores the
	 * expected inner-watchdog handler via sigaction() before arming
	 * alarm(1).  Every reinstall bumps both rows; keeping the repair
	 * counter separate leaves the raw clobber incidence intact for
	 * comparison with earlier read-only-probe runs.  Same probe
	 * sites, same RELAXED semantics as the paired _clobbered row. */
	unsigned long watchdog_sigalrm_reinstalled;
	unsigned long watchdog_sigxcpu_reinstalled;

	/* close_racer accounting.  See stats/subsys/close_racer.h. */
	struct close_racer_stats close_racer __attribute__((aligned(64)));

	/* socket_family_chain accounting.  See stats/subsys/socket_family_chain.h. */
	struct socket_family_chain_stats socket_family_chain __attribute__((aligned(64)));

	/* socket_family_grammar accounting.  See stats/subsys/socket_family_grammar.h. */
	struct socket_family_grammar_stats socket_family_grammar __attribute__((aligned(64)));

	/* Number of dispatches inside tracefs_fuzzer that landed on a
	 * function-tracer-subset op (set_ftrace_filter / set_ftrace_notrace /
	 * set_graph_function / current_tracer) but were short-circuited
	 * because the running kernel was built without CONFIG_FTRACE
	 * (current_tracer absent at init probe).  Static-event-tree paths
	 * keep running on the same kernel; this counts only the wasted
	 * function-tracer slots. */
	unsigned long tracefs_ftrace_subset_skipped;

	/* Auto-skipped socket families.  See stats/subsys/no_domains.h. */
	struct no_domains_stats no_domains __attribute__((aligned(64)));

	/* tls_rotate accounting.  See stats/subsys/tls_rotate.h. */
	struct tls_rotate_stats tls_rotate __attribute__((aligned(64)));

	/* sock_ulp_sockmap_layering childop counters */
	unsigned long sock_ulp_sockmap_layering_runs;		/* total invocations */
	unsigned long sock_ulp_sockmap_layering_setup_failed;	/* loopback TCP pair setup failed */
	unsigned long sock_ulp_sockmap_layering_map_failed;	/* BPF_MAP_CREATE(SOCKMAP) failed (no CONFIG_BPF_SYSCALL etc) */
	unsigned long sock_ulp_sockmap_layering_prog_failed;	/* BPF_PROG_LOAD(SK_SKB) failed (no CONFIG_BPF_STREAM_PARSER etc) */
	unsigned long sock_ulp_sockmap_layering_attach_failed;	/* BPF_PROG_ATTACH(STREAM_VERDICT) failed */
	unsigned long sock_ulp_sockmap_layering_layered_ok;	/* at least one fd ended up with both ULP+sockmap layered */

	/* packet_fanout_thrash childop counters */
	unsigned long packet_fanout_runs;		/* total packet_fanout_thrash invocations */
	unsigned long packet_fanout_setup_failed;	/* socket(AF_PACKET) failed (EPERM/no CONFIG_PACKET) */
	unsigned long packet_fanout_ring_failed;	/* PACKET_RX_RING setsockopt failed */
	unsigned long packet_fanout_rings_installed;	/* successful PACKET_RX_RING install */
	unsigned long packet_fanout_mmap_failed;	/* mmap of the RX ring failed */
	unsigned long packet_fanout_joins;		/* successful PACKET_FANOUT join */
	unsigned long packet_fanout_rejoins_ok;		/* second PACKET_FANOUT setsockopt accepted */
	unsigned long packet_fanout_rejoins_rejected;	/* second PACKET_FANOUT rejected (EALREADY etc) */

	/* eth_emitter childop counters: AF_PACKET/SOCK_RAW L2 emitter that
	 * crafts one frame per call from one of NR_TEMPLATES template
	 * families (ARP, IPv4 frag-zero, IPv6 NA, VLAN Q-in-Q, malformed
	 * EtherType) and sendto()s it to loopback.  per_tmpl[] indexes
	 * template successes so the operator can confirm coverage stays
	 * spread across all five families rather than collapsing on one. */
	unsigned long eth_emitter_runs;			/* total eth_emitter invocations */
	unsigned long eth_emitter_setup_failed;		/* socket(AF_PACKET) or bind() failed (EPERM/CAP_NET_RAW absent) */
	unsigned long eth_emitter_short;		/* template returned a length out of range; frame skipped */
	unsigned long eth_emitter_sends_ok;		/* sendto returned >0 */
	unsigned long eth_emitter_sends_failed;		/* sendto returned <=0 (queue full / EPERM / etc.) */
	unsigned long eth_emitter_per_tmpl[5];		/* per-template successful sends (NR_TEMPLATES in childops/net/eth-emitter.c) */

	/* pkt_builder_probe childop counters: prover for the composable
	 * layered structured-packet builder (include/pkt-builder.h + childops/
	 * net/pkt-builder.c).  per_recipe[] indexes deliveries per layer
	 * stack (NR_RECIPES in childops/net/pkt-builder-probe.c) so the
	 * operator can confirm coverage stays spread across all recipes.
	 * build/mutate/deliver counters split the pipeline so a regression
	 * in one stage is visible without cross-referencing another op. */
	unsigned long pkt_builder_runs;			/* total pkt_builder_probe invocations */
	unsigned long pkt_builder_setup_failed;		/* self-check failed or delivery latched off */
	unsigned long pkt_builder_built_ok;		/* pktb_push chain fully assembled */
	unsigned long pkt_builder_build_failed;		/* pktb_push refused a layer (overflow / bad kind) */
	unsigned long pkt_builder_mutated;		/* pktb_mutate_and_repair completed */
	unsigned long pkt_builder_truncated;		/* mutate pass hit a manifest truncation point */
	unsigned long pkt_builder_delivered_ok;		/* pktb_deliver returned >0 */
	unsigned long pkt_builder_delivery_failed;	/* pktb_deliver returned -1 / -2 (send error / bad frame) */
	unsigned long pkt_builder_delivery_disabled;	/* CAP_NET_RAW absent — permanent per-child latch */
	unsigned long pkt_builder_per_recipe[6];	/* per-recipe successful deliveries */

	/* iouring_net_multishot childop counters */
	unsigned long iouring_multishot_runs;		/* total iouring_net_multishot invocations */
	unsigned long iouring_multishot_setup_failed;	/* ring/socket/buffer-pool setup failed */
	unsigned long iouring_multishot_pbuf_ring_ok;	/* IORING_REGISTER_PBUF_RING accepted */
	unsigned long iouring_multishot_pbuf_legacy_ok;	/* fell back to PROVIDE_BUFFERS */
	unsigned long iouring_multishot_armed;		/* multishot RECV submitted+entered */
	unsigned long iouring_multishot_packets_sent;	/* peer UDP packets sendto()'d */
	unsigned long iouring_multishot_completions;	/* CQEs drained for the multishot */
	unsigned long iouring_multishot_cancel_submitted; /* ASYNC_CANCEL submitted+entered */
	unsigned long iouring_napi_register_ok;		/* IORING_REGISTER_NAPI accepted */
	unsigned long iouring_napi_register_fail;	/* IORING_REGISTER_NAPI rejected */
	unsigned long iouring_napi_unregister_ok;	/* IORING_UNREGISTER_NAPI accepted */
	unsigned long iouring_napi_unregister_fail;	/* IORING_UNREGISTER_NAPI rejected */

	/* tcp_ao_rotate accounting.  See stats/subsys/tcp_ao_rotate.h. */
	struct tcp_ao_rotate_stats tcp_ao_rotate __attribute__((aligned(64)));

	/* tcp_md5_listener_race childop counters */
	unsigned long tcp_md5_listener_race_runs;		/* total tcp_md5_listener_race invocations */
	unsigned long tcp_md5_listener_race_setup_failed;	/* loopback listen/socket/bind setup failed */
	unsigned long tcp_md5_listener_race_md5_set_ok;		/* TCP_MD5SIG install/rotate/delete accepted */
	unsigned long tcp_md5_listener_race_md5_set_failed;	/* TCP_MD5SIG rejected (EOPNOTSUPP/EINVAL/EPERM) */
	unsigned long tcp_md5_listener_race_connect_ok;		/* zero-linger client connect() egress observed */
	unsigned long tcp_md5_listener_race_rst_sent_ok;	/* zero-linger close() drove RST toward listener */
	unsigned long tcp_md5_listener_race_completed_ok;	/* full cycles reaching teardown */

	/* ipv6_ndisc_proxy accounting.  See stats/subsys/ipv6_ndisc_proxy.h. */
	struct ipv6_ndisc_proxy_stats ipv6_ndisc_proxy __attribute__((aligned(64)));

	/* ipfrag_source_churn childop counters */
	unsigned long ipfrag_source_runs;		/* total ipfrag_source_churn invocations */
	unsigned long ipfrag_packets_sent_ok;		/* raw IPv4 fragment sendto returned >0 */
	unsigned long ipfrag_send_failed;		/* sendto returned <=0 (queue full / EPERM / etc.) */
	unsigned long ipfrag_unique_srcs;		/* fragment pairs emitted with a fresh source IP */

	/* rtnl_vf_broadcast_getlink accounting.  See stats/subsys/rtnl_vf_broadcast.h. */
	struct rtnl_vf_broadcast_stats rtnl_vf_broadcast __attribute__((aligned(64)));

	/* obscure_af_churn childop counters.  Per-pattern arrays are
	 * indexed by enum abuse_pattern (childops/net/obscure-af-churn.c);
	 * NR_AP is currently 6.  Sized at 8 to leave headroom for a
	 * couple more patterns without re-cutting the shm layout. */
	unsigned long obscure_af_churn_runs;
	unsigned long obscure_af_churn_no_viable_pf;	/* every pf attempt was no_domains[] / proto NULL */
	unsigned long obscure_af_churn_pattern_runs[8];
	unsigned long obscure_af_churn_pattern_kernel_rejected[8];
	unsigned long obscure_af_churn_pattern_unexpected_success[8];

	/* ipv6_pmtu_race accounting.  See stats/subsys/ipv6_pmtu_race.h. */
	struct ipv6_pmtu_race_stats ipv6_pmtu_race __attribute__((aligned(64)));

	/* vrf_fib_churn childop counters */
	unsigned long vrf_fib_churn_runs;		/* total vrf_fib_churn invocations */
	unsigned long vrf_fib_churn_setup_failed;	/* unshare(CLONE_NEWNET) or rtnl socket failed */
	unsigned long vrf_fib_churn_link_ok;		/* RTM_NEWLINK kind=vrf accepted */
	unsigned long vrf_fib_churn_addr_ok;		/* RTM_NEWADDR on the vrf dev accepted */
	unsigned long vrf_fib_churn_up_ok;		/* RTM_NEWLINK setlink IFF_UP accepted */
	unsigned long vrf_fib_churn_rule_added;		/* RTM_NEWRULE FRA_TABLE accepted */
	unsigned long vrf_fib_churn_bound;		/* SO_BINDTODEVICE on the vrf accepted */
	unsigned long vrf_fib_churn_sendto_ok;		/* sendto() through bound vrf returned >=0 */
	unsigned long vrf_fib_churn_rule2_added;	/* mid-traffic higher-prio RTM_NEWRULE accepted */
	unsigned long vrf_fib_churn_rule_removed;	/* RTM_DELRULE for the bound rule accepted */
	unsigned long vrf_fib_churn_link_removed;	/* RTM_DELLINK vrf accepted (full cycle reached teardown) */

	/* ip6_udp_cork_splice accounting.  See stats/subsys/ip6_udp_cork_splice.h. */
	struct ip6_udp_cork_splice_stats ip6_udp_cork_splice __attribute__((aligned(64)));

	/* ip4_udp_cork_splice accounting.  See stats/subsys/ip4_udp_cork_splice.h. */
	struct ip4_udp_cork_splice_stats ip4_udp_cork_splice __attribute__((aligned(64)));

	/* mpls_route_churn accounting.  See stats/subsys/mpls_route_churn.h. */
	struct mpls_route_churn_stats mpls_route_churn __attribute__((aligned(64)));

	/* netlink_monitor_race accounting.  See stats/subsys/netlink_monitor_race.h. */
	struct netlink_monitor_race_stats netlink_monitor_race __attribute__((aligned(64)));

	/* tipc_link_churn childop counters */
	unsigned long tipc_link_churn_runs;		/* total tipc_link_churn invocations */
	unsigned long tipc_link_churn_setup_failed;	/* modprobe / AF_TIPC / family-resolve gate failed */
	unsigned long tipc_link_churn_bearer_enable_ok;	/* TIPC_NL_BEARER_ENABLE genl ack==0 */
	unsigned long tipc_link_churn_sock_rdm_ok;	/* socket(AF_TIPC, SOCK_RDM) returned >=0 */
	unsigned long tipc_link_churn_topsrv_connect_ok; /* SEQPACKET socket connected to TIPC_TOP_SRV */
	unsigned long tipc_link_churn_sub_ports_sent;	/* TIPC_SUB_PORTS subscription sent on topsrv socket */
	unsigned long tipc_link_churn_publish_ok;	/* bind() with TIPC_CLUSTER_SCOPE for publish accepted */
	unsigned long tipc_link_churn_bearer_disable_ok; /* TIPC_NL_BEARER_DISABLE genl ack==0 */

	/* tls_ulp_churn accounting.  See stats/subsys/tls_ulp_churn.h. */
	struct tls_ulp_churn_stats tls_ulp_churn __attribute__((aligned(64)));

	/* vxlan_encap_churn childop counters */
	unsigned long vxlan_encap_churn_runs;		/* total vxlan_encap_churn invocations */
	unsigned long vxlan_encap_churn_setup_failed;	/* unshare(CLONE_NEWNET) / rtnl_open / all-kinds latched */
	unsigned long vxlan_encap_churn_link_create_ok;	/* RTM_NEWLINK type=vxlan/gre/geneve accepted */
	unsigned long vxlan_encap_churn_fdb_add_ok;	/* RTM_NEWNEIGH NTF_SELF accepted (vxlan only) */
	unsigned long vxlan_encap_churn_link_up_ok;	/* RTM_NEWLINK setlink IFF_UP accepted */
	unsigned long vxlan_encap_churn_packet_sent_ok;	/* sendto on AF_PACKET raw bound to tunnel returned >0 */
	unsigned long vxlan_encap_churn_link_del_ok;	/* RTM_DELLINK accepted */

	/* ip_gre_churn accounting.  See stats/subsys/ip_gre_churn.h. */
	struct ip_gre_churn_stats ip_gre_churn __attribute__((aligned(64)));

	/* ovs_tunnel_vport_churn accounting.  See stats/subsys/ovs_tunnel_vport_churn.h. */
	struct ovs_tunnel_vport_churn_stats ovs_tunnel_vport_churn __attribute__((aligned(64)));

	/* bridge_fdb_stp childop counters */
	unsigned long bridge_fdb_stp_runs;		/* total bridge_fdb_stp invocations */
	unsigned long bridge_fdb_stp_setup_failed;	/* unshare(CLONE_NEWNET) / rtnl_open / bridge latched */
	unsigned long bridge_fdb_stp_bridge_create_ok;	/* RTM_NEWLINK type=bridge accepted */
	unsigned long bridge_fdb_stp_veth_create_ok;	/* RTM_NEWLINK type=veth accepted (per pair) */
	unsigned long bridge_fdb_stp_raw_send_ok;	/* AF_PACKET sendto on enslaved port returned >0 */
	unsigned long bridge_fdb_stp_stp_toggle_ok;	/* /sys/.../bridge/stp_state write succeeded */
	unsigned long bridge_fdb_stp_fdb_del_ok;	/* RTM_DELNEIGH on a learned fdb entry accepted */
	unsigned long bridge_fdb_stp_link_del_ok;	/* RTM_DELLINK on bridge accepted */
	unsigned long bridge_vlan_mass_runs;		/* mass-VLAN-add sub-mode invocations */
	unsigned long bridge_vlan_mass_max_n;		/* largest IFLA_BRIDGE_VLAN_INFO entry count attempted in one msg */
	unsigned long bridge_vlan_mass_enotbufs;	/* sendmsg -ENOBUFS / -EMSGSIZE on the oversize bulk message */

	/* bridge_conntrack_churn accounting.  See stats/subsys/bridge_ct.h. */
	struct bridge_ct_stats bridge_ct __attribute__((aligned(64)));

	/* bridge_ip6frag_refrag accounting.  See stats/subsys/bridge_ip6frag.h. */
	struct bridge_ip6frag_stats bridge_ip6frag __attribute__((aligned(64)));

	/* atm_vcc_churn childop counters */
	unsigned long atm_vcc_churn_runs;		/* total atm_vcc_churn invocations */
	unsigned long atm_vcc_churn_unsupported;	/* socket(AF_ATM*) returned EAFNOSUPPORT (CONFIG_ATM=n) */
	unsigned long atm_vcc_churn_socket_ok;		/* AF_ATMPVC/AF_ATMSVC vcc opened */
	unsigned long atm_vcc_churn_ioctls_sent;	/* ioctls dispatched against the vcc */
	unsigned long atm_vcc_churn_kernel_rejected;	/* ioctl returned <0 (expected without backend) */

	/* tty_ldisc_churn childop counters.  Targets the n_tty_receive_buf_standard
	 * KMSAN, n_tty_lookahead_flow_ctrl uninit, do_con_write slab-OOB cluster
	 * (May serial Monthly) plus the kbd_event UAFs (April input Monthly) by
	 * cycling pty pairs through TIOCSETD across 0..24, fuzzing per-iter
	 * write/read at the master end.  The per-disc histogram lets the operator
	 * see which N_* values are landing the most ldisc_set_ok hits, so a future
	 * dispatch can bias toward a struggling line discipline. */
	unsigned long tty_ldisc_churn_runs;		/* total tty_ldisc_churn invocations */
	unsigned long tty_ldisc_churn_setup_failed;	/* posix_openpt / grantpt / unlockpt / ptsname_r / open(pts) failed */
	unsigned long tty_ldisc_churn_ldisc_set_ok;	/* TIOCSETD accepted */
	unsigned long tty_ldisc_churn_ldisc_set_failed;	/* TIOCSETD rejected (autoload miss, gated, etc.) */
	unsigned long tty_ldisc_churn_write_ok;		/* write() at the pts end returned > 0 */
	unsigned long tty_ldisc_churn_read_ok;		/* read() at the master end returned > 0 */
	unsigned long tty_ldisc_churn_ldisc_set_ok_per_disc[25];	/* per-N_* hit histogram (slot 21 / N_GSM stays zero) */

	/* nftables_churn childop counters */
	unsigned long nftables_churn_runs;		/* total nftables_churn invocations */
	unsigned long nftables_churn_setup_failed;	/* unshare / nfnl_open / nf_tables latched */
	unsigned long nftables_churn_table_create_ok;	/* NFT_MSG_NEWTABLE accepted */
	unsigned long nftables_churn_set_create_ok;	/* NFT_MSG_NEWSET (anonymous) accepted */
	unsigned long nftables_churn_chain_create_ok;	/* NFT_MSG_NEWCHAIN (base or aux) accepted */
	unsigned long nftables_churn_rule_create_ok;	/* NFT_MSG_NEWRULE (append) accepted */
	unsigned long nftables_churn_packet_sent_ok;	/* loopback UDP sendto returned >0 (drives input hook) */
	unsigned long nftables_churn_rule_insert_ok;	/* NFT_MSG_NEWRULE at NFTA_RULE_POSITION accepted */
	unsigned long nftables_churn_rule_del_ok;	/* NFT_MSG_DELRULE bulk-del accepted */
	unsigned long nftables_churn_table_del_ok;	/* NFT_MSG_DELTABLE accepted */
	unsigned long nftables_churn_payload_expr_emit;	/* NEWRULE carried a structured nft_payload expression */
	unsigned long nftables_churn_meta_expr_emit;	/* NEWRULE carried a structured nft_meta expression */
	unsigned long nftables_churn_lookup_expr_emit;	/* NEWRULE carried a structured nft_lookup expression */
	unsigned long nftables_churn_log_expr_emit;	/* NEWRULE carried a structured nft_log expression */
	unsigned long nftables_churn_bitwise_expr_emit;	/* NEWRULE carried a structured nft_bitwise expression */
	unsigned long nftables_churn_cmp_expr_emit;	/* NEWRULE carried a structured nft_cmp expression */
	unsigned long nftables_churn_range_expr_emit;	/* NEWRULE carried a structured nft_range expression */
	unsigned long nftables_churn_byteorder_expr_emit;	/* NEWRULE carried a structured nft_byteorder expression */
	unsigned long nftables_churn_socket_expr_emit;	/* NEWRULE carried a structured nft_socket expression */
	unsigned long nftables_churn_quota_expr_emit;	/* NEWRULE carried a structured nft_quota expression */
	unsigned long nftables_churn_limit_expr_emit;	/* NEWRULE carried a structured nft_limit expression */
	unsigned long nftables_churn_numgen_expr_emit;	/* NEWRULE carried a structured nft_numgen expression */
	unsigned long nftables_churn_hash_expr_emit;	/* NEWRULE carried a structured nft_hash expression */
	unsigned long nftables_churn_synproxy_expr_emit;	/* NEWRULE carried a structured nft_synproxy expression */
	unsigned long nftables_churn_counter_expr_emit;	/* NEWRULE carried a structured nft_counter expression */
	unsigned long nftables_churn_connlimit_expr_emit;	/* NEWRULE carried a structured nft_connlimit expression */
	unsigned long nftables_churn_masq_expr_emit;	/* NEWRULE carried a structured nft_masq expression */
	unsigned long nftables_churn_redir_expr_emit;	/* NEWRULE carried a structured nft_redir expression */
	unsigned long nftables_churn_tproxy_expr_emit;	/* NEWRULE carried a structured nft_tproxy expression */
	unsigned long nftables_churn_xfrm_expr_emit;	/* NEWRULE carried a structured nft_xfrm expression */
	unsigned long nftables_churn_dup_netdev_expr_emit;	/* NEWRULE carried a structured nft_dup_netdev expression */
	unsigned long nftables_churn_dup_ipv4_expr_emit;	/* NEWRULE carried a structured nft_dup_ipv4 expression */
	unsigned long nftables_churn_dup_ipv6_expr_emit;	/* NEWRULE carried a structured nft_dup_ipv6 expression */
	unsigned long nftables_churn_fwd_netdev_expr_emit;	/* NEWRULE carried a structured nft_fwd_netdev expression */
	unsigned long nftables_churn_last_expr_emit;	/* NEWRULE carried a structured nft_last expression */
	unsigned long nftables_churn_rt_expr_emit;	/* NEWRULE carried a structured nft_rt expression */
	unsigned long nftables_churn_fib_expr_emit;	/* NEWRULE carried a structured nft_fib expression */
	unsigned long nftables_churn_exthdr_expr_emit;	/* NEWRULE carried a structured nft_exthdr expression */
	unsigned long nftables_churn_osf_expr_emit;	/* NEWRULE carried a structured nft_osf expression */
	unsigned long nftables_churn_queue_expr_emit;	/* NEWRULE carried a structured nft_queue expression */
	unsigned long nftables_churn_immediate_expr_emit;	/* NEWRULE carried a structured nft_immediate expression */
	unsigned long nftables_churn_dynset_expr_emit;	/* NEWRULE carried a structured nft_dynset expression */
	unsigned long nftables_churn_ct_expr_emit;	/* NEWRULE carried a structured nft_ct expression */
	unsigned long nftables_churn_objref_expr_emit;	/* NEWRULE carried a structured nft_objref expression */
	unsigned long nft_compat_validate_install_ok;		/* (target, hook) chain+rule accepted */
	unsigned long nft_compat_validate_install_fail;		/* (target, hook) chain+rule rejected (non-unsupported) */
	unsigned long nft_compat_validate_unsupported;		/* EOPNOTSUPP/EPROTONOSUPPORT (compat target absent) */
	unsigned long nft_compat_validate_per_hook_pairs;	/* (target, hook) pair install attempts */
	unsigned long nft_dormant_abort_iters;		/* dormant-table abort sub-mode invocations */
	unsigned long nft_dormant_abort_eperm;		/* sendmsg EPERM (CAP_NET_ADMIN gate) -- latches */
	unsigned long nft_dormant_abort_emsg;		/* sendmsg failures other than EPERM */
	unsigned long nft_dormant_abort_ok;		/* batch sent + drain completed */
	unsigned long xt_ct_iters;		/* xt_CT usersize sub-mode invocations */
	unsigned long xt_ct_eperm;		/* setsockopt EPERM (CAP_NET_ADMIN gate) -- latches */
	unsigned long xt_ct_unsupported;	/* xt_CT module absent (ENOENT/EOPNOTSUPP/ENOPROTOOPT) -- latches */
	unsigned long xt_ct_set_ok;		/* IPT/IP6T_SO_SET_REPLACE accepted */
	unsigned long xt_ct_get_ok;		/* IPT/IP6T_SO_GET_ENTRIES accepted (xt_target_to_user reply path) */
	unsigned long xt_ct_v2_seen;		/* revision 2 path actually accepted on this kernel */
	unsigned long nft_fwd_loop_runs;		/* nft_fwd_netdev loop sub-mode invocations */
	unsigned long nft_fwd_loop_ns_setup_failed;	/* veth/addr/netdev-table install failed -- latches */
	unsigned long nft_fwd_loop_probe_sent_ok;	/* ICMP probe via raw socket sendto returned >0 */
	unsigned long nft_fwd_loop_completed_ok;	/* full setup + chains + rules + probe completed */
	unsigned long nft_l4frag_iters;			/* L4-aware-on-fragment sub-mode invocations */
	unsigned long nft_l4frag_install_ok;		/* table + pre-defrag chain install accepted */
	unsigned long nft_l4frag_rule_ok;		/* NEWRULE carrying socket/tproxy/exthdr/osf accepted */
	unsigned long nft_l4frag_send_ok;		/* raw IPv4 fragment sendto returned >0 */
	unsigned long nft_l4frag_send_failed;		/* raw IPv4 fragment sendto returned <=0 (incl. EPERM on raw open) */

	/* tc_qdisc_churn childop counters */
	unsigned long tc_qdisc_churn_runs;		/* total tc_qdisc_churn invocations */
	unsigned long tc_qdisc_churn_setup_failed;	/* unshare / rtnl_open / dummy latched */
	unsigned long tc_qdisc_churn_link_create_ok;	/* RTM_NEWLINK type=dummy accepted */
	unsigned long tc_qdisc_churn_qdisc_create_ok;	/* RTM_NEWQDISC root accepted */
	unsigned long tc_qdisc_churn_tclass_create_ok;	/* RTM_NEWTCLASS accepted (per class) */
	unsigned long tc_qdisc_churn_tfilter_create_ok;	/* RTM_NEWTFILTER accepted */
	unsigned long tc_qdisc_churn_packet_sent_ok;	/* loopback UDP sendto on dummy returned >0 */
	unsigned long tc_qdisc_churn_qdisc_replace_ok;	/* RTM_NEWQDISC NLM_F_REPLACE accepted (mid-flow swap) */
	unsigned long tc_qdisc_churn_tfilter_del_ok;	/* RTM_DELTFILTER bulk-del accepted */
	unsigned long tc_qdisc_churn_qdisc_del_ok;	/* RTM_DELQDISC root accepted */
	unsigned long tc_qdisc_churn_link_del_ok;	/* RTM_DELLINK on dummy accepted */
	unsigned long tc_qdisc_peek_stack_runs;		/* deliberate peek-x-peek stack sub-mode fired */
	unsigned long tc_qdisc_peek_stack_install_ok;	/* parent + child grafted successfully */
	unsigned long tc_qdisc_peek_stack_install_fail;	/* parent or child install rejected */
	unsigned long tc_qdisc_peek_stack_burst_ok;	/* loopback UDP sendto on stacked tree returned >0 */
	unsigned long tc_qdisc_churn_bridge_parent_runs;	/* iter used a bridge slave veth as qdisc parent */
	unsigned long tc_qdisc_churn_bridge_dellink_race_ok;	/* RTM_DELLINK on bridge slave port accepted (raced flush burst) */
	unsigned long tc_qdisc_churn_gso_burst_ok;	/* UDP_SEGMENT sendto produced a GSO skb (reaches qdisc_pkt_len_segs_init) */

	/* tc_mirred_blockcast childop counters */
	unsigned long tc_mirred_blockcast_runs;		/* total tc_mirred_blockcast invocations */
	unsigned long tc_mirred_blockcast_setup_failed;	/* unshare / NETLINK_ROUTE open latched */
	unsigned long tc_mirred_blockcast_qdisc_ok;	/* clsact + TCA_EGRESS_BLOCK install accepted (per device) */
	unsigned long tc_mirred_blockcast_qdisc_fail;	/* clsact + TCA_EGRESS_BLOCK install rejected */
	unsigned long tc_mirred_blockcast_filter_ok;	/* matchall+mirred(blockid) on shared block accepted */
	unsigned long tc_mirred_blockcast_filter_fail;	/* matchall+mirred(blockid) on shared block rejected */
	unsigned long tc_mirred_blockcast_packet_sent_ok;	/* loopback UDP sendto on A bound dummy returned >0 */

	/* tc_live_traffic childop counters */
	unsigned long tc_live_traffic_runs;		/* total tc_live_traffic invocations */
	unsigned long tc_live_traffic_setup_failed;	/* userns / rtnl open / grandchild fork latched */
	unsigned long tc_live_traffic_qdisc_ok;		/* clsact install on the A veth end accepted */
	unsigned long tc_live_traffic_qdisc_fail;	/* clsact install on the A veth end rejected */
	unsigned long tc_live_traffic_filter_ok;	/* initial matchall+gact/mirred filter install accepted */
	unsigned long tc_live_traffic_filter_fail;	/* initial matchall+gact/mirred filter install rejected */
	unsigned long tc_live_traffic_filter_del_ok;	/* mid-burst RTM_DELTFILTER on the running slot accepted */
	unsigned long tc_live_traffic_filter_replace_ok;	/* mid-burst RTM_NEWTFILTER at a new prio slot accepted (races tcf_classify) */
	unsigned long tc_live_traffic_packet_sent_ok;	/* live UDP sendto through the classified ingress path returned >0 */
	unsigned long tc_live_traffic_link_del_ok;	/* RTM_DELLINK on the A veth end at teardown accepted */
	unsigned long tc_live_traffic_bpf_load_ok;	/* cls_bpf BPF_PROG_LOAD (SCHED_CLS) accepted */
	unsigned long tc_live_traffic_xdp_load_ok;	/* BPF_PROG_LOAD (BPF_PROG_TYPE_XDP) for the XDP-pass sub-chain accepted */
	unsigned long tc_live_traffic_xdp_attach_ok;	/* RTM_NEWLINK IFLA_XDP attach on the A veth end accepted */

	/* xfrm_churn childop counters */
	unsigned long xfrm_churn_runs;			/* total xfrm_churn invocations */
	unsigned long xfrm_churn_setup_failed;		/* unshare / NETLINK_XFRM open latched */
	unsigned long xfrm_churn_sa_added;		/* XFRM_MSG_NEWSA accepted */
	unsigned long xfrm_churn_tunnel_sa_added;	/* XFRM_MSG_NEWSA accepted with mode=XFRM_MODE_TUNNEL */
	unsigned long xfrm_churn_iptfs_sa_added;	/* XFRM_MSG_NEWSA accepted with mode=XFRM_MODE_IPTFS */
	unsigned long xfrm_churn_sa_updated;		/* XFRM_MSG_UPDSA accepted (mid-flow rekey) */
	unsigned long xfrm_churn_sa_deleted;		/* XFRM_MSG_DELSA accepted */
	unsigned long xfrm_churn_pol_added;		/* XFRM_MSG_NEWPOLICY accepted */
	unsigned long xfrm_churn_pol_deleted;		/* XFRM_MSG_DELPOLICY accepted */
	unsigned long xfrm_churn_esp_sent;		/* loopback UDP send through SP/SA bundle returned >0 */
	unsigned long xfrm_churn_zc_sent;		/* MSG_ZEROCOPY sendto returned >0 (SKBFL_SHARED_FRAG reached) */
	unsigned long xfrm_churn_zc_errq_drained;	/* SO_EE_ORIGIN_ZEROCOPY completions drained per burst */
	unsigned long xfrm_churn_pfkey_send_ok;		/* PF_KEYv2 SADB_FLUSH send returned >0 */
	unsigned long xfrm_ah_esn_setup_ok;		/* AH+ESN+async-algo NEWSA accepted */
	unsigned long xfrm_ah_esn_setup_fail;		/* AH+ESN+async-algo NEWSA rejected */
	unsigned long xfrm_ah_esn_async_runs;		/* AH+ESN+async-algo sub-mode invocations */
	unsigned long xfrm_ah_esn_delsa_races;		/* AH+ESN+async-algo DELSA accepted (race window) */
	unsigned long xfrm_churn_burn_runs;		/* burn-this-netns branch attempted */
	unsigned long xfrm_churn_burn_throttled;	/* burn-this-netns skipped: MAX_CONCURRENT_NEWNET cap reached */
	unsigned long xfrm_churn_burn_completed;	/* burn-this-netns reached the readers + larval insert */
	unsigned long xfrm_compat_sweep_runs;		/* xfrm_compat_msg_sweep sub-mode invocations */
	unsigned long xfrm_compat_sends_ok;		/* sweep sendto returned >= 0 */
	unsigned long xfrm_compat_sends_failed;		/* sweep sendto returned < 0 */
	unsigned long xfrm_compat_replies_seen;		/* sweep recv returned > 0 */

	/* nat_t_churn childop counters */
	unsigned long nat_t_churn_runs;			/* total nat_t_churn invocations */
	unsigned long nat_t_churn_setup_failed;		/* unshare / NETLINK_XFRM open latched */
	unsigned long nat_t_churn_sa_added;		/* XFRM_MSG_NEWSA with XFRMA_ENCAP accepted */
	unsigned long nat_t_churn_sa_deleted;		/* XFRM_MSG_DELSA accepted */
	unsigned long nat_t_churn_frames_sent;		/* ESP-in-UDP sendto returned >0 */
	/* nat_t_churn IPv6 / UDPv6-encap-ESP error-path branch counters.
	 * Drives the xfrm6 dst error path on UDPv6-encapsulated ESP SAs:
	 * AF_INET6 socket + UDP_ENCAP_ESPINUDP[_NON_IKE] + xfrm v6 SA +
	 * sendto an unreachable 2001:db8::/32 destination so the kernel
	 * walks xfrm_lookup -> esp6_output -> error-return path. */
	unsigned long nat_t_xfrm6_setup_ok;		/* AF_INET6 NEWSA + UDPv6 socket primed */
	unsigned long nat_t_xfrm6_setup_fail;		/* NEWSA / sock / setsockopt rejected */
	unsigned long nat_t_xfrm6_sendto_runs;		/* sendto() to unreachable v6 dest issued */
	unsigned long nat_t_xfrm6_delsa_races;		/* DELSA accepted while sendto burst inflight */

	/* bpf_cgroup_attach accounting.  See stats/subsys/bpf_cgroup_attach.h. */
	struct bpf_cgroup_attach_stats bpf_cgroup_attach __attribute__((aligned(64)));

	/* sctp_assoc_churn childop counters */
	unsigned long sctp_assoc_churn_runs;			/* total sctp_assoc_churn invocations */
	unsigned long sctp_assoc_churn_setup_failed;		/* socket/bind/listen setup failed (incl. !CONFIG_IP_SCTP) */
	unsigned long sctp_assoc_churn_bindx_added;		/* SCTP_SOCKOPT_BINDX_ADD accepted (incl. ASCONF emit) */
	unsigned long sctp_assoc_churn_bindx_removed;		/* SCTP_SOCKOPT_BINDX_REM accepted (incl. ASCONF emit) */
	unsigned long sctp_assoc_churn_bindx_rejected;		/* bindx ADD/REM rejected (EOPNOTSUPP/EADDRINUSE/EINVAL) */
	unsigned long sctp_assoc_churn_connect_failed;		/* SCTP_SOCKOPT_CONNECTX failed (non-EINPROGRESS) */
	unsigned long sctp_assoc_churn_connected;		/* connectx accepted/in-progress */
	unsigned long sctp_assoc_churn_accepted;		/* server-side accept() returned an assoc fd */
	unsigned long sctp_assoc_churn_packets_sent;		/* send() through ASCONF / data path returned >0 */
	unsigned long sctp_assoc_churn_peeled_off;		/* SCTP_SOCKOPT_PEELOFF accepted (assoc detach race) */
	unsigned long sctp_assoc_churn_peeloff_rejected;	/* peeloff rejected (EINVAL/ENOENT) */
	unsigned long sctp_assoc_churn_cycles;			/* full cycles reaching teardown */

	/* sctp_chunk_rx childop counters */
	unsigned long sctp_chunk_rx_runs;			/* total sctp_chunk_rx invocations */
	unsigned long sctp_chunk_rx_setup_failed;		/* userns_run_in_ns / listener / raw setup failed (incl. !CONFIG_IP_SCTP) */
	unsigned long sctp_chunk_rx_listener_ok;		/* SCTP listener created + bound + listen() accepted */
	unsigned long sctp_chunk_rx_packet_sent_ok;		/* sendto on IPPROTO_RAW returned >0 */

	/* esp_crafted_rx childop counters */
	unsigned long esp_crafted_rx_runs;			/* total esp_crafted_rx invocations */
	unsigned long esp_crafted_rx_setup_failed;		/* userns_run_in_ns / NETLINK_XFRM open failed (incl. kind-latched or !CONFIG_XFRM) */
	unsigned long esp_crafted_rx_sa_install_ok;		/* XFRM_MSG_NEWSA installing an inbound null-cipher/null-auth ESP SA accepted */
	unsigned long esp_crafted_rx_sa_install_failed;		/* XFRM_MSG_NEWSA rejected (any errno) */
	unsigned long esp_crafted_rx_packet_sent_ok;		/* sendto on IPPROTO_RAW (v4 or v6) returned >0 */
	unsigned long esp_crafted_rx_sa_delete_ok;		/* XFRM_MSG_DELSA on teardown accepted */
	unsigned long esp_crafted_rx_stacked_sa_install_ok;	/* one of the XFRM_MAX_DEPTH v6 stacked null-ESP SAs installed */
	unsigned long esp_crafted_rx_stacked_sent_ok;		/* sendto on IPPROTO_RAW v6 for a max-depth stacked-ESP frame returned >0 */

	/* fou_gue_mcast_rx childop counters */
	unsigned long fou_gue_mcast_rx_runs;			/* total fou_gue_mcast_rx invocations */
	unsigned long fou_gue_mcast_rx_setup_failed;		/* userns_run_in_ns / genl_open("fou") open failed (incl. kind-latched or !CONFIG_NET_FOU) */
	unsigned long fou_gue_mcast_rx_port_install_ok;		/* FOU_CMD_ADD installing a FOU/GUE receive port accepted */
	unsigned long fou_gue_mcast_rx_port_install_failed;	/* FOU_CMD_ADD rejected (any errno) */
	unsigned long fou_gue_mcast_rx_packet_sent_ok;		/* sendto on IPPROTO_RAW (v4 or v6) with UDP-encap frame returned >0 */
	unsigned long fou_gue_mcast_rx_port_delete_ok;		/* FOU_CMD_DEL on teardown accepted */

	/* geneve_rx childop counters */
	unsigned long geneve_rx_runs;			/* total geneve_rx invocations */
	unsigned long geneve_rx_setup_failed;		/* userns_run_in_ns / rtnl_open failed (incl. kind-latched or !CONFIG_GENEVE) */
	unsigned long geneve_rx_link_create_ok;		/* RTM_NEWLINK kind="geneve" accepted */
	unsigned long geneve_rx_link_create_failed;	/* RTM_NEWLINK rejected (any errno) */
	unsigned long geneve_rx_link_up_ok;		/* RTM_SETLINK IFF_UP on the geneve dev accepted */
	unsigned long geneve_rx_packet_sent_ok;		/* sendto on IPPROTO_RAW with UDP/GENEVE frame returned >0 */
	unsigned long geneve_rx_link_del_ok;		/* RTM_DELLINK on teardown accepted */

	/* bareudp_rx childop counters */
	unsigned long bareudp_rx_runs;			/* total bareudp_rx invocations */
	unsigned long bareudp_rx_setup_failed;		/* userns_run_in_ns / rtnl_open failed (incl. kind-latched or !CONFIG_BAREUDP) */
	unsigned long bareudp_rx_link_create_ok;	/* RTM_NEWLINK kind="bareudp" accepted */
	unsigned long bareudp_rx_link_create_failed;	/* RTM_NEWLINK rejected (any errno) */
	unsigned long bareudp_rx_link_up_ok;		/* RTM_SETLINK IFF_UP on the bareudp dev accepted */
	unsigned long bareudp_rx_packet_sent_ok;	/* sendto on IPPROTO_RAW with UDP/inner-L3 frame returned >0 */
	unsigned long bareudp_rx_link_del_ok;		/* RTM_DELLINK on teardown accepted */

	/* mpls_label_stack_rx childop counters */
	unsigned long mpls_label_stack_rx_runs;			/* total mpls_label_stack_rx invocations */
	unsigned long mpls_label_stack_rx_setup_failed;		/* userns_run_in_ns / rtnl_open / lo lookup failed (incl. kind-latched or !CONFIG_MPLS_ROUTING) */
	unsigned long mpls_label_stack_rx_config_ok;		/* net.mpls.platform_labels + conf.lo.input writes accepted */
	unsigned long mpls_label_stack_rx_config_failed;	/* sysctl open/write rejected (any errno) */
	unsigned long mpls_label_stack_rx_link_up_ok;		/* RTM_SETLINK IFF_UP on lo accepted */
	unsigned long mpls_label_stack_rx_packet_sent_ok;	/* sendto on AF_PACKET with ETH_P_MPLS_UC frame returned >0 */

	/* bridge_ip6_refrag_fraggap childop counters */
	unsigned long bridge_ip6_refrag_fraggap_runs;		/* total bridge_ip6_refrag_fraggap invocations */
	unsigned long bridge_ip6_refrag_fraggap_brnf_enabled;	/* bridge-nf-call-ip6tables sysctl write accepted */
	unsigned long bridge_ip6_refrag_fraggap_bursts;		/* per-iter frag-pair emission bursts inside the netns */
	unsigned long bridge_ip6_refrag_fraggap_frags_sent;	/* individual fragment frames sendto returned >0 */

	/* mptcp_pm_churn childop counters */
	unsigned long mptcp_pm_churn_runs;			/* total mptcp_pm_churn invocations */
	unsigned long mptcp_pm_churn_setup_failed;		/* socket/bind/listen/connect setup failed */
	unsigned long mptcp_pm_churn_sock_mptcp_ok;		/* IPPROTO_MPTCP server socket created (CONFIG_MPTCP=y) */
	unsigned long mptcp_pm_churn_addr_added_ok;		/* MPTCP_PM_CMD_ADD_ADDR ack 0 (endpoint installed) */
	unsigned long mptcp_pm_churn_addr_removed_ok;		/* MPTCP_PM_CMD_DEL_ADDR ack 0 (subflow teardown raced data) */
	unsigned long mptcp_pm_churn_send_ok;			/* send() through the live MPTCP socket returned >0 */
	unsigned long mptcp_setsockopt_unsupported;		/* IPPROTO_MPTCP socket() rejected during setsockopt_all_sf recipe */
	unsigned long mptcp_setsockopt_master_set;		/* setsockopt() on master mptcp socket succeeded */
	unsigned long mptcp_setsockopt_master_fail;		/* setsockopt() on master mptcp socket failed */
	unsigned long mptcp_getsockopt_verify_ok;		/* getsockopt() readback matched the value just set */
	unsigned long mptcp_getsockopt_verify_drift;		/* getsockopt() readback diverged from set value */
	unsigned long mptcp_sockopt_sweep_runs;			/* sockopt-inheritance sweep sub-mode invocations */
	unsigned long mptcp_sockopt_set_ok;			/* sweep: setsockopt() on master mptcp socket succeeded */
	unsigned long mptcp_sockopt_set_failed;			/* sweep: setsockopt() on master mptcp socket failed */
	unsigned long mptcp_sockopt_subflow_added;		/* sweep: MPTCP_INFO num_subflows bumped after ADD_ADDR */
	unsigned long mptcp_sockopt_readback_ok;		/* sweep: post-subflow getsockopt() returned the option */
	unsigned long mptcp_sockopt_inherit_mismatch;		/* sweep: master readback != value set (70ece9d7021c bug-signal) */
	unsigned long mptcp_sockopt_unsupported_latched;	/* sweep: opt latched out after EOPNOTSUPP/ENOPROTOOPT */

	/* devlink_port_churn childop counters */
	unsigned long devlink_port_churn_iterations;		/* per-loop iteration completed */
	unsigned long devlink_port_churn_split_ok;		/* DEVLINK_CMD_PORT_SPLIT ack 0 */
	unsigned long devlink_port_churn_split_fail;		/* DEVLINK_CMD_PORT_SPLIT non-zero ack (expected sometimes) */
	unsigned long devlink_port_churn_reload_ok;		/* DEVLINK_CMD_RELOAD action=DRIVER_REINIT ack 0 */
	unsigned long devlink_port_churn_reload_fail;		/* DEVLINK_CMD_RELOAD non-zero ack */
	unsigned long devlink_port_churn_create_skipped;	/* netdevsim absent / sysfs unwritable */

	/* handshake_req_abort accounting.  See stats/subsys/handshake_req_abort.h. */
	struct handshake_req_abort_stats handshake_req_abort __attribute__((aligned(64)));

	/* nf_conntrack_helper_churn accounting.  See stats/subsys/nf_conntrack_helper_churn.h. */
	struct nf_conntrack_helper_churn_stats nf_conntrack_helper_churn __attribute__((aligned(64)));

	/* ipset_churn accounting.  See stats/subsys/ipset_churn.h. */
	struct ipset_churn_stats ipset_churn __attribute__((aligned(64)));

	/* af_unix_scm_rights_gc accounting.  See stats/subsys/af_unix_scm_rights_gc.h. */
	struct af_unix_scm_rights_gc_stats af_unix_scm_rights_gc __attribute__((aligned(64)));

	/* af_unix_peek_race accounting.  See stats/subsys/af_unix_peek_race.h. */
	struct af_unix_peek_race_stats af_unix_peek_race __attribute__((aligned(64)));

	/* sysv_shm_orphan_race childop counters */
	unsigned long sysv_shm_orphan_race_runs;		/* total sysv_shm_orphan_race invocations */
	unsigned long sysv_shm_orphan_race_setup_failed;	/* probe latch fired or per-iter shared-state alloc failed */
	unsigned long sysv_shm_orphan_race_shmget_ok;		/* originator shmget(IPC_PRIVATE) created a fresh segment */
	unsigned long sysv_shm_orphan_race_shmget_failed;	/* originator shmget() failed or never published shmid */
	unsigned long sysv_shm_orphan_race_attach_ok;		/* parent / solo-burst shmat() returned a valid address */
	unsigned long sysv_shm_orphan_race_attach_failed;	/* parent / solo-burst shmat() returned -1 (typically EIDRM after destroy) */
	unsigned long sysv_shm_orphan_race_rmid_ok;		/* shmctl(IPC_RMID) returned 0 (originator already-RMID'd path NOT counted here) */
	unsigned long sysv_shm_orphan_race_rmid_failed;	/* shmctl(IPC_RMID) returned -1 (typically EIDRM; segment already destroyed -- expected coverage) */
	unsigned long sysv_shm_orphan_race_sibling_spawn_ok;	/* clone3(SIGCHLD) originator/attacher sibling spawned */
	unsigned long sysv_shm_orphan_race_sibling_spawn_failed;/* clone3() failed; fell back to single-task race burst */
	unsigned long sysv_shm_orphan_race_sibling_reaped_ok;	/* sibling exited normally and was reaped by parent */
	unsigned long sysv_shm_orphan_race_sibling_crashed;	/* sibling killed by signal (SEGV/BUS/KILL) -- forensic hint */

	/* map_shared_stress accounting.  See stats/subsys/map_shared_stress.h. */
	struct map_shared_stress_stats map_shared_stress __attribute__((aligned(64)));

	/* qrtr_bind_race childop counters */
	unsigned long qrtr_bind_race_runs;			/* total qrtr_bind_race invocations */
	unsigned long qrtr_bind_race_setup_failed;		/* AF_QRTR socket() probe latch fired */
	unsigned long qrtr_bind_race_iter;			/* outer-loop iterations entered */
	unsigned long qrtr_bind_race_fork_failed;		/* fork() of a bind worker failed */
	unsigned long qrtr_bind_race_spawn_pair_ok;		/* both bind workers spawned for this round */
	unsigned long qrtr_bind_race_sibling_reaped_ok;		/* worker exited normally and was reaped */
	unsigned long qrtr_bind_race_sibling_crashed;		/* worker killed by signal (SEGV/BUS/KILL) -- forensic hint */
	/* In-worker setup-fail: bumped from the forked bind-child when its
	 * own socket(AF_QRTR) or getsockname() returns -1 before the bind
	 * attempt.  Distinct from qrtr_bind_race_setup_failed, which only
	 * fires from the parent-side probe latch and is invisible to a worker
	 * that crashes during its own per-iter setup phase.  Without this
	 * counter an op whose workers all fail setup looks identical to one
	 * that succeeded silently. */
	unsigned long qrtr_bind_setup_fail;

	/* pfkey_spd_walk childop counters */
	unsigned long pfkey_spd_walk_runs;			/* total pfkey_spd_walk invocations */
	unsigned long pfkey_spd_walk_setup_failed;		/* AF_KEY probe or netns unshare latch fired */
	unsigned long pfkey_spd_walk_iter;			/* outer-loop iterations entered */
	unsigned long pfkey_spd_walk_fork_failed;		/* fork() of a walker/racer worker failed */
	unsigned long pfkey_spd_walk_spawn_pair_ok;		/* both walker + racer spawned for this round */
	unsigned long pfkey_spd_walk_sibling_reaped_ok;		/* worker exited normally and was reaped */
	unsigned long pfkey_spd_walk_sibling_crashed;		/* worker killed by signal (SEGV/BUS/KILL) -- forensic hint */
	/* SPDGET resolution counters.  The racer alternates SADB_X_SPDDUMP
	 * with SADB_X_SPDGET against a small set of policy ids; the SPDDUMP
	 * arm always finds something to walk, but kernel-assigned policy
	 * ids are sparse and the SPDGET arm typically never lands on a live
	 * id.  pfkey_spdget_resolved bumps when an inbound SPDGET reply
	 * carries sadb_msg_errno == 0 (the kernel resolved the id);
	 * pfkey_spdget_missed bumps when the reply carries a nonzero errno
	 * (typically -ESRCH).  A 0% resolved rate over a long run flags
	 * that the SPDGET arm is contributing no real coverage and the id
	 * pool needs to be steered toward live ids -- counter-only here;
	 * the sparse-id root cause is tracked separately. */
	unsigned long pfkey_spdget_resolved;
	unsigned long pfkey_spdget_missed;

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

	/* tcp_ulp_swap_churn childop counters */
	unsigned long tcp_ulp_swap_churn_runs;			/* total tcp_ulp_swap_churn invocations */
	unsigned long tcp_ulp_swap_churn_setup_failed;		/* loopback pair / connect / unsupported latch fired */
	unsigned long tcp_ulp_swap_churn_install_tls_ok;	/* setsockopt(TCP_ULP, "tls") accepted on connected sock */
	unsigned long tcp_ulp_swap_churn_tx_install_ok;		/* setsockopt(SOL_TLS, TLS_TX, &cinfo) accepted */
	unsigned long tcp_ulp_swap_churn_send_ok;		/* tls_sw_sendmsg drove a record onto the wire */
	unsigned long tcp_ulp_swap_churn_swap_rejected_ok;	/* setsockopt(TCP_ULP, "espintcp"|"smc") rejected post-connect (the bug surface) */
	unsigned long tcp_ulp_swap_churn_ifname_probe_ok;	/* SIOCGIFNAME / SIOCSIFNAME probe completed without disturbing lo */
	unsigned long tcp_ulp_swap_churn_uninstall_ok;		/* setsockopt(TCP_ULP, "") uninstall accepted */
	unsigned long tcp_ulp_swap_churn_reinstall_ok;		/* second setsockopt(TCP_ULP, "tls") accepted (re-init path) */
	unsigned long tcp_ulp_swap_churn_install_failed;	/* TCP_ULP install non-latch failure (runtime errno bump) */

	/* msg_zerocopy_churn accounting.  See stats/subsys/msg_zerocopy_churn.h. */
	struct msg_zerocopy_churn_stats msg_zerocopy_churn __attribute__((aligned(64)));

	/* rds_zcopy_crafted_send childop counters */
	unsigned long rds_zcopy_crafted_send_runs;			/* total rds_zcopy_crafted_send invocations */
	unsigned long rds_zcopy_crafted_send_setup_failed;		/* socket(AF_RDS) / bind / SO_ZEROCOPY / mmap / unsupported latch fired */
	unsigned long rds_zcopy_crafted_send_bind_ok;			/* bind(AF_RDS, 127.0.0.1:0) accepted */
	unsigned long rds_zcopy_crafted_send_zc_enable_ok;		/* setsockopt(SO_ZEROCOPY, 1) accepted on the AF_RDS sock */
	unsigned long rds_zcopy_crafted_send_hole_ok;			/* munmap punched a hole in the backing region (pin walk will fault) */
	unsigned long rds_zcopy_crafted_send_sends_ok;			/* sendmsg(MSG_ZEROCOPY) returned >=0 (full pin walk completed) */
	unsigned long rds_zcopy_crafted_send_sends_efault;		/* sendmsg(MSG_ZEROCOPY) returned EFAULT (partial-pin unwind reached) */
	unsigned long rds_zcopy_crafted_send_sends_failed;		/* sendmsg(MSG_ZEROCOPY) returned a non-EFAULT error (any errno) */
	unsigned long rds_zcopy_crafted_send_errqueue_drained;		/* recvmsg(MSG_ERRQUEUE) drained at least one zcopy completion cookie */

	/* iouring_send_zc_churn accounting.  See stats/subsys/iouring_send_zc_churn.h. */
	struct iouring_send_zc_churn_stats iouring_send_zc_churn __attribute__((aligned(64)));

	/* vsock_transport_churn childop counters */
	unsigned long vsock_transport_churn_runs;			/* total vsock_transport_churn invocations */
	unsigned long vsock_transport_churn_setup_failed;		/* socket / bind / listen / connect / unsupported latch fired */
	unsigned long vsock_transport_churn_bind_ok;			/* bind(VMADDR_CID_LOCAL) + listen accepted */
	unsigned long vsock_transport_churn_connect_ok;		/* loopback connect to listener accepted */
	unsigned long vsock_transport_churn_send_ok;			/* send(MSG_DONTWAIT) returned >=0 on the loopback transport */
	unsigned long vsock_transport_churn_buffer_size_ok;	/* setsockopt(SO_VM_SOCKETS_BUFFER_SIZE) accepted mid-flow */
	unsigned long vsock_transport_churn_timeout_ok;		/* setsockopt(SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW) accepted mid-flow */
	unsigned long vsock_transport_churn_get_cid_ok;		/* ioctl(IOCTL_VM_SOCKETS_GET_LOCAL_CID) returned the local cid */
	unsigned long vsock_seq_eom_runs;			/* SEQ_EOM 0-length burst sub-mode invocations */
	unsigned long vsock_seq_eom_sends_ok;			/* sendmsg(MSG_EOR, iov_len=0) returned >= 0 */
	unsigned long vsock_seq_eom_sends_failed;		/* sendmsg(MSG_EOR, iov_len=0) returned < 0 */
	unsigned long vsock_seq_eom_skipped;			/* sub-mode gated out: no socket / unsupported / wall-cap */

	/* bridge_vlan_churn accounting.  See stats/subsys/bridge_vlan_churn.h. */
	struct bridge_vlan_churn_stats bridge_vlan_churn __attribute__((aligned(64)));

	/* vlan_filter_churn accounting.  See stats/subsys/vlan_filter_churn.h. */
	struct vlan_filter_churn_stats vlan_filter_churn __attribute__((aligned(64)));

	/* igmp_mld_source_churn accounting.  See stats/subsys/igmp_mld_source_churn.h. */
	struct igmp_mld_source_churn_stats igmp_mld_source_churn __attribute__((aligned(64)));

	/* psp_key_rotate childop counters */
	unsigned long psp_key_rotate_runs;			/* total psp_key_rotate invocations */
	unsigned long psp_key_rotate_setup_failed;		/* unshare / netlink open / family probe latched */
	unsigned long psp_key_rotate_netdev_create_ok;		/* rtnl RTM_NEWLINK netdevsim accepted */
	unsigned long psp_key_rotate_family_resolve_ok;		/* CTRL_CMD_GETFAMILY resolved PSP family id */
	unsigned long psp_key_rotate_dev_get_ok;		/* PSP_CMD_DEV_GET dump returned without error */
	unsigned long psp_key_rotate_key_install_ok;		/* initial PSP_CMD_KEY_ROTATE accepted */
	unsigned long psp_key_rotate_spi_set_ok;		/* PSP_CMD_TX_ASSOC bound socket fd to dev (spec: spi_set_ok) */
	unsigned long psp_key_rotate_send_ok;			/* send() over PSP-bound socket returned >0 */
	unsigned long psp_key_rotate_rotate_ok;			/* mid-flow PSP_CMD_KEY_ROTATE accepted (race target) */
	unsigned long psp_key_rotate_spi_switch_ok;		/* mid-flow PSP_CMD_TX_ASSOC re-bind accepted */
	unsigned long psp_key_rotate_shutdown_ok;		/* shutdown(SHUT_RDWR) on PSP-bound socket returned 0 */

	/* psp_key_rotate sub-mode: psp_devlink_port_churn counters */
	unsigned long psp_devlink_port_churn_runs;		/* sub-mode invocations */
	unsigned long psp_devlink_port_churn_port_add_ok;	/* DEVLINK_CMD_PORT_NEW accepted */
	unsigned long psp_devlink_port_churn_port_del_ok;	/* DEVLINK_CMD_PORT_DEL accepted */
	unsigned long psp_devlink_port_churn_vf_spawn_ok;	/* sriov_numvfs write accepted */
	unsigned long psp_devlink_port_churn_unsupported_latched; /* family resolve / netdevsim spawn latched */

	/* afxdp_churn childop counters */
	unsigned long afxdp_churn_runs;				/* total afxdp_churn invocations */
	unsigned long afxdp_churn_setup_failed;			/* socket / mmap / setsockopt / cap-gate latched */
	unsigned long afxdp_churn_umem_reg_ok;			/* setsockopt(XDP_UMEM_REG) accepted */
	unsigned long afxdp_churn_rings_setup_ok;		/* all four XDP_*_RING setsockopts accepted */
	unsigned long afxdp_churn_prog_load_ok;			/* bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_XDP) accepted */
	unsigned long afxdp_churn_map_create_ok;		/* bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_XSKMAP) accepted */
	unsigned long afxdp_churn_map_update_ok;		/* bpf(BPF_MAP_UPDATE_ELEM) installed xsk_fd at xskmap key */
	unsigned long afxdp_churn_bind_ok;			/* bind(XDP_USE_NEED_WAKEUP, lo, qid=0) accepted */
	unsigned long afxdp_churn_link_attach_ok;		/* bpf(BPF_LINK_CREATE, BPF_XDP) attached prog to lo */
	unsigned long afxdp_churn_netlink_attach_ok;		/* RTM_NEWLINK + IFLA_XDP_FD fallback attached prog to lo */
	unsigned long afxdp_churn_attach_failed;		/* both attach paths failed -- RACE A window stays cold */
	unsigned long afxdp_churn_send_ok;			/* sendto() kick on bound xsk returned >=0 (or EAGAIN/ENOBUFS/EBUSY) */
	unsigned long afxdp_churn_recv_ok;			/* getsockopt(XDP_STATISTICS) on bound xsk succeeded */
	unsigned long afxdp_churn_map_delete_ok;		/* bpf(BPF_MAP_DELETE_ELEM) on bound xskmap key (race target) */
	unsigned long afxdp_churn_munmap_race_ok;		/* munmap of FILL ring while bound (race target) */
	unsigned long afxdp_xsg_iters;				/* per-iter knob enable_sg=1: USE_SG umem + XDP_USE_SG bind + chained TX desc */
	unsigned long afxdp_tx_metadata_iters;			/* per-iter knob enable_tx_md=1: tx_metadata_len umem + XDP_TX_METADATA stamp */
	unsigned long afxdp_tun_bind_iters;			/* per-iter knob: bound to tun (IFF_NAPI|IFF_NAPI_FRAGS) instead of lo */
	unsigned long afxdp_xsg_bind_failed;			/* UMEM_REG with XDP_UMEM_FLAGS_USE_SG rejected; latched off, retried without */
	unsigned long afxdp_tx_md_bind_failed;			/* UMEM_REG with tx_metadata_len rejected; latched off, retried without */

	/* veth_asymmetric_xdp childop counters */
	unsigned long veth_asym_iters;				/* total veth_asymmetric_xdp invocations */
	unsigned long veth_asym_eperm;				/* unshare/NEWLINK rejected with EPERM */
	unsigned long veth_asym_unsupported;			/* veth or XDP latched off (separate latches inside the op) */
	unsigned long veth_asym_pair_ok;			/* RTM_NEWLINK created an asymmetric-queue veth pair */
	unsigned long veth_asym_xdp_attach_ok;			/* RTM_NEWLINK + IFLA_XDP attached the prog (SKB mode) */
	unsigned long veth_asym_send_ok;

	/* ip6gre_bond_lapb_stack accounting.  See stats/subsys/ip6gre_lapb.h. */
	struct ip6gre_lapb_stats ip6gre_lapb __attribute__((aligned(64)));

	/* wireguard_decrypt_flood accounting.  See stats/subsys/wgdf.h. */
	struct wgdf_stats wgdf __attribute__((aligned(64)));

	/* blkdev_lifecycle_race accounting.  See stats/subsys/blkdev_lifecycle.h. */
	struct blkdev_lifecycle_stats blkdev_lifecycle __attribute__((aligned(64)));

	/* hfs_mount_fuzz accounting.  See stats/subsys/hfs_mount_fuzz.h. */
	struct hfs_mount_fuzz_stats hfs_mount_fuzz __attribute__((aligned(64)));

	/* iscsi_target_probe accounting.  See stats/subsys/iscsi_target_probe.h. */
	struct iscsi_target_probe_stats iscsi_target_probe __attribute__((aligned(64)));

	/* iscsi_walker accounting.  See stats/subsys/iscsi_walker.h. */
	struct iscsi_walker_stats iscsi_walker __attribute__((aligned(64)));

	/* ip6erspan_netns_migrate childop counters */
	unsigned long inm_iters;				/* total ip6erspan_netns_migrate invocations */
	unsigned long inm_eperm;				/* unshare/NEWLINK rejected with EPERM */
	unsigned long inm_unsupported;				/* per-kind ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP at create */
	unsigned long inm_link_create_ok;			/* RTM_NEWLINK created the link in the original ns */
	unsigned long inm_netns_migrate_ok;			/* RTM_SETLINK IFLA_NET_NS_FD moved the link to the sibling ns */
	unsigned long inm_changelink_ok;			/* RTM_NEWLINK NLM_F_REPLACE in target ns walked ->changelink */			/* AF_PACKET sendto to peer veth returned >0 */

	/* netdev_netns_migrate childop counters */
	unsigned long nnm_iters;				/* total netdev_netns_migrate invocations */
	unsigned long nnm_eperm;				/* helper -EPERM or RTM_NEWLINK EPERM */
	unsigned long nnm_unsupported;				/* per-kind ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP at create */
	unsigned long nnm_pin_sock_ok;				/* AF_INET SOCK_DGRAM pinned in source ns */
	unsigned long nnm_link_create_ok;			/* RTM_NEWLINK created the netdev in the source ns */
	unsigned long nnm_migrate_ok;				/* RTM_SETLINK IFLA_NET_NS_FD moved the netdev to the sibling ns */
	unsigned long nnm_migrate_rejected;			/* setlink IFLA_NET_NS_FD returned EOPNOTSUPP/EINVAL */
	unsigned long nnm_up_ok;				/* RTM_SETLINK IFF_UP in target ns succeeded */
	unsigned long nnm_addr_ok;				/* RTM_NEWADDR IPv4 in target ns succeeded */

	/* ipvs_sysctl_writer childop counters */
	unsigned long ipvs_sysctl_writer_runs;			/* total ipvs_sysctl_writer invocations */
	unsigned long ipvs_sysctl_writer_writes_ok;		/* sysctl write returned >0 */
	unsigned long ipvs_sysctl_writer_writes_failed;		/* open or write failed (kernel rejected payload) */
	unsigned long ipvs_sysctl_writer_unsupported_latched;	/* unshare/open ENOENT latched op off */
	unsigned long ipvs_sysctl_writer_burn_iters;		/* short-lived TCP connect/close iters into the in-test virtual service */

	/* flowtable_vlan accounting.  See stats/subsys/flowtable_vlan.h. */
	struct flowtable_vlan_stats flowtable_vlan __attribute__((aligned(64)));

	/* slab_cache_thrash childop: per-target burst invocation count,
	 * indexed by enum slab_target (defined in slab-cache-thrash.c, kept
	 * private to the childop since nothing else needs the symbolic
	 * names).  NR_SLAB_TARGETS is asserted equal to the enum tail at
	 * build time inside the childop, so a future target added there
	 * without resizing this array is caught by the assert. */
	unsigned long slab_cache_thrash_runs[NR_SLAB_TARGETS];

	/* ---- Group D: diagnostic / parent-side / one-shot ---- */

	/* fd lifecycle tracking */
	unsigned long fd_stale_detected __attribute__((aligned(64)));
	unsigned long fd_stale_by_generation;
	unsigned long fd_closed_tracked;
	unsigned long fd_duped;
	unsigned long fd_events_processed;
	unsigned long fd_events_dropped;
	/* Per-event-type counters bumped from apply_slot().  CLOSE means a
	 * child genuinely closed the fd; EVICT means the parent watchdog
	 * is expiring a stale pool slot whose fd may still be valid in a
	 * sibling.  Split so the two paths stay observable. */
	unsigned long fd_event_close_count;
	unsigned long fd_event_evict_count;

	/* get_random_fd() hit GET_RANDOM_FD_BUDGET outer iterations and
	 * returned -1 to its caller.  Non-zero means a child was about
	 * to tight-loop in argument generation (PREP-state record, so
	 * is_child_making_progress() can't see it) and we bailed instead.
	 * Persistent non-zero indicates fd providers exhausted, broken,
	 * or persistently returning untracked/<=2 fds. */
	unsigned long fd_random_exhausted;

	/* get_new_random_fd() drew a NULL entry from active_providers[] (or a
	 * provider with a NULL ->get).  Every registered provider has a
	 * non-NULL compile-time ->get and the pool is filled once at init, so
	 * a NULL here means the zmalloc'd active_providers array (or
	 * num_active_providers) was scribbled by an out-of-bounds write
	 * elsewhere -- a heap-corruption canary, not a normal condition.  The
	 * draw is retried within the existing inner budget; persistent
	 * non-zero is a strong corruption signal. */
	unsigned long fd_provider_invalid;

	/* fd_hash_reinsert() exhausted the linear-probe chain without
	 * finding a free slot and silently dropped the displaced entry.
	 * Only reachable when fd_hash_count == FD_HASH_SIZE; non-zero
	 * means we lost an fd registration during a removal-driven
	 * re-seat and the per-iter outputerr names which fd. */
	unsigned long fd_hash_reinsert_dropped;

	/* local_fd_hash_insert() exhausted the linear-probe chain in a
	 * per-child objhead's fd_hash[] (LOCAL_FD_HASH_SIZE slots) and
	 * silently returned without inserting.  Subsequent
	 * find_local_object_by_fd() lookups for that fd will return NULL
	 * and the operation drops the object metadata.  Non-zero means
	 * a child has more concurrent fds of one type than the per-child
	 * hash can index; the existing behaviour is preserved (still a
	 * silent return) — this counter just makes the loss visible. */
	unsigned long local_fd_hash_insert_dropped;

	/* Number of times a child won the CAS in arm_epoll_if_needed() and
	 * actually performed the EPOLL_CTL_ADD population for an unarmed
	 * epfd.  Should rise once per epfd seeded by init_epoll_fds().
	 * A flat counter means children aren't picking unarmed epfds —
	 * either the consumer wireup regressed or no one is calling
	 * get_typed_fd(ARG_FD_EPOLL) / get_rand_epoll_fd. */
	unsigned long epoll_lazy_armed;

	/* Number of fd-pickup attempts the watch-set sanitisers (arm_epoll,
	 * sanitise_epoll_ctl, sanitise_poll/ppoll, sanitise_select) refused
	 * because the candidate fd belonged to an fd_provider whose
	 * poll_can_block tag was set (FUSE / userfaultfd / KVM vCPU /
	 * io_uring / pidfd).  Drop the kernel into the four ep_item_poll
	 * blocking-poll callsites (do_epoll_ctl + ep_send_events +
	 * __ep_eventpoll_poll + ep_loop_check_proc) without this filter and
	 * a single FUSE daemon dying takes 100+ child slots into
	 * TASK_UNINTERRUPTIBLE on the per-fd waitqueue, which the watchdog
	 * cannot break and defer-slot-reuse cannot recycle.  A non-zero
	 * counter alongside steady epoll_lazy_armed growth means the filter
	 * is doing work; a flat counter while D-state child counts climb
	 * means a new blocking-poll fd_provider escaped the tagging. */
	unsigned long epoll_blocking_poll_skipped;

	/* Number of fds the generic ret_objtype post-hook auto-registered
	 * into a per-type OBJ_LOCAL pool because no syscall-specific .post
	 * had already done so. */
	unsigned long fd_runtime_registered;

	/* fd_runtime_skipped accounting.  See stats/subsys/fd_runtime_skipped.h. */
	struct fd_runtime_skipped_stats fd_runtime_skipped __attribute__((aligned(64)));

	/* Bumped by prop_ring_push_scalar() each time a typed scalar return
	 * (currently OBJ_KEY_SERIAL from register_returned_fd's add_key /
	 * keyctl path) was successfully mirrored into the per-child
	 * propagation ring after its own typed registrar accepted it.
	 * Reads as "key serials made available to untyped consumers via
	 * the prop_ring path" — distinct from kcov_shm->propagation_injected,
	 * which counts the consumer-side draws from the ring; this is the
	 * producer-side capture count for the bypass-the-OBJ_NONE-firewall
	 * push variant.  Skipped pushes (dedup against most recent slot,
	 * pointer-shape or fd-alias rejections, out-of-range) do NOT bump
	 * this -- the counter tracks publications, not call-attempts. */
	unsigned long propagation_injected_key_scalar;

	/* fds/bpf provisioning counters: cumulative count of fds we
	 * successfully published into the global object pool, including
	 * regenerations after stale-fd teardown.  Tells you how much of
	 * trinity's fd-providing infrastructure BPF actually contributes
	 * — zero means the kernel rejected every load and the BPF cross-
	 * subsystem surface (SO_ATTACH_BPF, PERF_EVENT_IOC_SET_BPF, etc.)
	 * is unreachable. */
	unsigned long bpf_maps_provided;
	unsigned long bpf_progs_provided;

	/* net/bpf/ebpf.c generator: cumulative count of programs that prepended
	 * an LD_MAP_FD loading a real bpf-map fd from the trinity object pool
	 * (Phase 3.3).  Bumped whenever the 5% base substitution rate or the
	 * tier2 dedicated map-exercise sub-strategy fires AND the pool had at
	 * least one map fd to hand out — empty-pool falls back silently to
	 * scalar-only generation and is not counted here. */
	unsigned long ebpf_gen_map_fd_substituted;

	/* Phase 3.4: bumped each time the eBPF generator emits a typed
	 * helper call — either via tier1's HELPER_CALL_WEIGHT_PCT lottery
	 * or the tier2 dedicated helper-call sub-strategy.  Counts only
	 * successful emissions; picks that bailed because no satisfiable
	 * helper existed in the current reg state (e.g. ARG_MAP_PTR with
	 * an empty map-reg slot) or the remaining buffer couldn't fit the
	 * arg-setup + CALL + EXIT do not increment this. */
	unsigned long ebpf_gen_helper_call_emitted;

	/* Phase 3.4.5: bumped each time the generator emits the map-value
	 * NULL-check + deref idiom after a map_lookup_elem.  Total counter
	 * plus a read/write breakdown: deref_read counts LDX_W loads of
	 * the value, deref_write counts STX_W stores; sum equals
	 * deref_emitted.  Gated on the 3% MAP_VAL_DEREF_WEIGHT_PCT lottery
	 * AND a live PTR_OR_NULL_TO_MAP_VALUE in R0 from a recent lookup,
	 * so the observed rate sits well below the lottery weight -- bumps
	 * here track the slice of programs that actually reach the
	 * verifier's check_map_access / map-value runtime path. */
	unsigned long ebpf_gen_map_value_deref_emitted;
	unsigned long ebpf_gen_map_value_deref_read;
	unsigned long ebpf_gen_map_value_deref_write;

	/* Slots held in zombie-pending state because the kernel still has
	 * the unkillable D-state task around and may yet wake it to write
	 * into childdata.  Reusing a slot before the kernel tears the task
	 * down lets the post-wake writes corrupt the replacement child. */
	unsigned long zombie_slots_pending;	/* current count (gauge) */
	unsigned long zombies_reaped;		/* total successfully reaped */
	unsigned long zombies_timed_out;	/* force-reused after timeout */

	/* sanitize_inherited_fds() closed an fd that the parent inherited
	 * from its launcher (or the launcher's parent) at startup.  We
	 * keep only {0,1,2} across the parent's fork boundary into the
	 * fuzz children; anything else came in from outside trinity and
	 * could end up being polled, watched, or otherwise wedged on by
	 * the reap path (e.g. a stuck-fs fd surfacing in the child-monitor
	 * watch set and blocking the parent's epoll/poll loop). */
	unsigned long parent_inherited_fds_closed;

	/* alloc_shared() / track_shared_region() ran with
	 * nr_shared_regions == MAX_SHARED_ALLOCS and parked the new region
	 * in the bounded overflow tail.  Non-zero means the static cap is
	 * demonstrably undersized -- consult this counter (not a guess) when
	 * deciding whether to raise MAX_SHARED_ALLOCS or move shared_regions[]
	 * to a dynamic registry.  Untracked-and-silent is no longer an option:
	 * range_overlaps_shared() relies on the bitmap, which the overflow
	 * path still sets, but a tail-exhaust BUG()s rather than under-
	 * protect. */
	unsigned long shared_region_overflow;

	/* fd-pool RAW observability -- ring-pointer canary rejections,
	 * event ring-full drop attribution, per-provider outstanding
	 * gauge, live-remove scan histogram, close-range enqueue
	 * accounting.  See stats/subsys/fd.h. */
	struct fd_stats fd __attribute__((aligned(64)));

	/* stats_ring_drain_all() found a child->stats_ring pointer that
	 * failed the canonical-address / minimum-address sanity check.
	 * Same defense-in-depth role as fd_event_ring_corrupted. */
	unsigned long stats_ring_corrupted;

	/* stats_ring_drain_all() found a live child->stats_ring that
	 * differed from the canary copy taken at init time.  Indicates
	 * the pointer was overwritten after init. */
	unsigned long stats_ring_overwritten;

	/* __destroy_object() rejected an obj whose array_idx didn't pass
	 * the head->array[array_idx] == obj invariant — either the index
	 * was out of bounds for the pool, or the slot held a different
	 * pointer.  Both shapes mean the obj's array_idx is stale or
	 * corrupted; following the swap-with-last would either OOB-write
	 * past head->array[num_entries) or destroy the unrelated object
	 * occupying that slot.  The destroy is dropped (no free, no
	 * destructor) and counted here. */
	unsigned long destroy_object_idx_corrupt;

	/* Bumped by objpool_check() on the bad-VA and wrong-type-tag
	 * rejection paths — i.e. the picker resolved a slot to an
	 * address that lies outside the user/heap VA window, or whose
	 * obj_type does not match the type the caller asked for.  Both
	 * shapes mean the consumer caught a wild or recycled obj
	 * pointer (release_obj() zeroes the chunk, and the
	 * deferred-free allocator can hand it back under the lockless
	 * reader) before dereferencing it.  The NULL/empty-pool path
	 * is not counted here. */
	unsigned long global_obj_uaf_caught;

	/* Bumped by childops/mm/pagecache-canary-check.c when a verifier
	 * read returned a byte that did not match the deterministic
	 * canary_expected_byte() pattern.  A non-zero counter here
	 * means a kernel code path mutated a canary file's contents
	 * mid-run via a route that bypassed the file's normal write-
	 * side validation — the bug class the oracle exists to catch.
	 * Each bump corresponds to one verifier invocation that found
	 * a divergence (the verifier logs offset+expected/actual
	 * windows and continues, so multiple invocations against the
	 * same corrupted file each contribute one bump). */
	unsigned long pagecache_canary_corrupt_caught;

	/* objhead_indexed_read() rejected a pick whose array snapshot
	 * either failed the cheap stateless provenance check on the
	 * captured head->array pointer, or whose post-load re-read of
	 * head->array_generation no longer matched the value sampled at
	 * pick time.  The first case is wild-pointer noise (early-init or
	 * a scribbled head->array); the second case is the racy-grow /
	 * teardown the field exists to detect -- an indexed read off a
	 * container the deferred-free TTL has handed back to glibc.
	 * Non-zero here means the array-generation gate caught the same
	 * UAF class the 0117 ASAN run flagged at get_random_object()'s
	 * head->array[idx] load. */
	unsigned long objpool_array_stale_caught;

	/* mmap-pool pick/reject accounting.  See stats/subsys/maps.h. */
	struct maps_stats maps __attribute__((aligned(64)));

	/* Per-rejection-reason sub-attributions of deferred_free_enqueue()
	 * in deferred-free.c.  The function has five distinct early-return
	 * rejection clauses; each of the five counters below is bumped once
	 * per call that exits via the corresponding clause.  Complementary
	 * to (does not replace):
	 *   - parent_stats.deferred_free_reject{,_pathname,_iovec,...}, which
	 *     attribute the corrupt-shape branch by post-handler argtype.
	 *   - parent_stats.snapshot_non_heap_reject, the parent/child shard
	 *     mechanism for the non-heap branch.
	 *   - the per-PC ring fed by deferred_free_reject_bump(), which
	 *     attributes the corrupt-shape and untracked branches by caller.
	 * What this block adds: a single shm->stats five-way split that
	 * makes the per-branch firing rate trivially comparable.  Lets
	 * residual-cores triage attribute observed reject windows (e.g. the
	 * 14/8/8-per-window seen at objects/registry.c add_object oldarray
	 * enqueue in run 1828) to a specific clause, and validates the
	 * alloc_track LRU widen post-rebuild by tracking the untracked
	 * branch's rate-of-change on the next live run.  Pure
	 * instrumentation -- no behaviour change. */

	/* ptr low bits set: ((unsigned long)ptr & 0x7) != 0.  glibc malloc
	 * always returns 8-byte aligned chunks on x86_64, so a low-bits-set
	 * candidate cannot be a real allocation start.  libasan CHECK-fails
	 * on misaligned addresses in its poisoning path before its bad-free
	 * reporter ever runs, so dropping these at the enqueue boundary
	 * preserves the symptom triage path.  See deferred-free.c clause 1. */
	unsigned long deferred_free_reject_misaligned;

	/* is_corrupt_ptr_shape(ptr) hit: pid-scribbled / canonical-out-of-
	 * range / heuristically-bad value reaching the enqueue.  Cluster
	 * 1/2/3 root cause (residual-cores triage 2026-05-02): sibling
	 * value-result syscall scribbles a tid/pid into rec->aN, post
	 * handler arrives here, N syscalls later deferred_free_tick() frees
	 * the pid -> SIGSEGV with si_addr==si_pid.  Complementary to the
	 * per-argtype parent_stats.deferred_free_reject_{pathname,iovec,
	 * sockaddr,other} attribution.  See deferred-free.c clause 2. */
	unsigned long deferred_free_reject_corrupt_shape;

	/* !is_in_glibc_heap(ptr): pointer passed shape heuristic but landed
	 * outside the brk arena cached at init (stack, library mapping,
	 * executable mapping, trinity's own MAP_PRIVATE region).  Cannot be
	 * a real malloc result, so the free() is undefined.  Complementary
	 * to parent_stats.snapshot_non_heap_reject (the parent/child shard
	 * mechanism for this same branch); this counter is the headline
	 * shm->stats sum the per-shard mechanism feeds into.  See
	 * deferred-free.c clause 3. */
	unsigned long deferred_free_reject_non_heap;

	/* !alloc_track_consume(ptr): ground-truth check refused a pointer
	 * that __zmalloc() never produced.  Same alloc_track LRU pressure
	 * class as [[maps_reject_alloc_track_miss]]: shared 256-slot LRU
	 * can rotate out legitimate live entries under fd-pressure
	 * cascades, false-rejecting them here.  Tracking this branch in
	 * isolation is the validation gate for the alloc_track 256->4096 widen:
	 * a successful widen should drive this counter's rate-of-change
	 * down on the next live run.  See deferred-free.c clause 4. */
	unsigned long deferred_free_reject_untracked;

	/* nested-address scrub (scrub_struct_addresses) refused to walk a
	 * struct base whose pointer either fails the stateless shape
	 * predicate (is_corrupt_ptr_shape: NULL-ish, non-canonical, or
	 * misaligned) or falls outside the cached glibc brk arena
	 * (is_in_glibc_heap).  Real zmalloc_tracked() struct slots always
	 * satisfy both; a pointer-shaped-but-invalid value scribbled into
	 * rec->aN (or into a nested FT_PTR_STRUCT/FT_PTR_ARRAY base field)
	 * by a sibling stomp in the publish->snapshot window does not, and
	 * dereferencing it would SEGV the sanitiser before the syscall
	 * fires.  Rate-of-change near zero on a clean run is the
	 * regression check that proves the guard is not false-rejecting
	 * legitimate struct bases.  See generate-args.c
	 * scrub_struct_addresses / nested_address_scrub. */
	unsigned long nested_scrub_reject_untracked;

	/* range_overlaps_shared(ptr, 1): pointer fell inside one of
	 * trinity's own mmap'd shared regions.  ASAN catches these as
	 * bad-free ("attempting free on address which was not malloc()-ed");
	 * non-ASAN runs silently corrupt the glibc allocator.  Root cause
	 * is always an arg generator handing back a tracked-mmap pointer
	 * for an arg slot whose argtype (PATHNAME, IOVEC, SOCKADDR) expects
	 * heap.  See deferred-free.c clause 5. */
	unsigned long deferred_free_reject_shared_region;

	/* post_state_release() rejected snap before deferred_freeptr.  The
	 * four-gate reject contract converts what used to be an
	 * abort-in-libc-free into a structured leak + counter bump.  See
	 * utils.c post_state_release for the gate ordering and rationale;
	 * the symmetric headline class is deferred_free_reject_untracked,
	 * which catches the same shape one layer down (post_state_release
	 * forwards a sanitised pointer into deferred_free_enqueue, so a
	 * non-zero counter here is the FIRST wall; the deferred_free_
	 * reject_* family is the SECOND wall for any reject path that
	 * still slips through).
	 *
	 *   _untracked      - snap absent from the ownership table.
	 *   _released       - snap already released by a prior call (the
	 *                     idempotency contract).
	 *   _wrong_owner    - snap is live but tagged to a different
	 *                     (syscall_nr, do32bit) than the caller.
	 *                     Skipped for untagged installers
	 *                     (post_state_register-only call sites).
	 *   _bad_magic      - snap is live and tagged to us but the
	 *                     leading-word cookie no longer matches the
	 *                     install-time magic.  Skipped for untagged
	 *                     installers (magic==0). */
	unsigned long post_state_release_reject_untracked;
	unsigned long post_state_release_reject_released;
	unsigned long post_state_release_reject_wrong_owner;
	unsigned long post_state_release_reject_bad_magic;

	/* deferred-free ring exerts pressure on the per-process VMA budget
	 * (/proc/sys/vm/max_map_count) via the mprotect bracket around its
	 * mmap'd ring page -- under fuzz pressure the bracket's RW flip can
	 * return -ENOMEM when the kernel runs out of VMA slots to split the
	 * surrounding mapping, at which point ring_unlock fails and the
	 * enqueue path can't access the slot.  The trio below surfaces the
	 * bound-and-fallback path that keeps the deferred-free instrumen-
	 * tation from killing a child whose VMA table fills up:
	 *
	 *   _outstanding_vmas: cross-fleet high-water mark of in-ring
	 *     deferred-free entries.  Each entry is one held-back free that
	 *     keeps an allocation (and its glibc-arena chunk) alive past its
	 *     natural lifetime; the conceptual model is one outstanding VMA
	 *     per entry, even though today's ring uses a single mprotect-
	 *     bracketed region rather than per-slot redzone mappings.  CAS
	 *     up-only so transient peaks survive a quieter trailing window.
	 *
	 *   _vma_fallback_immediate: soft-cap rejections -- enqueue saw the
	 *     local in-ring count above max_map_count/2 and routed the ptr
	 *     to immediate free() instead of admitting it.  The current
	 *     ring is bounded at 64 slots so the cap only fires on systems
	 *     with a small max_map_count (or if a future hardening pass
	 *     starts arming per-slot redzones), but tracking it keeps the
	 *     defensive bound observable for that case.
	 *
	 *   _enomem_drain: hard-cap events on the enqueue path -- ring_unlock
	 *     returned -ENOMEM despite the soft cap.  The ring is munmap'd
	 *     (releasing the VMA slot the kernel was short of) and the
	 *     current ptr is freed immediately so the caller's "no longer
	 *     your problem" contract holds; the ring stays NULL for the
	 *     rest of the child's life, so subsequent enqueues fall through
	 *     to plain free().  Non-zero is a real VMA-exhaustion event,
	 *     not a soft warning.
	 *
	 *   _rw_restore_enomem: same shape but on the drain path --
	 *     deferred_free_tick or deferred_free_flush couldn't restore RW
	 *     on the ring page before walking it.  The PROT_NONE page would
	 *     otherwise persist as fault-bait for sibling fuzzed value-
	 *     result syscalls, so the
	 *     drain path also munmap's the ring; the entries currently
	 *     queued are leaked (lost forever from glibc's tracking until
	 *     the child exits).  Cost of those leaks is bounded by the
	 *     64-slot ring; benefit is the page goes away instead of
	 *     thrashing on ENOMEM for the rest of the run. */
	unsigned long deferred_free_outstanding_vmas;
	unsigned long deferred_free_vma_fallback_immediate;
	unsigned long deferred_free_enomem_drain;
	unsigned long deferred_free_rw_restore_enomem;

	/* deferred_free_enqueue_or_leak() pressure path fired -- the
	 * queue refused to admit (VMA soft cap, ring==NULL after a prior
	 * ENOMEM dispose, RING_UNLOCK_ENOMEM, RING_UNLOCK_FAIL, or
	 * occupied_mask-saturated full-ring), and the variant
	 * intentionally LEAKED the ptr instead of falling back to a
	 * synchronous free().  The leak is bounded by the child's
	 * max_map_count and reclaimed at child exit; trinity child
	 * lifetimes are short, so a non-zero rate here is the visible
	 * cost of preserving "pre-dispatch caller does not own this
	 * buffer's lifecycle" against the UAF a sync free would
	 * otherwise cause.
	 *
	 * Bumped alongside the existing _vma_fallback_immediate /
	 * _enomem_drain counters (which keep counting the pressure
	 * EVENT) so operators can compare queue success rate against
	 * leak rate without having to subtract pre-dispatch hits out of
	 * a shared counter.  Companion to the pre-dispatch site
	 * migration (io_uring_setup, openat2, perf_event_open,
	 * landlock_create_ruleset, file/sched/mount/open_tree_attr,
	 * get/setxattrat, mq_open, listmount, statmount). */
	unsigned long deferred_free_pre_dispatch_leaked;

	/* rec_own() found rec->owned[] saturated at REC_OWNED_MAX and
	 * routed the overflowing pointer through deferred_free_enqueue()
	 * as the fallback owner.  The per-rec carrier is sized so this
	 * never fires in practice (heaviest in-tree callers own <= 3
	 * buffers; the bound is 8); a non-zero rate means a caller is
	 * registering more pointers per syscall than the carrier
	 * accommodates, and the fallback re-introduces the very
	 * pre-dispatch ring-enqueue shape the owned list was built to
	 * eliminate.  Treat any non-zero rate as a signal to either raise
	 * REC_OWNED_MAX or audit the offending caller -- the fallback is
	 * a safety net, not a steady-state path. */
	unsigned long rec_owned_overflow_to_ring;

	/* tracked_free_now() found @ptr already pinned in the deferred-
	 * free ring (inflight_hash_contains() == true at entry) and
	 * routed it through the ring-as-sole-owner path: alloc_track
	 * drained, free() skipped, inflight membership left intact so
	 * the TTL/evict path frees the chunk exactly once.  Non-zero
	 * empirically proves the ring-as-sole-owner path is engaged and
	 * the reuse-mediated double-free is closed off: an
	 * inflight_hash_remove() + free() here would let address reuse
	 * re-arm the value-keyed membership bit and
	 * ring_evict_oldest_safe() free the same address a second time.
	 * Rate-of-change is
	 * the headline metric: a count proportional to ring throughput
	 * is normal (any pointer admitted to the ring whose post-handler
	 * cleanup also routes through tracked_free_now() lands here);
	 * zero across a full run means either no such overlap occurs
	 * (suspect the gate isn't engaged) or the workload doesn't
	 * exercise it. */
	unsigned long deferred_free_ring_owned_skip;

	/* deferred_free_enqueue_internal() found @ptr already pinned in
	 * an occupied ring slot at admission time and refused to take a
	 * second slot.  Without this gate, an alloc_track_refresh() that
	 * re-admits a ring-resident @ptr lets the next enqueue pass the
	 * alloc_track_consume() check a second time and admit @ptr to
	 * two ring slots.  The reuse-mediated double-free then runs when
	 * the first slot's TTL fires and free()s @ptr; address reuse
	 * binds the same value to a new chunk; the second slot's TTL
	 * fires and free()s the new owner's chunk.  Non-zero proves the
	 * gate is engaged; rate-of-change correlates with refresh
	 * pressure on the maps.c / objects/ hot paths. */
	unsigned long deferred_free_double_admit_skip;

	/* tracked_free_now() could not verify ring residency because
	 * ring_unlock() returned non-OK (typically ENOMEM under VMA
	 * pressure -- same class as deferred_free_enomem_drain).  The
	 * chunk is leaked rather than freed because freeing without
	 * having verified the ring would risk a double-free against
	 * an eviction whose guards happen to pass.  Bounded by child
	 * lifetime; the kernel reclaims at exit.  Non-zero rate
	 * indicates VMA-pressure leaking into the cleanup path --
	 * correlate with deferred_free_enomem_drain. */
	unsigned long deferred_free_tracked_free_unverified_leak;

	/* ring_evict_oldest_safe() reclaimed a full-ring slot WITHOUT
	 * free()ing the evicted chunk.  Interim defense against the
	 * address-reuse window where a stale caller ref to a freed-and-
	 * reused chunk passes every value-keyed gate (heap-bounds,
	 * shared-region, alloc_track_consume) and eviction free()s a
	 * now-live chunk -- the surviving class of bad-free at the
	 * eviction site.  The durable fix is at the caller-lifecycle
	 * root (drop the retained ref).  This counter only fires when
	 * the ring is full (TTL eviction is rare given the 5-50 TTL
	 * range and per-syscall tick), so the leak is bounded; child
	 * exit reclaims it.  Cannot double-free because the site never
	 * free()s.  The RING_DRAIN / flush + immediate-free fallback
	 * paths intentionally KEEP freeing -- leaking everywhere would
	 * be a whole-ring RSS blowup, not a bounded eviction-only
	 * defense.  Expected to read as zero on a fixed caller chain;
	 * the next ASAN run is the validation gate (ring_evict bad-free
	 * count should drop to zero). */
	unsigned long ring_evict_leaked;

	/* alloc_track_refresh() found @ptr currently pinned in the
	 * deferred ring and skipped both the consume + re-add.  The
	 * ring already owns the chunk's lifecycle; re-admitting a
	 * fresh alloc_track entry for a ring-resident @ptr decouples
	 * that entry's lifetime from the original __zmalloc-time entry
	 * the ring's free-time consume gate relies on, leaving the
	 * address-reuse-then-stale-enqueue path through which eviction
	 * matches a fresh consume entry and free()s a now-live chunk
	 * owned by a different allocation.  Non-zero proves the gate
	 * is engaged on a refresh of a ring-resident ptr; rate-of-
	 * change correlates with the maps.c / objects/ refresh
	 * pressure that previously fed deferred_free_double_admit_skip
	 * at the enqueue dedup. */
	unsigned long alloc_track_refresh_ring_owned_skip;

	/* alloc_track_refresh() could not verify ring residency because
	 * ring_unlock() returned non-OK (typically ENOMEM under VMA
	 * pressure -- same class as deferred_free_enomem_drain).  The
	 * refresh is skipped entirely rather than risk re-adding a
	 * ring-resident @ptr; the only cost is the LRU position --
	 * the original alloc_track entry is untouched, so a follow-up
	 * lookup still resolves and the entry rotates out per the
	 * normal alloc_track[] aging.  Non-zero rate indicates VMA-
	 * pressure leaking into the refresh path -- correlate with
	 * deferred_free_enomem_drain and
	 * deferred_free_tracked_free_unverified_leak. */
	unsigned long alloc_track_refresh_unverified_skip;

	/* alloc_track_refresh() found @ptr was not currently tracked
	 * (alloc_track_consume miss) and bailed without re-inserting.
	 * Two indistinguishable causes: @ptr was a legitimate tracked
	 * allocation that rotated out under churn (the LRU bump is
	 * lost, the next deferred_free_enqueue rejects as untracked
	 * and leaks the chunk), or @ptr was never tracked -- a stale
	 * caller ref, an interior pointer derived from a scribbled
	 * head->array / localobj, or a fuzzed value-result syscall
	 * scribble.  The previous shape called deferred_alloc_track
	 * (@ptr, 0) unconditionally, which blessed the latter class
	 * as tracked and let the next tracked_free_checked() free() it
	 * -- ASAN bad-free at deferred-free.c:880 (free_ring_entry /
	 * ring_evict_oldest_safe / tracked_free_now) on an interior
	 * pointer that consume() approved on the falsely-blessed
	 * re-insert.  Non-zero proves the gate is engaged. */
	unsigned long alloc_track_refresh_consume_miss;

	/* Bumped by run_sequence_chain() when chain_corpus_pick() returns
	 * a chain_entry whose len is zero or greater than MAX_SEQ_LEN.
	 * The chain corpus is shared memory and tolerates lockless reads
	 * plus wild-write corruption; an out-of-range len would otherwise
	 * cause the replay loop to index past the stack-local replay.steps
	 * array before per-step safety checks ran.  Non-zero values mean
	 * the corpus saw either a torn lockless read or a real wild write
	 * into ring->slots[].len -- both are defended (fall back to a
	 * fresh chain) but worth tracking so spikes are visible. */
	unsigned long chain_replay_len_corrupt;

	/* Per-call abort counter for random_map_readfn().  Bumped each time
	 * the per-page memcpy in one of the read walks (read_one_page,
	 * read_whole_mapping, read_every_other_page, read_mapping_reverse,
	 * read_random_pages, read_last_page) takes a SIGBUS or SIGSEGV
	 * inside the sigsetjmp-guarded section and the walk siglongjmps out
	 * cleanly instead of killing the child.  Non-zero values surface
	 * the live truncate / hole-punch / MADV_REMOVE race rate against
	 * file-backed mmaps and the sibling-munmap rate against anon
	 * mappings — both are TOCTOU windows the local-snapshot+fstat clamp
	 * narrows but cannot fully close. */
	unsigned long read_walk_aborted;

	/* Per-call abort counter for random_map_writefn().  Bumped each time
	 * the per-page user store in one of the write walks (dirty_one_page,
	 * dirty_first_page, dirty_whole_mapping, dirty_every_other_page,
	 * dirty_mapping_reverse, dirty_random_pages, dirty_last_page) takes
	 * a SIGBUS or SIGSEGV inside the sigsetjmp-guarded section and the
	 * walk siglongjmps out cleanly instead of killing the child.  The
	 * write side already clamps via dirty_random_mapping (mm/maps.c)
	 * before dispatch, so this counter primarily reflects the residual
	 * sibling fallocate(PUNCH_HOLE) / fallocate(COLLAPSE_RANGE) /
	 * madvise(MADV_REMOVE) and ftruncate-shrink race rate that the
	 * pre-dispatch fstat cannot catch (st_size unchanged for hole punch,
	 * shrunk between clamp and store for ftruncate). */
	unsigned long write_walk_aborted;

	/* Number of bandit windows where the CMP-novelty term was non-zero
	 * after weighting -- i.e. the just-finished window saw at least
	 * CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL fresh comparison constants
	 * for the active arm and so contributed to the bandit's reward
	 * beyond the PC-edge headline signal.  Diagnostic: an operator can
	 * read this counter (and the per-arm cmp_share line in the strategy
	 * stats) to tell whether the CMP feedback is meaningfully steering
	 * arm selection or just tracking PC-edge growth.  Bumped from the
	 * CAS-serialised maybe_rotate_strategy() path so a plain unsigned
	 * long with __atomic_fetch_add suffices. */
	unsigned long bandit_cmp_reward_added;

	/* Sibling of bandit_cmp_reward_added for the edge-count secondary
	 * reward term (--bandit-reward-edge-count).  Bumped from
	 * bandit_record_pull() whenever the just-finished non-forced
	 * window's pc_edge_count delta produced a non-zero
	 * edge_count_term = pc_edge_count /
	 * EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL.  Bumped under both
	 * SHADOW_ONLY (where the term is computed but not folded into
	 * bandit_reward_calls[]) and COMBINED (where it is), so the counter
	 * measures "windows where the term would move the reward" rather
	 * than "windows where selection actually saw it" -- gives the
	 * operator a run's-worth of firing-rate data to gate the shadow-
	 * to-combined promotion on.  Bumped from the CAS-serialised
	 * maybe_rotate_strategy() path so a plain unsigned long with
	 * __atomic_fetch_add suffices, same discipline as
	 * bandit_cmp_reward_added above. */
	unsigned long bandit_edge_count_reward_added;

	/* STRATEGY_COVERAGE_FRONTIER picker observability -- pick regimes,
	 * per-syscall distributions, silent-streak decay shadow predicates,
	 * saturation-cooldown / barren-demote / live-cooldown / group-
	 * antilock shadow lanes, errno-plateau decay, cold-weight blend A/B.
	 * See stats/subsys/frontier.h. */
	struct frontier_stats frontier __attribute__((aligned(64)));

	/* Number of syscall picks the explorer pool forced to STRATEGY_RANDOM
	 * regardless of the bandit's current arm.  Bumped from set_syscall_nr
	 * when child->is_explorer is true.  Rate-of-change should track
	 * explorer_children * (per-child syscall throughput) -- divergence
	 * means the picker fast path is no longer respecting the explorer
	 * partition. */
	unsigned long strategy_explorer_picks;

	/* Calls by explorer-pool children that produced at least one new
	 * edge, bumped from dispatch_step's new-edge branch when
	 * child->is_explorer is true.  CALL-COUNT semantics: a call that
	 * uncovers 50 distinct edges bumps by 1, not 50 -- matches
	 * pc_edge_calls_by_strategy[]'s shape so the two are directly
	 * comparable.  Counted separately from the per-strategy series
	 * (which excludes explorer contributions to keep the bandit's
	 * reward signal honest) so the per-pool ratio is recoverable for
	 * tuning. */
	unsigned long explorer_pool_edges_discovered;

	/* Calls by non-explorer (bandit-pool) children that produced at least
	 * one new edge, bumped from the same branch in dispatch_step.  Equal
	 * to sum(pc_edge_calls_by_strategy[]) modulo the brief race between
	 * the per-strategy increment and the syscalls_at_last_switch CAS: the
	 * per-strategy counter is meaningful; this scalar gives the
	 * bandit-pool aggregate without iterating the per-strategy array.
	 * CALL-COUNT semantics, see explorer_pool_edges_discovered above. */
	unsigned long bandit_pool_edges_discovered;

	/* Per-syscall new-edge attribution, split by strategy pool.  Bumped
	 * from dispatch_step's new-edge branch with the real bucket-edge
	 * count returned by kcov_collect()'s new_edge_count out-param, so
	 * the increment matches the count of distinct new edges this syscall
	 * produced (NOT 1-per-call -- per_syscall_edges in kcov_shm uses
	 * that shape).  Earlier shape diff'd kcov_shm->edges_found around
	 * the call, which over-attributed other children's concurrent
	 * discoveries to whichever syscall happened to bracket them.
	 *
	 * Surfaced only via top_syscalls_periodic_dump() -- the array is
	 * sized 2 * MAX_NR_SYSCALL * sizeof(unsigned long) ~= 16 KiB and
	 * would dominate the JSON path; leaving it out of dump_stats keeps
	 * the consumer-of-JSON output stable while the dump tick gives the
	 * operator a per-pool top-N view of where each pool is finding
	 * coverage.  RELAXED add-fetch: cumulative diagnostic, not an event
	 * log; window deltas come from the dump's own snapshot+diff against
	 * its previous tick. */
	unsigned long edges_per_syscall_bandit[MAX_NR_SYSCALL];
	unsigned long edges_per_syscall_explorer[MAX_NR_SYSCALL];

	/* SHADOW-ONLY "deep but warm" call accounting.  A call qualifies
	 * when the post-collect signals show no new coverage of either
	 * kind -- new_edges == 0 AND new_cmp == 0 -- yet the call still
	 * executed a meaningful amount of kernel code, gauged by either:
	 *
	 *   (a) per-call local_distinct_pcs (dedup_inc first-sightings
	 *       walked in this trace) at least DEEP_WARM_PCS_MEAN_MULT
	 *       times the syscall's lifetime mean local_distinct_pcs, the
	 *       running mean being computed cheaply from the existing
	 *       per_syscall_diag[].distinct_pcs (sum across both arch
	 *       slots) divided by per_syscall_calls[nr].  Gated by a
	 *       warmup floor of DEEP_WARM_PCS_MIN_CALLS so the first
	 *       handful of calls on a syscall do not all qualify against
	 *       their own zero-mean.
	 *   (b) per-call PC trace length at least DEEP_WARM_TRACE_NUM /
	 *       DEEP_WARM_TRACE_DEN of the KCOV_TRACE_SIZE buffer cap --
	 *       a call that filled to 90% of the trace buffer ran a deep
	 *       slice of kernel even when bucket dedup zeroed out the
	 *       novelty signals.
	 *
	 * The two clauses are OR'd: either the per-call PC density
	 * outranks the syscall's own baseline, or the call approached
	 * raw trace truncation.  Both are population predicates that flag
	 * "warm but expensive" calls a future capped-reserve experiment
	 * (the STAGE B follow-up) would want to retain for replay.  This
	 * commit only counts them.
	 *
	 *  warm_reserve_candidates_total
	 *      Cumulative count across all syscalls.  Headline number for
	 *      "how often does the deep-but-warm predicate fire" once the
	 *      run has been going long enough for the per-syscall warmup
	 *      floor to clear on the hot syscalls.
	 *  warm_reserve_candidates[nr]
	 *      Per-syscall breakdown, indexed by raw syscall nr the same
	 *      shape as edges_per_syscall_bandit / frontier_picks_per_syscall.
	 *      Surfaced via a top_syscalls_periodic_dump() top-N row so the
	 *      operator can see which syscalls dominate the candidate set.
	 *
	 * SHADOW: no live-path code reads either counter.  The picker
	 * distribution, the per-strategy reward attribution, the bandit
	 * arms and the frontier-blend A/B path are byte-identical to the
	 * baseline -- only two relaxed adds run on the deep-but-warm tail
	 * of the post-collect path. */
	unsigned long warm_reserve_candidates_total;
	unsigned long warm_reserve_candidates[MAX_NR_SYSCALL];

	/* SHADOW-ONLY would-replay-demand counters, paired with the
	 * warm_reserve_candidates* pair above.  A deep-but-warm candidate
	 * is the population a STAGE B capped-reserve experiment would
	 * retain for replay; the plateau hypothesis CMP_RISING_PC_FLAT is
	 * the window in which that experiment would actually fire the
	 * replay (the same window the cmp-recent-first arm and the
	 * cmp-hyp live-inject path key off in cmp_hints.c).  These
	 * counters intersect the two: how often the deep-but-warm
	 * predicate fires AND the plateau is the CMP-rising-PC-flat
	 * hypothesis at the same time, i.e. the would-replay rate the
	 * STAGE B build needs to size its ring + dispatch path against.
	 *
	 *  warm_reserve_during_plateau_total
	 *      Cumulative across all syscalls.  Headline number for
	 *      "during a CMP_RISING_PC_FLAT plateau, how many deep-but-
	 *      warm candidates does this run actually see".  Compared
	 *      against warm_reserve_candidates_total it gives the
	 *      plateau-share of the candidate population; compared
	 *      against per-second dispatch volume it sizes the would-
	 *      replay budget.
	 *  warm_reserve_during_plateau[nr]
	 *      Per-syscall breakdown, same shape as
	 *      warm_reserve_candidates[].  Surfaces which syscalls would
	 *      dominate the replay traffic via top_syscalls_periodic_dump's
	 *      warm-reserve-plateau row.
	 *
	 * SHADOW: the live-pick / arg-gen / dispatch path is byte-
	 * identical to the baseline.  The plateau read uses the same
	 * RELAXED load + enum compare as the cmp_hyp_try_live_inject /
	 * cmp_recent_first paths in cmp_hints.c; the increment is gated
	 * inside the existing deep-but-warm predicate-fire block, so a
	 * syscall that doesn't fire the warm-reserve predicate doesn't
	 * even load the plateau field. */
	unsigned long warm_reserve_during_plateau_total;
	unsigned long warm_reserve_during_plateau[MAX_NR_SYSCALL];

	/* SHADOW-ONLY warm-plateau "wall lever" accounting -- the
	 * shadow gate that identifies high-call zero-yield syscalls during a
	 * warm-plateau window and projects the pick-budget those candidates
	 * would free if a live suppression variant were enabled.  Predicate
	 * lives in wall_lever_should_suppress_shadow() in strategy.c; the
	 * eligibility set is recomputed at every plateau-active rotation by
	 * wall_lever_refresh_baseline() so the gate adapts to the fleet's
	 * own per-syscall calls distribution rather than relying on a static
	 * denylist (the candidate syscalls mq_timedsend, io_destroy, munlockall,
	 * shmget, setsid, personality, unshare that motivated this lever
	 * surface as members of the data-driven eligible set, not as named
	 * constants).
	 *
	 *  wall_lever_eligible_total
	 *      Cumulative: one bump per pick where the shadow predicate was
	 *      evaluated (i.e. plateau_active and the per-syscall data was
	 *      readable) regardless of whether the candidate actually
	 *      qualified for suppression.  Provides the denominator against
	 *      which would_suppress_total reads as a fraction.
	 *  wall_lever_would_suppress_total
	 *      Cumulative: one bump per pick where the suppression predicate
	 *      (per_syscall_edges_total == 0 AND per_syscall_calls_total
	 *      >= WALL_LEVER_HIGH_MULT * wall_lever_baseline_calls AND calls
	 *      >= WALL_LEVER_MIN_FLOOR) fires under plateau_active -- the
	 *      projected pick share a live wall-lever variant would reclaim
	 *      for productive / cold syscalls.  Strictly <= eligible_total.
	 *  wall_lever_would_suppress[nr]
	 *      Per-syscall split of would_suppress_total.  Surfaces which
	 *      syscalls dominate the projected reclamation so a follow-up
	 *      live-variant rollout can be diff'd against the shadow tally.
	 *
	 * Observability only: live pickers in set_syscall_nr_heuristic /
	 * set_syscall_nr_random remain byte-identical to today's behaviour;
	 * the bumps fire AFTER the existing cold-skip / anti-prior gates so
	 * the candidate population is exactly the picks the wall lever would
	 * have to act on if it went live.  Mirrors the off-by-construction
	 * discipline the sibling frontier_decay_* / frontier_blend_* counters
	 * use. */
	unsigned long wall_lever_eligible_total;
	unsigned long wall_lever_would_suppress_total;
	unsigned long wall_lever_would_suppress[MAX_NR_SYSCALL];

	/* Shadow per-band counters for the reach-banded silent-regime
	 * picker weight adjustment.  Bumped from the band classification
	 * gate in frontier_cold_weight() (random-syscall.c) under
	 * SHADOW_ONLY or COMBINED mode; the REACH_BAND_OFF early-out at
	 * the gate keeps the default-mode call path byte-identical to a
	 * build before the row (the mode load is the only work done).
	 *
	 * The picker's selected weight is unchanged in every mode by the
	 * bumps themselves -- these counters strictly OBSERVE the band
	 * classification + would-demote/would-boost decisions.  Under
	 * COMBINED the live weight adjustment is applied separately by
	 * the gate, recorded by the existing frontier_silent_picks_per_
	 * syscall throughput counter; the per-band split below tells the
	 * operator how the call mass distributed across the three bands
	 * and how often the MID/HIGH branches actually fired their would-
	 * demote / would-boost arithmetic.
	 *
	 *  reach_band_picks_per_band[REACH_BAND_IDX_LOW / _MID / _HIGH]
	 *      Per-band classification count.  One bump per
	 *      frontier_cold_weight() call past the OFF early-out, indexed
	 *      by the band the syscall classified into on this call.
	 *      Sums to the total non-OFF entries to the gate (denominator
	 *      for the would-demote/would-boost rates below).
	 *  reach_band_would_demote_mid
	 *      Subset of reach_band_picks_per_band[REACH_BAND_IDX_MID]:
	 *      the MID-band calls where the staleness predicate fired and
	 *      the band gate halved the silent-regime weight.  Under
	 *      COMBINED this is the population the live demote acted on;
	 *      under SHADOW_ONLY this is the would-be population the
	 *      COMBINED switch would demote.
	 *  reach_band_would_boost_high
	 *      Subset of reach_band_picks_per_band[REACH_BAND_IDX_HIGH]:
	 *      the HIGH-band calls where the freshness predicate fired
	 *      (not stale) and the band gate lifted the silent-regime
	 *      weight by a fraction of the FRONTIER_COLD_SCALE headroom.
	 *      Same SHADOW_ONLY vs COMBINED reading as the demote
	 *      counter above.
	 *
	 * Each addend is 1UL; overflow needs ~2^64 samples -- comfortable
	 * for any fuzz horizon.  See include/reach-band.h for the band-
	 * boundary / multiplier rationale and the OFF / SHADOW_ONLY /
	 * COMBINED mode contract. */
	unsigned long reach_band_picks_per_band[REACH_BAND_NR];
	unsigned long reach_band_would_demote_mid;
	unsigned long reach_band_would_boost_high;

	/* Observability for the CMP-weighted frontier picker arm
	 * (--cmp-frontier=off|shadow-only|combined).  Bumped from the
	 * silent-regime accept gate in set_syscall_nr_coverage_frontier()
	 * on the non-OFF compute path; the OFF early-return MUST NOT
	 * bump any of these -- it is the byte-identity contract
	 * documented in include/cmp-frontier.h.
	 *
	 *  cmp_frontier_samples
	 *      Per-call samples denominator: one bump per silent-regime
	 *      entry past the cmp_frontier_mode OFF gate.  Sums to the
	 *      total non-OFF entries to the gate (denominator for the
	 *      plateau-hit and live-route rates below).
	 *  cmp_frontier_would_route
	 *      Subset of cmp_frontier_samples: the picks where the
	 *      plateau classifier currently reads CMP_RISING_PC_FLAT --
	 *      the would-be population the COMBINED switch would route
	 *      to the CMP-weighted weight.  Under SHADOW_ONLY this is
	 *      the projected route volume; under COMBINED it equals
	 *      cmp_frontier_live_routes below (mode-gated, not
	 *      condition-gated, so the two move in lock-step under
	 *      COMBINED).
	 *  cmp_frontier_live_routes
	 *      Subset of cmp_frontier_would_route: the picks where mode
	 *      is COMBINED AND the plateau gate fired, the population
	 *      where w was actually replaced with cmp_frontier_weight()
	 *      for the live accept roll.  Stays at zero under
	 *      SHADOW_ONLY by construction.
	 *
	 * Each addend is 1UL; overflow needs ~2^64 samples -- comfortable
	 * for any fuzz horizon. */
	unsigned long cmp_frontier_samples;
	unsigned long cmp_frontier_would_route;
	unsigned long cmp_frontier_live_routes;

	/* Observability for the adaptive expensive-syscall accept gate.
	 * Bumped from expensive_accept() in random-syscall.c on the
	 * adaptive compute path (mode != OFF, kcov_shm != NULL, nr in
	 * range).  The OFF / NULL-kcov / out-of-range early-return path
	 * MUST NOT bump any of these -- it is the byte-identity contract
	 * documented on expensive_accept().  See the helper comment in
	 * random-syscall.c for the SHADOW_ONLY / COMBINED mode contract
	 * and the EXPENSIVE_ADAPTIVE_FLOOR / CEILING / WARMUP / DECAY_
	 * STEPS constant block above the helper for the policy knobs.
	 * The shape mirrors the sibling frontier_blend_* counter family
	 * just above: per-call samples denominator + per-event dispositions.
	 *
	 *  expensive_adaptive_samples
	 *      Total computations -- one bump per expensive_accept() entry
	 *      past the OFF/NULL/out-of-range early-return, i.e. every
	 *      call into the adaptive compute path under SHADOW_ONLY or
	 *      COMBINED.  Denominator for the disposition counters below.
	 *  expensive_adaptive_extra_accepts
	 *      Mass of accepts the sub-floor n_adaptive rate is
	 *      contributing over the static 1/FLOOR baseline:
	 *
	 *        COMBINED.  Per-call bump when n_adaptive < FLOOR AND the
	 *        live ONE_IN(n_live=n_adaptive) draw returned true.  An
	 *        accept granted on the sub-floor path; the baseline 1/FLOOR
	 *        would have rejected on the corresponding draw with
	 *        probability (FLOOR-n_adaptive)/FLOOR, so this counter
	 *        upper-bounds the true "extra accept" count and converges
	 *        to it as n_adaptive shrinks toward the ceiling.
	 *
	 *        SHADOW_ONLY.  Per-call bump when n_adaptive < FLOOR (the
	 *        live accept stays at the floor and consumes no extra RNG,
	 *        so a per-draw observation is not available).  Counts the
	 *        opportunities -- multiplied by the average accept-rate
	 *        delta (1/n_adaptive - 1/FLOOR) this gives the would-be
	 *        extra-accept mass the COMBINED mode would unlock on the
	 *        same workload.  The unit-of-measure difference vs the
	 *        COMBINED bump is deliberate: SHADOW_ONLY's accept stream
	 *        is identical to OFF for a given seed, so a true per-event
	 *        shadow count is unavailable without additional RNG draws
	 *        (which would break the SHADOW_ONLY pick-parity invariant).
	 *  expensive_adaptive_demotes
	 *      Per-call bump from the stale-decay branch when the
	 *      total_calls -- last_edge_at[nr] gap pushed n_adaptive back
	 *      up toward the floor (the productive->stale re-cap).
	 *      Headline signal that the cheaper rate is being clawed back
	 *      once productivity stops; pair against extra_accepts to read
	 *      the net mass the lever is granting after decay. */
	unsigned long expensive_adaptive_samples;
	unsigned long expensive_adaptive_extra_accepts;
	unsigned long expensive_adaptive_demotes;

	/*
	 * Cost-pool one-shot selector observer counters (gated by
	 * cost_pool_selector_mode != OFF for the shadow_ pair; the live_
	 * pair bumps unconditionally so the analytical vs actual
	 * comparison is available on every run).  See the enum
	 * cost_pool_selector_mode comment in include/strategy.h for the
	 * shadow / live contract and the cost-pool-oneshot-selector
	 * spec section 4.1 for the closed-form identity the shadow rows
	 * accumulate.
	 *
	 *  cost_pool_selector_shadow_picks
	 *      Cumulative: one bump per HEURISTIC / RANDOM arm entry into
	 *      set_syscall_nr_* while cost_pool_selector_mode is SHADOW_
	 *      ONLY or COMBINED, after the arch table has been chosen and
	 *      before the retry loop's live rnd_modulo_u32 draw.
	 *      Denominator for the analytical fraction below.  Bumps
	 *      exactly once per pick call regardless of how many retries
	 *      the flat picker's expensive_accept early-out consumes; the
	 *      identity being validated is a per-pick property, not a
	 *      per-retry one.
	 *  cost_pool_selector_shadow_expensive_ppm_sum
	 *      Cumulative sum of the per-pick analytical expected
	 *      expensive-pool fraction, scaled to parts-per-million
	 *      (integer accumulation so the shadow bump path stays
	 *      allocation-free and lock-free).  Per-pick summand is
	 *      1_000_000 * n_exp / (n_cheap * R + n_exp) with R =
	 *      EXPENSIVE_ADAPTIVE_FLOOR = 1000 and n_cheap / n_exp read
	 *      RELAXED from the arch-specific nr_active_cheap /
	 *      nr_active_exp counters the Phase 0 pool bookkeeping
	 *      maintains.  Analytical expensive fraction over any window
	 *      = shadow_expensive_ppm_sum / (shadow_picks * 1_000_000);
	 *      by the section 4.1 identity this equals the flat draw-then-
	 *      reject expensive fraction in expectation, so it should
	 *      match the live_expensive_picks / (live_expensive_picks +
	 *      live_cheap_picks) actual fraction below on a real run.
	 *      Divide-by-zero guard: skipped entirely when the arch table
	 *      has n_cheap == 0 AND n_exp == 0 (no active syscalls on
	 *      this arch -- the flat picker will bail on nr_syscalls == 0
	 *      anyway).
	 *  cost_pool_selector_live_cheap_picks
	 *      Cumulative: one bump per successful set_syscall_nr_*
	 *      accepted pick whose finalised syscall is CHEAP under the
	 *      read-only EXPENSIVE bitmap (syscall_is_expensive() ==
	 *      false).  Gated on cost_pool_selector_mode != OFF alongside
	 *      the shadow_ pair so an OFF-mode build is bit-for-bit
	 *      identical to a pre-row build (no per-pick atomic add).
	 *      Placed at the pick-finalise site (immediately before
	 *      srec_publish_begin) so downstream picker gates that reject
	 *      (validate / cred-throttle) do not double-count -- the
	 *      accept-fraction being compared is the ACTUAL syscall the
	 *      child will execute.
	 *  cost_pool_selector_live_expensive_picks
	 *      Cumulative: sibling of live_cheap_picks above for the
	 *      EXPENSIVE half of the finalised-pick stream.
	 *  cost_pool_selector_predraw_cheap_picks
	 *      Cumulative: one bump per HEURISTIC / RANDOM arm draw whose
	 *      candidate syscall PASSED the expensive_accept gate but has
	 *      not yet been run past the downstream validate / anti_prior /
	 *      cred-throttle gates (i.e. bumped immediately after the
	 *      `if (!expensive_accept(...)) goto retry;` line and before
	 *      validate_specific_syscall_silent).  Cheap half of that pair
	 *      under the read-only EXPENSIVE bitmap (syscall_is_expensive()
	 *      == false).  Gated on cost_pool_selector_mode != OFF alongside
	 *      the shadow_ pair -- OFF-mode remains bit-for-bit identical
	 *      to a pre-row build (short-circuit before any shm access, no
	 *      per-draw atomic add).
	 *  cost_pool_selector_predraw_expensive_picks
	 *      Cumulative: EXPENSIVE sibling of predraw_cheap_picks above.
	 *
	 *      The predraw_ pair is the exact population the shadow closed-
	 *      form models: post-expensive_accept uniform-draw survivors,
	 *      before ANY downstream picker gate (validate / anti_prior /
	 *      cred-throttle) enriches the finalised stream in rare/
	 *      expensive syscalls.  Section 4.1 identity check:
	 *          shadow_expensive_ppm_sum / (shadow_picks * 1e6)
	 *        should match
	 *          predraw_expensive / (predraw_expensive + predraw_cheap)
	 *      to within Monte-Carlo noise.  The live_ pair remains the
	 *      "what actually executes" signal (post all gates, at
	 *      pick-finalise); it can and typically will diverge from the
	 *      shadow analytical fraction because anti_prior selectively
	 *      enriches rare/expensive syscalls in the accepted stream.
	 *
	 * Observability only in this commit: the shadow observer never
	 * returns a value, never gates any accept, never consumes any
	 * RNG.  cost_pool_selector_mode == COMBINED in this build behaves
	 * identically to SHADOW_ONLY (observer accumulates, live pick
	 * stays flat draw-then-reject); the COMBINED coin-then-draw wire-
	 * up lands in a follow-up commit.
	 */
	unsigned long cost_pool_selector_shadow_picks;
	unsigned long cost_pool_selector_shadow_expensive_ppm_sum;
	unsigned long cost_pool_selector_live_cheap_picks;
	unsigned long cost_pool_selector_live_expensive_picks;
	unsigned long cost_pool_selector_predraw_cheap_picks;
	unsigned long cost_pool_selector_predraw_expensive_picks;

	/* SHADOW-ONLY Path-A "regular_suppressed" context-axis projection
	 * (gated by --context-pool != off).  Sibling of the cost_pool_
	 * selector_* row above; the two rows share the same OFF /
	 * SHADOW_ONLY / COMBINED ramp and the same pick-finalise cadence,
	 * but partition the picker on different axes -- cost on the static
	 * EXPENSIVE bit, context on empirical per-syscall EPERM behaviour.
	 * See the enum context_pool_mode comment in include/strategy.h for
	 * the mode contract, CONTEXT_REGULAR_SUPPRESSED_CMIN /
	 * CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT for the classifier
	 * thresholds, and the implementation in
	 * strategy-frontier.c::context_regular_suppressed_shadow for the
	 * classifier + spare-lane composition.
	 *
	 * The classifier is data-gated (per_syscall_calls / per_syscall_
	 * errno[EPERM] / per_syscall_errno[SUCCESS] / per_syscall_edges),
	 * NOT a curated exception list -- a newly-productive syscall stops
	 * being regular_suppressed on its own without any manual map
	 * edit.  Shared spare-lane predicate (frontier_spare_lane_decide,
	 * strategy-frontier.c) is consumed at the site: a syscall whose
	 * K-window ring is nonzero (or which recently transitioned to a
	 * first CMP-insert / first SUCCESS) is spared from the would_skip
	 * attribution even when its lifetime EPERM rate clears the
	 * threshold, so the shadow projection tracks transient recovery
	 * honestly rather than latching on stale lifetime evidence.
	 *
	 *  context_regular_suppressed_candidates
	 *      Cumulative: one bump per finalised pick (matched to the
	 *      cost_pool_selector_live_note cadence so the ratio against
	 *      would_skip reads directly off the same denominator the
	 *      cost row uses).  The candidate set the classifier gets to
	 *      peel from.
	 *  context_regular_suppressed_would_skip
	 *      Cumulative: subset of candidates where the data-gated
	 *      classifier (calls >= CMIN AND success == 0 AND edges == 0
	 *      AND EPERM/calls >= CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT
	 *      AND no spare lane fires) says a live Path-A suppression
	 *      would remove the pick from the regular cost pools.  Ratio
	 *      against candidates is the projected regular-pool pick
	 *      share a live Path-A deactivation would reclaim.
	 *  context_regular_suppressed_spared_windowed
	 *      Cumulative: subset of candidates spared because the shared
	 *      spare-lane decide function returned FRONTIER_SPARE_WINDOWED_
	 *      EDGES -- the K-window frontier-edge ring is nonzero, so
	 *      the syscall is recently productive regardless of the
	 *      lifetime EPERM signal.  The bpf-class backstop analogue for
	 *      Path-A: a syscall that is EPERM-heavy in aggregate but
	 *      producing edges in the current window MUST NOT be classified
	 *      regular_suppressed.
	 *  context_regular_suppressed_spared_arggen
	 *      Cumulative: subset of candidates spared because the shared
	 *      spare-lane decide function returned FRONTIER_SPARE_ARGGEN --
	 *      a distinct CMP-insert landed since the last silent-baseline
	 *      reset OR a first-success TRANSITION fired (errno_base == 0
	 *      AND errno_now > 0).  Catches a syscall mid-penetration of
	 *      its struct args: it is EPERM-heavy in aggregate but the
	 *      arg-gen is progressing on it and a live suppression would
	 *      stall the breakthrough.  Same first-success-TRANSITION key
	 *      the satcool / live_cool siblings use.
	 *  context_regular_suppressed_spared_objproducer
	 *      Cumulative: subset of candidates spared because the shared
	 *      spare-lane decide function returned FRONTIER_SPARE_OBJPRODUCER
	 *      -- the syscall entry's ret_objtype is != OBJ_NONE and its
	 *      coverage credit is delayed and paid to a downstream consumer
	 *      of the produced object.  Same producer-observer bitmap the
	 *      satcool / live_cool siblings use.
	 *  context_regular_suppressed_would_skip_per_syscall[MAX_NR_SYSCALL]
	 *      Cumulative per-nr: bumped at the classifier gate keyed on
	 *      the candidate syscallnr whenever the would_skip event
	 *      fires.  The headline SHADOW_ONLY diagnostic: top entries
	 *      SHOULD be the measured EPERM hogs (fchown / chown / lchown
	 *      / fchownat + the cred family AS SEEN AT uid 1026 -- the
	 *      non-NEEDS_ROOT-flagged set the tables.c blanket
	 *      deactivation does not catch); a productive syscall showing
	 *      meaningful would_skip mass indicates the classifier is
	 *      mis-classifying it and the COMBINED ramp must wait.
	 *
	 * Observability only in this commit: the classifier-evaluation
	 * block is added inside the pick-finalise path with NO live
	 * suppression wired, so set_syscall_nr_heuristic() and
	 * set_syscall_nr_random() selection stays byte-identical to today
	 * regardless of which mode is selected.  COMBINED is reserved in
	 * the enum for a follow-up that wires the live regular-pool
	 * removal (deactivate_syscall_locked on the regular_suppressed
	 * subset) after SHADOW_ONLY validates the classifier distribution
	 * against a real run.  Mirrors the off-by-construction discipline
	 * the sibling cost_pool_selector_* / frontier_satcool_* /
	 * frontier_live_cool_* rows above use. */
	unsigned long context_regular_suppressed_candidates;
	unsigned long context_regular_suppressed_would_skip;
	unsigned long context_regular_suppressed_spared_windowed;
	unsigned long context_regular_suppressed_spared_arggen;
	unsigned long context_regular_suppressed_spared_objproducer;
	unsigned long context_regular_suppressed_would_skip_per_syscall[MAX_NR_SYSCALL];

	/* Adaptive remote-KCOV mode A/B disposition counters, bumped from
	 * dispatch_step in random-syscall.c on every productive-signal call
	 * into the PC-mode + remote_capable path so the operator can A/B
	 * compare the static remote-mode policy (per-syscall KCOV_REMOTE_
	 * HEAVY flag + ONE_IN(remote_reciprocal)) against the adaptive
	 * policy (per-syscall remote_pc_edge_calls / local_pc_edge_calls
	 * ratio against the REMOTE_ADAPTIVE_PROMOTE_MARGIN_* threshold,
	 * gated by REMOTE_ADAPTIVE_MIN_REMOTE_CALLS / MIN_LOCAL_CALLS sample
	 * floors).  All four counters bump in lock-step from BOTH the Arm A
	 * cohort (control: static policy is what dispatch_step uses for the
	 * live remote_mode flip on this call) and the Arm B cohort
	 * (treatment: the adaptive disposition is what dispatch_step uses
	 * for the live remote_mode flip on this call), so the would-be
	 * divergence between the two policies stays observable across the
	 * fleet regardless of the realised cohort split.  The live mode
	 * flip itself diverges only on Arm B; the cohort split lives in
	 * kcov_shm->remote_adaptive_arm_{a,b}_children and is the
	 * denominator the Arm-B-only live divergence is normalised against.
	 *
	 *  remote_adaptive_samples
	 *      Total computations -- one bump per dispatch_step entry into
	 *      the PC-mode + remote_capable path.  Denominator for the
	 *      disposition ratios below; the static-mode and non-capable
	 *      fast paths bypass the adaptive helper entirely (no shadow
	 *      bump there) so the counter measures only the surface that
	 *      could meaningfully disagree.
	 *  remote_adaptive_would_demote
	 *      Per-call disposition: adaptive policy would flip remote_mode
	 *      from true (the static decision said remote) to false because
	 *      the syscall is KCOV_REMOTE_HEAVY-flagged AND its lifetime
	 *      remote sample has crossed REMOTE_ADAPTIVE_MIN_REMOTE_CALLS
	 *      without producing a single edge.  Headline signal that the
	 *      HEAVY flag is mis-calibrated for that syscall in this
	 *      kernel.
	 *  remote_adaptive_would_promote
	 *      Per-call disposition: adaptive policy would flip remote_mode
	 *      from false to true because the syscall is NOT HEAVY-flagged,
	 *      its lifetime remote and local samples have BOTH crossed the
	 *      MIN_*_CALLS sample floors, the remote sample is non-empty,
	 *      AND the remote edge rate beats the local edge rate by the
	 *      configured PROMOTE_MARGIN_* relative margin (cross-multiplied,
	 *      no division).  Headline signal that the syscall has deferred-
	 *      work coverage the static unflagged trickle is under-sampling.
	 *  remote_adaptive_agree
	 *      Per-call disposition: adaptive policy matches the static
	 *      decision (neither demote nor promote fires).  Sum of
	 *      {_would_demote, _would_promote, _agree} equals _samples by
	 *      construction (the three dispositions are mutually exclusive
	 *      and exhaustive on the adaptive-helper entry path).
	 *  remote_adaptive_would_gate_promote
	 *      Shadow disposition for the proposed plateau gate on the
	 *      promote branch: bumped from BOTH arms in lock-step whenever
	 *      the cross-multiplied edge-rate margin fires (i.e. the
	 *      _would_promote condition holds) AND the parent-published
	 *      plateau hypothesis is NOT PLATEAU_HYPOTHESIS_REMOTE_DOMINANT
	 *      at the time of the decision.  Strict subset of
	 *      _would_promote -- it counts the would-be divergence between
	 *      today's always-promote behaviour and a future
	 *      "promote only under a remote-dominant plateau" rule, before
	 *      that rule is flipped on by default.  Live disposition is
	 *      not touched (adaptive_remote still flips to true); the
	 *      counter answers "how often would a plateau gate suppress
	 *      a live promote?" so the gate-on-by-default decision can
	 *      be made against measured impact rather than hypothesis.
	 *      Demote branch is intentionally unconditional and is NOT
	 *      covered by this counter.
	 *  remote_adaptive_would_force
	 *      Per-call disposition: adaptive policy widens the promote
	 *      branch under PLATEAU_HYPOTHESIS_REMOTE_DOMINANT and flips
	 *      remote_mode from false to true on an unflagged syscall
	 *      whose static decision was local, whose lifetime remote
	 *      sample has crossed REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_REMOTE
	 *      _CALLS (the looser plateau-emergency floor, 128 vs the
	 *      regular 512), and whose lifetime remote_pc_edge_calls has
	 *      crossed REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_EDGES (1 -- ever
	 *      yielded once).  Mutually exclusive with _would_promote on
	 *      the same call: the regular promote rule (rate beats local
	 *      by PROMOTE_MARGIN_NUM/DEN) is evaluated first, the force
	 *      rule only runs if that didn't fire.  Bumped from BOTH arms
	 *      in lock-step; the live remote_mode diverges only on Arm B,
	 *      same contract as the existing _would_promote/_would_demote
	 *      counters.  Adds a fourth slot to the disposition ladder so
	 *      the sum _would_demote + _would_promote + _would_force +
	 *      _agree continues to equal _samples by construction. */
	unsigned long remote_adaptive_samples;
	unsigned long remote_adaptive_would_demote;
	unsigned long remote_adaptive_would_promote;
	unsigned long remote_adaptive_agree;
	unsigned long remote_adaptive_would_gate_promote;
	unsigned long remote_adaptive_would_force;

	/* Coverage-plateau detector transition counters, bumped from
	 * kcov_plateau_check() on the rising edge (healthy -> plateau, when
	 * the sliding-window edge-discovery rate falls below
	 * KCOV_PLATEAU_ENTER_THRESHOLD) and the falling edge (plateau ->
	 * healthy, when the rate recovers).  Distinct from the one-shot
	 * stats.log warning so a forensic / cron consumer can tell how many
	 * distinct plateau episodes a long fuzz hit without parsing the
	 * mirrored log.  Bumped from the parent-only tick path so the relaxed
	 * add-fetch is for ordering hygiene rather than concurrent writers. */
	unsigned long plateau_entered;
	unsigned long plateau_exited;

	/* bucket_seen[] integrity-canary counters, bumped from
	 * kcov_bitmap_canary_check() on the parent's periodic tick.
	 * kcov_collect() sets bucket_seen bits monotonically and bumps
	 * edges_found once per bit-flip, so popcount(bucket_seen) ==
	 * edges_found is a by-construction identity (see the comment on
	 * kcov_bitmap_recount).  A wild writer that scribbles bucket_seen
	 * mid-run silently breaks the identity until the next save path
	 * notices.  The canary samples and popcount-compares against an
	 * in-source deficit threshold (KCOV_BITMAP_CANARY_DEFICIT) chosen
	 * to clear realistic per-scan memory-ordering jitter while still
	 * catching the page-class scribbles operators have seen.  Stats:
	 *   bucket_canary_checks   - every successful sample, the
	 *                            denominator for the deficit rate.
	 *   bucket_canary_deficits - samples where (edges_before -
	 *                            popcount) exceeded the threshold,
	 *                            i.e. the alarm fired.  Non-zero
	 *                            means the wild-writer hypothesis
	 *                            has direct evidence in the current
	 *                            run; cross-reference the matching
	 *                            stats.log CANARY line for the
	 *                            deficit magnitude.
	 * Both fields are parent-only writers; the RELAXED add-fetch is
	 * for read-side ordering hygiene only. */
	unsigned long bucket_canary_checks;
	unsigned long bucket_canary_deficits;

	/* Mutation-attribution win/trial inversion canary, bumped from
	 * minicorpus_mut_attrib_canary_check() on the parent's periodic
	 * tick.  The win bump is lexically nested under the trial bump
	 * in minicorpus.c and gated on (found_new && baseline_established),
	 * so mut_wins[i] <= mut_trials[i] (and the structured equivalent)
	 * is a by-construction identity at every instant.  A stray writer
	 * scribbling a wins[] counter word silently inverts the ratio and
	 * misleads the bandit's per-op weighting until the next stats
	 * dump notices.  Bumped once per inverted op per scan; non-zero
	 * is evidence the wins/trials counter region took a hit in the
	 * current run, with the matching stats.log CANARY line carrying
	 * the witnessed op + counts.  Parent-only writer; the RELAXED
	 * add-fetch is for read-side ordering hygiene only. */
	unsigned long mut_attrib_inversion_caught;

	/* Number of windows the orchestrator above the strategy picker
	 * forced STRATEGY_RANDOM in response to plateau_active, i.e. windows
	 * with selection_reason == SR_PLATEAU_FORCE.  Excluded from the
	 * UCB learner's reward history; surfaced separately in
	 * dump_strategy_stats() so the operator can size the intervention
	 * cohort against the policy-chosen cohort.  Bumped by the CAS-winning
	 * child inside select_next_strategy(); relaxed because the rotation
	 * path already serialises via syscalls_at_last_switch CAS. */
	unsigned long plateau_forced_windows;

	/* Per-vCPU ioctl dispatches into kvm_vcpu_grp.  Bumped from
	 * kvm_vcpu_sanitise() each time pick_random_ioctl() lands on an ioctl
	 * destined for an OBJ_FD_KVM_VCPU fd.  Distinct from the flat KVM
	 * ioctl group so a zero count here while the flat KVM group stat ticks
	 * means the per-vCPU fd_test path is dropping the fd and the dispatch
	 * is still bouncing off /dev/kvm with ENOTTY -- the very state Phase 3
	 * exists to fix.  Surfaced via periodic_counter_rates_dump() so an
	 * operator sees the per-window dispatch rate without waiting for the
	 * end-of-run summary. */
	unsigned long kvm_vcpu_ioctls_dispatched;

	/* Per-VM ioctl dispatches into kvm_vm_grp.  Bumped from
	 * kvm_vm_sanitise() each time pick_random_ioctl() lands on an ioctl
	 * destined for an OBJ_FD_KVM_VM fd.  Same diagnostic role as
	 * kvm_vcpu_ioctls_dispatched for the per-vCPU group: a flat counter
	 * while VM fds exist in the pool means kvm_vm_fd_test isn't winning
	 * arbitration and the dispatch is still bouncing off /dev/kvm with
	 * ENOTTY. */
	unsigned long kvm_vm_ioctls_dispatched;

	/* btrfs ioctl dispatches into btrfs_grp.  Bumped from btrfs_sanitise()
	 * each time pick_random_ioctl() lands on an ioctl destined for an
	 * OBJ_FD_TESTFILE fd matching btrfs_fd_test().  A non-zero count
	 * confirms the seeded-struct path (TREE_SEARCH / INO_LOOKUP /
	 * GET_SUBVOL_INFO etc.) is reaching the kernel parsers rather than
	 * EFAULTing on a random arg pointer; flat counter with active testfile
	 * fds means find_ioctl_group() arbitration isn't picking btrfs_grp. */
	unsigned long btrfs_ioctls_dispatched;

	/* kvm_run_churn childop counters */
	unsigned long kvm_run_invocations;		/* total KVM_RUN ioctls issued */
	unsigned long kvm_run_exit_io;			/* exit_reason == KVM_EXIT_IO */
	unsigned long kvm_run_exit_mmio;		/* exit_reason == KVM_EXIT_MMIO */
	unsigned long kvm_run_exit_hlt;			/* exit_reason == KVM_EXIT_HLT */
	unsigned long kvm_run_exit_shutdown;		/* exit_reason == KVM_EXIT_SHUTDOWN */
	unsigned long kvm_run_exit_fail_entry;		/* exit_reason == KVM_EXIT_FAIL_ENTRY */
	unsigned long kvm_run_exit_internal_error;	/* exit_reason == KVM_EXIT_INTERNAL_ERROR */
	unsigned long kvm_run_exit_intr;		/* exit_reason == KVM_EXIT_INTR (alarm-induced) */
	unsigned long kvm_run_exit_other;		/* every other exit_reason value */
	unsigned long kvm_run_errors;			/* KVM_RUN ioctl returned -1 */
	unsigned long kvm_gpc_memslot_race_runs;	/* memslot-race sub-mode invocations */
	unsigned long kvm_gpc_memslot_race_deletes;	/* KVM_SET_USER_MEMORY_REGION{,2} delete ioctls issued by writer */
	unsigned long kvm_gpc_memslot_race_unsupported;	/* sub-mode latched off (cap absent or ENODEV/EOPNOTSUPP) */

	/* nl80211_churn childop counters.  Drives cfg80211 state-machine
	 * fuzz under a mac80211_hwsim test radio inside CLONE_NEWNET.
	 * Race surface targeted by CVE-2022-41674 (cfg80211_update_notlisted_
	 * nontrans OOB), CVE-2023-3090 (nl80211 wiphy index race), and
	 * CVE-2025-21672 (cfg80211_scan_done UAF). */
	unsigned long nl80211_runs;			/* total nl80211_churn invocations */
	unsigned long nl80211_setup_failed;		/* unshare / netlink open / family resolve / hwsim absent */
	unsigned long nl80211_scan_triggered;		/* NL80211_CMD_TRIGGER_SCAN accepted */
	unsigned long nl80211_connect_attempted;	/* NL80211_CMD_CONNECT issued */
	unsigned long nl80211_connect_succeeded;	/* NL80211_CMD_CONNECT accepted (no kernel rejection) */
	unsigned long nl80211_disconnect_attempted;	/* NL80211_CMD_DISCONNECT issued */
	unsigned long nl80211_regdom_changed;		/* NL80211_CMD_SET_REG accepted */
	unsigned long nl80211_iface_created;		/* NL80211_CMD_NEW_INTERFACE accepted */
	unsigned long nl80211_iface_destroyed;		/* NL80211_CMD_DEL_INTERFACE accepted */
	unsigned long nl80211_bursts_sent;		/* loopback UDP sendto on wlan iface returned >0 */
	unsigned long nl80211_pmsr_runs;		/* NL80211_CMD_PEER_MEASUREMENT_START FTM request issued */
	unsigned long nl80211_pmsr_ok;			/* NL80211_CMD_PEER_MEASUREMENT_START accepted (no kernel rejection) */
	unsigned long nl80211_admin_gate_runs;		/* admin-gate probe forked + ran (per upstream 381cd547bc6e audit) */
	unsigned long nl80211_admin_gate_eperm_ok;	/* probed cmd correctly returned -EPERM under dropped caps */
	unsigned long nl80211_admin_gate_unexpected;	/* probed cmd returned non-EPERM (regression or unreachable) */

	/* splice_protocols accounting.  See stats/subsys/splice_protocols.h. */
	struct splice_protocols_stats splice_protocols __attribute__((aligned(64)));

	/* rxrpc_key_install accounting.  See stats/subsys/rxrpc_key_install.h. */
	struct rxrpc_key_install_stats rxrpc_key_install __attribute__((aligned(64)));

	/* af_alg_weak_cipher_probe accounting.  See stats/subsys/af_alg_weak_cipher_probe.h. */
	struct af_alg_weak_cipher_probe_stats af_alg_weak_cipher_probe __attribute__((aligned(64)));

	/* af_alg_template_probe childop counters.  One-shot enumeration
	 * of which AF_ALG crypto template names this kernel accepts via
	 * bind(2); per-template accept/reject lives in the parallel
	 * arrays, indexed by the probe_table[] order in
	 * childops/net/af-alg-template-probe.c.  af_alg_probe_done is the
	 * fleet-wide CAS latch that elects a single child to run the
	 * probe — not a counter, but lives here so it shares the shm
	 * mapping and survives across childdata recycles. */
#define NR_AF_ALG_PROBE_TEMPLATES	12
	unsigned int  af_alg_probe_done;	/* 0 -> 1 CAS election latch */
	unsigned long af_alg_probe_runs;	/* probe winners (should == 1 fleet-wide) */
	unsigned long af_alg_probe_unsupported;	/* socket(AF_ALG) returned EAFNOSUPPORT */
	unsigned long af_alg_probe_accept_total;	/* sum of per-template binds that returned 0 */
	unsigned long af_alg_probe_reject_total;	/* sum of per-template binds that returned -1 */
	unsigned long af_alg_probe_accept[NR_AF_ALG_PROBE_TEMPLATES];
	unsigned long af_alg_probe_reject[NR_AF_ALG_PROBE_TEMPLATES];

	/* af_alg_recvmsg_churn childop counters.  Drives the AF_ALG
	 * setkey -> sendmsg(cmsg) -> recvmsg(rotating-iov) data-plane
	 * path that the upstream aead_recvmsg memcpy_sglist GPF and
	 * af_alg_pull_tsgl slab-OOB upstream CI reproducers hit; the
	 * existing af_alg_template/af_alg_weak_cipher probes only walk
	 * bind+accept and so don't reach the sg/tsgl rotation logic. */
	unsigned long af_alg_recvmsg_runs;		/* total invocations */
	unsigned long af_alg_recvmsg_setkey_sent;	/* CMSG_ALG_SET_KEY emitted (alg_setkey_cmsg) */
	unsigned long af_alg_recvmsg_iv_sent;		/* CMSG_ALG_SET_IV emitted (alg_setiv_cmsg) */
	unsigned long af_alg_recvmsg_oob_iov;		/* slab-OOB-shaped sendmsg iov layout used */
	unsigned long af_alg_recvmsg_zerolen;		/* recvmsg() with a 0-length output iov */
	unsigned long af_alg_recvmsg_oversize;		/* recvmsg() with an oversize (64KB) output iov */
	unsigned long af_alg_recvmsg_empty_cmsg_no_more; /* sendmsg() cmsg-only, empty payload, no MSG_MORE */
	unsigned long af_alg_recvmsg_unsupported;	/* socket(AF_ALG)/proc-crypto latched off */

	/* inplace_crypto_oracle childop counters.
	 * See stats/subsys/inplace_crypto.h. */
	struct inplace_crypto_stats inplace_crypto __attribute__((aligned(64)));

	/* sock_diag_walker childop counters */
	unsigned long sock_diag_walker_runs;		/* total invocations */
	unsigned long sock_diag_walker_setup_failed;	/* socket(NETLINK_SOCK_DIAG) failed */
	unsigned long sock_diag_walker_inet;		/* inet_diag_req_v2 variant dispatched */
	unsigned long sock_diag_walker_unix;		/* unix_diag_req variant dispatched */
	unsigned long sock_diag_walker_netlink;		/* netlink_diag_req variant dispatched */
	unsigned long sock_diag_walker_packet;		/* packet_diag_req variant dispatched */
	unsigned long sock_diag_walker_vsock;		/* vsock_diag_req variant dispatched */

	/* altname_thrash childop counters */
	unsigned long altname_thrash_invocations;	/* total altname_thrash invocations */
	unsigned long altname_thrash_unshare_failed;	/* unshare(CLONE_NEWNET) failed (latched) */
	unsigned long altname_thrash_addprop_done;	/* RTM_NEWLINKPROP IFLA_PROP_LIST accepted */
	unsigned long altname_thrash_delprop_done;	/* RTM_DELLINKPROP IFLA_PROP_LIST accepted */
	unsigned long altname_thrash_getlink_done;	/* RTM_GETLINK targeted with RTEXT_FILTER_VF accepted */

	/* ipmr_cache_report childop counters */
	unsigned long ipmr_cache_report_iters;		/* per-iteration loop body entries */
	unsigned long ipmr_cache_report_eperm;		/* MRT_INIT returned -EPERM (CAP_NET_ADMIN gate) */
	unsigned long ipmr_cache_report_emit_ok;	/* sendto a NOCACHE multicast group succeeded */

	/* ublk_lifecycle accounting.  See stats/subsys/ublk_lifecycle.h. */
	struct ublk_lifecycle_stats ublk_lifecycle __attribute__((aligned(64)));

	/*
	 * Wall-clock high-water-mark for the periodic minicorpus snapshot.
	 * Companion to minicorpus_shm->edges_at_last_snapshot but lives in
	 * shm->stats so the field is allocated alongside the rest of the
	 * snapshot trigger state and the operator's stats dump can surface
	 * it without crossing into the corpus-only shared region.  Short
	 * runs that die before the edge-delta threshold trips would
	 * otherwise lose the entire mid-run corpus.  Initialised at
	 * minicorpus_enable_snapshots() time and advanced by the single
	 * CAS-elected saver after minicorpus_save_file() returns.
	 */
	unsigned long minicorpus_last_snapshot_time;

	/*
	 * Bumped from runid_corpus_entries_total() each time a per-syscall
	 * minicorpus ring is observed with count > CORPUS_RING_SIZE.  Every
	 * save path (in-run minicorpus_save_with_reason() and the on-disk
	 * loader) caps count at CORPUS_RING_SIZE before publishing, and the
	 * picker / snapshot readers also clamp before indexing entries[];
	 * a value above the cap is therefore not reachable through the
	 * documented writer flow and is a zero-false-positive signal that
	 * a sibling wild write has scribbled the ring's count word.  The
	 * sum reader silently clamped before this counter existed, which
	 * surfaced as a wildly inflated corpus_entries headline at run-end
	 * (e.g. 5,178,716 vs the real 1,565) with no other breadcrumb.
	 */
	unsigned long corpus_count_overcap_caught;

	/* rxrpc_sendmsg_cmsg_churn childop counters */
	unsigned long rxrpc_sendmsg_cmsg_runs;			/* total rxrpc_sendmsg_cmsg_churn invocations */
	unsigned long rxrpc_sendmsg_cmsg_socket_failed;		/* socket()/bind() rejected (incl EPROTONOSUPPORT-latch trip) */
	unsigned long rxrpc_sendmsg_cmsg_sent[8];		/* per-cmsg-slot histogram (USER_CALL_ID..CHARGE_ACCEPT) */
	unsigned long rxrpc_sendmsg_cmsg_sendmsg_ok;		/* sendmsg() returned >=0 */
	unsigned long rxrpc_sendmsg_cmsg_sendmsg_fail;		/* sendmsg() returned -1 (kernel rejected the cmsg shape) */

	/*
	 * init_child()'s pid-handshake loop observed pid_alive(mainpid)
	 * == false -- the parent died (or otherwise lost its pid slot)
	 * before publishing this child's slot in pids[].  The original
	 * shape called outputerr("BUG!: parent went away!") right after
	 * the dup2 redirect to /dev/null, so the diagnostic was lost.
	 * Bumping a shm counter survives the operator-side teardown:
	 * any reader that attaches to the still-mapped shm post-mortem
	 * sees a non-zero value here and knows the parent-loss path
	 * actually fired, distinct from a child that exited for any
	 * other reason.  Cumulative across the run; expected zero on a
	 * healthy fleet.
	 */
	unsigned long child_dead_parent_observed;

	/*
	 * perf_event_chains ensure_discovery() observed pmu_count == 0
	 * after the discover_pmus() sweep, so the childop is disabling
	 * itself for the remainder of this child's life.  The original
	 * shape called outputerr from inside a pmu_warned_unsupported
	 * one-shot gate (one log per child), but the dup2 redirect to
	 * /dev/null in init_child swallowed the message.  Bumping a
	 * counter under the same one-shot gate leaves a survivor signal:
	 * a high count is the fingerprint of a sysctl-locked-down host
	 * or a kernel build with the perf subsystem absent.
	 */
	unsigned long perf_event_chains_pmu_unsupported;

	/*
	 * heap_bounds_init() encountered an [anon:NAME] allocator region
	 * after extra_heap_regions[] already held MAX_EXTRA_HEAP_REGIONS
	 * entries, so the region was silently dropped instead of being
	 * captured.  is_in_glibc_heap() and range_overlaps_libc_heap()
	 * will not consider that allocator region, which can let a fuzzed
	 * pointer land inside it and let the kernel scribble allocator
	 * metadata (the bad-free / asan-self-kill cluster the captured
	 * regions exist to prevent).  The existing one-shot warned-bool
	 * outputerr fires for the first overflow only; this counter
	 * advances for every subsequent dropped region so the deficit
	 * size, not just the existence of a deficit, is observable post-
	 * mortem.  A non-zero value across runs is the actionable signal
	 * to raise MAX_EXTRA_HEAP_REGIONS or replace the static array
	 * with a growable registry.
	 */
	unsigned long heap_extra_regions_overflow;

	/*
	 * ip6erspan_netns_migrate's warn_once_unsupported() latched
	 * ns_unsupported_ip6erspan after an unshare/setns/open or a
	 * create-time ENOENT/EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP
	 * disabled the childop for the rest of this child's life.  The
	 * original shape called outputerr from inside the one-shot
	 * latch arm, but the dup2 redirect to /dev/null in init_child
	 * swallowed the message, so a kernel missing the rtnl tunnel
	 * machinery this op exercises looked identical to a healthy
	 * one in the operator's log.  Bumping a shm counter under the
	 * same one-shot gate leaves a survivor signal: one tick per
	 * child first-observation, so a high count fingerprints a host
	 * (or build) where the ip6erspan path is unreachable.
	 */
	unsigned long inm_ip6erspan_unsupported_observed;

	/*
	 * ip6erspan_netns_migrate observed -EOPNOTSUPP from the
	 * post-migration RTM_NEWLINK NLM_F_REPLACE: the kind has no
	 * ->changelink op so create + migrate + teardown still walk
	 * but the dev_net-vs-t->net path under test cannot fire.  The
	 * original shape called outputerr from inside a one-shot
	 * ns_unsupported_changelink gate; the dup2 redirect to
	 * /dev/null in init_child lost that diagnostic.  Bumping a
	 * counter under the same one-shot gate keeps a post-mortem
	 * signal -- one tick per child first-observation, so a non-
	 * zero value is the fingerprint of a kernel build whose
	 * rtnl_link_ops lacks the changelink hook for the rolled
	 * kind.
	 */
	unsigned long inm_changelink_unsupported_observed;

	/*
	 * netdev_netns_migrate latched itself off after helper -EPERM
	 * or a setup-side EPERM/setns/unshare failure.  One-shot per
	 * child first-observation, mirroring the ip6erspan_netns_migrate
	 * counter above -- a non-zero value fingerprints a host where
	 * the unprivileged userns + private-netns setup this childop
	 * relies on is unavailable (user.max_user_namespaces=0 /
	 * kernel.unprivileged_userns_clone=0 / capability restriction).
	 */
	unsigned long nnm_unsupported_observed;

	/*
	 * netdev_netns_migrate observed -EOPNOTSUPP from the post-
	 * migration RTM_SETLINK IFF_UP: the kernel refused to bring
	 * the migrated device up in the target ns for the rolled
	 * kind, so create + migrate + teardown still walk but the
	 * post-migration drive step cannot fire.  One-shot per child
	 * first-observation; a non-zero value is the fingerprint of
	 * a kernel build where one of the rolled kinds cannot be
	 * brought up in an unprivileged userns-owned netns.
	 */
	unsigned long nnm_drive_unsupported_observed;

	/*
	 * userns_fuzzer's make_root_private() observed a failing
	 * mount("none", "/", MS_REC|MS_PRIVATE) before the per-op
	 * tmpfs mount.  The original shape called output(0, ...) so
	 * an operator watching the run could see that the inner mount
	 * ns wasn't isolated from the host's mount tree before the
	 * tmpfs attempt -- but make_root_private() runs from child
	 * context, where init_child has redirected stderr to /dev/null,
	 * so the diagnostic was lost.  Bump a shm counter on every
	 * failure (no one-shot: this fires per-iteration and the
	 * accumulating count is the survivor signal that mount-ns
	 * isolation is broken on the host).  A non-zero value across a
	 * run says the tmpfs mount path was being run unprotected.
	 */
	unsigned long userns_root_private_failed;

	/* sysfs_string_race childop counters */
	unsigned long sysfs_string_race_runs;		/* total sysfs_string_race invocations */
	unsigned long sysfs_string_race_setup_failed;	/* no curated target was writable on this host (probe latched unsupported) */
	unsigned long sysfs_string_race_target_missing;	/* per-iteration open of a previously-writable target failed (raced removal / perms) */
	unsigned long sysfs_string_race_target_used;	/* both writer children spawned against a target */
	unsigned long sysfs_string_race_fork_failed;	/* fork() of a writer child failed (EAGAIN / RLIMIT) */
	unsigned long sysfs_string_race_writes_ok;	/* child pwrite() returned >0 (.store() accepted) */
	unsigned long sysfs_string_race_writes_failed;	/* child pwrite() returned <=0 (EINVAL / EBUSY / etc.) */

	/* pci_bind accounting.  See stats/subsys/pci_bind.h. */
	struct pci_bind_stats pci_bind __attribute__((aligned(64)));

	/* accept-unblocker counters.  Fires a loopback connect() at a
	 * pooled listening socket so a concurrent accept() sees a non-empty
	 * backlog and never parks in inet_csk_accept's wait loop.  See
	 * net/unblocker.c for the loopback-only safety check. */
	unsigned long accept_unblocker_connects_fired;		/* fire-and-forget connect() issued at a listener (SYN sent or EINPROGRESS) */
	unsigned long accept_unblocker_loopback_only_skipped;	/* listener bound to non-loopback addr; refused to connect */
	unsigned long accept_unblocker_probe_failed;		/* getsockopt(SO_ACCEPTCONN) / getsockname / socket() / connect() returned an unexpected error */

	/* pipe-waker counters.  Iterates pipe writer-end fds and writes a
	 * single byte non-blocking, so a concurrent reader on an empty
	 * pipe never parks in wait_event_interruptible_exclusive(pipe->rd_wait).
	 * The kernel already makes pipe-reads killable; this is a belt-and-
	 * suspenders defense against orphaned blocking readers (see
	 * fds/pipes.c open_pipe_pair() comment). */
	unsigned long pipe_waker_bytes_written;			/* successful 1-byte write() to a writer-end pipe fd */
	unsigned long pipe_waker_no_target;			/* fired but the pool walk returned no writer-end fd */
	unsigned long pipe_waker_write_failed;			/* write() returned <0 (EAGAIN on full pipe, EBADF on closed fd, etc.) */

	/* Chain-corpus duplicate-shape rate
	 * (sequence.c).  Bumped from chain_corpus_save() under the
	 * ring lock: dup means the incoming chain's
	 * (nr, do32bit) tuple shape matched at least one of the
	 * CHAIN_CORPUS_DUP_LOOKBACK most-recent saved slots;
	 * unique means no match.  Rate dup / (dup + unique) is the
	 * realised duplicate-shape rate a per-shape chain quota
	 * is gated on. */
	unsigned long chain_corpus_save_dup_shape;
	unsigned long chain_corpus_save_unique_shape;

	/* Resource-type chain-generation telemetry (Phase 3;
	 * --chain-resource-typing=off|shadow|live).  All arrays are
	 * indexed by enum chain_resource_kind (CHAIN_RESTYPE_NR wide);
	 * ordering is defined by that enum and MUST NOT change without
	 * updating the resource table in sequence.c.
	 *
	 * chain_restype_produced[k]     : a chain step matched the (nr, args)
	 *                                 pattern for a kind-k producer with a
	 *                                 non-negative retval.  Bumped in every
	 *                                 non-OFF mode -- the classifier itself
	 *                                 is the always-on observability.
	 * chain_restype_would_bias[k]   : SHADOW mode only.  Bumped when the
	 *                                 next chain link EXISTS and a consumer
	 *                                 NR for kind k WOULD have been picked
	 *                                 as the LIVE arm's override.
	 * chain_restype_biased[k]       : LIVE mode only.  Bumped when the next
	 *                                 chain link was actually overridden to
	 *                                 a consumer of kind k (the accept-
	 *                                 probability roll landed inside the
	 *                                 bias budget AND the biased dispatch
	 *                                 did not FAIL fall-back to fresh).
	 * chain_restype_save[k]         : chain got admitted to the corpus and
	 *                                 carried at least one producer of kind
	 *                                 k in its steps.
	 * chain_restype_replay_win[k]   : a replayed chain that carried a
	 *                                 kind-k producer earned any novelty
	 *                                 signal on at least one step.  Ratio
	 *                                 chain_restype_replay_win[k] /
	 *                                 chain_restype_save[k] answers "does
	 *                                 this resource family pay for its bias
	 *                                 budget" -- the whole point of the row.
	 *
	 * All RELAXED atomics; dashboards read once per stats tick and there
	 * is no cross-counter ordering invariant. */
	unsigned long chain_restype_produced[CHAIN_RESTYPE_NR];
	unsigned long chain_restype_would_bias[CHAIN_RESTYPE_NR];
	unsigned long chain_restype_biased[CHAIN_RESTYPE_NR];
	unsigned long chain_restype_save[CHAIN_RESTYPE_NR];
	unsigned long chain_restype_replay_win[CHAIN_RESTYPE_NR];

	unsigned long syscall_walltime_ns;
	unsigned long syscalls_in_childops;
	unsigned long syscalls_random;
	unsigned long random_syscall_dispatches;

	/* Credential-syscall observability oracle (always on) + flag-gated
	 * throttle counters.  See include/cred_throttle.h for the contract.
	 * cred_class_calls counts EVERY completed credential syscall in the
	 * class (the denominator).  cred_class_success / cred_class_eperm /
	 * cred_class_einval are the bucket splits the throttle predicate
	 * reads to decide "provably impossible".  cred_class_throttled is
	 * bumped each time the --cred-throttle gate rejected a pick for
	 * this class -- always zero when the flag is off, so the dump
	 * column doubles as a "flag was active" indicator. */
	unsigned long cred_class_calls[CRED_CLASS_NR];
	unsigned long cred_class_success[CRED_CLASS_NR];
	unsigned long cred_class_eperm[CRED_CLASS_NR];
	unsigned long cred_class_einval[CRED_CLASS_NR];
	unsigned long cred_class_throttled[CRED_CLASS_NR];

	/* RedQueen -> PC-edge conversion attribution, per-syscall.
	 *
	 * rq_sourced_saves_per_syscall[nr]
	 *     Bumped from minicorpus_save_with_reason() each time a corpus
	 *     entry is admitted to syscall nr's ring with the rq_sourced
	 *     provenance tag set (i.e. the saving child's in_reexec was true
	 *     -- the args came from a redqueen_reexec_step harvest).
	 *
	 * rq_sourced_pcedge_wins_per_syscall[nr]
	 *     Bumped from frontier_record_new_edge() (strategy.c) when the
	 *     call that produced the new PC bucket-edge for nr was a replay
	 *     of a corpus entry whose rq_sourced flag was set -- i.e. a
	 *     downstream PC win from a RedQueen-sourced save.
	 *
	 * The pair answers the harvest->edge bottleneck question: do the
	 * args RedQueen re-exec harvests actually convert to new PC edges
	 * once they're replayed?  Surfaced only via top_syscalls_periodic_
	 * dump() (alongside the existing per-pool per-syscall arrays) so
	 * the operator gets a per-window view of which syscalls have the
	 * highest RedQueen-sourced save rate vs which produce the highest
	 * downstream PC-edge wins.  Observability only -- no selection /
	 * reward / injection path consumes either array.  RELAXED add-fetch:
	 * cumulative diagnostic, window deltas come from the dump's
	 * snapshot+diff against the previous tick. */
	unsigned long rq_sourced_saves_per_syscall[MAX_NR_SYSCALL];
	unsigned long rq_sourced_pcedge_wins_per_syscall[MAX_NR_SYSCALL];

	/* errno-gradient-save SHADOW + LIVE counters and per-syscall
	 * attribution.  The trigger fires in handle_syscall_ret() on the
	 * first non-EFAULT errno bucket per syscall per run window (cheap-
	 * first version of the broader gradient predicate).
	 *
	 * errno_grad_save_would_save
	 *     Bumped on EVERY trigger event regardless of the
	 *     --corpus-save-errno-grad-live A/B flag.  Establishes the
	 *     would-be-save volume before the live distribution change is
	 *     enabled, so the operator can size the impact of flipping the
	 *     flag without touching the corpus admission distribution.
	 *
	 * errno_grad_save_did_save
	 *     Bumped only when the trigger event ACTUALLY admitted to the
	 *     ring (--corpus-save-errno-grad-live=true AND entry->sanitise
	 *     == NULL AND minicorpus_save_with_reason() passed its filters).
	 *     Stays at zero in the default-off behavior-neutral build.  The
	 *     would_save - did_save delta is the count of trigger events
	 *     the A/B gate or the sanitise filter suppressed.
	 *
	 * errno_sourced_saves_per_syscall[nr]
	 *     Bumped from minicorpus_save_with_reason() each time an entry
	 *     is admitted to syscall nr's ring with the errno_sourced
	 *     provenance tag set (CORPUS_SAVE_REASON_ERRNO).  Mirror of
	 *     rq_sourced_saves_per_syscall[].
	 *
	 * errno_sourced_pcedge_wins_per_syscall[nr]
	 *     Bumped from frontier_record_new_edge() (strategy.c) when the
	 *     call that produced the new PC bucket-edge for nr was a replay
	 *     of a corpus entry whose errno_sourced flag was set -- the
	 *     errno-source conversion-rate counter.  Mirror of
	 *     rq_sourced_pcedge_wins_per_syscall[].
	 *
	 * Observability only -- no selection / reward / injection path
	 * consumes any of these.  RELAXED add-fetch matches the surrounding
	 * accounting.  All four start at zero on parent boot; warm-start
	 * does not persist stats counters. */
	unsigned long errno_grad_save_would_save;
	unsigned long errno_grad_save_did_save;
	unsigned long errno_sourced_saves_per_syscall[MAX_NR_SYSCALL];
	unsigned long errno_sourced_pcedge_wins_per_syscall[MAX_NR_SYSCALL];

	/* Per-strategy transition-reward attribution.  Parallel in shape to
	 * shm->pc_edge_calls_by_strategy[] / shm->pc_edge_count_by_strategy[]
	 * (which live in shm_s, not here -- the strategy-indexed pair was
	 * the established home before stats.h gained transition fields) but
	 * carrying the transition-coverage signal instead of the PC-edge
	 * signal.  Bumped from random-syscall.c at the kcov_collect call
	 * site using child->strategy_at_pick when transitions_this_call > 0,
	 * gated on:
	 *
	 *   !child->kcov.remote_mode
	 *       Remote-mode traces merge coverage copied from remote
	 *       contexts into the same buffer; the ordering of the merged
	 *       PCs is not verified to preserve transition adjacency, so
	 *       remote-mode transitions are excluded from any live reward
	 *       input even under COMBINED.  See the kcov_transition_reward_
	 *       mode enum in include/kcov.h for the contract.
	 *
	 *   kcov_transition_reward_mode != KCOV_TRANSITION_REWARD_OFF
	 *       OFF disables the reward path entirely (zero compute, zero
	 *       accounting).  COMBINED (default) and SHADOW_ONLY both bump
	 *       these counters so the operator can read the per-strategy
	 *       transition divergence regardless of whether live selection
	 *       is consuming the signal.
	 *
	 * transition_edge_calls_by_strategy[strat]
	 *     Bumps by 1 per kcov_collect() call that flipped >=1 new
	 *     transition slot (matching the per_syscall_transition_edges
	 *     call-count semantics).  Window delta against transition_edge_
	 *     calls_at_window_start gives the per-strategy "how many calls
	 *     under this arm produced a transition this window" — symmetric
	 *     to the PC-edge call-count rotation reads.
	 *
	 * transition_edge_count_by_strategy[strat]
	 *     Bumps by min(transitions_this_call, TRANSITION_PER_CALL_
	 *     REWARD_CAP) per kcov_collect() call (raw real-flip count,
	 *     capped per-call to keep one pathological trace from
	 *     monopolizing the per-strategy delta).  See the
	 *     TRANSITION_PER_CALL_REWARD_CAP comment in include/kcov.h for
	 *     the cap rationale; the uncapped per_syscall_transition_edges_
	 *     real array stays the stats-dump observability signal.  The
	 *     per-strategy window delta is what bandit_record_pull() reads
	 *     and folds into the bandit reward total under COMBINED.
	 *
	 * transition_edge_count_at_window_start
	 *     Single-slot snapshot of transition_edge_count_by_strategy[next]
	 *     reseeded at every rotation in maybe_rotate_strategy(), matching
	 *     the existing pc_edge_count_at_window_start / bandit_cmp_at_
	 *     window_start cadence.  Read at the top of bandit_record_pull
	 *     to compute the per-window transition delta the COMBINED-mode
	 *     reward folds in.  Lives here (not in shm_s) — semantically
	 *     equivalent to the shm-side window-start snapshots since the
	 *     rotation handler is the single writer.
	 *
	 * transition_edge_calls_at_window_start
	 *     Companion snapshot for the calls-by-strategy counter.  Same
	 *     reseed cadence; consumers that want a "productive call rate"
	 *     numerator (per-strategy calls-with-transitions / total calls)
	 *     read this snapshot the same way the bandit reads the count
	 *     snapshot. */
	unsigned long transition_edge_calls_by_strategy[NR_STRATEGIES];
	unsigned long transition_edge_count_by_strategy[NR_STRATEGIES];
	unsigned long transition_edge_count_at_window_start;
	unsigned long transition_edge_calls_at_window_start;

	/* SHADOW-ONLY per-syscall stuck-child accounting.  The exit_reason=19
	 * (EXIT_EPOCH_DONE) shutdown survey shows the fleet repeatedly tailing
	 * out with most slots wedged in D-state (io_getevents, futex,
	 * memfd_secret, pwritev2, shmdt, ...): edge discovery stalls because
	 * the slots cannot be recycled.  These two arrays attribute that loss
	 * to the syscall the wedged child was running, so the next iteration
	 * has data to throttle / isolate the worst offenders on.  Accounting
	 * and a top-N shutdown row only -- no throttle/isolation decision
	 * is taken from either array yet, so the picker, the bandit, the
	 * canary queue, the fleet sizing and every other live-path decision
	 * stay byte-identical to the baseline.
	 *
	 * Indexed by raw syscall nr conflated across the do32 dimension, the
	 * same shape edges_per_syscall_bandit[] / frontier_picks_per_syscall[]
	 * use.  The existing per-syscall top-N dump path
	 * (top_syscalls_periodic_dump) already scans only the 64-bit table
	 * under biarch to avoid the 32/64 collision in nr; the wedge top-N row
	 * follows the same convention.
	 *
	 *  syscall_wedge_count[nr]
	 *      Bumped once per stuck-child detection event, at the first
	 *      is_child_making_progress() pass that finds diff >= 30 s for
	 *      this child.  Latched per-child via childdata.wedge_accounted so
	 *      a child that stays wedged across many watchdog ticks counts as
	 *      one event, not one per tick.  RELAXED add-fetch -- diagnostic,
	 *      not an event log.
	 *  syscall_wedge_total_us[nr]
	 *      Cumulative microseconds across all wedge events for this
	 *      syscall.  Added in reap_child() once the kernel has finally
	 *      released the slot (or the unkillable-D-state path forces slot
	 *      reuse via register_zombie_slot), so the duration reflects the
	 *      full time the slot was unreusable.  CLOCK_MONOTONIC so an NTP
	 *      step cannot regress the elapsed; clamped at the read site so a
	 *      reordered read of the start tp cannot underflow to ~ULLONG_MAX.
	 *      RELAXED add-fetch.
	 *
	 * Surfaced via dump_stats_top_wedging_syscalls() at shutdown only --
	 * not on the JSON path (the array is 2 * MAX_NR_SYSCALL * 8 = 16 KiB,
	 * same rationale as edges_per_syscall_bandit / frontier_picks_per_
	 * syscall which also stay text-only). */
	unsigned long syscall_wedge_count[MAX_NR_SYSCALL];
	unsigned long long syscall_wedge_total_us[MAX_NR_SYSCALL];

	/* SHADOW-ONLY topology-pair sample ring + companion counters.
	 * See stats/subsys/topo_pair.h. */
	struct topo_pair_stats topo_pair __attribute__((aligned(64)));

	/* SHADOW-ONLY census of scrub-eligible address-family arg slots
	 * walked by blanket_address_scrub() -- one bump per set bit in
	 * entry->address_scrub_mask consumed by the ctz loop, i.e. once per
	 * ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE slot the relocator
	 * actually visits.  Telemetry only: the live inject/scrub path is
	 * unchanged and avoid_shared_buffer_out() still fires for every
	 * visited slot.  Denominator for a future per-slot "relocated vs
	 * not" split, which needs a signature change on
	 * avoid_shared_buffer_out and so is intentionally not landed here.
	 * RELAXED add-fetch -- diagnostic, not an event log. */
	unsigned long blanket_address_scrub_slots_walked;

	/* arg-generation observability (meta sidecar + object-size-relative
	 * ARG_LEN draws).  See stats/subsys/arg.h. */
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

	/* Per-group shadow of blob_fills.  Bumped once per non-OFF
	 * blob_fill() invocation, keyed on the group of the syscall
	 * whose (nr, do32) the caller passed in (looked up via
	 * get_syscall_entry(nr, do32)).  Sums to blob_fills by
	 * construction (modulo the entry == NULL / group >= NR_GROUPS
	 * defensive gate the bump site keeps).  Purpose: make the per-
	 * group blob_fill invocation distribution directly visible so
	 * the group-bias vs blob-starvation relationship is
	 * quantifiable from a single run without re-deriving the split
	 * from picker-side counters.  Pure observability: OFF short-
	 * circuits before the bump so the OFF arm stays byte-identical
	 * and no live selection logic reads this array. */
	unsigned long blob_fills_by_group[NR_GROUPS];

	/* --blob-ab-mode within-run A/B harness counters.  See
	 * stats/subsys/blob_ab.h for the per-field commentary. */
	struct blob_ab_stats blob_ab;

	/* Cause-attribution for the epoll wait-family (epoll_wait,
	 * epoll_pwait, epoll_pwait2) rejects landing in
	 * validate_arg_coupling() with maxevents > 0 && events == NULL.
	 * The bare validator_rejected headline conflates every coupled-
	 * pair rule; these split the epoll subset by why a2 was zero:
	 *
	 *   alloc_fail       -- the initial address the arg generator
	 *                       produced for a2 (ARG_NON_NULL_ADDRESS)
	 *                       was already 0 at sanitise entry.  Real
	 *                       cause today: get_writable_address()
	 *                       returning NULL when mapping_sizes[] drew
	 *                       the GB(1) bucket that exceeds the 1 MiB
	 *                       writable_pool, so get_non_null_address()
	 *                       returned NULL.
	 *   shared_reject    -- a2 was non-zero at sanitise entry but
	 *                       zero at sanitise exit.  No live code path
	 *                       zeroes *addr inside avoid_shared_buffer_
	 *                       out today; retained as a bucket so a
	 *                       future ASB reject that DOES zero the slot
	 *                       is attributed on first sight instead of
	 *                       silently collapsing back into the
	 *                       headline.
	 *
	 * A "late mutation" residual (a2 was non-zero at sanitise exit
	 * but zero at validate_arg_coupling() time -- a sibling stomp
	 * between the two) is not accounted here; it is derivable as
	 * (epoll validator-rejects - alloc_fail - shared_reject) once a
	 * per-family split of validator_rejected is added.  Bumped with
	 * RELAXED atomics on shm->stats -- multi-producer, low rate,
	 * dump-side reader only. */
	unsigned long epoll_wait_null_events_alloc_fail;
	unsigned long epoll_wait_null_events_shared_reject;
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

/* Implemented in childops/recipe/runner.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void recipe_runner_dump_stats(void) __cold;

/* Implemented in childops/io_uring/recipes.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void iouring_recipes_dump_stats(void) __cold;

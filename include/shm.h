#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "arch.h"
#include "child-api.h"
#include "efault_cache.h"
#include "exit.h"
#include "files.h"
#include "locks.h"
#include "net.h"
#include "object-types.h"
#include "picker-context.h"
#include "scratch_block.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"
#include "types.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
struct io_uringobj;

void create_shm(void);
void init_shm(void);

/* Fleet-wide in-flight cap for unshare(CLONE_NEWNET) / clone() /
 * clone3() with CLONE_NEWNET.  See Documentation/shm-state.md
 * (CLONE_NEWNET throttle) for the kernel-side reason this cap exists. */
#define MAX_CONCURRENT_NEWNET 4

struct shm_s {
	char __padding[4096];

	/* Frequently updated by all children — own cache line. */
	struct stats_s stats __attribute__((aligned(64)));

	/* Wall-clock time init_shm() ran.  Read-only after init; used by
	 * dump_stats() to log absolute runtime alongside iters/s, which lets
	 * crash post-mortem correlate trinity output to external logs.
	 * Do NOT subtract from time(NULL) to compute elapsed -- an NTP
	 * backward step would flip the delta negative.  Elapsed is computed
	 * from start_mono_ns below. */
	time_t start_time;

	/* CLOCK_MONOTONIC anchor for the run, stamped in init_shm() alongside
	 * start_time.  Read-only after init.  Elapsed-runtime computations
	 * (dump_stats runtime header) subtract mono_ns() from this so an
	 * NTP wall-clock step -- forward or backward -- cannot skew the
	 * displayed uptime or (worse) drive a would-be duration negative. */
	uint64_t start_mono_ns;

	/*
	 * Identity of trinity's own binary, captured once in init_shm() via
	 * stat("/proc/self/exe", ...).  Read-only after init; written exactly
	 * once before any child forks, so children inherit the populated cache
	 * via shared mapping and the execve sanitiser can fstatat() the target
	 * of a fuzzed execve / execveat and refuse the syscall if the resolved
	 * (dev, ino) matches.  Catches every path that resolves to the trinity
	 * binary regardless of name -- /proc/self/exe, /proc/<pid>/exe,
	 * hardlinks, bind-mounted aliases, the literal path the operator
	 * launched with, and execveat(fd, "", AT_EMPTY_PATH) where fd is
	 * inherited from the parent.  valid == false means the startup stat
	 * failed (very unlikely; /proc not mounted or similar) and the guard
	 * short-circuits to "no protection" -- degraded behaviour matches the
	 * pre-guard baseline.  See sanitise_execve() in syscalls/execve.c.
	 */
	struct {
		dev_t dev;
		ino_t ino;
		bool valid;
	} trinity_self_exe;

	/*
	 * Monotonic generation counter bumped by each new child after it
	 * completes its sibling-childdata freeze in init_child.  Each child
	 * caches the last value it saw and re-checks it at the top of the
	 * child_process loop; a mismatch triggers a catch-up refreeze that
	 * pulls any newly-spawned sibling into our PROT_READ set.
	 *
	 * Closes the startup race where a sibling that was mid-syscall when
	 * a fresh child was forked still has the new child's childdata at
	 * PROT_READWRITE in its view.  In that window a value-result kernel
	 * write triggered by the busy sibling can land inside the new
	 * child's not-yet-frozen region (childdata is alloc_shared and so
	 * occupies a discrete 4 KiB-aligned mmap slot per child — random
	 * pointer args from the busy sibling can fall there).  The window
	 * closes once each existing sibling reaches its next loop top
	 * check — typically one syscall worth of latency.
	 *
	 * Lives next to start_time deliberately: that slot was padding
	 * before the 64-byte-aligned fd_hash cacheline, so adding the
	 * counter doesn't introduce false sharing with anything hot.  Only
	 * written on spawn (rare); reads are RELAXED-equivalent loads on
	 * the loop top — one pulled cacheline shared across all readers.
	 */
	unsigned int sibling_freeze_gen;

	/* Written by main process — own cache line to avoid
	 * false sharing with child-written stats above. */
	unsigned int running_childs __attribute__((aligned(64)));

	/* rng related state */
	unsigned int seed;

	/* Indices of syscall in syscall table that are active.
	 * All indices shifted by +1. Empty index equals to 0.
	 *
	 * 'active_syscalls' is only used on uniarch. The other two
	 * are only used on biarch. */
	int active_syscalls32[MAX_NR_SYSCALL];
	int active_syscalls64[MAX_NR_SYSCALL];
	int active_syscalls[MAX_NR_SYSCALL];
	unsigned int nr_active_syscalls;
	unsigned int nr_active_32bit_syscalls;
	unsigned int nr_active_64bit_syscalls;

	/*
	 * Cost-partitioned active pools maintained BESIDE the flat
	 * active_syscalls*[] arrays above.  Every syscall live in a flat
	 * array is also live in exactly one of these two pools, split by
	 * whether syscall_is_expensive() returns true for its table
	 * index -- the authoritative source of truth is the read-only
	 * EXPENSIVE bitmap that select_syscall_tables() builds once at
	 * init from entry->flags & EXPENSIVE, so a scribbled
	 * entry->flags cannot mis-classify.
	 *
	 * Same +1 index encoding as the flat arrays (val = calln + 1,
	 * val == 0 is the empty slot), same swap-with-last mutation
	 * discipline, same shm->syscalltable_lock coverage as the flat
	 * arrays' mutations in deactivate_syscall_locked().  The
	 * per-entry back-index for pool-side swap-with-last is
	 * syscall_rt(entry)->pool_number in the parallel syscall_runtime
	 * array (see include/syscall.h), mirroring active_number's role
	 * for the flat array.
	 *
	 * Partition invariant, checked from within the activate /
	 * deactivate paths under the lock:
	 *   nr_active_cheap + nr_active_exp == nr_active_syscalls
	 *   nr_active_cheap_32bit + nr_active_exp_32bit == nr_active_32bit_syscalls
	 *   nr_active_cheap_64bit + nr_active_exp_64bit == nr_active_64bit_syscalls
	 *
	 * BEHAVIOUR-NEUTRAL storage: the live picker still draws from
	 * the flat active_syscalls*[] + expensive_accept.  These pools
	 * are maintained but NOT read by random_syscall/ -- they are
	 * the foundation for the later O(1) cost-selector phases.
	 *
	 * Uniarch builds only touch the un-suffixed pair; biarch builds
	 * only touch the _32bit / _64bit pairs, mirroring the flat
	 * arrays' arch-only-touches convention.
	 */
	int active_cheap[MAX_NR_SYSCALL];
	int active_expensive[MAX_NR_SYSCALL];
	int active_cheap32[MAX_NR_SYSCALL];
	int active_expensive32[MAX_NR_SYSCALL];
	int active_cheap64[MAX_NR_SYSCALL];
	int active_expensive64[MAX_NR_SYSCALL];
	unsigned int nr_active_cheap;
	unsigned int nr_active_exp;
	unsigned int nr_active_cheap_32bit;
	unsigned int nr_active_exp_32bit;
	unsigned int nr_active_cheap_64bit;
	unsigned int nr_active_exp_64bit;

	/*
	 * Cached "table has at least one active syscall" booleans for the
	 * biarch picker.  Maintained by validate_syscall_table_{32,64}() at
	 * startup and invalidated by the deactivate_syscall{32,64}() paths
	 * (and the 32-on-64 emulation auto-disable) when the corresponding
	 * nr_active_*bit_syscalls counter falls to zero.  Lets
	 * choose_syscall_table() short-circuit the per-pick walk through
	 * validate_syscall_table_{32,64}() with two single-byte loads.
	 *
	 * Only meaningful on biarch builds; uniarch never reads them.
	 */
	bool valid_syscall_table_32;
	bool valid_syscall_table_64;

	/*
	 * Per-syscall consecutive validation-failure counter.  Bumped by
	 * the pickers when validate_specific_syscall_silent() returns
	 * false; reset to 0 when validation passes.  Deactivation only
	 * triggers once the count hits VALIDATE_FAIL_THRESHOLD, so a
	 * transient flap (e.g. a probe that EAGAIN'd once) no longer
	 * permanently kills the entry on the first failure.  u8 is plenty:
	 * we only compare against the small threshold and reset on
	 * success.  All accesses are relaxed atomic so concurrent pickers
	 * across children can race the same slot without a lock.
	 *
	 * Dimensioned [2][MAX_NR_SYSCALL] so biarch builds keep the 32-bit
	 * and 64-bit tables' failure counters separate -- slot N in one
	 * table is usually a different syscall than slot N in the other,
	 * and a single-dimension array let resets and threshold trips on
	 * one arch silently overwrite or be driven by observations from
	 * the sibling.  Uniarch builds only ever touch index [0], matching
	 * the existing do32 ? 1 : 0 convention used elsewhere (see
	 * cmp_hints_strip).
	 */
	unsigned char syscall_validation_failures[2][MAX_NR_SYSCALL];

#ifdef ARCH_IS_BIARCH
	/* Check that 32bit emulation is available. */
	unsigned int syscalls32_succeeded;
	unsigned int syscalls32_attempted;
#endif
	/* io_uring ring with valid mappings, shared across children.
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless).
	 * Destructor nulls this. */
	struct io_uringobj *mapped_ring;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t buglock;

	/*
	 * Shared-string heap state (bump cursor, per-bucket freelist
	 * heads, and the per-slot bucket record that gates
	 * free_shared_str's bucket choice on the allocated size instead
	 * of a payload-derived strlen) lives in utils/shared_str_heap.c,
	 * carved from its own alloc_shared_pool region so that TU stays
	 * standalone and unit-testable without the shm.h include chain.
	 */

	/* various flags. */
	enum exit_reasons exit_reason;
	/* set by check_uid alongside panic(EXIT_UID_CHANGED) so main can
	 * include the offending uid in the bail message. */
	uid_t uid_at_exit;
	bool dont_make_it_fail;

	/* Set to true once we detect that /proc/self/fail-nth can't be
	 * opened (kernel built without CONFIG_FAULT_INJECTION, etc.).
	 * Lives in shm so the flag propagates across fork(). */
	bool no_fail_nth;
	bool spawn_no_more;
	bool ready;
	bool postmortem_in_progress;

	/* global debug flag.
	 * This is in the shm so we can do things like gdb to the main pid,
	 * and have the children automatically take notice.
	 * This can be useful if for some reason we don't want to gdb to the child.
	 */
	bool debug;

	/* set to true if a child hits an EPERM/EINVAL trying to
	 * unshare(CLONE_NEWPID). Stored in shm so the flag propagates
	 * across fork() — a process-local static would be duplicated
	 * into each child's address space. */
	bool no_pidns;

	/* set to true if a child fails the MS_REC|MS_PRIVATE remount
	 * after unshare(CLONE_NEWNS). Stored in shm so the flag
	 * propagates across fork() — a process-local static would be
	 * duplicated into each child's address space. Used to suppress
	 * log spam over long fuzz runs and to skip the unshare+remount
	 * dance once we know it can't be made private. */
	bool no_private_ns;

	/*
	 * Parent-provisioned startup-isolation latches.  Written once by
	 * setup_startup_isolation() in the parent's pre-fork window;
	 * children read RELAXED in init_child_setup_sandbox to decide
	 * whether to do the per-child net/mount unshare or inherit the
	 * parent's provisioned ns.  Either latch false degrades to the
	 * per-child unshare path with zero behaviour change.  Design
	 * rationale (independent latching, degrade ladder, memory
	 * ordering, why netns_fd is stashed here):
	 * Documentation/shm-state.md
	 *
	 *   net_ready:   parent's private-netns provisioning succeeded.
	 *   mnt_ready:   parent's private-mount-ns unshare AND
	 *                MS_REC|MS_PRIVATE remount of '/' both succeeded.
	 *   netns_fd:    dup'd /proc/self/ns/net handle to the provisioned
	 *                netns; -1 sentinel means "not published".
	 *                Initialised to -1 by create_shm() over the
	 *                memset-zero so the sentinel is honest even before
	 *                setup runs.
	 */
	struct {
		bool net_ready;
		bool mnt_ready;
		int netns_fd;

		/*
		 * Scratch block-device pool, populated by fds/scratch_block.c
		 * during open_fds() when mnt_ready is latched.  The provider
		 * runs in the parent's brief root window, calls
		 * /dev/loop-control -> LOOP_CTL_GET_FREE -> LOOP_CONFIGURE
		 * over scratch image files and (best-effort) formats one with
		 * mkfs.ext4 then mounts it inside the parent's private mount
		 * ns.  A tmpfs slot is added unconditionally (default:
		 * tmpfs always; ext4 when the loop side + mkfs.ext4 both
		 * succeed).
		 *
		 * This pool is the BOX-SAFETY CHOKEPOINT for fuzzed block
		 * I/O: it is the ONLY source of loop fds + device paths that
		 * a child can draw, by construction.  A host disk node can
		 * never enter the pool because every entry's loop number
		 * came from the kernel's own LOOP_CTL_GET_FREE allocation
		 * and the parent retains the loop fd for the run's lifetime
		 * (children inherit it via fork; a child close drops only
		 * that child's ref).  Childops needing /dev/loopN draw
		 * their loop number from this pool rather than reaching
		 * for arbitrary host block devices, so the node is always
		 * a fuzz-safe parent-owned entry, never a host disk node.
		 *
		 * Children consult scratch_block_ready before reading any
		 * other field; when false (non-root, mnt_ready degraded, or
		 * provider init failed), childops fall back to today's
		 * per-child tmpfs/ramfs path.  loop_fd / loop_num are -1
		 * for the tmpfs slot, so an entry with loop_num >= 0 is the
		 * only kind a block-fd consumer should pick.
		 *
		 * Parent teardown via atexit (mirror self_cgroup_cleanup):
		 * unmount + LOOP_CLR_FD on every published entry, close the
		 * parent-held loop fd, unlink the backing image, rmdir the
		 * scratch subtree.  Idempotent against partial teardown.
		 */
		bool scratch_block_ready;
		unsigned int scratch_block_count;
		struct scratch_block_entry scratch_block[SCRATCH_BLOCK_MAX];
	} isolation;

	/* Live in-flight count for the CLONE_NEWNET throttle.  See
	 * Documentation/shm-state.md (CLONE_NEWNET throttle). */
	int newnet_in_flight;

	/* recipe_runner discovery latches: a recipe whose first invocation
	 * detects an absent kernel feature (ENOSYS, missing config) flips
	 * its slot here so siblings stop probing.  Indexed by the recipe's
	 * slot in the static catalog inside recipe-runner.c. */
	bool recipe_disabled[MAX_RECIPES];

	/* iouring_recipes discovery latches: mirrors recipe_disabled but
	 * scoped to the iouring-recipes childop catalog. */
	bool iouring_recipe_disabled[MAX_IOURING_RECIPES];

	/* Set to true once we confirm io_uring_setup returns ENOSYS.
	 * Avoids repeated failed probes from every child. */
	bool iouring_enosys;

	/* socket_family_chain childop unsupported latch.  Set to true after
	 * an invocation hits a burst of ESRCH/EPERM/ENOPROTOOPT errors,
	 * indicating the kernel was built without CRYPTO_USER_API or AF_ALG
	 * is otherwise locked down.  Siblings then skip the chain entirely. */
	bool socket_family_chain_unsupported;

	/* Per-family latch for the socket-family-grammar dispatcher
	 * (net/socket-family-grammar-core.c).  sfg_unsupported[family] is set
	 * when can_run() probes fail or when run_grammar_chain() exhausts
	 * its ERR_BURST_LIMIT for that family — siblings then skip the
	 * grammar entry on subsequent picks.  No auto-clear; module load
	 * mid-run takes the hit, same recovery story as the AF_ALG latch
	 * above. */
	bool sfg_unsupported[TRINITY_PF_MAX];

	/*
	 * Per-childop feature-absent latches for childops that build
	 * their kernel objects inside a transient userns_run_in_ns()
	 * grandchild.  The rejection (RTM_NEWLINK / socket() / setsockopt()
	 * / open() etc.) is observed after _exit(), so a process-local
	 * static would die with the grandchild and every subsequent
	 * invocation would re-attempt the same unsupported kind forever
	 * (latch-in-grandchild bug).  RELAXED atomic load/store from
	 * multiple grandchildren is safe -- only false -> true, and the
	 * write is idempotent.  No auto-clear.  See
	 * Documentation/shm-state.md (Per-childop feature-absent latches)
	 * for per-latch trigger errnos and CONFIG dependencies.
	 *
	 * vxlan_encap_kind_unsupported[] and veth_xdp_kind_unsupported[]
	 * are indexed by file-local enums whose indices are PINNED by a
	 * _Static_assert in vxlan-encap.c and veth-asymmetric-xdp.c.
	 */
#define VXLAN_ENCAP_NR_KINDS 3
	bool vxlan_encap_kind_unsupported[VXLAN_ENCAP_NR_KINDS];
	bool ip_gre_kind_unsupported;
	/* ip_gre-churn per-grandchild lo-up latch (childops/net/
	 * ip_gre-churn.c).  Written inside the userns_run_in_ns()
	 * grandchild's ip_gre_in_ns() path -- a process-local static
	 * would die with the grandchild on _exit() and every subsequent
	 * invocation would re-pay the rtnetlink "lo up" round-trip
	 * forever.  Living in shm lets one successful lo-up persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent write. */
	bool ip_gre_churn_lo_brought_up;
	bool sctp_chunk_rx_kind_unsupported;
	bool esp_crafted_rx_kind_unsupported;
	/* esp-crafted-rx per-grandchild lo-up latch (childops/net/
	 * esp-crafted-rx.c).  Written inside the userns_run_in_ns()
	 * grandchild's esp_crafted_rx_in_ns() path -- a process-local
	 * static would die with the grandchild on _exit() and every
	 * subsequent invocation would re-open a NETLINK_ROUTE socket
	 * and re-pay the "lo up" rtnetlink round-trip forever.  Living
	 * in shm lets one successful lo-up persist fleet-wide.  RELAXED
	 * atomic load/store is safe -- only false -> true, idempotent
	 * write. */
	bool esp_crafted_rx_lo_brought_up;
	bool fou_gue_mcast_rx_kind_unsupported;
	/* fou-gue-mcast-rx per-grandchild lo-up latch (childops/net/
	 * fou-gue-mcast-rx.c).  Written inside the userns_run_in_ns()
	 * grandchild's fou_gue_mcast_rx_in_ns() path -- a process-local
	 * static would die with the grandchild on _exit() and every
	 * subsequent invocation would re-open a NETLINK_ROUTE socket
	 * and re-pay the "lo up" rtnetlink round-trip forever.  Living
	 * in shm lets one successful lo-up persist fleet-wide.  RELAXED
	 * atomic load/store is safe -- only false -> true, idempotent
	 * write. */
	bool fou_gue_mcast_rx_lo_brought_up;
	bool geneve_rx_kind_unsupported;
	/* geneve-rx per-grandchild lo-up latch (childops/net/
	 * geneve-rx.c).  Written inside the userns_run_in_ns()
	 * grandchild's geneve_rx_in_ns() path -- a process-local static
	 * would die with the grandchild on _exit() and every subsequent
	 * invocation would re-pay the rtnetlink "lo up" round-trip
	 * forever.  Living in shm lets one successful lo-up persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent write. */
	bool geneve_rx_lo_brought_up;
	bool bareudp_rx_kind_unsupported;
	/* bareudp-rx per-grandchild lo-up latch (childops/net/
	 * bareudp-rx.c).  Written inside the userns_run_in_ns()
	 * grandchild's bareudp_rx_in_ns() path -- a process-local static
	 * would die with the grandchild on _exit() and every subsequent
	 * invocation would re-pay the rtnetlink "lo up" round-trip
	 * forever.  Living in shm lets one successful lo-up persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent write. */
	bool bareudp_rx_lo_brought_up;
	bool mpls_label_stack_rx_kind_unsupported;
	bool espintcp_coalesce_kind_unsupported;
#define VETH_XDP_NR_KINDS 4
	bool veth_xdp_kind_unsupported[VETH_XDP_NR_KINDS];
	bool veth_xdp_xdp_unsupported;

	/* nftables_churn per-subsystem latches (childops/net/netfilter/
	 * nftables/churn.c).  Grandchild observes NETLINK_NETFILTER socket
	 * EPROTONOSUPPORT (CONFIG_NF_NETLINK=n), NEWTABLE
	 * EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT (nf_tables absent), or
	 * AF_INET SOCK_DGRAM socket() refusal. */
	bool nft_churn_ns_unsupported_nfnetlink;
	bool nft_churn_ns_unsupported_nf_tables;
	bool nft_churn_ns_unsupported_inet;

	/* bridge-conntrack-churn per-subsystem latches (childops/net/
	 * bridge-conntrack-churn.c).  Grandchild observes RTM_NEWLINK
	 * bridge rejection, nf_tables NEWTABLE/NEWCHAIN rejection on the
	 * bridge family, or ctnetlink IPCTNL_MSG_CT_FLUSH rejection. */
	bool bridge_ct_churn_ns_unsupported_bridge;
	bool bridge_ct_churn_ns_unsupported_nf_tables;
	bool bridge_ct_churn_ns_unsupported_ctnetlink;

	/* bridge-ip6frag-refrag per-subsystem latches (childops/net/
	 * bridge-ip6frag-refrag.c).  Grandchild observes RTM_NEWLINK
	 * bridge rejection, nf_tables NEWTABLE/NEWCHAIN/NEWRULE rejection,
	 * or AF_PACKET SOCK_RAW socket() refusal. */
	bool bridge_ip6frag_ns_unsupported_bridge;
	bool bridge_ip6frag_ns_unsupported_nf_tables;
	bool bridge_ip6frag_ns_unsupported_af_packet;

	/* bridge-ip6-refrag-fraggap per-subsystem latches (childops/net/
	 * bridge-ip6-refrag-fraggap.c).  Grandchild observes RTM_NEWLINK
	 * bridge rejection, nf_tables NEWTABLE/NEWCHAIN rejection, or the
	 * bridge-nf-call-ip6tables sysctl being absent. */
	bool bridge_ip6_fraggap_ns_unsupported_bridge;
	bool bridge_ip6_fraggap_ns_unsupported_nf_tables;
	bool bridge_ip6_fraggap_ns_unsupported_brnf;

	/* ip6erspan-netns-migrate grandchild latches (childops/net/
	 * ip6erspan-netns-migrate.c).  Master gate + changelink secondary
	 * gate.  Write sites include the userns_run_in_ns() grandchild
	 * body; process-local statics would die with the grandchild and
	 * every subsequent invocation would re-attempt the same
	 * unsupported create_link / setns / changelink forever. */
	bool ip6erspan_ns_unsupported;
	bool ip6erspan_ns_unsupported_changelink;

	/* flowtable-encap-vlan grandchild latches (childops/net/netfilter/
	 * flowtable-encap-vlan.c).  ns_unsupported latches on NEWFLOWTABLE
	 * EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT inside the
	 * userns_run_in_ns() grandchild (or on outer wrapper -EPERM);
	 * ip_forward_set is a one-shot gate on the grandchild's
	 * /proc/sys/net/ipv4/ip_forward flip.  Statics would die with the
	 * grandchild and every subsequent invocation would re-pay the
	 * NEWFLOWTABLE round-trip / re-write ip_forward. */
	bool flowtable_vlan_ns_unsupported;
	bool flowtable_vlan_ip_forward_set;

	/* bridge-fdb-stp per-grandchild setup latch (childops/net/
	 * bridge-fdb-stp.c).  "lo up" write site sits inside the
	 * userns_run_in_ns() grandchild body; a process-local static
	 * would die with the grandchild and every subsequent invocation
	 * would re-pay the rtnetlink round-trip. */
	bool bridge_fdb_stp_lo_brought_up;

	/* nftables/churn per-grandchild "lo up" setup latch (childops/net/
	 * netfilter/nftables/churn.c).  Write site sits inside the
	 * userns_run_in_ns() grandchild body; a process-local static
	 * would die with the grandchild and every subsequent invocation
	 * would re-pay the rtnetlink round-trip. */
	bool nftables_churn_lo_brought_up;

	/* bridge-conntrack-churn per-grandchild "lo up" setup latch
	 * (childops/net/bridge-conntrack-churn.c).  Write site sits
	 * inside the userns_run_in_ns() grandchild body; a process-local
	 * static would die with the grandchild and every subsequent
	 * invocation would re-pay the rtnetlink round-trip. */
	bool bridge_conntrack_lo_up_done;

	/* nl80211-churn per-grandchild first-wiphy cache (childops/net/
	 * netlink/nl80211-churn.c).  Both the cached wiphy index and the
	 * "cached" gate live in shm; write sites sit inside the
	 * userns_run_in_ns() grandchild (coordinator +
	 * discovery.c hwsim_present).  Process-local statics would die
	 * with the grandchild and every subsequent invocation would
	 * re-pay the GET_WIPHY enumerate. */
	uint32_t nl80211_phy0;
	bool nl80211_phy0_cached;

	/* ip6gre-bond-lapb-stack per-grandchild unsupported latch
	 * (childops/net/ip6gre-bond-lapb-stack.c).  Write sites sit
	 * inside the userns_run_in_ns() grandchild body; a process-local
	 * static would die with the grandchild and every subsequent
	 * invocation would re-attempt the same unsupported ip6gre /
	 * bond_enslave / lapb-lookup. */
	bool ip6gre_bond_lapb_ns_unsupported;

	/* bridge-vlan-churn per-grandchild unsupported latch (childops/
	 * net/bridge-vlan-churn.c).  Write sites include the
	 * userns_run_in_ns() grandchild body (CONFIG-absent bridge create
	 * probe) plus the outer wrapper -EPERM branch; a process-local
	 * static would die with the grandchild and every subsequent
	 * invocation would re-attempt the same unsupported bridge
	 * create. */
	bool bridge_vlan_churn_ns_unsupported;

	/* vlan-filter-churn per-grandchild unsupported latch (childops/
	 * net/vlan-filter-churn.c).  Write sites include the
	 * userns_run_in_ns() grandchild body (veth / vlan-dev create
	 * rejection) plus the outer wrapper -EPERM branch; a process-local
	 * static would die with the grandchild and every subsequent
	 * invocation would re-attempt the same unsupported create. */
	bool vlan_filter_churn_ns_unsupported;

	/* vsock-transport-churn per-grandchild unsupported latch
	 * (childops/net/vsock-transport-churn.c).  Write sites include
	 * vsock_transport_iter_setup() (AF_VSOCK socket()/bind() reject)
	 * which fires from both the parent iter_one path and the
	 * userns_run_in_ns() grandchild's iter_one_in_fresh_netns path,
	 * plus the outer wrapper -EPERM branch; a process-local static
	 * would die with the grandchild and every subsequent invocation
	 * would re-attempt the same unsupported AF_VSOCK setup. */
	bool vsock_transport_churn_ns_unsupported;

	/* netns-teardown-churn per-grandchild unsupported latch (childops/
	 * misc/netns-teardown-churn.c).  Write sites include setns() /
	 * setns-back failure inside the userns_run_in_ns() grandchild body
	 * plus the outer wrapper -EPERM branch; a process-local static
	 * would die with the grandchild and every subsequent invocation
	 * would re-attempt the same broken setns. */
	bool netns_teardown_ns_unsupported;

	/* tc/mirred-blockcast per-subsystem latches (childops/net/tc/
	 * mirred-blockcast.c).  Grandchild observes NETLINK_ROUTE
	 * socket refusal, RTM_NEWLINK "dummy" rejection, RTM_NEWQDISC
	 * clsact rejection, cls_matchall/act_mirred rejection, or
	 * AF_INET SOCK_DGRAM socket() refusal. */
	bool tc_mirred_bc_ns_unsupported_rtnl;
	bool tc_mirred_bc_ns_unsupported_dummy;
	bool tc_mirred_bc_ns_unsupported_clsact;
	bool tc_mirred_bc_ns_unsupported_mirred;
	bool tc_mirred_bc_ns_unsupported_matchall;
	bool tc_mirred_bc_ns_unsupported_inet;

	/* tc/mirred-blockcast per-grandchild setup latches (childops/net/
	 * tc/mirred-blockcast.c).  Written inside the userns_run_in_ns()
	 * grandchild -- a process-local static would die with the
	 * grandchild on _exit() and every subsequent invocation would
	 * re-pay the full lo-up / modprobe cost forever.  Living in shm
	 * lets one successful "lo up" or one modprobe attempt persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent write. */
	bool tc_mirred_bc_lo_brought_up;
	bool tc_mirred_bc_modprobe_tried_ingress;
	bool tc_mirred_bc_modprobe_tried_matchall;
	bool tc_mirred_bc_modprobe_tried_mirred;

	/* tc/live-traffic per-subsystem latches (childops/net/tc/
	 * live-traffic.c).  Grandchild observes NETLINK_ROUTE socket
	 * refusal, RTM_NEWLINK "veth" rejection, RTM_NEWQDISC clsact
	 * rejection, cls_matchall rejection, cls_bpf BPF_PROG_LOAD
	 * refusal, AF_INET SOCK_DGRAM socket() refusal, or XDP prog
	 * load / attach refusal. */
	bool tc_live_ns_unsupported_rtnl;
	bool tc_live_ns_unsupported_veth;
	bool tc_live_ns_unsupported_clsact;
	bool tc_live_ns_unsupported_matchall;
	bool tc_live_ns_unsupported_bpf_cls;
	bool tc_live_ns_unsupported_inet;
	bool tc_live_ns_unsupported_xdp;

	/* tc/live-traffic per-grandchild setup latches (childops/net/tc/
	 * live-traffic.c).  Written inside the userns_run_in_ns()
	 * grandchild -- a process-local static would die with the
	 * grandchild on _exit() and every subsequent invocation would
	 * re-pay the full lo-up / modprobe cost forever.  Living in shm
	 * lets one successful "lo up" or one modprobe attempt persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent write. */
	bool tc_live_lo_brought_up;
	bool tc_live_modprobe_tried_ingress;
	bool tc_live_modprobe_tried_matchall;
	bool tc_live_modprobe_tried_cls_bpf;
	bool tc_live_modprobe_tried_act_mirred;
	bool tc_live_modprobe_tried_act_police;

	/* tc/qdisc-churn per-grandchild setup latches (childops/net/tc/
	 * qdisc-churn.c).  Same rationale as the tc_live_* latches above:
	 * the write sites sit inside the userns_run_in_ns() grandchild, so
	 * a process-local static would die with the grandchild on _exit()
	 * and every subsequent invocation would re-pay the same rtnl / inet
	 * / bridge / dummy setup probe and the "lo up" rtnetlink round-trip
	 * forever.  Living in shm lets one negative probe or one successful
	 * lo-up persist fleet-wide.  RELAXED atomic load/store is safe --
	 * only false -> true, idempotent write. */
	bool tc_qdisc_churn_ns_unsupported_rtnl;
	bool tc_qdisc_churn_ns_unsupported_dummy;
	bool tc_qdisc_churn_ns_unsupported_inet;
	bool tc_qdisc_churn_ns_unsupported_bridge;
	bool tc_qdisc_churn_lo_brought_up;

	/* mpls-route-churn per-grandchild setup latches (childops/net/
	 * mpls-route-churn.c).  Written inside the userns_run_in_ns()
	 * grandchild (_exit reaps the writes); use __ATOMIC_RELAXED
	 * load/store so the parent sees monotonic false->true. */
	bool mpls_route_modprobe_tried_mpls_router;
	bool mpls_route_ns_unsupported_mpls;
	bool mpls_route_ns_unsupported_lwtunnel;
	/* wireguard-decrypt-flood per-grandchild setup latches
	 * (childops/net/wireguard-decrypt-flood.c).  Same rationale as the
	 * tc_qdisc_churn_* latches above: the write sites sit inside the
	 * userns_run_in_ns() grandchild -- a process-local static would die
	 * with the grandchild on _exit() and every subsequent invocation
	 * would re-probe the same wireguard-module-absent errno or re-run
	 * wgdf_setup() forever.  Living in shm lets one negative probe or
	 * one successful setup persist fleet-wide.  RELAXED atomic
	 * load/store is safe -- only false -> true (bools) or once-set
	 * monotonic (ints), and the writes are idempotent.  wgdf_udp_fd /
	 * wgdf_wg_ifindex zero-initialise rather than -1; correctness does
	 * not depend on that because reads are gated on wgdf_setup_done
	 * being true, which is only set after wgdf_open_udp() /
	 * if_nametoindex() have returned a valid handle. */
	bool wg_ns_unsupported;
	bool wgdf_setup_done;
	int wgdf_udp_fd;
	int wgdf_wg_ifindex;

	/* xfrm-churn per-grandchild setup latches (childops/net/xfrm/
	 * xfrm-churn.c: lo_brought_up / ns_unsupported_iptfs /
	 * ns_unsupported_zerocopy are written inside the
	 * userns_run_in_ns() grandchild -- a process-local static would
	 * die with the grandchild on _exit() and every subsequent call
	 * would re-pay the full rtnetlink / SA-install / setsockopt cost.
	 * RELAXED atomic load/store is safe -- only false -> true, and
	 * the write is idempotent. */
	bool xfrm_churn_lo_brought_up;
	bool xfrm_churn_ns_unsupported_iptfs;
	bool xfrm_churn_ns_unsupported_zerocopy;

	/* ipmr-cache-report per-grandchild setup latches
	 * (childops/net/ipmr-cache-report.c). Written inside the
	 * userns_run_in_ns() grandchild callback; a process-local static
	 * dies with the grandchild on _exit() — the persistent child
	 * never observes the write. Moved to shm so the probe is paid
	 * once per fleet rather than per grandchild. RELAXED atomic
	 * load/store is safe -- only false -> true, idempotent. */
	bool ipmr_cache_report_ns_unsupported;
	bool ipmr_cache_report_ns_eperm;

	/* netdev-netns-migrate grandchild latches
	 * (childops/net/netdev-netns-migrate.c).  Master gate is written
	 * from mixed sites: latch_master() is called both from inside the
	 * userns_run_in_ns() grandchild (create/migrate/drive failures)
	 * and from the outer wrapper on userns_run_in_ns() -EPERM.  The
	 * grandchild-side writes to a process-local static would die on
	 * _exit() and the persistent child would keep retrying the same
	 * unsupported RTM_NEWLINK / setns / unshare forever.  Drive gate
	 * is written only inside the grandchild after post-migration
	 * IFF_UP returns EOPNOTSUPP -- pure grandchild leak in the
	 * static-storage form.  Moved to shm so both latches persist
	 * fleet-wide.  RELAXED atomic load/store is safe -- only
	 * false -> true, idempotent. */
	bool ns_unsupported_netdev_migrate;
	bool ns_unsupported_netdev_migrate_drive;

	/*
	 * Distinct-sequence-hash ring for run_grammar_chain's per-walk
	 * phase ordering.  Each walk computes an FNV-1a hash over the
	 * step-IDs it actually executed and calls sfg_seq_record()
	 * to fold it into this ring.  The ring's population is surfaced
	 * as stats.socket_family_grammar_distinct_seq — a value greater
	 * than one proves the phase-order table is live.
	 *
	 * Fixed capacity keeps the memory footprint small (128 * 4 =
	 * 512 bytes) and the counter saturates when the ring fills — the
	 * metric is a variety signal, not a full inventory.  Multiple
	 * children write concurrently; a compare-exchange on sfg_seq_count
	 * makes the append race-free without a lock.  Losers of the CAS
	 * re-scan the ring (the winner just wrote a slot that may match
	 * their hash), so a duplicate under a lost race is possible only
	 * if two children race with the same NEW hash simultaneously —
	 * an over-count of one is acceptable for a variety metric.
	 */
#define SFG_SEQ_HASH_CAP 128
	uint32_t sfg_seq_hashes[SFG_SEQ_HASH_CAP];
	unsigned int sfg_seq_count;

	/*
	 * P4 feedback-scheduler reward arms, parallel to sfg_seq_hashes[]
	 * and keyed by the same slot index (returned by sfg_seq_record).
	 * A legal grammar walk credits the slot for its executed sequence
	 * with the new-edge count harvested over the walk; the picker
	 * rolls these up per (family, order-index) arm to tilt selection
	 * toward productive orderings.  sfg_seq_arm holds the arm id that
	 * owns each slot (stamped on first credit).  Zero-initialised with
	 * the rest of shm; an uncredited slot has attempts == 0 and is
	 * skipped by the rollup.  No second unbounded structure — this is
	 * a fixed extension of the existing ring (128 * 12 = 1536 bytes).
	 */
	uint32_t sfg_seq_attempts[SFG_SEQ_HASH_CAP];
	uint32_t sfg_seq_reward[SFG_SEQ_HASH_CAP];
	uint32_t sfg_seq_arm[SFG_SEQ_HASH_CAP];

	/*
	 * Multi-strategy syscall picker + UCB1 bandit -- fleet-wide state
	 * for the rotation cadence, the per-window edge-count bookkeeping,
	 * and the learner reward series.  Field-by-field rationale (write
	 * discipline, atomic ordering, why calls-with-new-edge vs real
	 * bucket count, why current_selection_reason is stored):
	 * Documentation/shm-state.md (Multi-strategy syscall picker).
	 * See include/strategy.h for the enum definitions.
	 */
	int current_strategy;
	int current_selection_reason;
	unsigned long syscalls_at_last_switch;
	unsigned long pc_edge_calls_at_window_start;
	unsigned long pc_edge_count_at_window_start;
	unsigned long pc_edge_calls_by_strategy[NR_STRATEGIES];
	unsigned long pc_edge_count_by_strategy[NR_STRATEGIES];
	int picker_mode;
	unsigned long bandit_pulls[NR_STRATEGIES];
	unsigned long bandit_reward_calls[NR_STRATEGIES];
	unsigned long bandit_reward_pc_edge_count[NR_STRATEGIES];

	/* Per-arm x chaos-state cohort accumulators (chaos-mode V2,
	 * observation-only): three parallel matrices bucketed by chaos_state
	 * (chaos_off=0 / chaos_on=1) so per-arm reward and diagnostic-fire
	 * rates split by cmp_hints suppression can be compared without
	 * re-running the fuzzer.  Nothing in the picker reads these -- the
	 * learner formula is unchanged.  Rationale (write discipline, why
	 * bandit_warn_fires_by_chaos has no lifetime companion, V3 plan):
	 * Documentation/shm-state.md (Chaos-cohort observation counters). */
	unsigned long bandit_pulls_by_chaos[NR_STRATEGIES][2];
	unsigned long bandit_reward_calls_by_chaos[NR_STRATEGIES][2];
	unsigned long bandit_warn_fires_by_chaos[NR_STRATEGIES][2];

	/*
	 * Per-arm syscall-level exposure counters -- the denominators the
	 * bandit reward series (bandit_pulls[], pc_edge_calls_by_strategy[],
	 * bandit_reward_calls[]) leave implicit.  Multi-producer, RELAXED
	 * fetch_add on the hot path; RELAXED loads in dump_strategy_stats()
	 * at end of run.  Design rationale (why explicit denominators, how
	 * A/B tuning uses these) in Documentation/shm-state.md.
	 *
	 *   strategy_picks[]:             every syscall pick credited to an
	 *     arm, bumped in set_syscall_nr() after arm resolution.  Widest
	 *     population -- all dispatched syscalls (explorer + bandit).
	 *   strategy_bandit_pool_ops[]:   strict subset of strategy_picks
	 *     bumped only on the bandit-pool path.  Pairs cleanly with
	 *     pc_edge_calls_by_strategy[] (both exclude explorer).
	 *   strategy_completed_calls[]:   bumped at end of dispatch_step
	 *     after the syscall returned.  Excludes set_syscall_nr() FAIL
	 *     returns, so completed/picks is the per-arm dispatch success
	 *     rate.
	 */
	unsigned long strategy_picks[NR_STRATEGIES];
	unsigned long strategy_bandit_pool_ops[NR_STRATEGIES];
	unsigned long strategy_completed_calls[NR_STRATEGIES];

	/* Per-arm return-class exposure: partition strategy_completed_calls[]
	 * by the syscall's return disposition so a late-run operator can see
	 * whether the arm is still surfacing genuine kernel work (success or
	 * a subsystem-depth error) or has degenerated into replaying shallow
	 * validation rejects.  The three counters sum to strategy_completed_
	 * calls[arm] within the usual RELAXED lost-update tolerance.
	 *
	 *   strategy_ret_success[]         rec->retval != (unsigned long)-1
	 *   strategy_ret_shallow_reject[]  failure with errno in the pre-
	 *                                  entry validation set (EINVAL /
	 *                                  EBADF / EPERM / EACCES / ENOENT /
	 *                                  EFAULT / ENOSYS / ENOTTY /
	 *                                  EOPNOTSUPP / ENOTDIR / ELOOP /
	 *                                  ENAMETOOLONG / EDOM / ERANGE /
	 *                                  EOVERFLOW / EAFNOSUPPORT /
	 *                                  EPROTONOSUPPORT / ENODEV /
	 *                                  ENOEXEC / EBADR / EMSGSIZE /
	 *                                  EISDIR / ENOTSOCK)
	 *   strategy_ret_deep_error[]      failure with any other errno
	 *                                  (ENOMEM / EAGAIN / EBUSY / EIO /
	 *                                  ENOSPC / ETIMEDOUT / EINTR /
	 *                                  ENOMSG / ENOBUFS / EPIPE /
	 *                                  ECONNREFUSED / ...) -- reached
	 *                                  the subsystem before bailing
	 *
	 * A shallow-heavy arm is buying validation-path replay, not new
	 * kernel depth, and its completed/picks success rate overstates its
	 * true information yield.  Bumped at the same site as strategy_
	 * completed_calls[] in dispatch_step so the three ret_* buckets and
	 * the completed counter stay in lockstep.  RELAXED add-fetch,
	 * multi-producer. */
	unsigned long strategy_ret_success[NR_STRATEGIES];
	unsigned long strategy_ret_deep_error[NR_STRATEGIES];
	unsigned long strategy_ret_shallow_reject[NR_STRATEGIES];

	/* Per-arm-per-selection-reason reward attribution.  Each window's
	 * outcome is bucketed into [arm][reason] independent of the
	 * learner-facing bandit_pulls[] series so operator- and classifier-
	 * side analysis can see how each arm's exposure splits across
	 * selection paths (SR_NORMAL_UCB / SR_COLD_START / SR_ROUND_ROBIN /
	 * SR_PLATEAU_FORCE).  SR_PLATEAU_FORCE windows are deliberately
	 * excluded from the learner-facing series but recorded here so the
	 * intervention cohort is visible.  Rationale (per-reason semantics,
	 * write protocol): Documentation/shm-state.md
	 * (Per-selection-reason attribution). */
	unsigned long bandit_pulls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_calls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_pc_edge_count_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];

	/* Random-rescue classifier counters -- see classify_random_rescue
	 * in include/strategy.h.  Each new-edge syscall completed during an
	 * SR_PLATEAU_FORCE window is classified into an RRC_* bucket and the
	 * corresponding slot here is bumped; multi-producer RELAXED
	 * fetch_add.  Rationale (why the picker consults these, why
	 * per-class contention is acceptable):
	 * Documentation/shm-state.md (Random-rescue classifier). */
	unsigned long random_rescue_class_count[RRC_NR_CLASSES];

	/* Currently-amplified random-rescue class, published by
	 * select_next_strategy at every rotation.  RRC_NR_CLASSES is the
	 * "no amplification" sentinel.  Held as int (not the enum) so the
	 * shm layout stays language-stable across enum reorders.  Read on
	 * the hot pick / arg-generation path to conditionally relax
	 * structured filters (cold-skip disable, cmp-hint boost) inside
	 * the intervention window.  See Documentation/shm-state.md
	 * (Random-rescue classifier). */
	int plateau_rescue_amplified_class;

	/*
	 * Plateau intervention mode rotation state.  Inside an
	 * SR_PLATEAU_FORCE window the orchestrator round-robins
	 * PIM_UNIFORM_RANDOM / PIM_ANTI_PRIOR / PIM_RRC_BIASED /
	 * PIM_COVERAGE_FRONTIER at each rotation.  Design rationale
	 * (rotation dispatch, anti-prior fast path, visibility hand-off):
	 * Documentation/shm-state.md
	 *
	 *   plateau_intervention_mode_current: latched mode for the current
	 *     intervention window; published by select_next_strategy at
	 *     rotation.  Held as int so the shm layout stays language-stable
	 *     across enum reorders.  Reset to PIM_UNIFORM_RANDOM on every
	 *     non-intervention rotation so a stale mode cannot keep the
	 *     anti-prior gate latched on after the plateau lifts.
	 *   plateau_anti_prior_baseline_calls: cached mean of
	 *     kcov_shm->per_syscall.per_syscall_calls across the active syscall set,
	 *     refreshed at every PIM_ANTI_PRIOR rotation.  Zero == "no
	 *     baseline yet"; the accept gate short-circuits to "pass" in
	 *     that state so cold-start picks degenerate to uniform.
	 *   plateau_anti_prior_accept_weight[MAX_NR_SYSCALL]: per-syscall
	 *     pre-computed acceptance numerator in [1,
	 *     ANTI_PRIOR_THRESHOLD_SCALE] (= 64).  uint8_t suffices because
	 *     no per-syscall weight can exceed SCALE by construction.
	 *     Visibility hand-off piggybacks on the RELEASE store of
	 *     current_strategy that publishes the mode.
	 *   plateau_intervention_rotation_counter: monotonic per-intervention
	 *     counter, fetch_add on every plateau-window rotation; the
	 *     selected mode is the post-increment modulo NR_PIM_MODES.
	 *     Only ticks while plateau_active is set so each intervention
	 *     resumes where the previous one left off.
	 *   plateau_intervention_mode_windows[NR_PIM_MODES]: per-mode
	 *     window count, bumped at the same rotation site as the mode
	 *     selection so end-of-run analysis has an exact denominator per
	 *     mode.  Attributed to the EFFECTIVE mode after the cold-ring
	 *     substitution in select_plateau_intervention_strategy (a
	 *     PIM_COVERAGE_FRONTIER rotation that ran with empty per-syscall
	 *     frontier rings lands in plateau_intervention_mode_windows
	 *     [PIM_UNIFORM_RANDOM]).
	 *   plateau_intervention_mode_calls[NR_PIM_MODES]:
	 *   plateau_intervention_mode_pc_edge_calls[NR_PIM_MODES]:
	 *   plateau_intervention_mode_pc_edges[NR_PIM_MODES]:
	 *   plateau_intervention_mode_cmp_wins[NR_PIM_MODES]:
	 *     Per-mode outcome numerators paired with the windows[] denominator
	 *     above.  Bumped at window CLOSE in maybe_rotate_strategy from the
	 *     already-computed per-strategy deltas, attributed to the mode
	 *     latched from plateau_intervention_mode_current at the top of the
	 *     close path (BEFORE select_next_strategy publishes the next mode),
	 *     and only when the just-closed window's selection reason was
	 *     SR_PLATEAU_FORCE.  Attribution matches the denominator: because
	 *     mode_current is stored post-substitution at pick time, a
	 *     degraded FRONTIER window's outcomes land under UNIFORM_RANDOM.
	 *     _calls counts fleet ops observed during the window (same delta
	 *     as the rotation output's syscalls=... field), _pc_edge_calls
	 *     counts productive (>=1 new edge) calls, _pc_edges counts total
	 *     new PC edges, _cmp_wins counts CMP novel constants exposed.
	 *     Observation-only substrate for later plateau soft-saturation
	 *     work; no live-policy consumer today.
	 */
	int plateau_intervention_mode_current;
	unsigned long plateau_anti_prior_baseline_calls;
	/* [nr][picker_context] -- see the block comment above; the
	 * context dim splits INIT-user weight computation from other
	 * caller-context picks.  Baseline: INIT slice byte-identical to
	 * the pre-widening flat counter. */
	uint8_t plateau_anti_prior_accept_weight[MAX_NR_SYSCALL][PICKER_NCTX];
	unsigned long plateau_intervention_rotation_counter;
	unsigned long plateau_intervention_mode_windows[NR_PIM_MODES];
	unsigned long plateau_intervention_mode_calls[NR_PIM_MODES];
	unsigned long plateau_intervention_mode_pc_edge_calls[NR_PIM_MODES];
	unsigned long plateau_intervention_mode_pc_edges[NR_PIM_MODES];
	unsigned long plateau_intervention_mode_cmp_wins[NR_PIM_MODES];

	/* Wall-lever shadow gate.  Identifies high-call zero-yield syscalls
	 * during a warm-plateau window so a future live variant can reclaim
	 * their pick budget.  Baseline + per-syscall {0,1} suppress carrier
	 * (uint8_t) refreshed at every plateau-active rotation; picker-side
	 * gate reads a single RELAXED byte per candidate.  Publish ordering
	 * mirrors plateau_anti_prior_accept_weight.  Rationale (baseline
	 * math, zero-baseline short-circuit): Documentation/shm-state.md
	 * (Wall-lever shadow gate). */
	unsigned long wall_lever_baseline_calls;
	/* [nr][picker_context] -- see the block comment above; the
	 * context dim splits the suppress carrier per caller-context.
	 * Baseline: INIT slice byte-identical to the pre-widening flat
	 * counter. */
	uint8_t wall_lever_suppress[MAX_NR_SYSCALL][PICKER_NCTX];

	/* Phase 2 plateau intervention: shm mirror of strategy.c's
	 * parent-private hypothesis_current.  Published by
	 * strategy_plateau_hypothesis_tick() (parent only); read RELAXED by
	 * select_next_strategy() on every rotation.  PLATEAU_HYPOTHESIS_NONE
	 * reverts to round-robin.  Held as int (not the enum) for shm
	 * layout stability.  See Documentation/shm-state.md
	 * (Plateau-hypothesis mirror). */
	int plateau_current_hypothesis;

	/*
	 * Discounted "recent" counters the UCB1 picker scores against
	 * instead of the lifetime bandit_pulls[]/bandit_reward_calls[]
	 * series.  Fixed-point parts-per-thousand (suffix _x1000) so the
	 * EMA arithmetic stays in integer math; SR_PLATEAU_FORCE windows
	 * skip both decay and increment.  Same CAS-serialised single-writer
	 * protocol as bandit_pulls[]; RELAXED reads.  Design rationale
	 * (non-stationarity, why every arm decays every window, plateau
	 * skip, fixed-point encoding): Documentation/shm-state.md
	 *
	 *   recent_pulls_x1000[]:  discounted effective sample count.  Each
	 *     non-intervention window decays every arm by (1 - alpha) and
	 *     adds BANDIT_EMA_SCALE to the active arm.  Asymptote for an
	 *     always-picked arm is SCALE/alpha.
	 *   recent_reward_x1000[]: discounted total reward in the same
	 *     fixed-point.  Mean per-window reward is
	 *     recent_reward_x1000[i] / recent_pulls_x1000[i] (x1000 cancels)
	 *     so the UCB1 exploit term works without an explicit rescale.
	 */
	unsigned long recent_pulls_x1000[NR_STRATEGIES];
	unsigned long recent_reward_x1000[NR_STRATEGIES];

	/* Monotonic rotation counter, bumped by the CAS-winning child in
	 * maybe_rotate_strategy() once per completed window.  Used as the
	 * generation tag for cmp_novelty[] bloom decay.  See
	 * Documentation/shm-state.md (Cmp-novelty bloom + reward). */
	unsigned long bandit_window_count;

	/* Per-syscall comparison-constant novelty bloom (128-byte bloom +
	 * generation tag per entry) -- see include/strategy.h
	 * (bandit_cmp_observe) and Documentation/shm-state.md
	 * (Cmp-novelty bloom + reward).  Indexed by [syscall_nr][do32?1:0];
	 * biarch builds split per arch so nr=N in each arch does not poison
	 * the other.  bandit_cmp_new_constants[] is the per-arm cumulative
	 * miss count; bandit_cmp_at_window_start snapshots the active arm's
	 * counter for the window-close delta. */
	struct cmp_novelty_entry {
		uint32_t window_tag;
		uint8_t bloom[128];
	} cmp_novelty[MAX_NR_SYSCALL][2];
	unsigned long bandit_cmp_new_constants[NR_STRATEGIES];
	unsigned long bandit_cmp_at_window_start;

	/* Snapshot of kcov_shm->kmsg.kmsg_warn_fires at the start of the
	 * current bandit window; single global (not per-arm) because the
	 * chaos-cohort attribution that consumes the delta needs only
	 * "WARNs this window", not per-arm.  See
	 * Documentation/shm-state.md (Cmp-novelty bloom + reward). */
	unsigned long kmsg_warn_fires_at_window_start;

	/* Per-arm cumulative sum of (cmp_term * 1000 / total_reward) across
	 * windows where cmp_term > 0; divided by bandit_pulls[arm] at end
	 * of run to print the average per-window CMP contribution share for
	 * tuning CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL.  See
	 * Documentation/shm-state.md (Cmp-novelty bloom + reward). */
	unsigned long bandit_cmp_share_sum_x1000[NR_STRATEGIES];

	/* Per-syscall frontier-edge ring + cached recent-count / max.  The
	 * coverage-frontier picker biases its uniform pick by each
	 * syscall's recent NEW-edge count.  frontier_history[nr][slot]
	 * counts new edges per rotation window (multi-producer, atomic
	 * add); frontier_slot advances once per rotation; the *_cached
	 * fields let the picker read the recent-count / max with single
	 * RELAXED loads.  See include/strategy.h and
	 * Documentation/shm-state.md (Coverage-frontier picker state). */
	/* [nr][picker_context][slot] and [nr][picker_context] -- the
	 * picker_context dim splits the frontier-edge ring and its
	 * cached sum per caller-context so a context-specific edge
	 * cluster does not poison the INIT-slice weight the roulette
	 * wheel consumes.  frontier_window_advance() rotates every
	 * per-nr slice across every context, so an idle context's
	 * ring/cache still ages out (a no-op sweep at baseline since
	 * PICKER_CTX_INIT is the only writer).  Baseline: INIT slice
	 * byte-identical to the pre-widening flat counter. */
	uint32_t frontier_history[MAX_NR_SYSCALL][PICKER_NCTX][FRONTIER_DECAY_WINDOWS];
	uint32_t frontier_slot;
	uint32_t frontier_recent_count_cached[MAX_NR_SYSCALL][PICKER_NCTX];
	unsigned int frontier_max_weight_cached;

	/* EFAULT-probe cache for ioctl arg classification; open-addressing
	 * hashmap keyed on (group_idx, request).  Lives in shm so a verdict
	 * reached by one child is reused by all the others (the kernel's
	 * ioctl tables are global and the probe has side effects worth
	 * amortising).  packed == 0 is the empty-slot sentinel; see
	 * ioctls/efault_cache.c for the slot encoding and probing
	 * protocol. */
	uint64_t ioctl_efault_cache[IOCTL_EFAULT_CACHE_SIZE];
};
extern struct shm_s *shm;
extern unsigned int shm_size;

/* Low-bit admission ticket the CLONE_NEWNET throttle stamps onto
 * rec->post_state.  See Documentation/shm-state.md
 * (CLONE_NEWNET throttle). */
#define NEWNET_INFLIGHT_TICKET	0x1UL

/* Single-CAS admission for the CLONE_NEWNET throttle.  Returns true iff
 * this caller now owns one ticket against shm->newnet_in_flight; caller
 * MUST stamp NEWNET_INFLIGHT_TICKET onto rec->post_state and release
 * with release_newnet_ticket() from the post hook.  See
 * Documentation/shm-state.md (CLONE_NEWNET throttle). */
static inline bool try_admit_newnet(void)
{
	int old = __atomic_load_n(&shm->newnet_in_flight, __ATOMIC_RELAXED);

	while (old < MAX_CONCURRENT_NEWNET) {
		if (__atomic_compare_exchange_n(&shm->newnet_in_flight,
						&old, old + 1,
						false,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return true;
		/* CAS failure refreshed `old` with the witnessed value;
		 * loop re-checks the cap against the fresh observation. */
	}
	return false;
}

/* Single-RMW ticket release for the CLONE_NEWNET throttle.  Atomically
 * clears NEWNET_INFLIGHT_TICKET on rec->post_state and decrements
 * shm->newnet_in_flight iff the bit was set on entry (idempotent).
 * See Documentation/shm-state.md (CLONE_NEWNET throttle). */
static inline void release_newnet_ticket(struct syscallrecord *rec)
{
	unsigned long old = __atomic_fetch_and(&rec->post_state,
					       ~NEWNET_INFLIGHT_TICKET,
					       __ATOMIC_RELAXED);

	if (old & NEWNET_INFLIGHT_TICKET)
		__atomic_fetch_sub(&shm->newnet_in_flight, 1,
				   __ATOMIC_RELAXED);
}

/* Data-segment externs paired with shm state.  These live OUTSIDE the
 * shared region (COW-per-child) so a stray write in one child cannot
 * perturb parent or siblings; canary arrays let drain paths detect and
 * work around wild-write damage to per-child ring pointers.  See
 * Documentation/shm-state.md (Data-segment externs). */
extern struct childdata **children;
extern size_t childdata_mapping_len;
extern struct fd_event_ring **expected_fd_event_rings;
extern struct stats_ring **expected_stats_rings;

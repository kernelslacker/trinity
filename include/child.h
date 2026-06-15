#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "types.h"
#include "breadcrumb_ring.h"
#include "bug_backtrace.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "objects.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "syscall.h"

struct fd_event_ring;

/*
 * Circular ring of file descriptors returned by recent fd-creating syscalls.
 * Used to bias ARG_FD generation toward fds that are known to be open.
 */
#define CHILD_FD_RING_SIZE 16

struct child_fd_ring {
	int fds[CHILD_FD_RING_SIZE];
	unsigned int head;
};

/*
 * Per-child ring of recently completed syscall records.  The owning child
 * is the sole producer; the parent reads the ring in post-mortem context
 * to assemble a chronological fleet-wide trace of what was running just
 * before the kernel taint flag flipped.  Lock-free SPSC: producer issues
 * a release-store of head after writing the slot; consumer issues an
 * acquire-load of head before reading slots.  Size must be a power of 2.
 *
 * Each slot holds only the structured fields the post-mortem reader needs
 * to reconstruct a one-line summary (syscall name, args, return value,
 * errno, timestamp) — not the 4 KiB pre-rendered prebuffer/postbuffer
 * that the live -v output uses.  Keeps the per-syscall push to a
 * field-by-field copy of ~80 bytes instead of a 4 KiB struct copy that
 * trashed L1/L2 on every call.
 */
#define CHILD_SYSCALL_RING_SIZE 16

struct chronicle_slot {
	struct timespec tp;		/* CLOCK_MONOTONIC at syscall return. */
	unsigned long a1, a2, a3, a4, a5, a6;	/* arg values as the kernel saw them. */
	unsigned long retval;		/* return value the kernel reported. */
	unsigned int nr;		/* index into the syscall table. */
	int errno_post;			/* errno after return. */
	bool do32bit;			/* selects which table nr indexes. */
	bool valid;			/* false in zero-init slots; the post-mortem
					 * reader uses this to skip slots a freshly
					 * spawned child has not yet filled. */
};

struct child_syscall_ring {
	struct chronicle_slot recent[CHILD_SYSCALL_RING_SIZE];
	uint32_t head;
};

/*
 * Cached previous-tick reading of the curated "should be deterministic
 * across short windows" syscall set.  Populated each time periodic_work
 * runs the divergence sentinel; the next tick re-reads and compares.
 *
 * Only the fields that are stable across two adjacent ticks AND not
 * legitimately mutable by syscalls trinity itself fuzzes are kept --
 * sysinfo's loads/uptime/freeram drift between samples on their own,
 * while utsname's nodename, RLIMIT_NOFILE's rlim_cur/rlim_max, and the
 * task's sched_priority are routinely changed by successful
 * sethostname / setrlimit / prlimit64 / sched_setparam calls and would
 * generate false-positive divergences.
 *
 * The intent is to catch fuzzed value-result syscall buffers whose
 * destination addresses overlap one of these cached readings: a stray
 * write into the cache surfaces as a divergence at the next tick, and a
 * stray write into an unrelated kernel-managed datum (utsname's
 * boot-stable strings, sysinfo's boot-stable scalars) shows up as the
 * live re-read disagreeing with what we captured the previous tick.
 * __NEW_UTS_LEN is 64 -- arrays sized 65 to include the trailing NUL
 * the kernel always copies.
 */
struct sentinel_reading {
	char sysname[65];
	char release[65];
	char version[65];
	char machine[65];
	unsigned long sysinfo_totalram;
	unsigned long sysinfo_totalswap;
	unsigned long sysinfo_totalhigh;
	unsigned int sysinfo_mem_unit;
	bool valid;
};

enum child_op_type {
	CHILD_OP_SYSCALL = 0,	/* default: fuzz random syscalls */
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_MEMORY_PRESSURE,
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
	CHILD_OP_SIGNAL_STORM,
	CHILD_OP_FUTEX_STORM,
	CHILD_OP_PIPE_THRASH,
	CHILD_OP_FORK_STORM,
	CHILD_OP_FLOCK_THRASH,
	CHILD_OP_CGROUP_CHURN,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_IOURING_FLOOD,
	CHILD_OP_CLOSE_RACER,
	CHILD_OP_SOCKET_FAMILY_CHAIN,
	CHILD_OP_XATTR_THRASH,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_MADVISE_CYCLER,
	CHILD_OP_EPOLL_VOLATILITY,
	CHILD_OP_KEYRING_SPAM,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_SLAB_CACHE_THRASH,
	CHILD_OP_TLS_ROTATE,
	CHILD_OP_PACKET_FANOUT_THRASH,
	CHILD_OP_IOURING_NET_MULTISHOT,
	CHILD_OP_TCP_AO_ROTATE,
	CHILD_OP_VRF_FIB_CHURN,
	CHILD_OP_NETLINK_MONITOR_RACE,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_TLS_ULP_CHURN,
	CHILD_OP_VXLAN_ENCAP_CHURN,
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_NFTABLES_CHURN,
	CHILD_OP_TC_QDISC_CHURN,
	CHILD_OP_XFRM_CHURN,
	CHILD_OP_BPF_CGROUP_ATTACH,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_MPTCP_PM_CHURN,
	CHILD_OP_DEVLINK_PORT_CHURN,
	CHILD_OP_HANDSHAKE_REQ_ABORT,
	CHILD_OP_NF_CONNTRACK_HELPER,
	CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
	CHILD_OP_NETNS_TEARDOWN_CHURN,
	CHILD_OP_TCP_ULP_SWAP_CHURN,
	CHILD_OP_MSG_ZEROCOPY_CHURN,
	CHILD_OP_IOURING_SEND_ZC_CHURN,
	CHILD_OP_VSOCK_TRANSPORT_CHURN,
	CHILD_OP_BRIDGE_VLAN_CHURN,
	CHILD_OP_IGMP_MLD_SOURCE_CHURN,
	CHILD_OP_PSP_KEY_ROTATE,
	CHILD_OP_AFXDP_CHURN,
	CHILD_OP_KVM_RUN_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_NAT_T_CHURN,
	CHILD_OP_SPLICE_PROTOCOLS,
	CHILD_OP_RXRPC_KEY_INSTALL,
	CHILD_OP_INPLACE_CRYPTO_ORACLE,
	CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE,
	CHILD_OP_AF_ALG_TEMPLATE_PROBE,
	CHILD_OP_AF_ALG_RECVMSG_CHURN,
	CHILD_OP_IOURING_CMD_PASSTHROUGH,
	CHILD_OP_PAGECACHE_CANARY_CHECK,
	CHILD_OP_MPLS_ROUTE_CHURN,
	CHILD_OP_SOCK_DIAG_WALKER,
	CHILD_OP_ALTNAME_THRASH,
	CHILD_OP_IPMR_CACHE_REPORT,
	CHILD_OP_UBLK_LIFECYCLE,
	CHILD_OP_VETH_ASYMMETRIC_XDP,
	CHILD_OP_IP6ERSPAN_NETNS_MIGRATE,
	CHILD_OP_IPVS_SYSCTL_WRITER,
	CHILD_OP_TCP_MD5_LISTENER_RACE,
	CHILD_OP_IPV6_NDISC_PROXY,
	CHILD_OP_IPFRAG_SOURCE_CHURN,
	CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
	CHILD_OP_OBSCURE_AF_CHURN,
	CHILD_OP_BRIDGE_CT_CHURN,
	CHILD_OP_ATM_VCC_CHURN,
	CHILD_OP_IP6GRE_BOND_LAPB_STACK,
	CHILD_OP_FLOWTABLE_ENCAP_VLAN,
	CHILD_OP_IPV6_PMTU_TEARDOWN_RACE,
	CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN,
	CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	CHILD_OP_TTY_LDISC_CHURN,
	CHILD_OP_WIREGUARD_DECRYPT_FLOOD,
	CHILD_OP_BLKDEV_LIFECYCLE_RACE,
	CHILD_OP_ISCSI_TARGET_PROBE,
	CHILD_OP_ISCSI_LOGIN_WALKER,
	CHILD_OP_ETH_EMITTER,
	CHILD_OP_VMA_SPLIT_STORM,
	CHILD_OP_SYSFS_STRING_RACE,
	CHILD_OP_PCI_BIND,
	CHILD_OP_AF_UNIX_PEEK_RACE,
	CHILD_OP_SYSV_SHM_ORPHAN_RACE,
	CHILD_OP_QRTR_BIND_RACE,
	CHILD_OP_TC_MIRRED_BLOCKCAST,
	CHILD_OP_PFKEY_SPD_WALK,
	CHILD_OP_L2TP_IFNAME_RACE,
	CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
	CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	CHILD_OP_UMOUNT_RACE,
	NR_CHILD_OP_TYPES,
};

/* Per-handler attribution ring for the post_handler_corrupt_ptr counter.
 * Sized to comfortably hold the long tail of distinct handlers without
 * inflating the per-child footprint -- 32 entries cover the unique
 * post-handler count with headroom (the syscall table currently has
 * ~30 .post hooks that call looks_like_corrupted_ptr).  A reserved nr
 * value tags the non-syscall (rec==NULL) pseudo-handler bucket. */
#define CORRUPT_PTR_ATTR_SLOTS		32
#define CORRUPT_PTR_ATTR_NR_NONE	((unsigned int) ~0u)

/* Caller-PC sub-attribution ring keyed by (nr, do32bit, pc).  Sized to
 * comfortably hold ~30 hot post handlers x ~2 distinct caller PCs each
 * plus the deferred-free call sites and headroom. */
#define CORRUPT_PTR_PC_SLOTS		64

struct corrupt_ptr_attr_entry {
	unsigned int nr;
	bool do32bit;
	unsigned long count;
};

struct corrupt_ptr_pc_entry {
	unsigned int nr;
	bool do32bit;
	void *pc;
	/* Optional site tag passed by the caller of
	 * post_handler_corrupt_ptr_bump_site to disambiguate distinct
	 * rejection sites that share a single PC bucket after LTO
	 * inlining (e.g. the four add_object: defence-in-depth walls
	 * that all collapse onto dispatch_step+0x336 under
	 * __builtin_return_address(0) capture).  NULL when the caller
	 * passed no tag; the dump path then renders the bare PC. */
	const char *site;
	unsigned long count;
};

struct deferred_free_reject_pc_entry {
	void *pc;
	unsigned long count;
};

/*
 * Layout note — the leading 64 bytes are the per-syscall hot block.
 *
 * Every field in the leading cacheline is read or written on (almost)
 * every syscall by the dispatch_step / __do_syscall / kcov_collect path
 * or the random-syscall picker.  Keeping them packed in one line saves
 * the 1-3 cacheline misses per call the previous layout incurred when
 * the giant 4 KiB syscallrecord (with PREBUFFER_LEN=4096) sat at the
 * front of the struct and pushed every other hot field out into
 * cachelines that had to be re-fetched on each call.
 *
 * The static_assert in child.c pins op_nr (the last hot field) to an
 * offset under 64 so a future field reorder that breaks this property
 * fails the build instead of silently regressing the hot path.
 *
 * struct childdata itself is aligned to 64 bytes so each per-child
 * allocation starts on a fresh cacheline; without this, alloc_shared
 * could hand out a struct whose first 8 bytes share a line with the
 * preceding allocation's tail.
 */
struct childdata {
	/* ---- Hot leading cacheline (64 bytes) ---- */

	/* Per-child KCOV state (PC fd + CMP fd + trace buffers + active/
	 * cmp_capable/remote flags).  Touched on every syscall: dispatch_step
	 * gates remote_mode off kcov.remote_capable, __do_syscall hands
	 * &kcov to the kcov_enable_X / kcov_disable wrappers (PC and CMP
	 * always run together on every syscall), and kcov_collect /
	 * kcov_collect_cmp mutate dedup + current_generation + the shared
	 * CMP-records counter per call. */
	struct kcov_child kcov;

	/* Last syscall group executed, for group biasing.
	 * Read every call (group_bias gate) and conditionally written. */
	unsigned int last_group;

	/* Per-iteration child-op counter, written every loop iteration in
	 * child_process and consulted by the stall detector. */
	unsigned long op_nr;

	/* ---- End of hot leading cacheline ---- */

	/* Warm fields: read or written per call but not in inner retry
	 * loops.  Kept adjacent so the second cacheline absorbs whatever
	 * the first one missed. */

	/* Pointer to the active-syscall lookup table for this child's
	 * current pick.  Uniarch: set once at child init to
	 * shm->active_syscalls and never written again.  Biarch: refreshed
	 * by choose_syscall_table on every pick (the do32 dice picks one
	 * of shm->active_syscalls{32,64}).  Per-child storage so the
	 * biarch update doesn't need an atomic store on a process-global. */
	int *active_syscalls;

	/* last time the child made progress. */
	struct timespec tp;

	enum child_op_type op_type;

	/* per-child fd caching to avoid cross-child races */
	int current_fd;
	unsigned int fd_lifetime;
	/* Per-slot generation snapshot from current_fd's fd_hash entry,
	 * taken when the fd was fetched.  A mismatch on the next iteration
	 * indicates the slot was emptied or the fd number was recycled
	 * onto a fresh object; either way the cached fd is no longer
	 * trustworthy. */
	uint32_t cached_fd_generation;

	/* fd to /proc/self/fail-nth, opened once per child.  -1 means
	 * fault injection is unavailable on this kernel/config.  Read on
	 * every call by maybe_inject_fault. */
	int fail_nth_fd;

	unsigned int seed;

	unsigned int num;

	/* Snapshot of shm->sibling_freeze_gen taken when we last ran the
	 * sibling-childdata mprotect sweep.  Read at the top of every
	 * child_process loop iteration; on mismatch we re-run the sweep so
	 * any sibling spawned since our last pass joins our PROT_READ set.
	 * See the comment on shm_s::sibling_freeze_gen for the race this
	 * closes. */
	unsigned int last_seen_freeze_gen;

	/* Stall detection state: consecutive alarm timeouts without progress. */
	unsigned int stall_count;
	unsigned int stall_last;

	unsigned char xcpu_count;

	unsigned char kill_count;

	/* Set when the watchdog sends a SIGKILL to a stuck child; cleared
	 * on reap.  Suppresses the per-cycle re-print of the kill banner
	 * (and the stuck-syscall dump that produces it) while the kill is
	 * in flight — without this, is_child_making_progress's ~25 ms poll
	 * re-fires the banner every cycle until kill_count saturates. */
	bool kill_in_flight;

	/* One-shot latch for the D-state diagnostic snapshot fired by
	 * is_child_making_progress() when it first observes the child in
	 * TASK_UNINTERRUPTIBLE.  Set true after the snapshot lands; cleared
	 * on reap (clean_childdata) so a fresh occupant of this slot can
	 * snapshot its own first wedge.  Independent of kill_in_flight so a
	 * future change to the kill-cadence gating cannot accidentally
	 * un-throttle the snapshot. */
	bool dstate_diag_dumped;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	/* Hybrid bandit/explorer split: true for the explorer slice
	 * [alt_op_children, alt_op_children + explorer_children) of the
	 * child array.  Slots strictly below alt_op_children are dedicated
	 * alt-op children; slots at or above the explorer end run the
	 * default/bandit mix.  Stamped once in init_child() and never
	 * mutated for the child's lifetime, so the syscall picker can
	 * branch off it without an atomic load and the bandit-reward
	 * attribution can filter explorer contributions out of
	 * pc_edge_calls_by_strategy[] / pc_edge_count_by_strategy[] /
	 * bandit_cmp_new_constants[].  Always false when
	 * explorer_children is 0. */
	bool is_explorer;

	/* Mid-chain step (i >= 1) of a sequence-chain iteration.  Set by
	 * run_sequence_chain around steps that need to distinguish a
	 * mid-chain dispatch from step 0 / a standalone call.  Lives
	 * outside the leading hot cacheline because the static_assert in
	 * child.c pins op_nr at the end of that line -- adding a field
	 * anywhere ahead of op_nr would push it past 64 bytes and break
	 * the hot-path budget. */
	bool in_chain_mid_step;

	/* Set across the duration of an alt-op op_fn dispatch by
	 * child_process()'s per-op bracket; cleared immediately after.
	 * Read at the call-complete enqueue site in random_syscall_step()
	 * so a random_syscall() invocation made from inside a childop
	 * recipe (e.g. sched_cycler) lands in the syscalls_in_childops
	 * bucket of the childop_split telemetry instead of being
	 * mis-attributed to syscalls_random.  Owner-only field (the
	 * child is the sole writer and the sole reader). */
	bool in_childop;

	/* Strategy enum (enum strategy_t) snapshotted in set_syscall_nr()
	 * at the moment this child's current syscall was picked.  Read by
	 * the post-syscall reward attribution sites (PC edges in
	 * random_syscall_step and CMP novelty in bandit_cmp_observe) so a
	 * strategy rotation that lands between pick and reward credits the
	 * new edges/constants to the arm that actually selected the
	 * syscall, not whichever arm happens to be shm->current_strategy by
	 * the time the syscall returns.  -1 is the "unstamped" sentinel;
	 * both reward sites gate on (strat >= 0 && strat < NR_STRATEGIES)
	 * so the sentinel naturally skips attribution for explorer children
	 * (who bypass the stamp write entirely) and for any pre-first-pick
	 * reads.  Owner-only field, no cross-process coherence needed. */
	int strategy_at_pick;

	/* FD leak instrumentation: count fds created and closed by
	 * this child's syscalls, with per-group breakdown.
	 * On child exit, if fd_created - fd_closed > threshold,
	 * we log which syscall groups are responsible. */
	unsigned long fd_created;
	unsigned long fd_closed;
	unsigned long fd_created_by_group[NR_GROUPS];

	/* Per-child storm-containment counters.  Bumped in lock-step with
	 * the existing global stats.{post_handler_corrupt_ptr,
	 * get_writable_address_scribbled_*} from the same call
	 * sites; the global counters lose attribution across the fleet, so
	 * these per-child shadows are what the storm-rate check below scores
	 * against.  Owner-only writes from inside the child, no cross-process
	 * coherence needed.  Reset in clean_childdata so a fresh occupant of
	 * the slot starts from zero.  See storm_check_last_* below for the
	 * sliding-window accounting. */
	unsigned long local_post_handler_corrupt_ptr;
	unsigned long local_scribbled_slots_caught;

	/* Rate limiter for the OBJ_LOCAL ANON pool lazy top-up in
	 * get_map_handle().  Bumped on every draw exhaustion; once it
	 * reaches MAPS_LOCAL_REFILL_PERIOD we re-clone the OBJ_GLOBAL
	 * ANON snapshot into the child's OBJ_LOCAL pool and zero the
	 * counter again.  Per-child so the cost is bounded regardless
	 * of fleet width.  Reset in clean_childdata so a slot's fresh
	 * occupant does not inherit the previous child's near-trigger
	 * state. */
	unsigned int maps_local_refill_credit;

	/* Per-child bitmask of nonempty OBJ_LOCAL OBJ_MMAP_* pools, used
	 * by get_map_handle() to skip pools that are guaranteed to return
	 * NULL from get_random_object().  Bit 0 = OBJ_MMAP_ANON,
	 * bit 1 = OBJ_MMAP_FILE, bit 2 = OBJ_MMAP_TESTFILE, matching the
	 * map_pool_types[] order used by the handle picker.
	 *
	 * The picker preserves the prior equal-pool bias: it picks one of
	 * the set bits uniformly (1/popcount) rather than weighting by
	 * num_entries.  This deliberately matches the pre-mask uniform
	 * pick over {ANON, FILE, TESTFILE} restricted to the nonempty
	 * subset; the only behavior change is that previously-burnt
	 * iterations on empty pools no longer happen.
	 *
	 * Maintained at the 0<->1 transitions of head->num_entries in
	 * add_object_publish (set bit on first insert) and
	 * __destroy_object (clear bit on last removal); destroy_objects()
	 * also flows through __destroy_object so a teardown of a whole
	 * pool clears the bit too.  Reset in clean_childdata so a slot's
	 * fresh occupant starts from "all empty" and re-discovers
	 * non-emptiness through the post-fork init_child_mappings /
	 * clone_global_mmap_pool seeding (which goes through add_object
	 * and so naturally re-sets the bits). */
	unsigned int mmap_pool_nonempty_mask;

	/* Sliding-window state for the per-child storm-rate check.
	 * storm_check_last_time is the monotonic timestamp at which the
	 * three local_* counters above last passed the rate gate (or the
	 * time clean_childdata ran, whichever is most recent).  The three
	 * snapshots are the values of each counter at that same instant.
	 * The check (in child_process) re-reads CLOCK_MONOTONIC and the
	 * counters every LOCAL_STORM_CHECK_PERIOD iterations and triggers
	 * a recycle when (counter_now - snapshot) / (now - last_time)
	 * exceeds LOCAL_STORM_RATE_THRESHOLD events/sec for any of the
	 * three signals AND the window has been open for at least
	 * LOCAL_STORM_WINDOW_SEC seconds.  The window-floor is what
	 * suppresses single-spike false positives; a transient burst that
	 * cannot sustain over 10 s gets absorbed into the next snapshot
	 * roll instead of recycling the child. */
	struct timespec storm_check_last_time;
	unsigned long storm_check_last_post_handler;
	unsigned long storm_check_last_scribbled;

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	/* Ring buffer for child-produced stats deltas drained by the parent
	 * into struct stats_aggregate.  Allocated in shared memory, one per
	 * child, write-only-by-this-child / read-only-by-parent.  See
	 * include/stats_ring.h for the field set and overflow policy. */
	struct stats_ring *stats_ring;

	/* Name of the recipe currently executing inside recipe_runner(),
	 * or NULL when no recipe is in flight.  Read by post-mortem to
	 * attribute a kernel taint to a specific multi-syscall sequence. */
	const char *current_recipe_name;

	/* Set by __BUG() in the child immediately before _exit() so the
	 * parent's reap path can attribute a "child gone" event to a self-
	 * inflicted assertion failure rather than a kernel zombie or wild
	 * SIGKILL.  bug_text is a string-literal pointer (the bugtxt arg
	 * passed to __BUG, which is always a literal at the call site).
	 * bug_lineno + bug_func let the parent print the call site too. */
	bool hit_bug;
	/* Latched once the parent's dump_child_bug() has surfaced this
	 * child's BUG to the real stderr.  Idempotent gate so the per-tick
	 * poll and the zombie watchdog (and any future caller) print the
	 * forensic exactly once; hit_bug stays set so the zombie watchdog
	 * can still attribute "child gone" to the assertion. */
	bool bug_dumped;
	const char *bug_text;
	const char *bug_func;
	unsigned int bug_lineno;
	/* Raw backtrace frame pointers captured inside __BUG() before the
	 * child starts spinning; symbolised in parent context by
	 * dump_child_bug() so the backtrace survives init_child's
	 * stderr->/dev/null redirect.  See include/bug_backtrace.h. */
	struct bug_backtrace bug_backtrace;

	/* Signal-time fault context stamped by child_fault_handler before
	 * any libc-touching call, so the parent can surface the death
	 * class even when the in-handler backtrace_symbols_fd / open /
	 * dup2 chain re-faults walking a corrupted ld.so writable segment.
	 * Re-symbolised in parent context by dump_child_fault_beacon().
	 * See include/bug_backtrace.h. */
	struct child_fault_beacon fault_beacon;
	/* Latched once the parent's dump_child_fault_beacon() has surfaced
	 * this beacon to the real stderr.  Mirrors bug_dumped above:
	 * idempotent gate so the per-tick poll and any future caller print
	 * the forensic exactly once; fault_beacon.written stays set so
	 * post-reap diagnostics can still see the child died with a
	 * stamped beacon. */
	bool fault_beacon_dumped;

	/* Per-child taint watcher.  tainted_fd is opened once at child init
	 * against /proc/sys/kernel/tainted and cached for the child's
	 * lifetime; -1 means the open failed and the watcher is disabled.
	 * last_tainted holds the most recent kernel taint mask we observed,
	 * baseline-read at init.  The dispatch loop XORs a fresh read against
	 * this on each non-syscall childop completion to catch soft taints
	 * (lockdep WARN, RCU stall, reckless module load) tied to a specific
	 * op even when no oops fires. */
	int tainted_fd;
	unsigned long last_tainted;

	/* ---- Cold tail: large rings and the per-call syscallrecord with
	 * its 4 KiB prebuffer.  Pushed past every hot/warm field so reads
	 * of any field above land in the leading cacheline(s) instead of
	 * dragging the prebuffer's lines into L1. ---- */

	/* Ring of fds returned by recent fd-creating syscalls.
	 * Consulted preferentially when generating ARG_FD arguments. */
	struct child_fd_ring live_fds;

	/* Sibling of live_fds for non-fd returns: small-int scalars
	 * (cookies, key serials, queue ids, signal numbers, ...) that
	 * arrive on RET_NONE syscalls and get propagated forward into
	 * ARG_UNDEFINED slots of subsequent calls.  Capture happens in
	 * handle_syscall_ret() after register_returned_fd; consume
	 * happens at low probability in gen_undefined_arg(). */
	struct child_prop_ring prop_ring;

	/*
	 * Per-child OBJ_LOCAL objhead array.  Allocated lazily by
	 * init_object_lists() in the owning child's private heap (zmalloc).
	 * Unreachable from any other process's address space, so a sibling
	 * fuzzed value-result write cannot land here and the parent must
	 * not deref it for foreign-child diagnostic dumps.  The pointer
	 * itself sits in the writable section of struct childdata (in
	 * MAP_SHARED), but every byte it addresses is private to this
	 * child.
	 */
	struct objhead *objects;

	/*
	 * Per-child snapshot copy of the parent's pre-fork OBJ_GLOBAL
	 * pool.  Populated by clone_global_objects_to_child() in init_child
	 * right after the fork-time OBJ_LOCAL bring-up; sized
	 * MAX_OBJECT_TYPES.  Each objhead's array[] holds shallow copies of
	 * the parent's slot pointers — the obj structs themselves and any
	 * kernel resources they describe (fds, mmap regions) are reached
	 * via fork's table dup, so a snapshot of bookkeeping is the only
	 * per-child state this lift adds.  Mutations from inside this
	 * child stay local; sibling pools cannot reach each other through
	 * cross-process scribble.  NULL between fork and the clone — the
	 * resolver (get_objhead) falls back to shm->global_objects in that
	 * window so any early lookup degrades gracefully instead of
	 * dereferencing NULL.
	 */
	struct objhead *global_objects;

	/*
	 * Per-child snapshot of the parent's pre-fork fd->object hash and
	 * its parallel compact live-fd list.  Captures every entry the
	 * parent published via fd_hash_insert before fork; child lookups
	 * resolve against this snapshot instead of the shm-resident table,
	 * which lets the shm table die alongside the OBJ_GLOBAL pool.
	 * Allocated by clone_global_objects_to_child(); NULL between fork
	 * and the clone, in which case the per-process router falls back
	 * to shm->fd_hash / shm->fd_live the same way the objhead resolver
	 * does for early lookups.
	 */
	struct fd_hash_entry *fd_hash;
	int *fd_live;
	unsigned int fd_hash_count;
	unsigned int fd_live_count;

	/* Per-child shards of the corrupted-pointer attribution rings.
	 * Sole writer is the owning child (the *_record functions in
	 * utils.c); sole reader is the parent at periodic-dump time,
	 * which merges every child's shard into a single ranked table.
	 * No cross-process lock because the writer and reader sets are
	 * each a single context.  this_child()==NULL callers (parent
	 * post-mortem paths, deferred-free tick on the main process)
	 * drop the record -- per-child storage has no parent fallback,
	 * and those callers are vanishingly rare relative to the per-
	 * child rejection volume the dump is summarising. */
	struct corrupt_ptr_attr_entry local_corrupt_ptr_attr[CORRUPT_PTR_ATTR_SLOTS];
	struct corrupt_ptr_pc_entry local_corrupt_ptr_pc[CORRUPT_PTR_PC_SLOTS];
	struct deferred_free_reject_pc_entry local_deferred_free_reject_pc[CORRUPT_PTR_PC_SLOTS];

	/* Per-fire payload that the (nr, do32bit) / (nr, do32bit, pc)
	 * attribution shards drop on the floor: the scribbled pointer
	 * value, the arg slot it was caught on (when the caller knows),
	 * and a short site tag.  Owner-only writes from inside the child;
	 * parent reads at periodic-dump time.  See include/breadcrumb_ring.h
	 * for the coherence model. */
	struct corrupt_ptr_breadcrumb_ring breadcrumb_ring;

	/* Ring of recently completed syscall records, drained by the parent
	 * during post-mortem to reconstruct a fleet-wide chronology. */
	struct child_syscall_ring syscall_ring;

	/* Compact rolling history of recently completed syscalls, drained
	 * on __BUG() to recover what this child was doing just before an
	 * assertion failure (most often a parent-side list/fd-event drain
	 * crash caused by a child wild write hundreds of syscalls back). */
	struct pre_crash_ring pre_crash;

	/* Previous-tick reading for the periodic_work divergence sentinel.
	 * .valid is false on the first tick after clean_childdata so the
	 * first sample populates without a (meaningless) compare. */
	struct sentinel_reading sentinel_prev;

	/* Per-child tick counter for the divergence sentinel.  Bumped on
	 * each tick after the initial full-populate; parity selects which
	 * syscall family is refreshed this tick (even=uname, odd=sysinfo)
	 * so a tick pays one of the two kernel-rwsem syscalls instead of
	 * both.  Reset in clean_childdata so a fresh slot occupant starts
	 * the staggered cycle from a known phase. */
	unsigned int sentinel_tick_ix;

	/* Per-child seen-bloom over (cmp_ip, value, size) tuples consulted
	 * by cmp_hints_collect() to short-circuit pool_add_locked's per-call
	 * linear-scan dedup when this child has already pushed the tuple into
	 * the pool within the last CMP_HINTS_BLOOM_RESET CMP records.
	 * See include/cmp_hints.h for the size / FPR tradeoff and the
	 * "false positives are benign" argument.  Owner-only writes from
	 * inside the child, no cross-process coherence needed.
	 *
	 * Indexed by [do32 ? 1 : 0] for the same reason the shm pools and
	 * cmp_novelty arrays are 2D: under biarch, the same numeric (ip,
	 * value, size) tuple may legitimately be a fresh observation in
	 * one arch's pool even if it was just inserted by the other arch's,
	 * and a single shared bloom would falsely suppress the second
	 * insert. */
	struct cmp_hints_bloom cmp_hints_seen[2];

	/* Greedy CMP RedQueen re-exec per-child state.
	 *
	 * reexec_pending[] is the per-call attribution scratch the per-record
	 * loop in cmp_hints_collect() writes to: each (cmp_ip, value, size,
	 * slot) tuple is one (kernel comparison, runtime operand match)
	 * proposal that the dispatch_step tail will optionally drain into a
	 * fresh dispatch with the named slot pinned to value.
	 *
	 * reexec_pending_count counts how many slots in [0, MAX_REEXEC_PENDING)
	 * are populated; the per-dispatch cap (initially 1) lives
	 * at the consumer site, not here -- the buffer always reflects the
	 * full attribution census the harvest pass produced, regardless of
	 * how many the consumer chooses to spend.
	 *
	 * in_reexec is the recursion guard: set true around redqueen_reexec_step
	 * so the re-exec's own kcov_collect_cmp pass does NOT emit fresh
	 * attribution into the buffer (which would self-reinforce a runaway
	 * loop) and the dispatch_step tail does NOT drain a second tier of
	 * re-execs.  The pool / bloom inserts still run inside the re-exec --
	 * those records are real harvest signal.
	 *
	 * redqueen_enabled is the A/B-comparison stamp: half the CMP-mode
	 * children get true (re-exec active), half get false (the control
	 * group).  Stamped once at child init and never mutated, so per-
	 * window comparisons of (reexec-enabled vs control) cohort metrics
	 * isolate the re-exec's contribution from time-of-day environmental
	 * drift.
	 *
	 * Owner-only writes from inside the child; the buffer is per-call
	 * scratch and the two booleans are read-only after child init / drain
	 * boundary.  No cross-process coherence needed.
	 */
	struct reexec_pending reexec_pending[MAX_REEXEC_PENDING];
	unsigned int reexec_pending_count;
	bool in_reexec;
	bool redqueen_enabled;
	/* Sliding-window cap on greedy re-exec dispatches.  The design caps
	 * the per-child rate at STRATEGY_WINDOW / 4 (~25% of the bandit's
	 * rotation budget) so a hot attributing syscall can't burn the
	 * window's whole syscall budget on re-execs.  Reset cadence is
	 * STRATEGY_WINDOW child iterations from window_start_op; cap
	 * exceedance bumps reexec_window_cap_hit in kcov_shm and skips
	 * the would-be re-exec.  Per-child storage means no cross-process
	 * atomic and the cap is enforced symmetrically across the fleet. */
	unsigned long reexec_count_window;
	unsigned long reexec_window_start_op;

	/* per-call latch, set from any of the four
	 * cmp_hints_try_get() callsites in generate-args.c that commit the
	 * returned hint to a produced syscall arg.  Cleared at the top of
	 * generate_syscall_args() so each new call starts with a fresh
	 * status, and read in kcov_collect()'s found_new branch to attribute
	 * a PC-edge win to the cmp-hint pipeline when the call that flipped
	 * the new edge had a hint injected into its arg surface.  Owner-only
	 * writes from inside the child; the parent's stats consumer reads
	 * the resulting per_syscall_cmp_hint_pc_wins[] counter, never this
	 * flag directly. */
	bool cmp_hint_injected_this_call;

	/* The actual syscall records each child uses.  Dominated by a 4 KiB
	 * prebuffer + 128 B postbuffer used by -v rendering — only nr / a1..a6
	 * / retval / lock / state are touched on the hot path, and those are
	 * already in the rec's own first cacheline. */
	struct syscallrecord syscall;
} __attribute__((aligned(64)));

extern unsigned int max_children;

/*
 * Per-child corruption-rate storm-containment thresholds.  When any of
 * post_handler_corrupt_ptr / scribbled_slots_caught
 * sustains LOCAL_STORM_RATE_THRESHOLD events/sec or more over a window
 * of at least LOCAL_STORM_WINDOW_SEC seconds, the child voluntarily
 * exits its main loop so the parent can fork a replacement.  Rationale:
 * the corruption is a per-child accumulator (a scribbled OBJ_LOCAL slot
 * or a poisoned libc arena) -- it does not survive across fork(), so a
 * fresh child re-inherits clean state and breaks the burn-arg-gen-cycles
 * feedback loop the storm produces.  Containment, not root-cause fix.
 *
 * LOCAL_STORM_CHECK_PERIOD is a power-of-two so the per-iteration gate
 * is a single AND + branch, with no clock_gettime() in the hot path.
 */
#define LOCAL_STORM_RATE_THRESHOLD	50	/* events/sec sustained */
#define LOCAL_STORM_WINDOW_SEC		10	/* must hold for >= this long */
#define LOCAL_STORM_CHECK_PERIOD	1024	/* iterations between checks */

/*
 * Compute the adaptive iteration count for an opt-in childop.  Reads
 * the per-op multiplier (Q8.8 fixed point) maintained by adapt_budget()
 * out of shm->stats.childop_budget_mult[op] and scales `base` by it.
 *
 * If the slot is zero (uninitialised, or wild-write zeroed), fall back
 * to `base` so the loop never collapses to zero iterations — this is
 * the fixed childop budget used before adaptive budget multipliers, and
 * it remains the safe default.
 *
 * Caller must have shm.h in scope (childop .c files already do).  The
 * macro evaluates `op` and `base` exactly once each via statement-
 * expression locals, which matters because callers sometimes pass
 * expressions with side effects for `base` (none today, but cheap to
 * future-proof).
 */
#define BUDGETED(op, base) ({						\
	uint16_t _m = __atomic_load_n(&shm->stats.childop_budget_mult[(op)], \
				      __ATOMIC_RELAXED);		\
	unsigned int _b = (unsigned int)(base);				\
	_m ? ((_b * (unsigned int)_m) >> 8) : _b;			\
})

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void child_fd_ring_push(struct child_fd_ring *ring, int fd);
void child_fd_ring_remove(struct child_fd_ring *ring, int fd);
void child_fd_ring_remove_range(struct child_fd_ring *ring, int lo, int hi);

void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec);

/*
 * Periodic-work divergence sentinel.  Re-issues a curated set of
 * "should be deterministic across short windows" syscalls (uname,
 * sysinfo, getrlimit/prlimit64 RLIMIT_NOFILE, sched_getparam(0)),
 * compares against child->sentinel_prev, and reports any unexpected
 * drift via pre_crash_ring + a stats counter.  First tick populates
 * the cache and returns without comparing.  See child-sentinel.c.
 */
void divergence_sentinel_tick(struct childdata *child);

void init_child_mappings(void);

void child_process(struct childdata *child, int childno);

void oom_score_adj(int adj);

/* Dedicated alt-op children: when --alt-op-children=N is set, the first
 * N child slots run a fixed alt op for life (round-robin from a static
 * rotation table) instead of the default 95%-syscall / 5%-altop mix.
 * Lets slow VMA / inode / mlock / fork-storm paths get continuous
 * exercise without slowing the throughput-optimised default children.
 *
 * assign_dedicated_alt_op() runs in the parent right before fork(),
 * stamping child->op_type so the freshly-spawned child reads its
 * assigned op out of shared memory before it enters the dispatch loop.
 *
 * log_alt_op_config() prints the reservation count and the start of the
 * rotation under -v.  No-op when --alt-op-children is 0.
 */
void assign_dedicated_alt_op(struct childdata *child, int childno);
void log_alt_op_config(void);

/* init_altop_dispatch() builds the dense vector of currently-enabled
 * alt-ops from dormant_op_disabled[].  Must run before pick_op_type()
 * is first invoked (i.e. before fork_children); a fresh call is required
 * if dormant gates ever become runtime mutable -- the canary queue
 * re-invokes it on every state transition that mutates the gate.  See
 * child-canary.c. */
void init_altop_dispatch(void);

/* Runtime mutators for the dormant-op gate.  Exposed for the canary
 * queue's promote/demote transitions; both functions live in child.c
 * next to the gate storage so the array itself stays file-static.
 * dormant_op_set() implicitly re-invokes init_altop_dispatch() to
 * keep the dense enabled_altops[] vector in sync; the canary queue
 * therefore never has to know that vector exists. */
void dormant_op_set(enum child_op_type op, bool dormant);
bool dormant_op_is_active(enum child_op_type op);
int dormant_op_slot_for(enum child_op_type op);

/* String form of a child_op_type for log/diagnostic output.  Returns
 * a stable string literal; the returned pointer is never freed.
 * alt_op_lookup_by_name() is the inverse: returns NR_CHILD_OP_TYPES
 * if the name is unknown.  Lives in child.c next to the op tables. */
const char *alt_op_name(enum child_op_type op);
enum child_op_type alt_op_lookup_by_name(const char *name);

/* ---- Canary queue (child-canary.c) ---------------------------------
 *
 * Promotes dormant childops by reserving a small number of canary
 * child slots (carved from the front of the --alt-op-children pool),
 * running one dormant op at a time for a fixed iteration budget, and
 * flipping dormant_op_disabled[] when the op proves itself by
 * producing edges without self-crashing.  Parent-private state; the
 * children only observe the queue's effect via the existing
 * enabled_altops[] dense vector init_altop_dispatch() rebuilds.
 */
enum canary_state {
	CANARY_STATE_DORMANT = 0,	/* in queue, not currently running */
	CANARY_STATE_CANARYING,		/* currently in canary window */
	CANARY_STATE_PROMOTED,		/* graduated into random picker */
	CANARY_STATE_DEMOTED,		/* failed window; backoff before re-queue */
	CANARY_STATE_CONFIG_BLOCKED,	/* terminal: kconfig/prereq absent */
};

struct canary_op_state {
	/* identity */
	enum child_op_type op;		/* keyed by op enum */
	const char *name;		/* cached alt_op_name(op) for log lines */
	enum canary_state state;

	/* per-window counters (reset on CANARYING entry) */
	unsigned long window_start_invocations;	/* shm->stats.childop_invocations[op] snapshot at window open;
						 * window size is measured in invocations of the
						 * canary op itself, not fleet-wide ops */
	unsigned long window_start_edges;	/* childop_edges_discovered[op] snapshot */
	unsigned int  window_crashes;		/* incremented by parent reap path */

	/* Per-window snapshots of fleet-wide defence counters, used by
	 * leave_canarying_promote() to tag the promotion with a coarse
	 * health verdict.  These three sources are fleet-wide (not per-op
	 * attributed): parent_stats.{post_handler_corrupt_ptr,
	 * deferred_free_reject} aggregate every child's bumps, and
	 * kcov_shm->pc_diag.first_ebadf_op_nr is a first-failure-wins gate
	 * latched across the whole run.  The window deltas are therefore
	 * a coincidence signal ("this counter moved during this op's
	 * window") rather than an attribution.  Owner-only writes from
	 * parent context, no atomics needed. */
	unsigned long window_start_post_handler_corrupt_ptr;
	unsigned long window_start_deferred_free_reject;
	unsigned long window_start_kcov_first_ebadf_op_nr;

	/* cumulative diagnostics */
	unsigned int  canary_iterations;	/* lifetime windows entered */
	unsigned int  total_promotions;
	unsigned int  total_demotions;

	/* timestamps (CLOCK_MONOTONIC seconds, parent context) */
	time_t        last_state_transition;
	time_t        last_canary_window_start;

	/* Set at startup for ops the audit flagged as needing isolation
	 * (root-only / inner fork / SR-IOV / driver-binding prereq).  The
	 * picker silently skips entries with this bit set; the dormant
	 * gate is left untouched so the op behaves identically to before
	 * the queue existed. */
	bool          phase1_ineligible;
};

void canary_queue_init(void);
void canary_queue_tick(void);
void canary_queue_summary(void);
void canary_queue_on_crash(int childno, int signo);
void canary_queue_on_child_respawn(int childno);

/* Predicate used by the dedicated-alt-op stamping path: returns true
 * if the given child slot is reserved as a canary slot AND the queue
 * is currently running an op.  When true, the caller stamps
 * child->op_type with canary_active_op() rather than the
 * alt_op_rotation[] entry it would otherwise use.  Returns false when
 * the queue is disabled (--no-canary-queue or canary_slots==0). */
bool canary_slot_active(int childno);
enum child_op_type canary_active_op(void);

/* Returns true iff the canary queue has graduated the given op into
 * CANARY_STATE_PROMOTED.  Used by parent-side post-mortem paths (e.g.
 * the watchdog kill record) to attribute a stuck child to a recently-
 * promoted op.  Returns false when the queue is disabled, when the op
 * is out of range, or for any non-promoted state. */
bool canary_op_is_promoted(enum child_op_type op);

void set_dontkillme(struct childdata *child, bool state);

void reap_child(struct childdata *child, int childno);

/* Childops */
bool random_syscall(struct childdata *child);
bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
struct chain_step;
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
bool mmap_lifecycle(struct childdata *child);
bool mprotect_split(struct childdata *child);
bool mlock_pressure(struct childdata *child);
bool inode_spewer(struct childdata *child);
void inode_spewer_cleanup(void);
void inode_spewer_reap(pid_t pid);
bool procfs_writer(struct childdata *child);
void procfs_writer_init(void);
bool memory_pressure(struct childdata *child);
bool userns_fuzzer(struct childdata *child);
bool sched_cycler(struct childdata *child);
bool barrier_racer(struct childdata *child);
bool genetlink_fuzzer(struct childdata *child);
bool perf_event_chains(struct childdata *child);
void perf_event_chains_init(void);
bool tracefs_fuzzer(struct childdata *child);
void tracefs_fuzzer_init(void);
bool bpf_lifecycle(struct childdata *child);
bool fault_injector(struct childdata *child);
bool recipe_runner(struct childdata *child);
bool iouring_recipes(struct childdata *child);
bool fd_stress(struct childdata *child);
bool refcount_auditor(struct childdata *child);
bool fs_lifecycle(struct childdata *child);
bool signal_storm(struct childdata *child);
bool futex_storm(struct childdata *child);
bool pipe_thrash(struct childdata *child);
bool fork_storm(struct childdata *child);
bool flock_thrash(struct childdata *child);
bool cgroup_churn(struct childdata *child);
bool mount_churn(struct childdata *child);
bool uffd_churn(struct childdata *child);
bool iouring_flood(struct childdata *child);
bool close_racer(struct childdata *child);
bool socket_family_chain(struct childdata *child);
bool xattr_thrash(struct childdata *child);
bool pidfd_storm(struct childdata *child);
bool madvise_cycler(struct childdata *child);
bool epoll_volatility(struct childdata *child);
bool keyring_spam(struct childdata *child);
bool vdso_mremap_race(struct childdata *child);
bool numa_migration_churn(struct childdata *child);
bool cpu_hotplug_rider(struct childdata *child);
bool slab_cache_thrash(struct childdata *child);
bool tls_rotate(struct childdata *child);
bool sock_ulp_sockmap_layering(struct childdata *child);
bool packet_fanout_thrash(struct childdata *child);
bool iouring_net_multishot(struct childdata *child);
bool tcp_ao_rotate(struct childdata *child);
bool vrf_fib_churn(struct childdata *child);
bool netlink_monitor_race(struct childdata *child);
bool tipc_link_churn(struct childdata *child);
bool tls_ulp_churn(struct childdata *child);
bool vxlan_encap_churn(struct childdata *child);
bool bridge_fdb_stp(struct childdata *child);
bool nftables_churn(struct childdata *child);
bool tc_qdisc_churn(struct childdata *child);
bool tc_mirred_blockcast(struct childdata *child);
bool xfrm_churn(struct childdata *child);
bool bpf_cgroup_attach(struct childdata *child);
bool sctp_assoc_churn(struct childdata *child);
bool mptcp_pm_churn(struct childdata *child);
bool devlink_port_churn(struct childdata *child);
bool handshake_req_abort(struct childdata *child);
bool nf_conntrack_helper_churn(struct childdata *child);
bool af_unix_scm_rights_gc_churn(struct childdata *child);
bool af_unix_peek_race(struct childdata *child);
bool sysv_shm_orphan_race(struct childdata *child);
bool qrtr_bind_race(struct childdata *child);
bool netns_teardown_churn(struct childdata *child);
bool tcp_ulp_swap_churn(struct childdata *child);
bool msg_zerocopy_churn(struct childdata *child);
bool iouring_send_zc_churn(struct childdata *child);
bool vsock_transport_churn(struct childdata *child);
bool bridge_vlan_churn(struct childdata *child);
bool igmp_mld_source_churn(struct childdata *child);
bool psp_key_rotate(struct childdata *child);
void psp_key_rotate_cleanup_child(void);
bool afxdp_churn(struct childdata *child);
bool kvm_run_churn(struct childdata *child);
bool nl80211_churn(struct childdata *child);
bool nat_t_churn(struct childdata *child);
bool splice_protocols(struct childdata *child);
bool rxrpc_key_install(struct childdata *child);
bool inplace_crypto_oracle(struct childdata *child);
bool af_alg_weak_cipher_probe(struct childdata *child);
bool af_alg_template_probe(struct childdata *child);
const char *af_alg_probe_template_label(unsigned int idx);
bool af_alg_recvmsg_churn(struct childdata *child);
bool iouring_cmd_passthrough(struct childdata *child);
bool pagecache_canary_check(struct childdata *child);
bool mpls_route_churn(struct childdata *child);
bool sock_diag_walker(struct childdata *child);
bool altname_thrash(struct childdata *child);
bool ipmr_cache_report(struct childdata *child);
bool ublk_lifecycle(struct childdata *child);
bool veth_asymmetric_xdp(struct childdata *child);
bool ip6erspan_netns_migrate(struct childdata *child);
bool ipvs_sysctl_writer(struct childdata *child);
bool tcp_md5_listener_race(struct childdata *child);
bool ipv6_ndisc_proxy(struct childdata *child);
bool ipfrag_source_churn(struct childdata *child);
bool rtnl_vf_broadcast_getlink(struct childdata *child);
bool obscure_af_churn(struct childdata *child);
bool bridge_conntrack_churn(struct childdata *child);
bool atm_vcc_churn(struct childdata *child);
bool ip6gre_bond_lapb_stack(struct childdata *child);
bool flowtable_encap_vlan(struct childdata *child);
bool ipv6_pmtu_teardown_race(struct childdata *child);
bool rxrpc_sendmsg_cmsg_churn(struct childdata *child);
bool ovs_tunnel_vport_churn(struct childdata *child);
bool tty_ldisc_churn(struct childdata *child);
bool wireguard_decrypt_flood(struct childdata *child);
bool blkdev_lifecycle_race(struct childdata *child);
bool iscsi_target_probe(struct childdata *child);
bool iscsi_login_walker(struct childdata *child);
bool eth_emitter(struct childdata *child);
bool vma_split_storm(struct childdata *child);
bool sysfs_string_race(struct childdata *child);
bool pci_bind(struct childdata *child);
bool pfkey_spd_walk(struct childdata *child);
bool l2tp_ifname_race(struct childdata *child);
bool statmount_idmap_overflow(struct childdata *child);
bool umount_race(struct childdata *child);

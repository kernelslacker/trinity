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
#include "socket-family-grammar.h"
#include "syscall.h"

#include "kernel/if_packet.h"
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
	CHILD_OP_IP6_UDP_CORK_SPLICE,
	CHILD_OP_IP_GRE_CHURN,
	CHILD_OP_FUTEX_PI_REQUEUE_ROLLBACK,
	CHILD_OP_VLAN_FILTER_CHURN,
	CHILD_OP_SCTP_CHUNK_RX,
	CHILD_OP_PKT_BUILDER_PROBE,
	CHILD_OP_ESP_CRAFTED_RX,
	CHILD_OP_FOU_GUE_MCAST_RX,
	CHILD_OP_GENEVE_RX,
	CHILD_OP_NETNS_MOUNTNS_SETUP_PROBE,
	CHILD_OP_BAREUDP_RX,
	CHILD_OP_MPLS_LABEL_STACK_RX,
	CHILD_OP_DEEP_PATH_NESTING,
	CHILD_OP_ESPINTCP_COALESCE_CHURN,
	CHILD_OP_CRED_TRANSITION_CHURN,
	CHILD_OP_NETDEV_NETNS_MIGRATE,
	NR_CHILD_OP_TYPES,
};

/* Per-childop one-shot latch reason codes published to
 * shm->stats.childop_latch_reason[op] when a childop disables itself for
 * the remainder of the run.  Compact enum (rendered as the integer code
 * in stats; no string table is materialised at this layer -- decoding is
 * the operator's job).  CHILDOP_LATCH_NONE = 0 matches the create_shm()
 * memset so a never-latched op renders as absent in the per-op dump.
 *
 * Keep this list small and generic -- the reason a childop latches off
 * usually reduces to one of "this kernel can't do it" (missing config /
 * netns scope / cap), "the one-shot init step returned an error", or "a
 * persistent resource exhaustion is happening".  Childop-specific detail
 * stays in that childop's own counters; this enum is the cross-childop
 * summary the per-arm-yield telemetry consumes. */
enum childop_latch_reason {
	CHILDOP_LATCH_NONE = 0,
	CHILDOP_LATCH_UNSUPPORTED,		/* kernel feature absent / built out */
	CHILDOP_LATCH_NS_UNSUPPORTED,		/* namespace or capability scope refused */
	CHILDOP_LATCH_INIT_FAILED,		/* one-shot setup/init step returned error */
	CHILDOP_LATCH_RESOURCE_EXHAUSTED,	/* persistent ENOMEM/EMFILE/EAGAIN at setup */
	CHILDOP_LATCH_OTHER,
};

/* Per-pick regime stamp written by set_syscall_nr_coverage_frontier at the
 * two accept sites and consumed by the post-call attribution path in
 * random_syscall_step.  Lets the post-call yield attribution
 * (frontier_productive_wins_per_syscall, frontier_live_misses_per_syscall
 * in include/stats.h) know which accept regime owned the pick that
 * produced the call -- the same regime split the scalar frontier_live_
 * picks / frontier_silent_picks counters surface fleet-wide, but kept
 * per-call instead of per-window so the productive_win / live_miss
 * decision can be attributed against the live-vs-silent split.
 *
 *   FRONTIER_PICK_NONE    Reset value, written at the top of
 *                         set_syscall_nr() before strategy dispatch so a
 *                         non-frontier strategy pick (RANDOM / HEURISTIC)
 *                         naturally leaves the slot at NONE and the
 *                         post-call attribution path skips it.
 *   FRONTIER_PICK_LIVE    Live-ring regime: max_weight > 2 in
 *                         set_syscall_nr_coverage_frontier, the picker is
 *                         biasing off frontier_recent_count.
 *   FRONTIER_PICK_SILENT  Silent-ring regime: max_weight <= 2, the
 *                         plateau-fallback cold-weight path is steering
 *                         the pick.
 *
 * Owner-only writes from inside the child; no cross-process coherence
 * needed.  Read by no live-path code -- the per-call attribution path is
 * the sole consumer, and the picker accept/retry math does not consume
 * this stamp, so any drift cannot perturb live selection. */
enum frontier_pick_regime {
	FRONTIER_PICK_NONE = 0,
	FRONTIER_PICK_LIVE,
	FRONTIER_PICK_SILENT,
};

/* Unified per-childop outcome record (AGGREGATED across the run, NOT a
 * per-invocation event).  One coherent snapshot for consumers that want
 * a single record per op instead of scraping a dozen parallel
 * shm->stats.childop_* arrays.
 *
 * Telemetry-only.  No policy decision reads this record; no field has
 * back-pressure on the picker, canary queue, or promote / demote
 * heuristic.  Fields without a backing per-childop counter today
 * (direct_syscalls, transition_edges, crashes, dstate_wedges,
 * asan_runtime_failure) stay at 0 / false until producers are wired,
 * mirroring the skip-zero convention the existing per-childop dumps
 * use.
 *
 * Counter mapping for the populated fields (see include/stats.h):
 *   clean_edges       shm->stats.childop_edges_clean[op]
 *   noisy_edges       shm->stats.childop_edges_discovered[op] - clean_edges
 *   wall_ns           shm->stats.childop_wall_ns[op]
 *   wedges            shm->stats.childop_wedge_count[op]
 *   timeout_observed  shm->stats.childop_timeout_observed[op]
 *   timeout_missed    shm->stats.childop_timeout_missed[op]
 *   setup_failures    shm->stats.childop_invocations[op]
 *                     - shm->stats.childop_setup_accepted[op]
 *   taint_transition  shm->stats.taint_transitions[op] > 0
 *
 * Subtractions are clamped at zero: the source counters race under
 * RELAXED add-fetch from multiple producers, and a few childops bump
 * setup_accepted more than once per dispatch (the existing setup-yield
 * permille dump in dump_stats clamps for the same reason), so the
 * minuend can momentarily trail the subtrahend across a non-atomic pair
 * of reads. */
struct childop_outcome {
	enum child_op_type op;
	uint64_t wall_ns;
	uint64_t direct_syscalls;
	uint64_t clean_edges;
	uint64_t noisy_edges;
	uint64_t transition_edges;
	uint32_t crashes;
	uint32_t wedges;
	uint32_t dstate_wedges;
	uint32_t setup_failures;
	uint32_t timeout_observed;
	uint32_t timeout_missed;
	bool asan_runtime_failure;
	bool taint_transition;
};

/* Snapshot the aggregated outcome record for one childop.  Reads shm
 * counters under RELAXED loads; the resulting record is a coincident-
 * point-in-time view, not a transactional one (sibling producers can
 * advance any source counter between two field reads).  Safe to call
 * from any context that already has shm mapped; never modifies shm. */
void childop_outcome_snapshot(enum child_op_type op,
			      struct childop_outcome *out);

/* Render a per-childop window summary line via output(1, ...) for every
 * op that has been invoked at least once this run.  Skips
 * CHILD_OP_SYSCALL (the syscall path attributes its work through the
 * per-strategy counters, matching the surrounding per-childop tables)
 * and skips never-invoked ops (skip-zero convention).  No-op until a
 * caller is wired in. */
void childop_outcome_window_dump(void);

/* SHADOW telemetry: derive utility + penalty scores from the outcome
 * record and emit two ranked tables -- top by good-utility (clean and
 * noisy edges per second of wall time, fixed-point integer) and top
 * by bad-utility (sum of wedge / dstate / crash / setup-failure /
 * asan-failure accumulators).  Surfaces the "clean-canary-zero but
 * noisy-wins" shape (clean_edges=0 with noisy_edges large) the per-op
 * window dump leaves at default rank.  No scheduler / canary picker /
 * promotion or demotion path reads these scores -- compute and dump
 * only.
 *
 * Under __SANITIZE_ADDRESS__ a third ranked table is emitted: an
 * ASAN-adjusted bad-utility score that re-weights the failure classes
 * whose runtime cost is several times higher in an ASAN build
 * (poisoning CHECK aborts, allocator / mmap reservation failures
 * against the 32-512 GiB shadow steal, sigaltstack reentry from
 * wedged childops with no canary edges), and a one-third wall-time
 * budget hint.  The failure class is detected from the existing
 * outcome fields, not a hardcoded childop list.  Compile-detected; no
 * CLI knob.  Same shadow contract as the other two tables. */
void childop_score_dump(void);

/* SHADOW per-childop decaying edge+wall recency ring helpers.  The bump
 * helpers add into the active ring slot
 * (childop_edge_history[op][childop_decay_slot & mask] /
 * childop_wall_history[op][...]) and bump the matching cached running
 * sum in lockstep, mirroring the multi-producer frontier_record_new_
 * edge() discipline (RELAXED add-fetch; per-window child-count drift
 * tolerated).  Called from child_process()'s per-dispatch wall and
 * clean-edge accumulation sites in child.c.  No-op for op values
 * outside [0, NR_CHILD_OP_TYPES) and for zero deltas, so the producer
 * sites need no extra guards.
 *
 * childop_window_advance() ages the oldest slot out of the ring and
 * recomputes the cached running sums; runs from the periodic-surface
 * tick that drives the operator-visibility dumps.  Clear-then-publish:
 * the next slot is exchanged to zero under the old cursor, the cached
 * sums are subtracted under a CAS retry (saturating-subtract guard
 * against a racing producer fetch-add), and only then is
 * childop_decay_slot bumped -- a producer racing the rotation keeps
 * bumping the previous slot for a handful of instructions (bounded
 * window-boundary attribution error), never has its addition silently
 * dropped, and never drives the cached sum negative.  Deliberately not
 * borrowing strategy-frontier.c's frontier_window_advance() -- the two
 * ring lifecycles stay disjoint, per the C2 spec. */
void childop_decay_record_edges(enum child_op_type op, unsigned long edges);
void childop_decay_record_wall(enum child_op_type op, unsigned long ns);
void childop_window_advance(void);

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

	/* Per-child staging for the kcov global counters.  See struct
	 * kcov_child_local_stats in include/kcov.h for the field set and
	 * the flush contract.  MUST sit after op_nr -- folding the
	 * counters into struct kcov_child itself would push op_nr past
	 * the 64-byte hot cacheline budget (the static_assert in child.c
	 * pins op_nr there) and the static_assert below pins this field
	 * to >= 64 so a future reorder that drags it into the hot line
	 * fails the build. */
	struct kcov_child_local_stats *local_stats;

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

	/* SHADOW-ONLY stuck-child accounting latch.  Set true by
	 * is_child_making_progress() on the first detection of diff>=30s for
	 * this child, alongside an increment of
	 * shm->stats.syscall_wedge_count[wedge_nr] and
	 * shm->stats.childop_wedge_count[wedge_op_type].  reap_child() then
	 * adds the CLOCK_MONOTONIC elapsed (now - wedge_start_tp) into
	 * shm->stats.syscall_wedge_total_us[wedge_nr] and
	 * shm->stats.childop_wedge_total_us[wedge_op_type] before the slot
	 * is recycled.  wedge_start_tp is seeded from child->tp (the child's
	 * last-progress timestamp) rather than from the detection moment so
	 * the accumulated duration covers the FULL window the slot was
	 * unreusable -- the watchdog's 30 s grace period included -- and
	 * matches the semantics the operator expects when reading "wedged
	 * total".  Latched per-child so a child that survives many watchdog
	 * ticks contributes one event with a real duration, not one event
	 * per tick with zero duration.  Cleared in clean_childdata so the
	 * next occupant of the slot starts fresh.  Diagnostic-only -- no
	 * live-path decision reads either array yet.  See the comments on
	 * shm->stats.syscall_wedge_count[] / childop_wedge_count[] in
	 * include/stats.h for the exit_reason=19 motivation. */
	bool wedge_accounted;
	bool wedge_do32;
	unsigned int wedge_nr;
	enum child_op_type wedge_op_type;
	struct timespec wedge_start_tp;

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

	/* Heuristic-arm group-bias anti-lock-in damper state -- F-RSEQ.
	 * Per-pin streak + windowed coverage watermark + fd-warm flag the
	 * SHADOW group-pin predicate reads at the group_bias gate.  Owner-
	 * only writes from the dispatch_step tail (account_fd_and_group,
	 * gated on frontier_group_antilock_mode != OFF and on group_bias);
	 * read by the gate-site shadow predicate at random-syscall.c
	 * heuristic-arm set_syscall_nr.  Bookkeeping order in the dispatch
	 * tail: on entry->group != child->last_group (group changed) ->
	 * reset all three to 0; ALWAYS group_streak_len++ after the
	 * potential reset; ON found-local-coverage (new PC-edge OR new
	 * local transition-edge) -> last_cov_at_streak = group_streak_len;
	 * ON entry->rettype == RET_FD with rec->retval != -1UL ->
	 * group_fd_created_in_streak++.  No cross-process coherence
	 * needed; no shm, no atomics.
	 *
	 *  group_streak_len
	 *      Heuristic picks since last_group last CHANGED.  Starts at
	 *      0 after each group-change reset, bumped at the end of
	 *      every per-call account_fd_and_group invocation so a pin's
	 *      first member sees group_streak_len == 1 at the NEXT gate
	 *      hit.  Unsigned-int sized; wraps at ~4G picks, well past
	 *      any realistic fuzzer-run pin length.
	 *  last_cov_at_streak
	 *      Watermark: the group_streak_len value at the most recent
	 *      coverage credit within this pin.  Reset to 0 on every
	 *      group change so a fresh pin starts un-credited; advanced
	 *      to the current streak_len whenever this call yielded a
	 *      new PC-edge or a new LOCAL transition-edge (NOT remote,
	 *      since remote-collected coverage can land on whichever
	 *      syscall happened to harvest it and falsely productive-
	 *      mark a pure observer -- the same _real_local lane satcool
	 *      already isolates).  pin_stale = (streak_len > MIN_STREAK)
	 *      && (streak_len - last_cov_at_streak > COV_WINDOW): the
	 *      sliding window inside the pin so a single incidental
	 *      edge does not make a junk-drawer pin immortal (the
	 *      whole-pin cov>0 version would have).
	 *  group_fd_created_in_streak
	 *      Count of fds the pin's calls have returned since the
	 *      last group change.  pin_warm = (group_fd_created_in_
	 *      streak > 0): a pin building live state (warm setup
	 *      socket->bind->sendmsg, openat->read->close) is spared
	 *      from release even when coverage-barren, because the
	 *      produced object is the locality the group bias is really
	 *      protecting.  Pure getters never produce fds and so never
	 *      set this -- pure-getter pins are not spared by the warm
	 *      lane regardless of streak length. */
	unsigned int group_streak_len;
	unsigned int last_cov_at_streak;
	unsigned int group_fd_created_in_streak;

	/* Per-child storm-containment counter.  Bumped in lock-step with
	 * the global stats.post_handler_corrupt_ptr from the same call
	 * sites; the global counter loses attribution across the fleet, so
	 * this per-child shadow is what the storm-rate check below scores
	 * against.  Owner-only writes from inside the child, no cross-process
	 * coherence needed.  Reset in clean_childdata so a fresh occupant of
	 * the slot starts from zero.  See storm_check_last_* below for the
	 * sliding-window accounting. */
	unsigned long local_post_handler_corrupt_ptr;

	/*
	 * Per-child bump-cursor into the parent's writable_pool (see
	 * writable_pool_init in rand/random-address.c).  COW-inherited
	 * from the parent's zero-init at fork; get_writable_address()
	 * advances it forward and wraps when the next allocation would
	 * overrun the pool.  Owner-only writes from inside the child,
	 * no cross-process coherence needed.
	 */
	unsigned long writable_pool_cursor;

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
	 * local_post_handler_corrupt_ptr counter above last passed the
	 * rate gate (or the time clean_childdata ran, whichever is most
	 * recent).  The snapshot is the value of the counter at that same
	 * instant.  The check (in child_process) re-reads CLOCK_MONOTONIC
	 * and the counter every LOCAL_STORM_CHECK_PERIOD iterations and
	 * triggers a recycle when (counter_now - snapshot) / (now -
	 * last_time) exceeds LOCAL_STORM_RATE_THRESHOLD events/sec AND the
	 * window has been open for at least LOCAL_STORM_WINDOW_SEC
	 * seconds.  The window-floor is what suppresses single-spike false
	 * positives; a transient burst that cannot sustain over 10 s gets
	 * absorbed into the next snapshot roll instead of recycling the
	 * child. */
	struct timespec storm_check_last_time;
	unsigned long storm_check_last_post_handler;

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

	/* Last socket-family-grammar illegal-step this child fired, or
	 * {SFG_ILLEGAL_NONE, SFG_CONN_INIT, 0} if the child has never
	 * fired one.  Mirrors the corrupt_ptr breadcrumb model:
	 * owner-only writes from inside the child (sfg_publish_illegal in
	 * net/socket-family-grammar.c, called immediately before the raw
	 * illegal syscall), read by the parent's post-mortem walk to
	 * label the crash context when the kernel oopses inside the
	 * illegal path.  No cross-process coherence needed -- the parent
	 * reads only after the child is quiesced by panic(). */
	struct {
		enum sfg_illegal_op op;
		enum sfg_conn_state at;
		int family;
	} last_sfg_illegal;

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
	/* A/B-comparison stamp for the cmp_hints "uninteresting constant"
	 * substitution-pool drop mask.  Half the children get Arm A (the
	 * historical ~3UL mask -- drop 0/1/2/3) and half get Arm B (~7UL --
	 * also drop 4/5/6/7).  The widened band crosses common meaningful
	 * bounds (struct sizes, low flag bits), so per-arm cohort metrics
	 * (unique pool inserts, downstream new-edge wins per substituted
	 * hint) reveal whether those low values were carrying real signal
	 * or were just bloat in the 16-slot per-syscall pool.  Stamped once
	 * at child init and never mutated, matching the redqueen_enabled
	 * stamp pattern so time-of-day environmental drift is common to
	 * both arms.  Read-only after stamp; owner-only writes; no
	 * cross-process coherence needed.  Strategy.c's
	 * cmp_novelty_interesting() intentionally stays at val < 4 -- the
	 * in-tree comment there keeps the two filters decoupled so the
	 * novelty signal can drift independently of the pool-substitution
	 * threshold; this stamp drives only the pool-side filter. */
	bool boring_filter_arm_b;
	/* Per-child A/B stamp for the frontier_cold_weight blend promotion.
	 * Arm A (false) returns the historical OLD weight to the live picker
	 * so selection stays byte-identical to the pre-blend baseline; Arm B
	 * (true) returns the BLENDED weight (call-count + ilog2(bucket_bits)
	 * + 2*ilog2(distinct_pcs) + ilog2(transition_edges_real_local)) so
	 * the operator can read the live divergence between cohorts off the
	 * frontier_blend_* shm counters.  Stamped once at child init via
	 * ONE_IN(2) and never mutated, matching the boring_filter_arm_b
	 * stamp pattern so time-of-day environmental drift is common to
	 * both arms.  Read-only after stamp; owner-only writes; no
	 * cross-process coherence needed. */
	bool frontier_blend_arm_b;
	/* A/B-comparison stamp for the errno-plateau decay in the coverage-
	 * frontier picker's silent-regime accept site.  Arm A (false) is the
	 * control: shadow counters bump but no live reject, so selection
	 * stays byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) additionally engages the REJECT_DENOM-1 / REJECT_DENOM
	 * probabilistic reject in the picker when the predicate fires, so the
	 * operator can read the live divergence between cohorts off the
	 * frontier_errno_decay_live_rejects shm counter (Arm B only) against
	 * the symmetric frontier_errno_decay_would_skip shm counter (both
	 * arms).  Stamped once at child init via ONE_IN(2) and never mutated,
	 * matching the frontier_blend_arm_b pattern above so time-of-day
	 * environmental drift is common to both arms.  Read-only after stamp;
	 * owner-only writes; no cross-process coherence needed. */
	bool frontier_errno_decay_arm_b;
	/* A/B-comparison stamp for the silent-streak decay at the coverage-
	 * frontier picker's silent-regime accept site.  Arm A (false) is the
	 * control: the shadow counters (frontier_decay_candidates /
	 * frontier_decay_would_skip) still bump in lock-step but selection
	 * stays byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) additionally engages the FRONTIER_SILENT_DECAY_REJECT_DENOM-1
	 * / FRONTIER_SILENT_DECAY_REJECT_DENOM probabilistic reject when the
	 * predicate fires (streak >= FRONTIER_SHADOW_DECAY_STREAK AND the
	 * no-CMP-and-no-SUCCESS-errno-shift UNLESS clause holds), so the
	 * operator can read the live divergence between cohorts off the
	 * frontier_silent_decay_live_rejects shm counter (Arm B only) against
	 * the symmetric frontier_decay_would_skip shm counter (both arms).
	 * Independent of the sibling frontier_errno_decay_arm_b above so the
	 * two decay-axis cohort comparisons stay un-confounded; the goto retry
	 * the silent-streak reject takes preempts the errno-plateau check that
	 * follows it at the picker site, so a single pick can never be
	 * double-demoted within one accept iteration regardless of how the two
	 * arm-B stamps cross.  Stamped once at child init via ONE_IN(2) and
	 * never mutated, matching the frontier_errno_decay_arm_b pattern above
	 * so time-of-day environmental drift is common to both arms.  Read-
	 * only after stamp; owner-only writes; no cross-process coherence
	 * needed. */
	bool frontier_silent_decay_arm_b;
	/* Per-pick frontier accept-regime stamp.  Written by set_syscall_nr_
	 * coverage_frontier at the two accept sites (LIVE for max_weight > 2,
	 * SILENT for max_weight <= 2) and consumed by random_syscall_step's
	 * post-call attribution path so the per-syscall frontier_productive_
	 * wins / frontier_live_misses arrays (include/stats.h) can attribute
	 * the outcome to the accept regime that owned the pick.  Reset to
	 * FRONTIER_PICK_NONE at the top of set_syscall_nr() before strategy
	 * dispatch so non-frontier strategy picks naturally leave the slot
	 * unstamped and the post-call attribution gate skips them.  Cleared
	 * in clean_childdata() so a fresh slot occupant starts from NONE.
	 * Owner-only writes from inside the child; no cross-process coherence
	 * needed.  See enum frontier_pick_regime above for the contract. */
	enum frontier_pick_regime frontier_pick_regime;
	/* A/B-comparison stamp for the adaptive remote-KCOV mode decision in
	 * dispatch_step.  Arm A (false) is the control: the static policy
	 * (per-syscall KCOV_REMOTE_HEAVY flag + ONE_IN(remote_reciprocal))
	 * runs unchanged and the live remote_mode for the upcoming dispatch
	 * is byte-identical to the pre-row baseline for that cohort.  Arm B
	 * (true) replaces the static decision with the adaptive read of the
	 * per-syscall mode-keyed yield counters (remote_pc_calls /
	 * remote_pc_edge_calls / local_pc_calls / local_pc_edge_calls in
	 * struct kcov_shared) -- a HEAVY-flagged syscall whose lifetime
	 * remote samples have failed to produce a single edge is demoted off
	 * the heavy rate, and an unflagged syscall whose remote edge rate
	 * beats its local edge rate by the configured margin is promoted to
	 * remote sampling.  The shadow disposition counters
	 * remote_adaptive_{samples,would_demote,would_promote,agree} in
	 * shm->stats are bumped in lock-step from BOTH arms so the would-be
	 * divergence stays observable across the cohort split, regardless of
	 * which arm this child was stamped into.  Stamped once at child init
	 * via ONE_IN(2) and never mutated, matching the
	 * frontier_errno_decay_arm_b pattern above so time-of-day
	 * environmental drift is common to both arms.  Read-only after
	 * stamp; owner-only writes; no cross-process coherence needed. */
	bool remote_adaptive_arm_b;
	/* Replay-side companion to corpus_entry::rq_sourced.  Set inside
	 * minicorpus_replay() right after the snapshot picks an entry whose
	 * args were captured under in_reexec; cleared unconditionally at the
	 * top of minicorpus_mut_attrib_commit() so the next iteration starts
	 * with a known-clear flag.  Consumed by frontier_record_new_edge()
	 * (strategy.c) to credit later PC-edge wins from RedQueen-sourced
	 * corpus saves to rq_sourced_pcedge_wins_per_syscall[], separate
	 * from the in_reexec/redqueen_enabled axes above which describe the
	 * current dispatch's RedQueen role rather than the source provenance
	 * of the corpus entry being replayed.  Owner-only writes from inside
	 * the child; no cross-process coherence needed. */
	bool replay_rq_sourced;
	/* Replay-side companion to corpus_entry::errno_sourced for
	 * errno-gradient-save.  Same lifecycle as replay_rq_sourced:
	 * set by minicorpus_replay() from the picked snapshot, cleared by
	 * minicorpus_mut_attrib_commit().  Consumed by
	 * frontier_record_new_edge() to credit later PC-edge wins from
	 * errno-sourced corpus saves to
	 * errno_sourced_pcedge_wins_per_syscall[] -- the conversion-rate
	 * counter that pairs with errno_sourced_saves_per_syscall[].  Owner-
	 * only writes from inside the child; no cross-process coherence
	 * needed. */
	bool replay_errno_sourced;
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

	/* A/B-comparison stamp for the cmp-hint baseline injection denom.
	 * Half the children are stamped Arm A (false: ONE_IN(BASELINE) =
	 * the historical 1-in-16 baseline rate) and half are stamped Arm B
	 * (true: ONE_IN(BASELINE_ARM_B) = the more aggressive 1-in-12 rate).
	 * Read at the three baseline callsites in generate-args.c via
	 * cmp_hint_baseline_should_inject(); the amplified callsites are
	 * NOT branched on this flag (the SR_PLATEAU_FORCE / CMP_RISING_PC_
	 * FLAT path already overrides the denom to AMPLIFIED for both arms,
	 * and the separate denom(9)/denom(10) amplified callsites are out of
	 * scope by design).  Stamped once in init_child_runtime_config() at
	 * ONE_IN(2), independent of the KCOV mode pick so the comparison is
	 * not entangled with [redqueen_enabled]'s CMP-mode-only split, and
	 * cleared in clean_childdata so a fresh slot occupant restamps.
	 * Owner-only writes from inside the child; the parent's stats
	 * consumer reads the kcov_shm-resident cmp_inject_arm_* counters
	 * the helper bumps, not this flag directly. */
	bool cmp_hint_inject_arm_b;

	/* A/B-comparison stamp for the prop_ring injection at handle_arg_op's
	 * ARG_OP callsite (the second prop_ring consumer; the first lives in
	 * gen_undefined_arg and is not gated by this stamp).  Arm A (false) is
	 * the control: no prop_ring_try_get pull, the handle_arg_op RNG
	 * sequence stays byte-identical to the pre-row behaviour.  Arm B (true)
	 * attempts a low-prob pull after the existing cmp_hints try has missed;
	 * a successful pull returns a recent kernel-handed-back scalar as the
	 * ARG_OP command code.  Stamped once in init_child_runtime_config() at
	 * ONE_IN(2), independent of cmp_hint_inject_arm_b / redqueen_enabled /
	 * boring_filter_arm_b / frontier_blend_arm_b so the five A/B axes can
	 * cross without confounding each other's cohort comparisons, and
	 * cleared in clean_childdata so a fresh slot occupant restamps.
	 * Owner-only writes from inside the child; the parent's stats consumer
	 * reads the kcov_shm-resident prop_ring_argop_arm_* counters the
	 * callsite bumps, not this flag directly. */
	bool prop_ring_argop_arm_b;

	/* A/B-comparison stamp for the SHADOW structure-aware arm picker in
	 * mutate_arg (the doubled-pool weighted_pick_case_shadow_structured()
	 * draw).  Arm A (false) is the control: the shadow picker is not
	 * called, so mutate_arg's RNG sequence stays byte-identical to the
	 * pre-shadow (pre-139a829f) behaviour and the live weighted_pick_case()
	 * draw is the only rnd_modulo_u32() step on the picker path.  Arm B
	 * (true) calls the shadow picker on structured-eligible slots after
	 * the live op is already in hand, burns one extra rnd_modulo_u32 from
	 * the doubled 2 * MUT_NUM_OPS pool, and bumps mut_structured_shadow_
	 * samples / mut_structured_shadow_divergences for the cohort.  The
	 * per-child stamp is the only correct way to measure the shadow's
	 * downstream effect: an unconditional shadow draw (the 139a829f shape)
	 * perturbs the live RNG fleet-wide on every structured-eligible slot,
	 * leaving no clean control arm.  Stamped once in init_child_runtime_
	 * config() at ONE_IN(2), independent of cmp_hint_inject_arm_b /
	 * redqueen_enabled / boring_filter_arm_b / frontier_blend_arm_b /
	 * prop_ring_argop_arm_b so the six A/B axes can cross without
	 * confounding each other's cohort comparisons, and cleared in
	 * clean_childdata so a fresh slot occupant restamps.  Owner-only writes
	 * from inside the child; the parent's stats consumer reads the
	 * minicorpus_shm-resident mut_structured_arm_* counters bumped at fork
	 * + the mut_structured_shadow_* counters bumped at the callsite, not
	 * this flag directly. */
	bool mut_structured_arm_b;

	/* A/B-comparison stamp for the typed prop_ring consumer rows at the
	 * gen_arg_* sites in generate-args.c.  Arm A (false) skips the
	 * typed pull entirely, leaving the existing kind-agnostic
	 * prop_ring_try_get() callsites in gen_undefined_arg /
	 * handle_arg_op as the only consumers and the per-call RNG
	 * sequence byte-identical to the pre-typing baseline.  Arm B
	 * (true) calls prop_ring_try_get_kind() at the typed callsites
	 * (currently gen_arg_key_serial) and bumps the per-kind consume
	 * counters in kcov_shm so the operator can read the typed-pull
	 * fire rate against the population split.  Stamped once in
	 * init_child_runtime_config() at ONE_IN(2), independent of all
	 * other A/B axes so they can cross without confounding each
	 * other's cohort comparisons, and cleared in clean_childdata so
	 * a fresh slot occupant restamps.  Owner-only writes from inside
	 * the child; the parent reads the kcov_shm-resident counters the
	 * callsite bumps, not this flag directly. */
	bool prop_ring_typed_arm_b;

	/* SHADOW per-entry feedback scoring scratch ([11-feedback-loop]
	 * PHASE 4).  cmp_hints_try_get_ex() pushes one entry per successful
	 * pull (capped at CMP_HINT_CONSUMED_STASH_MAX; overflow drops the
	 * excess).  Cleared at the top of generate_syscall_args() (via
	 * cmp_hints_feedback_reset_stash) and drained by exactly ONE of the
	 * cmp_hints_feedback_credit_* calls in dispatch_step's post-call
	 * bookkeeping, which credit per-entry wins/misses on the matching
	 * pool entries and bump the flat cmp_hint_wins / cmp_hint_misses /
	 * cmp_hint_cmp_novelty_wins counters.  Owner-only writes from
	 * inside the child; no cross-process coherence needed. */
	struct cmp_hint_consumed_entry
		cmp_hints_consumed_stash[CMP_HINT_CONSUMED_STASH_MAX];
	unsigned int cmp_hints_consumed_count;

	/* SHADOW-ONLY topology-pair latch.
	 * Tracks the most recent non-syscall childop ("setup") this child
	 * has dispatched, plus the op_nr at which it was stamped.  Stamped
	 * from child_process() at the top of the dispatch arm for is_alt_op
	 * iterations (before op_fn runs, so a setup that itself produces
	 * new coverage attributes to its own op rather than the prior one)
	 * and read by frontier_record_new_edge() / _transition_edge() to
	 * build a per-event {setup_op, age_in_syscalls, syscall_nr, reason}
	 * tuple in shm->stats.topo_pair_ring[].  NR_CHILD_OP_TYPES is the
	 * "no setup observed yet on this child" sentinel; productive events
	 * that fire before any setup has run bump
	 * topo_pair_no_setup_observed instead of being recorded.  Owner-only
	 * writes from inside the child; no cross-process coherence needed.
	 * Reset in clean_childdata so a fresh slot occupant does not inherit
	 * the previous child's latched setup. */
	enum child_op_type last_setup_op;
	unsigned long last_setup_op_nr;

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

/*
 * Periodic-work cap-drop oracle.  Sampled (ONE_IN(1024)) invariant
 * asserting that the capset()-to-empty in init_child_setup_sandbox
 * actually held: bpf(PROG_LOAD) / mount() / setsockopt(SO_RCVBUFFORCE)
 * each expect EPERM, and capget(self) expects empty masks across both
 * v3 data slots.  Any deviation bumps shm->stats.capdrop_oracle_anomalies
 * and emits an output(0, ...) line.  See child-capdrop-oracle.c.
 *
 * capdrop_oracle_capture_init_ns_anchors() stamps the (st_dev, st_ino)
 * identity of /proc/self/ns/{user,mnt,net} so subsequent ticks can skip
 * the ns-scoped probes after a legitimate userns/mntns/netns transition
 * (statmount-idmap-overflow's in-place unshare, transient-fork capdrop
 * helper) that would otherwise false-fire them.  Call once at child
 * sandbox setup, immediately after the capset()-to-empty drop.  The
 * bpf(KPROBE) probe is never gated -- its cap check pins to the init
 * userns and is the load-bearing init-ns invariant.
 */
void capdrop_oracle_tick(void);
void capdrop_oracle_capture_init_ns_anchors(void);

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

/* Structural predicate: does this op participate in the per-call outer
 * KCOV bracket that publishes childop_edges_clean[op]?  Returns false
 * for ops whose dispatch shape cannot carry the bracket (e.g.
 * CHILD_OP_SYSCALL, CHILD_OP_SCHED_CYCLER); these ops' clean-edge
 * slot stays at zero regardless of attribution mode, so any consumer
 * that reads childop_edges_clean[op] to derive a yield signal must
 * gate the read on this predicate (see canary queue close_window). */
bool op_uses_outer_bracket(enum child_op_type op);

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

/* SHADOW state machine: the seven recommended-state slots the rewritten
 * childop policy will eventually drive (see the rewrite plan's state
 * list).  Today these names are emitted in the per-window canary shadow
 * log only -- no canary_op_state.state setter assigns from this enum,
 * no picker / promote / demote path reads it, no map exists from this
 * enum back to the live enum canary_state.  Telemetry-only naming.
 *
 *   DORMANT                 queued, not currently a canary candidate.
 *   CANARY_CLEAN            window closed clean; keep canarying.
 *   PROMOTED_CLEAN          window crossed the clean-edge threshold;
 *                           promote on the strength of the clean signal.
 *   PROMOTED_INTERFERENCE   clean signal weak, but noisy/interference
 *                           edges accrued -- the op is still valuable
 *                           even if the outer bracket cannot prove it.
 *                           THIS is the new state the rewrite adds; the
 *                           live decision would demote on "zero_edges".
 *   THROTTLED               one expensive wedge / crash window; cool off.
 *   QUARANTINED             repeated bad windows with no wins; exponential
 *                           backoff before re-canary.
 *   CONFIG_BLOCKED          dispatch shape has no outer KCOV bracket
 *                           (matches the live canary-ineligible exit).
 */
enum childop_recommended_state {
	CHILDOP_REC_DORMANT = 0,
	CHILDOP_REC_CANARY_CLEAN,
	CHILDOP_REC_PROMOTED_CLEAN,
	CHILDOP_REC_PROMOTED_INTERFERENCE,
	CHILDOP_REC_THROTTLED,
	CHILDOP_REC_QUARANTINED,
	CHILDOP_REC_CONFIG_BLOCKED,
};

/* Render the recommended-state enum as its uppercase name (e.g.
 * "PROMOTED_INTERFERENCE") for the canary shadow log line.  Returns a
 * pointer to a static string with run lifetime; never NULL. */
const char *childop_recommended_state_name(enum childop_recommended_state s);

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

	/* Per-window snapshots for the SHADOW recommended-state computation
	 * (see enum childop_recommended_state).  The live decision in
	 * close_window_and_decide() runs off the clean-edge delta only and
	 * is unaffected; these snapshots feed the parallel score-driven
	 * recommendation that bumps childop_would_demote[] / childop_would_
	 * promote[] and emits the canary_shadow log line.  Owner-only writes
	 * from parent context, no atomics needed. */
	unsigned long window_start_noisy_edges;
	unsigned long window_start_wedges;
	unsigned long window_start_setup_accepted;
	unsigned long window_start_setup_failures;
	unsigned long window_start_wall_ns;	/* shm->stats.childop_wall_ns[op] snapshot at window
						 * open; close - open is the per-window wall delta
						 * reported in the canary_shadow line.  Telemetry
						 * only, no live decision reads it. */

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
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out);
struct chain_step;
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out);
/*
 * Fresh-args dispatch for a specific pre-picked syscall NR.  Skips
 * set_syscall_nr() (and its strategy attribution) the same way
 * replay_syscall_step does, then generates fresh args, applies the
 * usual chain retval substitution, and enters dispatch_step.  Used by
 * the sequence-chain executor when --chain-resource-typing=live has
 * biased the next link to a specific consumer NR; the caller falls
 * back to plain random_syscall_step() when this returns FAIL (unknown
 * NR, deactivated, sanitise, or per-syscall AVOID gate).
 */
bool random_syscall_step_biased(struct childdata *child,
				unsigned int bias_nr, bool bias_do32,
				bool have_substitute,
				unsigned long substitute_retval,
				bool *found_new,
				unsigned long *new_transition_out,
				unsigned long *new_cmp_out);
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
bool futex_pi_requeue_rollback(struct childdata *child);
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
bool ip_gre_churn(struct childdata *child);
bool bridge_fdb_stp(struct childdata *child);
bool nftables_churn(struct childdata *child);
bool tc_qdisc_churn(struct childdata *child);
bool tc_mirred_blockcast(struct childdata *child);
bool xfrm_churn(struct childdata *child);
bool bpf_cgroup_attach(struct childdata *child);
bool sctp_assoc_churn(struct childdata *child);
bool sctp_chunk_rx(struct childdata *child);
bool mptcp_pm_churn(struct childdata *child);
bool devlink_port_churn(struct childdata *child);
bool handshake_req_abort(struct childdata *child);
bool nf_conntrack_helper_churn(struct childdata *child);
bool af_unix_scm_rights_gc_churn(struct childdata *child);
bool af_unix_peek_race(struct childdata *child);
bool sysv_shm_orphan_race(struct childdata *child);
bool qrtr_bind_race(struct childdata *child);
bool netns_teardown_churn(struct childdata *child);
bool cred_transition_churn(struct childdata *child);
bool netdev_netns_migrate(struct childdata *child);
bool netns_mountns_setup_probe(struct childdata *child);
bool tcp_ulp_swap_churn(struct childdata *child);
bool msg_zerocopy_churn(struct childdata *child);
bool iouring_send_zc_churn(struct childdata *child);
bool vsock_transport_churn(struct childdata *child);
bool bridge_vlan_churn(struct childdata *child);
bool vlan_filter_churn(struct childdata *child);
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
bool ip6_udp_cork_splice(struct childdata *child);
bool pkt_builder_probe(struct childdata *child);
bool esp_crafted_rx(struct childdata *child);
bool fou_gue_mcast_rx(struct childdata *child);
bool geneve_rx(struct childdata *child);
bool bareudp_rx(struct childdata *child);
bool mpls_label_stack_rx(struct childdata *child);
bool deep_path_nesting(struct childdata *child);
bool espintcp_coalesce_churn(struct childdata *child);

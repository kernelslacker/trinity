#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "types.h"
#include "edgepair.h"
#include "kcov.h"
#include "objects.h"
#include "pre_crash_ring.h"
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
	_Atomic uint32_t head;
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
	NR_CHILD_OP_TYPES,
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

	/* Last syscall number executed, for edge-pair tracking.
	 * Read every call (edgepair_is_cold gate) and written every call
	 * (post-dispatch update). */
	unsigned int last_syscall_nr;

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

	/* HEALER per-child sequence buffer.  Holds the last two completed
	 * syscall numbers, written from the per-call bookkeeping path right
	 * after last_syscall_nr is updated.  Read at observer-hook fire to
	 * recover the (pred_a, pred_b) tuple the new-edge event is credited
	 * to.  seq_count is a saturating counter used to gate the observer
	 * until both slots are populated -- the very first two syscalls of a
	 * child's life produce no predset, since there is no "two completed
	 * syscalls before this one" to point at.  Owner-only state, no shm
	 * coherence needed. */
	unsigned int healer_seq[2];
	unsigned int healer_seq_count;

	unsigned char xcpu_count;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	bool dropped_privs;

	/* Hybrid bandit/explorer split: true for the first
	 * `explorer_children` child slots (childno < explorer_children).
	 * Stamped once in init_child() and never mutated for the child's
	 * lifetime, so the syscall picker can branch off it without an
	 * atomic load and the bandit-reward attribution can filter
	 * explorer contributions out of edges_by_strategy[] /
	 * bandit_cmp_new_constants[].  Always false when
	 * explorer_children is 0. */
	bool is_explorer;

	/* FD leak instrumentation: count fds created and closed by
	 * this child's syscalls, with per-group breakdown.
	 * On child exit, if fd_created - fd_closed > threshold,
	 * we log which syscall groups are responsible. */
	unsigned long fd_created;
	unsigned long fd_closed;
	unsigned long fd_created_by_group[NR_GROUPS];

	/* Per-child storm-containment counters.  Bumped in lock-step with
	 * the existing global stats.{post_handler_corrupt_ptr,maps_uaf_caught,
	 * get_writable_address_scribbled_slots_caught} from the same call
	 * sites; the global counters lose attribution across the fleet, so
	 * these per-child shadows are what the storm-rate check below scores
	 * against.  Owner-only writes from inside the child, no cross-process
	 * coherence needed.  Reset in clean_childdata so a fresh occupant of
	 * the slot starts from zero.  See storm_check_last_* below for the
	 * sliding-window accounting. */
	unsigned long local_post_handler_corrupt_ptr;
	unsigned long local_maps_uaf_caught;
	unsigned long local_scribbled_slots_caught;

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
	unsigned long storm_check_last_maps_uaf;
	unsigned long storm_check_last_scribbled;

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	/* Ring buffer for child-produced stats deltas drained by the parent
	 * into struct stats_aggregate.  Allocated in shared memory, one per
	 * child, write-only-by-this-child / read-only-by-parent.  See
	 * include/stats_ring.h for the field set and overflow policy. */
	struct stats_ring *stats_ring;

	/* Ring buffer for child-produced HEALER observation events drained
	 * by the parent into struct healer_aggregate.  Allocated in shared
	 * memory, one per child, write-only-by-this-child / read-only-by-
	 * parent.  See include/healer_ring.h for the slot layout and
	 * overflow policy. */
	struct healer_ring *healer_ring;

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
	const char *bug_text;
	const char *bug_func;
	unsigned int bug_lineno;

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

	/*
	 * Per-child OBJ_LOCAL objhead array.  Lives in its own page-aligned
	 * MAP_SHARED region (allocated lazily by init_object_lists() via
	 * local_objects_alloc()) rather than being embedded in struct
	 * childdata so that the per-child mprotect-RO defence (see
	 * local_objects_freeze() in objects.c) can target just the objhead
	 * pages without dragging in the surrounding hot-path fields
	 * (syscall_ring, sentinel_prev, syscallrecord with its 4 KiB
	 * prebuffer) that share whatever pages the embedded array used to
	 * straddle.  The pointer itself lives in the writable section of
	 * struct childdata; only the region it addresses flips RO/RW.
	 */
	struct objhead *objects;
	/*
	 * True iff the per-child *objects region is currently mprotect'd
	 * PROT_READ in this process's address space.  Lives outside the
	 * protected region (would otherwise be unmodifiable when set) so
	 * the owning child can flip it as part of the thaw/freeze brackets
	 * around legit add_object()/destroy_object() writes.  Reads/writes
	 * are owner-only -- siblings see the childdata page itself RO via
	 * the freeze_sibling_childdata sweep, and the parent never
	 * mutates per-child OBJ_LOCAL state.
	 */
	bool objects_protected;

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

	/* The actual syscall records each child uses.  Dominated by a 4 KiB
	 * prebuffer + 128 B postbuffer used by -v rendering — only nr / a1..a6
	 * / retval / lock / state are touched on the hot path, and those are
	 * already in the rec's own first cacheline. */
	struct syscallrecord syscall;
} __attribute__((aligned(64)));

extern unsigned int max_children;

/*
 * Per-child corruption-rate storm-containment thresholds.  When any of
 * post_handler_corrupt_ptr / maps_uaf_caught / scribbled_slots_caught
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
 * to `base` so the loop never collapses to zero iterations — preserves
 * the pre-CV.13 behaviour as the safe default.
 *
 * Caller must have shm.h in scope (childop .c files already do).  The
 * macro evaluates `op` and `base` exactly once each via statement-
 * expression locals, which matters because callers sometimes pass
 * expressions with side effects for `base` (none today, but cheap to
 * future-proof).
 */
#define BUDGETED(op, base) ({						\
	uint16_t _m = shm->stats.childop_budget_mult[(op)];		\
	unsigned int _b = (unsigned int)(base);				\
	_m ? ((_b * (unsigned int)_m) >> 8) : _b;			\
})

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void child_fd_ring_push(struct child_fd_ring *ring, int fd);

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
 * if dormant gates ever become runtime mutable. */
void init_altop_dispatch(void);

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
bool drop_privs(struct childdata *child);
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
bool tracefs_fuzzer(struct childdata *child);
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
bool xfrm_churn(struct childdata *child);
bool bpf_cgroup_attach(struct childdata *child);
bool sctp_assoc_churn(struct childdata *child);
bool mptcp_pm_churn(struct childdata *child);
bool devlink_port_churn(struct childdata *child);
bool handshake_req_abort(struct childdata *child);
bool nf_conntrack_helper_churn(struct childdata *child);
bool af_unix_scm_rights_gc_churn(struct childdata *child);
bool netns_teardown_churn(struct childdata *child);
bool tcp_ulp_swap_churn(struct childdata *child);
bool msg_zerocopy_churn(struct childdata *child);
bool iouring_send_zc_churn(struct childdata *child);
bool vsock_transport_churn(struct childdata *child);
bool bridge_vlan_churn(struct childdata *child);
bool igmp_mld_source_churn(struct childdata *child);
bool psp_key_rotate(struct childdata *child);
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

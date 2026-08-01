#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

struct childdata;
struct syscallrecord;
struct chain_step;
struct fd_event_ring;
struct stats_ring;

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

/*
 * enum child_op_type -- generated from include/childop.def.  Row order
 * in the .def file is load-bearing: it fixes the numeric value of
 * every CHILD_OP_* constant.  CHILD_OP_SYSCALL is the first row and
 * therefore always evaluates to 0 (relied on as the "default: fuzz
 * random syscalls" pick).  NR_CHILD_OP_TYPES sits at the end as the
 * count sentinel.
 */
enum child_op_type {
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket) enum_name,
#include "childop.def"
#undef CHILDOP
	NR_CHILD_OP_TYPES,
};

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
 * v3 data slots.  Any deviation bumps shm->stats.oracle.capdrop_oracle_anomalies
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
 * child-canary-state.c. */
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

/* ---- Canary queue (child-canary-*.c) -------------------------------
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
 *   NO_OUTER_BRACKET        dispatch shape has no outer KCOV bracket
 *                           (matches the live canary-ineligible exit).
 *                           NOT a host-config failure: the op still
 *                           runs, it just cannot populate the clean
 *                           outer-bracket attribution signal.
 */
enum childop_recommended_state {
	CHILDOP_REC_DORMANT = 0,
	CHILDOP_REC_CANARY_CLEAN,
	CHILDOP_REC_PROMOTED_CLEAN,
	CHILDOP_REC_PROMOTED_INTERFERENCE,
	CHILDOP_REC_THROTTLED,
	CHILDOP_REC_QUARANTINED,
	CHILDOP_REC_NO_OUTER_BRACKET,
	/* childop_edges_clean[op] == 0 during the window but
	 * childop_edges_discovered[op] grew, AND at least one
	 * kcov_shm->childop_kcov_op_skipped_*[op] counter is non-zero.
	 * The outer PC bracket rejected this op (KCOV_MODE_CMP child,
	 * nested bracket, inactive/failed enable) so the clean/noisy split
	 * that PROMOTED_INTERFERENCE keys off is a MODE ARTIFACT, not a
	 * true "sibling interference only" signal.  Neither promote nor
	 * demote: the ratchet cannot see this op's real yield, so we
	 * explicitly opt it out of both would_promote and would_demote
	 * shadow tallies to keep the decision surface honest.  Named
	 * (rather than folded into CANARY_CLEAN or NO_OUTER_BRACKET) so an
	 * operator triaging the shadow log can grep for the confound
	 * without also catching the two adjacent cases. */
	CHILDOP_REC_UNATTRIBUTED_EDGES,
};

/* Render the recommended-state enum as its uppercase name (e.g.
 * "PROMOTED_INTERFERENCE") for the canary shadow log line.  Returns a
 * pointer to a static string with run lifetime; never NULL. */
const char *childop_recommended_state_name(enum childop_recommended_state s);

/* Why a childop's setup path returned failure on every dispatch of a
 * canary window.  Populated from a static per-op hint table when the
 * queue closes a window with setup_ok=0 setup_failures>=threshold;
 * hint-less ops record SETUP_FAIL_REASON_UNKNOWN.  Surfaced in the
 * BROKEN-SETUP / AUTO-BLOCKED log lines and in the startup CONFIG_
 * BLOCKED enumeration so an operator can tell at a glance which host
 * feature is missing without cross-referencing source. */
enum canary_setup_fail_reason {
	SETUP_FAIL_REASON_UNKNOWN = 0,
	SETUP_FAIL_REASON_CAP_MISSING,
	SETUP_FAIL_REASON_MODULE_MISSING,
	SETUP_FAIL_REASON_SYSCTL_DISABLED,
	SETUP_FAIL_REASON_MOUNT_UNAVAILABLE,
	SETUP_FAIL_REASON_NS_UNSUPPORTED,
	SETUP_FAIL_REASON_DEVICE_MISSING,
	SETUP_FAIL_REASON_SCRATCH_UNAVAILABLE,
	SETUP_FAIL_REASON_FS_UNSUPPORTED,
	SETUP_FAIL_REASON_QUOTA_HIT,
};

/* Sub-reason distinguishing the three distinct paths into CANARY_STATE_
 * CONFIG_BLOCKED.  The state itself is terminal-and-never-picked in all
 * three cases, but the operator-facing meaning is very different:
 *
 *   CONFIG_ABSENT       Static config-blocked table hit at queue init:
 *                       the host kernel is not compiled with the feature
 *                       this op exercises.  Not a code bug; the fix is
 *                       either a kernel rebuild or accepting the op will
 *                       not run on this fleet.
 *   SETUP_BROKEN        Auto-block after CANARY_SETUP_BROKEN_AUTOBLOCK_N
 *                       consecutive 100%-setup-failure windows.  The op
 *                       code (or a host prereq the hint table names) is
 *                       broken; this is actionable.
 *   NO_OUTER_BRACKET    leave_canarying_ineligible(): the op's dispatch
 *                       shape cannot carry the outer KCOV bracket, so
 *                       the canary mechanism has no signal to score it
 *                       on.  Not a failure of the op -- it still runs
 *                       via the promoted-picker path if enabled -- just
 *                       an acknowledgement that the queue cannot rate
 *                       it.  Distinct from CONFIG_ABSENT because the op
 *                       is not blocked from running at all, only from
 *                       canary-based promotion.
 *
 * NONE is the sentinel value for ops whose state is not CONFIG_BLOCKED;
 * the field must not be read without first checking state. */
enum canary_blocked_reason {
	CANARY_BLOCKED_REASON_NONE = 0,
	CANARY_BLOCKED_REASON_CONFIG_ABSENT,
	CANARY_BLOCKED_REASON_SETUP_BROKEN,
	CANARY_BLOCKED_REASON_NO_OUTER_BRACKET,
};

struct canary_op_state {
	/* identity */
	enum child_op_type op;		/* keyed by op enum */
	const char *name;		/* cached alt_op_name(op) for log lines */
	enum canary_state state;

	/* Sub-reason for state == CANARY_STATE_CONFIG_BLOCKED.  NONE
	 * otherwise.  See enum canary_blocked_reason for the three
	 * paths and their distinct operator meanings. */
	enum canary_blocked_reason blocked_reason;

	/* per-window counters (reset on CANARYING entry) */
	unsigned long window_start_invocations;	/* shm->stats.childop.invocations[op] snapshot at window open;
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
	unsigned long window_start_wall_ns;	/* shm->stats.childop.wall_ns[op] snapshot at window
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

	/* Consecutive count of window closes into leave_canarying_demote_
	 * setup_broken() (100%-setup-failure shape) without any
	 * intervening non-setup-broken outcome.  Reset by promote / crash-
	 * threshold demote / zero-edges demote / canary-ineligible close.
	 * When the count reaches CANARY_SETUP_BROKEN_AUTOBLOCK_N the op
	 * auto-transitions to CANARY_STATE_CONFIG_BLOCKED so the canary
	 * slot is not re-spent every CANARY_SETUP_BROKEN_BACKOFF_TIME on
	 * an op whose setup path is structurally missing a host prereq. */
	unsigned int  consecutive_setup_broken;

	/* Snapshots of the per-op PC-bracket attempts / opens counters at
	 * window open (kcov_shm->childop_kcov.childop_kcov_op_{attempts,
	 * bracketed}[op]).  Their close-time deltas let close_window_and_
	 * decide() distinguish "no PC bracket opened because every canary-
	 * slot child that ran this window happened to be KCOV_MODE_CMP"
	 * (bracketed_delta==0 but attempts_delta>0) from "no PC bracket
	 * opened because childop-kcov attribution is off run-wide"
	 * (both deltas 0).  Only the former is eligible for the pre-demote
	 * PC-trial retry.  Owner-only writes from parent context, no
	 * atomics needed. */
	unsigned long window_start_kcov_op_attempts;
	unsigned long window_start_kcov_op_bracketed;

	/* Consecutive count of canary windows for this op that closed with
	 * a non-zero bracket attempt count but zero opens (every dispatch
	 * hit an outer-bracket reject arm, dominantly KCOV_MODE_CMP).  Bumped
	 * by the PC-trial retry gate in close_window_and_decide(); reset by
	 * any terminal exit (promote / demote / ineligible / wedged /
	 * setup_broken).  When the count reaches CANARY_PC_TRIAL_RETRIES_MAX
	 * the op falls through to the normal demote path so a pathological
	 * all-CMP draw cannot loop the canary slot forever. */
	unsigned int  consecutive_no_pc_bracket;

	/* Last-observed setup-failure reason for this op.  Written by
	 * leave_canarying_demote_setup_broken() (per-window) and by
	 * canary_queue_init() when populating the startup CONFIG_BLOCKED
	 * table; read by the log-line emitters and by the startup
	 * enumeration.  UNKNOWN when the op is not in the hint table. */
	enum canary_setup_fail_reason setup_fail_reason;
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

void reap_child(struct childdata *child, int childno, bool child_dead);

/* Childops */
bool random_syscall(struct childdata *child);
bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out);
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
/* Comma-separated distinct-class list of the compile-time deny policy
 * applied by discover_targets().  Emitted from the run-identity block
 * so a crash triage can immediately see which host-global control
 * classes were withheld from mutation.  Cached; safe to call from any
 * context. */
const char *procfs_writer_deny_policy_summary(void);
/* Comma-separated distinct-class list of the compile-time allow policy
 * -- the parser-shaped families this childop was built to fuzz, admitted
 * unconditionally past the deny table. */
const char *procfs_writer_allow_policy_summary(void);
/* "safe" if the deny table is enforced (the default), "dangerous" if
 * --dangerous has lifted the deny and host-global control writes are
 * being admitted.  Sampled at emit time; --dangerous is set during
 * option parsing before fork_children so the value is stable. */
const char *procfs_writer_mode_summary(void);
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
const char *slab_target_name(unsigned int idx);
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
bool bridge_ip6_refrag_fraggap(struct childdata *child);
bool ipset_churn(struct childdata *child);
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
bool map_shared_stress(struct childdata *child);
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
bool tc_live_traffic(struct childdata *child);
bool hfs_mount_fuzz(struct childdata *child);
bool rds_zcopy_crafted_send(struct childdata *child);
bool bridge_ip6frag_refrag(struct childdata *child);
bool ip4_udp_cork_splice(struct childdata *child);
bool nexthop_replace_churn(struct childdata *child);

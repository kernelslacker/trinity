#pragma once

#include "types.h"

/* glibc headers might be older than the kernel, define our own PF_MAX */
#define TRINITY_PF_MAX 46
#define TAINT_PROPRIETARY_MODULE        0
#define TAINT_FORCED_MODULE             1
#define TAINT_UNSAFE_SMP                2
#define TAINT_FORCED_RMMOD              3
#define TAINT_MACHINE_CHECK             4
#define TAINT_BAD_PAGE                  5
#define TAINT_USER                      6
#define TAINT_DIE                       7
#define TAINT_OVERRIDDEN_ACPI_TABLE     8
#define TAINT_WARN                      9
#define TAINT_CRAP                      10
#define TAINT_FIRMWARE_WORKAROUND       11
#define TAINT_OOT_MODULE                12
#define TAINT_UNSIGNED_MODULE           13
#define TAINT_SOFTLOCKUP                14
#define TAINT_LIVEPATCH                 15
#define TAINT_AUX                       16
#define TAINT_RANDSTRUCT                17
#define TAINT_TEST                      18

/* command line args. */
void parse_args(int argc, char *argv[]);

/*
 * Apply the derived max_children cap to the default num_online_cpus*4
 * value when -C was not used.  No-op when -C is in effect: the parser
 * already validated user_specified_children against the same cap.
 */
void clamp_default_max_children(void);

extern bool set_debug;

extern bool do_32_arch;
extern bool do_64_arch;

extern bool do_specific_syscall;
extern bool do_exclude_syscall;
extern unsigned int specific_domain;
extern bool do_specific_domain;
extern char *specific_domain_optarg;
extern bool no_domains[TRINITY_PF_MAX];
extern bool dry_run;
extern bool show_unannotated;
extern bool show_syscall_list;
extern bool show_ioctl_list;
extern bool show_disabled_syscalls;
extern unsigned char verbosity;
extern bool dangerous;
extern bool do_syslog;
extern unsigned char desired_group;
extern bool group_bias;
/*
 * --cred-throttle: A/B scaffold for sharply downweighting credential
 * syscalls (setregid/setreuid/...) when the oracle in cred_throttle.c
 * has classified the class as "provably impossible" in this run.
 * DEFAULT OFF: the picker distribution is byte-identical to a build
 * without this flag when cred_throttle is false.  Always-on observability
 * (oracle counters) is independent of this flag.
 */
extern bool cred_throttle;
/*
 * --frontier-live-cooldown: gate for the LIVE-regime early ring-decay
 * variant of frontier_window_advance().  When set, syscalls whose
 * per-syscall LIVE-regime miss-streak has crossed
 * FRONTIER_LIVE_MISS_COOLDOWN have their cached frontier_recent_count
 * halved on the next rotation -- driving the per-nr ring sum toward
 * zero faster than the trailing-K-window subtraction alone, so the
 * cached frontier_max_weight falls and the picker reaches the silent
 * decay path on the cooled-off syscalls.  DEFAULT OFF: the rotation
 * arithmetic is byte-identical to the pre-flag baseline when this
 * stays false; the F3 shadow miss-streak counters and the
 * frontier_live_cooldown_decays observability counter are always-on
 * regardless.  Read RELAXED on the rotation hot path.
 */
extern bool frontier_live_cooldown;

/*
 * --writer-pin-sweep / --writer-pin-stride=N:
 * DEFAULT-OFF debug-only Stage-1 detector for the writer-pinning
 * canary.  Per-syscall sweep over the shared minicorpus rings; on hit,
 * hands a stomped address off (does NOT name the wild writer -- Stage 2
 * --writer-watch is the namer).  Inert at default; the hot path adds a
 * single branch-predicted `if` test.  Heavyweight debug tool -- only
 * enable for a targeted corruption hunt on a host that can absorb the
 * per-syscall sweep cost.
 */
extern bool writer_pin_sweep;
extern unsigned int writer_pin_stride;

/*
 * --writer-watch=<hexaddr>: DEFAULT-OFF Stage-2 NAMER for the writer-
 * pinning canary.  perf hardware WRITE breakpoint armed per-child after
 * fork (writer-watch.c).  Synchronous trap in the writing child at the
 * exact instruction; SIGTRAP handler in signals.c::writer_trap_handler
 * dumps writer_pc + syscall nr + childop + op_nr + pid.  Zero =
 * disabled.  Heavyweight debug tool -- only enable for a targeted
 * corruption hunt; the perf fd has real cost and the handler _exit()s
 * on hit.
 */
extern unsigned long writer_watch_addr;
extern bool user_set_seed;
extern char *victim_paths[];
extern unsigned int nr_victim_paths;
#define MAX_VICTIM_PATHS 32
extern bool random_selection;
extern unsigned int random_selection_num;

extern bool clowntown;
extern bool show_stats;
extern bool stats_json;
extern bool quiet;

extern unsigned int kernel_taint_mask;
extern bool kernel_taint_param_occured;

extern unsigned int user_specified_children;
extern unsigned int alt_op_children;
extern bool user_specified_alt_op_children;
void clamp_default_alt_op_children(void);

/* Canary queue (child-canary.c).  canary_slots is carved from the
 * front of the alt_op_children pool: the first canary_slots dedicated
 * alt-op slots are stamped with the queue's currently-canarying op
 * instead of the alt_op_rotation[] entry they would otherwise use.
 * canary_window_iters is the iteration budget per canary window.
 * canary_queue_disabled forces the queue to behave as a no-op (the
 * dormant gate is consulted as the historical compile-time-static
 * vector).  canary_seed_override / canary_seed_override_count is the
 * --canary-seed override list, parsed at startup; when count is zero
 * the queue uses the built-in priority seed list.
 *
 * canary_slots auto-couples to alt_op_children.  The queue carves
 * slots from the front of the alt-op pool, so a non-zero default is
 * only meaningful once alt_op_children is also non-zero -- otherwise
 * the queue has nowhere to host a canary and the run would emit a
 * warning and silently disable the feature on every default
 * invocation.  When --canary-slots is not passed, canary_slots is
 * filled in by clamp_default_canary_slots() AFTER parse_args has
 * finalised alt_op_children, and the derived value is
 * min(alt_op_children, 2): zero on a default run, and the historical
 * default of 2 once the operator opts into a pool with at least 2
 * slots.  An explicit --canary-slots=N records the operator's intent
 * in user_specified_canary_slots and bypasses the auto-derive; the
 * downstream clamp against alt_op_children in trinity.c still
 * applies, and the warning for --canary-slots=N with
 * --alt-op-children=0 fires only on that explicit-override path,
 * since the auto-derive can no longer reach that state. */
extern unsigned int canary_slots;
extern bool user_specified_canary_slots;
void clamp_default_canary_slots(void);
extern unsigned int canary_window_iters;
extern bool canary_queue_disabled;
#define CANARY_SEED_OVERRIDE_MAX	32
extern unsigned char canary_seed_override[CANARY_SEED_OVERRIDE_MAX];
extern unsigned int canary_seed_override_count;

/* Opt-in (--fork-pressure-drain): under sustained spawn_child()
 * failure in the parent fork loop, temporarily stop the canary
 * picker from scheduling pid-heavy ops so the canary slot stops
 * adding fork demand to a parent already losing the spawn race.
 * Default false; gates the entire drain code path so a default
 * invocation is byte-identical to the pre-flag behaviour. */
extern bool fork_pressure_drain;

/*
 * Hybrid bandit/explorer split: when --strategy=bandit is in effect, a
 * dedicated explorer slice of the child slots ignores the bandit's pick
 * and runs STRATEGY_RANDOM unconditionally as an always-on uniform
 * baseline.  Coverage discoveries from those slots are recorded
 * separately and excluded from the bandit's reward signal so the
 * explorer pool acts as an independent canary rather than biasing arm
 * selection.
 *
 * Slot layout (disjoint, computed at startup):
 *   [0,                        alt_op_children)            dedicated alt-op
 *   [alt_op_children,          alt_op_children+expl)       explorer
 *   [alt_op_children+expl,     max_children)               default/bandit
 * Reserving the alt-op slice first keeps the explorer baseline from
 * silently overlapping the dedicated alt-op range under
 * --strategy=bandit --alt-op-children=N.
 *
 * Default (when --explorer-children is not passed) is
 * (max_children - alt_op_children) / 4, computed by
 * clamp_default_explorer_children() AFTER parse_args has finalised both
 * max_children and alt_op_children, and ONLY when picker_mode_arg ==
 * PICKER_BANDIT_UCB1.  Under any other picker mode (round-robin,
 * heuristic, etc.) the explorer pool defaults to zero so the active
 * strategy is what every non-alt-op child slot actually runs -- the
 * explorer pool is a bandit-specific baseline and would otherwise
 * silently divert ~25% of the fleet to STRATEGY_RANDOM regardless of
 * the operator's --strategy choice.  The operator can still override
 * with --explorer-children=N in any picker mode; that path is clamped
 * against (max_children - alt_op_children) / 2 to keep both the
 * disjoint-layout invariant and a viable bandit pool.
 * user_specified_explorer_children records whether the operator passed
 * the flag explicitly so the default-fill path can leave their value
 * alone.
 */
extern unsigned int explorer_children;
extern bool user_specified_explorer_children;
void clamp_default_explorer_children(void);

extern unsigned long epoch_iterations;
extern unsigned int epoch_timeout;
extern bool max_runtime_set;

extern bool no_warm_start;
extern char *warm_start_path;

extern bool no_kcov_warm_start;
extern bool no_cmp_hints_warm_start;

/*
 * --kcov-trace-size=N: per-child KCOV PC-trace buffer size, in number
 * of unsigned longs.  Default = KCOV_TRACE_SIZE (see include/kcov.h).
 * Validated by parse_args() to be a power-of-2 within
 * [KCOV_TRACE_SIZE, KCOV_TRACE_SIZE_MAX] so the lower bound preserves
 * the historical baseline (an under-sized buffer would just reintroduce
 * the truncation problem this knob exists to A/B against) and the upper
 * bound caps the per-child memory blast radius.  Read on the cold init
 * / cleanup / recovery paths and on the per-call truncation-clamp; not
 * mutated after parse_args, so no atomic / barrier discipline is
 * needed.
 */
extern unsigned int kcov_trace_size;

/* errno-gradient-save A/B flag: when true, the errno-gradient
 * trigger in handle_syscall_ret() admits CORPUS_SAVE_REASON_ERRNO
 * entries to the minicorpus ring (live distribution change).  Default
 * false: the trigger still bumps the errno_grad_save_would_save shadow
 * counter so the would-be-save volume is measurable BEFORE the live
 * path is flipped on, but the save call is skipped and the corpus
 * admission distribution stays byte-identical to the pre-feature
 * baseline.  Operator opt-in via --corpus-save-errno-grad-live. */
extern bool corpus_save_errno_grad_live;

/* self-cgroup containment knobs (see self_cgroup.c).  NULL string args
 * mean "use the default" (60%/50%/20% of MemTotal).  no_cgroup skips
 * the sub-cgroup creation entirely. */
extern char *memory_max_arg;
extern char *memory_high_arg;
extern char *memory_swap_max_arg;
extern bool no_cgroup;

/*
 * --no-startup-isolation: operator opt-out for the parent-side
 * net/mount-ns spine.  Default false: when launched as root we
 * unshare into a private net+mount ns and remount '/' as MS_REC|
 * MS_PRIVATE before forking.  Flag set => behave as today (skip the
 * parent unshare entirely, every child does its own per-child
 * unshare in init_child_setup_sandbox).  Useful for debugging the
 * per-child path or running on a host where parent-side ns
 * provisioning misbehaves.  Non-root runs ignore this flag --
 * setup_startup_isolation() never attempts the syscalls there.
 */
extern bool no_startup_isolation;

extern char *stats_log_path;

/*
 * --redqueen-pending-pick={random,first}: retained for compatibility,
 * no-op.  The RedQueen re-exec consumer at the dispatch_step tail
 * (random-syscall.c) drains every staged reexec_pending[] entry per
 * parent dispatch -- there is no per-call selection between entries
 * anymore, so neither mode alters which entries (or how many) get
 * re-executed.  Parsing is preserved so existing invocations do not
 * break; the enum, parser and name helper are kept for the
 * dump_stats policy label only.  Per-pending-index success counters
 * (kcov_shm->reexec_pending_pick_success[]) are still bumped at each
 * entry's true index inside redqueen_reexec_step(), so per-slot /
 * per-index re-exec lift remains directly readable.
 */
enum redqueen_pending_pick_mode_t {
	REDQUEEN_PENDING_PICK_RANDOM = 0,
	REDQUEEN_PENDING_PICK_FIRST,
};

extern enum redqueen_pending_pick_mode_t redqueen_pending_pick_mode_arg;

bool parse_redqueen_pending_pick(const char *name,
				 enum redqueen_pending_pick_mode_t *out);
const char *redqueen_pending_pick_name(enum redqueen_pending_pick_mode_t mode);

/*
 * --cmp-recent-pool={off,recent-first}: A/B selection policy for the
 * run-local CMP "recent" tier.  The recent ring
 * absorbs every fresh pool_add_locked() insert into a small per-syscall
 * circular buffer that the durable pool's LRU never touches, so late-run
 * constants survive past the saturated-durable-pool eviction floor.
 *
 *   OFF (default)    -- cmp_hints_try_get_ex() samples the durable pool
 *                       exactly as before.  Shadow counters
 *                       (cmp_recent_inserts, cmp_recent_would_pick, ...)
 *                       are still active so the would-be-pick rate is
 *                       legible from a default run before the live
 *                       behaviour flips.  The commit ships
 *                       behaviour-neutral until this knob is moved.
 *   RECENT_FIRST     -- during a CMP_RISING_PC_FLAT plateau, sample the
 *                       recent ring first; fall through to the durable
 *                       pool on an empty ring or off-plateau.  Bumps
 *                       cmp_recent_live_picks on every recent-served
 *                       return so the live picker's rate is directly
 *                       comparable to the OFF arm's would_pick.
 */
enum cmp_recent_pool_mode_t {
	CMP_RECENT_POOL_OFF = 0,
	CMP_RECENT_POOL_RECENT_FIRST,
};

extern enum cmp_recent_pool_mode_t cmp_recent_pool_mode_arg;

bool parse_cmp_recent_pool(const char *name,
			   enum cmp_recent_pool_mode_t *out);
const char *cmp_recent_pool_name(enum cmp_recent_pool_mode_t mode);

void enable_disable_fd_usage(void);

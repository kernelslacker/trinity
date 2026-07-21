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
extern bool self_corrupt_canary;
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
extern bool no_chain_warm_start;

/*
 * --chain-resource-typing: bias chain generation to pair resource
 * producers (e.g. epoll_create1, socket, io_uring_setup) with their
 * consumers (e.g. epoll_ctl, sendmsg, io_uring_enter).  Consulted by
 * the chain executor in sequence.c AFTER a step whose (nr, args) match
 * a producer in the small high-confidence resource table:
 *
 *   OFF     - default.  Byte-identical to a build without this flag:
 *             the classify/bias hook returns before touching any
 *             counter, and the next chain link is picked exactly as
 *             it would have been.  Guarantees a fixed-seed run
 *             reproduces the pre-row behaviour bit-for-bit.
 *   SHADOW  - classify producers, count both chain_restype_produced[kind]
 *             and chain_restype_would_bias[kind] (the consumer NR the
 *             LIVE arm WOULD have overridden the next link with), but
 *             the pick stream stays identical to OFF.  Pure observation
 *             so operators can measure the opportunity BEFORE flipping
 *             the live path on.
 *   LIVE    - actually override the next chain link with a random
 *             consumer of the produced resource kind, with probabilistic
 *             acceptance (not a hard override) so other links stay
 *             possible.  Bumps chain_restype_biased[kind].
 *
 * The chain-corpus save gate is unchanged: a chain that discovered a
 * new producer->consumer pair only gets saved when it also earned a
 * PC/TRANSITION/CMP novelty signal.  chain_restype_save[kind] and
 * chain_restype_replay_win[kind] are the per-kind productivity
 * counters this row exists to measure.
 */
enum chain_resource_typing_mode {
	CHAIN_RESTYPE_MODE_OFF = 0,
	CHAIN_RESTYPE_MODE_SHADOW = 1,
	CHAIN_RESTYPE_MODE_LIVE = 2,
};

extern enum chain_resource_typing_mode chain_resource_typing_mode;

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

/*
 * --frontier-noise-sample=N: SHADOW-ONLY per-syscall clean-vs-noisy
 * attribution sampler.  When N > 0, every Nth per-syscall enable/disable
 * bracket in dispatch/syscall.c snapshots the shared edges_found counter
 * before enable and after disable, records the delta into
 * kcov_shm->per_syscall.per_syscall_edges_noisy[nr], and bumps
 * per_syscall_noisy_samples[nr] so a reader can scale the sampled sum
 * back up by N to estimate the full-population global-delta denominator.
 * Paired with the pre-existing per_syscall_edges[] clean numerator and
 * the Phase-1 per_syscall_edges_clean_remote[] split, this lets the
 * dump surface per-syscall attribution confidence without changing any
 * live selection or scoring code.
 *
 * Default 0: feature fully off.  The sampled edges_found loads are the
 * only new hot-path cost this row adds (the noisy counter is a shared
 * write-hot atomic that every child bumps on every new edge; sampling
 * bounds the cross-child cacheline bounce to ~1/N of the naive per-call
 * cost).  With N==0 the sampler helpers short-circuit at the earliest
 * gate and issue zero edges_found loads, keeping the default build
 * byte-identical on the selection path to the pre-row baseline.
 */
extern unsigned int frontier_noise_sample;

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

void enable_disable_fd_usage(void);

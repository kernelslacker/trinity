/*
 * Global tunable storage for the params cluster.  Definitions only;
 * the public extern declarations for these symbols live in
 * include/params.h so callers outside main/params/ can read them
 * without pulling params-internal helpers into their include set.
 */

#include <stdbool.h>

#include "kcov.h"
#include "params.h"
#include "strategy.h"

bool set_debug = false;
bool do_specific_syscall = false;
bool do_exclude_syscall = false;

bool do_32_arch = true;
bool do_64_arch = true;

unsigned int specific_domain = 0;
unsigned int user_specified_children = 0;
unsigned int alt_op_children = 0;
bool user_specified_alt_op_children = false;
unsigned int explorer_children = 0;
bool user_specified_explorer_children = false;

/* Canary queue knobs.  The canary queue carves slots from the front
 * of the alt_op_children pool, so a non-zero canary_slots default is
 * only meaningful when alt_op_children is also non-zero.  Rather than
 * hardcode a value that produces a noisy startup warning whenever the
 * operator runs trinity with default flags (alt_op_children=0), the
 * default tracks min(alt_op_children, 2) and is filled in by
 * clamp_default_canary_slots() AFTER parse_args has finalised
 * alt_op_children.  An explicit --canary-slots=N records operator
 * intent in user_specified_canary_slots and bypasses the auto-derive
 * -- range enforcement against alt_op_children still applies in
 * trinity.c.  CANARY_WINDOW_ITERS_DEFAULT and the queue's other
 * defaults live in child-canary.c. */
unsigned int canary_slots = 0;
bool user_specified_canary_slots = false;
unsigned int canary_window_iters = 10000;
bool canary_queue_disabled = false;

/* Opt-in drain mode: under sustained fork() failure, temporarily stop
 * scheduling pid-heavy canary ops (PIDFD_STORM and the per-childop
 * subworker-forking races) so the canary picker stops piling new
 * fork demand on a parent already losing the spawn race.  Default
 * off -- this only engages in a degenerate state and the canary
 * picker is not normally a contributor to fork pressure, but the
 * flag exists so an operator who sees the bail snapshot in the log
 * can re-run with the suppression in place. */
bool fork_pressure_drain = false;
unsigned char canary_seed_override[CANARY_SEED_OVERRIDE_MAX];
unsigned int canary_seed_override_count = 0;

bool do_specific_domain = false;
bool no_domains[TRINITY_PF_MAX];

bool dry_run = false;
bool self_corrupt_canary = false;
bool show_unannotated = false;
bool show_syscall_list = false;
bool show_ioctl_list = false;
bool show_disabled_syscalls = false;
unsigned char verbosity = 1;
bool dangerous = false;
bool do_syslog = false;
bool random_selection = false;
unsigned int random_selection_num;

bool clowntown = false;
bool show_stats = false;
bool stats_json = false;
bool quiet = false;
bool group_bias = false;
bool cred_throttle = false;

/* --writer-pin-sweep / --writer-pin-stride=N
 * Default-OFF debug-only writer-pinning canary, Stage-1 detector.  Per-
 * syscall sweep of the shared minicorpus rings for a stomped wp_canary
 * or a count>32 invariant violation.  Hands a stomped address off; does
 * NOT name the wild writer (Stage-2 --writer-watch is the namer).
 * Heavyweight debug tool -- the sweep is a 1024-iteration strided load
 * on the post-syscall hot path; default-off, not for routine fuzzing. */
bool writer_pin_sweep = false;
unsigned int writer_pin_stride = 1;

/* --writer-watch=<hexaddr>
 * Default-OFF debug-only writer-pinning canary, Stage-2 NAMER.  perf
 * hardware WRITE breakpoint on the given 8-byte address; armed per-
 * child after fork (writer-watch.c::writer_watch_arm_child()); SIGTRAP
 * fires synchronously in the writing child at the exact instruction;
 * the handler in signals.c::writer_trap_handler dumps writer_pc +
 * syscall nr + childop + op_nr + pid -- the exact wild writer.  The
 * address is typically the bad_addr surfaced by a prior Stage-1
 * --writer-pin-sweep run.  Zero = disabled (default). */
unsigned long writer_watch_addr = 0;

unsigned long epoch_iterations = 0;
unsigned int epoch_timeout = 0;
bool max_runtime_set = false;

bool no_warm_start = false;
char *warm_start_path = NULL;

bool no_kcov_warm_start = false;
bool no_cmp_hints_warm_start = false;
bool no_chain_warm_start = false;

enum chain_resource_typing_mode chain_resource_typing_mode =
	CHAIN_RESTYPE_MODE_OFF;

/* Default tracks the compile-time KCOV_TRACE_SIZE so a default run is
 * byte-identical to a build without this knob (init / mmap / munmap /
 * truncation-clamp all read the same value the #define would have
 * substituted).  Operator override comes via --kcov-trace-size=N. */
unsigned int kcov_trace_size = KCOV_TRACE_SIZE;

/* Default 0 = feature fully off (see extern comment in include/params.h).
 * Zero at parse-args time short-circuits the sampler at its earliest
 * gate; no edges_found loads and no picker-visible effect. */
unsigned int frontier_noise_sample = 0;

bool corpus_save_errno_grad_live = false;

char *memory_max_arg = NULL;
char *memory_high_arg = NULL;
char *memory_swap_max_arg = NULL;
bool no_cgroup = false;
bool no_startup_isolation = false;

char *stats_log_path = NULL;

/*
 * Retained for compatibility; no-op.  The dispatch_step-tail RedQueen
 * re-exec consumer (random-syscall.c) now drains every staged
 * reexec_pending[] entry per parent dispatch, so neither
 * REDQUEEN_PENDING_PICK_RANDOM nor REDQUEEN_PENDING_PICK_FIRST alters
 * which entries (or how many) get re-executed -- both modes drain all.
 * Default stays RANDOM so the dump_stats policy label
 * (redqueen_pending_pick_name) reads the same as before in default runs.
 */
enum redqueen_pending_pick_mode_t redqueen_pending_pick_mode_arg =
	REDQUEEN_PENDING_PICK_RANDOM;

bool user_set_seed = false;

unsigned char desired_group = GROUP_NONE;

char *specific_domain_optarg = NULL;

char *victim_paths[MAX_VICTIM_PATHS];
unsigned int nr_victim_paths;

unsigned int kernel_taint_mask = 0xFFFFFFFF;
bool kernel_taint_param_occured = false;

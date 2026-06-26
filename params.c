#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "bdevs.h"
#include "child.h"
#include "fd.h"
#include "kcov.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "self_cgroup.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"	// progname, max_files_rlimit
#include "utils.h"

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
bool frontier_live_cooldown = false;

unsigned long epoch_iterations = 0;
unsigned int epoch_timeout = 0;
bool max_runtime_set = false;

/*
 * Parse a duration string with optional suffix:
 *   s = seconds (default if no suffix)
 *   m = minutes
 *   h = hours
 *   d = days
 * On success, writes the value (in seconds) to *out and returns true.
 * Returns false for empty input, garbage, multi-char suffix, unknown
 * suffix, negative values, zero, or anything that overflows unsigned int.
 */
static bool parse_duration(const char *s, unsigned int *out)
{
	char *end;
	unsigned long val;
	unsigned long mult = 1;

	if (s == NULL || *s == '\0')
		return false;

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || errno == ERANGE)
		return false;

	if (val == 0)
		return false;

	if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 's': mult = 1; break;
		case 'm': mult = 60UL; break;
		case 'h': mult = 60UL * 60; break;
		case 'd': mult = 60UL * 60 * 24; break;
		default: return false;
		}
	}

	if (mult != 0 && val > ULONG_MAX / mult)
		return false;
	val *= mult;

	if (val > UINT_MAX)
		return false;

	*out = (unsigned int)val;
	return true;
}

/*
 * Parse a non-negative decimal integer from optarg.  Requires the entire
 * string be consumed (no trailing junk), rejects empty input and overflow,
 * and optionally rejects zero.  On success writes the value to *out and
 * returns true; on failure prints a diagnostic and returns false.
 */
static bool parse_unsigned(const char *s, const char *name,
			   bool allow_zero, unsigned long *out)
{
	char *end;
	unsigned long val;

	if (s == NULL || *s == '\0') {
		outputerr("--%s: missing value\n", name);
		return false;
	}

	/*
	 * strtoul() silently accepts a leading '-' and returns the negation
	 * modulo ULONG_MAX+1, turning "-1" into a huge "unsigned" limit.
	 * Reject it up front so the parser matches its documented contract.
	 */
	if (s[0] == '-') {
		outputerr("--%s: negative value '%s' not allowed\n", name, s);
		return false;
	}

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || *end != '\0') {
		outputerr("--%s: can't parse '%s' as a number\n", name, s);
		return false;
	}
	if (errno == ERANGE) {
		outputerr("--%s: value '%s' out of range\n", name, s);
		return false;
	}
	if (!allow_zero && val == 0) {
		outputerr("--%s: zero is not a meaningful value\n", name);
		return false;
	}

	*out = val;
	return true;
}

/* ------------------------------------------------------------------ *
 * max_children cap derivation
 *
 * Ceilings on max_children to keep a typo (-C 999999999) from turning
 * into a host-level fork/allocation storm.  Three independent budgets:
 *
 *   (a) shared_regions[] capacity:  each child consumes
 *       SHARED_REGIONS_PER_CHILD slots in alloc_shared()'s static
 *       tracker, with SHARED_REGIONS_GLOBAL_RESERVE held back for
 *       fixed allocations (shm, syscall table, kcov, image segments,
 *       etc).
 *   (b) RLIMIT_NPROC - HOST_NPROC_RESERVE: leave headroom for the
 *       parent and the operator's surrounding processes.
 *   (c) RLIMIT_NOFILE - PARENT_NOFILE_RESERVE: parent opens one
 *       /proc/<pid>/stat fd per child plus its own ancillary fds.
 *
 * The derived cap is the smallest of those plus PROJECT_MAX_CHILDREN.
 * derive_max_children_cap() also reports which budget is binding so
 * the operator-facing error/warning can name the source.
 * ------------------------------------------------------------------ */

#define HOST_NPROC_RESERVE	32
#define PARENT_NOFILE_RESERVE	64
#define PROJECT_MAX_CHILDREN	16384

enum max_children_binding {
	BINDING_PROJECT_MAX,
	BINDING_SHARED_REGIONS,
	BINDING_NPROC,
	BINDING_NOFILE,
};

static const char *binding_name(enum max_children_binding b)
{
	switch (b) {
	case BINDING_PROJECT_MAX:    return "project sanity limit";
	case BINDING_SHARED_REGIONS: return "shared_regions[] capacity";
	case BINDING_NPROC:          return "RLIMIT_NPROC";
	case BINDING_NOFILE:         return "RLIMIT_NOFILE";
	}
	return "?";
}

static unsigned long derive_max_children_cap(enum max_children_binding *out_binding)
{
	unsigned long cap = PROJECT_MAX_CHILDREN;
	enum max_children_binding b = BINDING_PROJECT_MAX;
	unsigned long shared_cap;
	struct rlimit nproc;

	shared_cap = (MAX_SHARED_ALLOCS - SHARED_REGIONS_GLOBAL_RESERVE) /
		     SHARED_REGIONS_PER_CHILD;
	if (shared_cap < cap) {
		cap = shared_cap;
		b = BINDING_SHARED_REGIONS;
	}

	if (getrlimit(RLIMIT_NPROC, &nproc) == 0 &&
	    nproc.rlim_cur != RLIM_INFINITY) {
		unsigned long nproc_cap;

		if (nproc.rlim_cur > HOST_NPROC_RESERVE)
			nproc_cap = nproc.rlim_cur - HOST_NPROC_RESERVE;
		else
			nproc_cap = 0;
		if (nproc_cap < cap) {
			cap = nproc_cap;
			b = BINDING_NPROC;
		}
	}

	if (max_files_rlimit.rlim_cur != RLIM_INFINITY) {
		unsigned long nofile_cap;

		if (max_files_rlimit.rlim_cur > PARENT_NOFILE_RESERVE)
			nofile_cap = max_files_rlimit.rlim_cur - PARENT_NOFILE_RESERVE;
		else
			nofile_cap = 0;
		if (nofile_cap < cap) {
			cap = nofile_cap;
			b = BINDING_NOFILE;
		}
	}

	if (out_binding != NULL)
		*out_binding = b;
	return cap;
}

/*
 * Compute the default explorer-pool size when --explorer-children was not
 * passed.  The default is mode-aware: max_children/4 (25%) under
 * PICKER_BANDIT_UCB1 (for -C64 → 16 explorers, -C16 → 4, -C8 → 2, -C4
 * → 1), zero under every other picker mode.
 *
 * The explorer pool exists to provide a strategy-independent baseline
 * alongside the bandit's learned policy, with its coverage discoveries
 * recorded separately and excluded from the bandit's reward signal.
 * That role only makes sense when the bandit is the active picker --
 * under round-robin or any other deterministic picker the explorer
 * slots would silently divert 25% of the fleet to STRATEGY_RANDOM and
 * the active strategy would only actually run on 75% of children, which
 * contradicts what --strategy advertises.  Default to zero outside
 * bandit mode so non-bandit pickers run pure.
 *
 * The operator can still force a non-zero pool in any mode by passing
 * --explorer-children=N; that path is unconditional and only the upper
 * ceiling (max_children/2) is enforced -- more than half being
 * explorers would leave the bandit pool too small for UCB1 to
 * differentiate arms, and even in non-bandit modes the same imbalance
 * argument applies to the active strategy.
 *
 * Called from main() after clamp_default_max_children() so max_children
 * is final.  Mirrors the alt_op_children clamp pattern in trinity.c.
 */
/* Default-fill canary_slots when the operator did not pass
 * --canary-slots.  Called from main() after parse_args has finalised
 * alt_op_children so the derived value tracks the final pool size.
 * The auto-couple is min(alt_op_children, 2): zero when there is no
 * alt-op pool to carve from (skipping the noisy --canary-slots-vs-
 * --alt-op-children=0 warning on default runs), and the historical
 * default of 2 once the operator opts into an alt-op pool with at
 * least 2 slots.  An explicit --canary-slots=N is recorded in
 * user_specified_canary_slots and left untouched here -- the
 * downstream clamps in trinity.c handle range enforcement against
 * alt_op_children for both auto-derived and explicit values. */
void clamp_default_canary_slots(void)
{
	if (user_specified_canary_slots)
		return;

	canary_slots = (alt_op_children < 2) ? alt_op_children : 2;
}

/* Default-fill alt_op_children when the operator did not pass
 * --alt-op-children.  Without a non-zero default, canary_slots
 * auto-couples to zero, the canary queue stays dark, and the static
 * dormant_op_disabled[] vector hides the majority of alt ops from
 * ever being promoted.  Default to max(2, max_children/8): the floor
 * of 2 keeps the downstream canary_slots = min(alt_op_children, 2)
 * derivation at its historical cap, and the /8 scaling keeps the
 * alt-op reservation modest as the fleet grows.  An explicit
 * --alt-op-children=N (including =0) is recorded in
 * user_specified_alt_op_children and bypasses the auto-derive --
 * range enforcement against max_children still applies in
 * trinity.c. */
void clamp_default_alt_op_children(void)
{
	if (user_specified_alt_op_children)
		return;

	alt_op_children = (max_children / 8 < 2) ? 2 : max_children / 8;
}

void clamp_default_explorer_children(void)
{
	/* Explorer slots are reserved AFTER the dedicated alt-op slots
	 * (see init_child() in child.c), so the ceiling is computed
	 * against the slots that remain once alt_op_children has been
	 * carved off the front -- not against raw max_children, which
	 * would let the explorer range overlap the alt-op range and
	 * silently consume the random-explorer baseline. */
	unsigned int remaining = (max_children > alt_op_children) ?
				 max_children - alt_op_children : 0;
	unsigned int ceiling = remaining / 2;

	if (!user_specified_explorer_children) {
		if (picker_mode_arg == PICKER_BANDIT_UCB1)
			explorer_children = remaining / 4;
		/* else: leave explorer_children at its 0 init so the
		 * active strategy runs on every non-alt-op child slot. */
		return;
	}

	if (explorer_children > ceiling) {
		outputerr("warning: --explorer-children=%u exceeds (max_children-alt_op_children)/2 (%u); clamping to %u\n",
			  explorer_children, ceiling, ceiling);
		explorer_children = ceiling;
	}
}

void clamp_default_max_children(void)
{
	enum max_children_binding b;
	unsigned long cap;

	/* -C path validates against the cap inside parse_args; nothing to do. */
	if (user_specified_children != 0)
		return;

	cap = derive_max_children_cap(&b);
	if (cap == 0) {
		outputerr("cannot run trinity: %s leaves no budget for children\n",
			  binding_name(b));
		exit(EXIT_FAILURE);
	}
	if ((unsigned long)max_children > cap) {
		outputerr("warning: default max_children=%u (num_online_cpus*4) "
			  "exceeds %s cap of %lu; clamping\n",
			  max_children, binding_name(b), cap);
		max_children = (unsigned int)cap;
	}
}

bool no_warm_start = false;
char *warm_start_path = NULL;

bool no_kcov_warm_start = false;
bool no_cmp_hints_warm_start = false;

/* Default tracks the compile-time KCOV_TRACE_SIZE so a default run is
 * byte-identical to a build without this knob (init / mmap / munmap /
 * truncation-clamp all read the same value the #define would have
 * substituted).  Operator override comes via --kcov-trace-size=N. */
unsigned int kcov_trace_size = KCOV_TRACE_SIZE;

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

bool parse_redqueen_pending_pick(const char *name,
				 enum redqueen_pending_pick_mode_t *out)
{
	if (name == NULL || out == NULL)
		return false;

	if (strcmp(name, "random") == 0) {
		*out = REDQUEEN_PENDING_PICK_RANDOM;
		return true;
	}
	if (strcmp(name, "first") == 0) {
		*out = REDQUEEN_PENDING_PICK_FIRST;
		return true;
	}
	return false;
}

const char *redqueen_pending_pick_name(enum redqueen_pending_pick_mode_t mode)
{
	switch (mode) {
	case REDQUEEN_PENDING_PICK_RANDOM:	return "random";
	case REDQUEEN_PENDING_PICK_FIRST:	return "first";
	}
	return "unknown";
}

/*
 * Default = OFF so the commit ships behaviour-neutral: cmp_hints_try_get_ex()
 * samples the durable pool exactly as before, while the shadow counters
 * around the recent ring (cmp_recent_inserts / would_pick / would_miss)
 * accumulate so an operator reading stats from a default run can already
 * see the would-be-pick rate before flipping the live arm.  Distribution
 * changes ship shadow-first: counters land before the live arm flips.
 */
enum cmp_recent_pool_mode_t cmp_recent_pool_mode_arg = CMP_RECENT_POOL_OFF;

bool parse_cmp_recent_pool(const char *name,
			   enum cmp_recent_pool_mode_t *out)
{
	if (name == NULL || out == NULL)
		return false;

	if (strcmp(name, "off") == 0) {
		*out = CMP_RECENT_POOL_OFF;
		return true;
	}
	if (strcmp(name, "recent-first") == 0) {
		*out = CMP_RECENT_POOL_RECENT_FIRST;
		return true;
	}
	return false;
}

const char *cmp_recent_pool_name(enum cmp_recent_pool_mode_t mode)
{
	switch (mode) {
	case CMP_RECENT_POOL_OFF:		return "off";
	case CMP_RECENT_POOL_RECENT_FIRST:	return "recent-first";
	}
	return "unknown";
}

bool user_set_seed = false;

unsigned char desired_group = GROUP_NONE;

static const struct {
	const char *name;
	unsigned char id;
} group_names[] = {
	{ "vm",       GROUP_VM },
	{ "vfs",      GROUP_VFS },
	{ "net",      GROUP_NET },
	{ "ipc",      GROUP_IPC },
	{ "process",  GROUP_PROCESS },
	{ "signal",   GROUP_SIGNAL },
	{ "io_uring", GROUP_IO_URING },
	{ "bpf",      GROUP_BPF },
	{ "sched",    GROUP_SCHED },
	{ "time",     GROUP_TIME },
	{ "xattr",    GROUP_XATTR },
};

char *specific_domain_optarg = NULL;

char *victim_paths[MAX_VICTIM_PATHS];
unsigned int nr_victim_paths;

unsigned int kernel_taint_mask = 0xFFFFFFFF;
bool kernel_taint_param_occured = false;

void enable_disable_fd_usage(void)
{
	dump_fd_provider_names();
}

struct option_help {
	const char *name;	/* long option name (NULL = end of table) */
	char shortopt;		/* short option char, or 0 if none */
	const char *desc;	/* help text */
};

static const struct option_help option_descs[] = {
	{ "alt-op-children",	 0,  "reserve N children to run dedicated alt ops (mmap_lifecycle, mprotect_split, ...) round-robin instead of mixing them at 1% in every child (default: max(2, --children/8))" },
	{ "arch",		'a', "selects syscalls for the specified architecture (32 or 64). Both by default." },
	{ "bdev",		'b', "Add /dev node to list of block devices to use for destructive tests." },
	{ "canary-seed",	 0,  "comma-separated list of childop names to override the built-in priority canary seed list. Names match alt_op_name (e.g. 'genetlink_fuzzer,bpf_lifecycle'). Unknown names abort startup." },
	{ "canary-slots",	 0,  "reserve N slots from the front of --alt-op-children to run the dormant-op canary queue (default: min(alt-op-children, 2) when unset). Clamped to min(N, alt_op_children); N=0 disables the queue identically to --no-canary-queue." },
	{ "canary-window",	 0,  "invocations of the active canary op per window (default 10000, range 1000..1000000). Counted against the per-op invocation counter, not the fleet-wide op count, so window size is independent of -C and --canary-slots. Lower windows are too noisy to promote on; higher windows let a useless op squat a slot for too long." },
	{ "childop-kcov-attribution", 0, "per-childop KCOV attribution mode: off (no bracketing, childop_edges_clean stays zero; budget multipliers stay at unity and canary windows always demote on zero_edges), dual (default; bracket every eligible alt-op and publish the per-call edge delta to childop_edges_clean -- adapt_budget and the canary queue consume this clean signal, the global-delta path keeps writing childop_edges_discovered as a diagnostic comparator), or on (reserved; identical to dual until the discovered counter is retired)." },
	{ "children",		'C', "specify number of child processes" },
	{ "clowntown",		 0,  "enable clowntown mode" },
	{ "cmp-recent-pool", 0, "A/B selection policy for the run-local CMP recent-pool tier.  Accepts 'off' (default; cmp_hints_try_get_ex samples the durable per-syscall pool exactly as before) or 'recent-first' (during a CMP_RISING_PC_FLAT plateau, sample the recent ring first and fall through to the durable pool on an empty ring or off-plateau).  Shadow counters (cmp_recent_inserts / would_pick / would_miss) are active in BOTH modes so the would-be-pick rate is observable from a default run before the live arm is flipped." },
	{ "corpus-save-errno-grad-live", 0, "DEFAULT OFF. Enable the errno-gradient corpus save trigger (CORPUS_SAVE_REASON_ERRNO): when a syscall returns a non-EFAULT errno bucket for the first time this run, admit its args to the per-syscall ring. Flag off keeps the corpus admission distribution byte-identical to a build without this trigger; the errno_grad_save_would_save shadow counter is bumped regardless of this flag so the would-be-save volume is measurable before flipping live." },
	{ "cred-throttle",	 0,  "DEFAULT OFF. Enable the credential-syscall throttle: when a credential class (setregid/setreuid/setresuid/setresgid/setgid/setuid/setfsuid/setfsgid/setgroups) has accumulated >=64 attempts with zero successes and EPERM+EINVAL dominating >=90% of returns, downweight the class by rejecting 31/32 of subsequent picks. Flag off keeps the picker distribution byte-identical to a build without this row; the per-class observability counters are bumped regardless of this flag." },
	{ "frontier-live-cooldown", 0, "DEFAULT OFF. Enable the LIVE-regime early ring-decay: on every window rotation, syscalls whose per-syscall LIVE-regime miss-streak has crossed FRONTIER_LIVE_MISS_COOLDOWN have their cached frontier_recent_count halved so the cached max weight falls and the picker reaches the silent decay path on the cooled-off syscalls. The halving is folded into the existing CAS-clamped per-nr rotation loop and uses the same underflow-safe arithmetic. Flag off keeps the rotation byte-identical to a build without this row; the frontier_live_cooldown_decays observability counter and the F3 miss-streak counters are bumped regardless." },
	{ "frontier-saturation-cooldown", 0, "saturation-cooldown predicate mode for the coverage-frontier picker's silent-regime accept site (default off): off (skip the satcool predicate entirely, byte-identical to today; selection AND shadow counters both stay zero), shadow-only (compute the corrected windowed-edge plateau + FRONTIER_SATCOOL_CMIN magnitude + distinct-CMP / first-success / ret_objtype spare-lane predicate inside the silent-regime accept block and bump frontier_satcool_* shadow counters; selection stays byte-identical -- no goto-retry is gated on the predicate), or combined (RESERVED: the enum value exists for a future commit that wires the live reject; THIS BUILD treats combined identically to shadow-only -- predicate evaluates and counters bump, no live reject fires). Validate the per-syscall would-skip distribution against syncfs / sendfile / semget / writev (expected high) and removexattrat / futex / io_uring_setup / bpf (expected ~0) under shadow-only before tuning C_min or wiring the COMBINED reject." },
	{ "dangerous",		'd', "enable dangerous mode" },
	{ "debug",		'D', "enable debug" },
	{ "disable-fds",	 0,  NULL },	/* handled separately */
	{ "domain",		'P', "specify specific network domain for sockets" },
	{ "dry-run",		 0,  "run arg-gen + sanitise but skip the syscall (safe ASAN/repro mode)" },
	{ "enable-fds",		 0,  NULL },	/* handled separately */
	{ "epoch-iterations",	 0,  "syscalls per epoch before restarting (must be > 0; omit to disable)" },
	{ "epoch-timeout",	 0,  "seconds per epoch before restarting (must be > 0; omit to disable)" },
	{ "exclude",		'x', "don't call a specific syscall" },
	{ "explorer-children",	 0,  "reserve N children to always run STRATEGY_RANDOM as a strategy-independent explorer pool (default: max_children/4 under --strategy=bandit, 0 otherwise; max: max_children/2). Works in any picker mode; non-bandit modes get no explorer pool unless this is set." },
	{ "fork-pressure-drain", 0, "opt-in: under sustained fork() failure (>=100 consecutive spawn_child failures), suppress canary picks of pid-heavy ops (pidfd_storm, qrtr_bind_race, pfkey_spd_walk, l2tp_ifname_race, statmount_idmap_overflow, sysfs_string_race) for 30 s so the canary picker stops piling new fork demand on a parent already losing the spawn race. fork_storm is always skipped via the risky-defer set. Default off." },
	{ "group",		'g', "only run syscalls from a certain group (vfs,vm,net,ipc,process,signal,io_uring,bpf,sched,time,xattr)" },
	{ "group-bias",		 0,  "bias syscall selection toward the same group as the previous call" },
	{ "help",		'h', "show this help" },
	{ "ioctls",		'I', "list all ioctls" },
	{ "kcov-trace-size", 0, "per-child KCOV PC-trace buffer size in number of unsigned longs (default: KCOV_TRACE_SIZE = 262144 longs = 2 MB on 64-bit). Must be a power of 2 in [KCOV_TRACE_SIZE, KCOV_TRACE_SIZE_MAX] (max 4M longs = 32 MB). A/B knob for testing whether the hot syscalls (mincore/mlock/writev/shmget/shmat) that today saturate trace_buf[0] at KCOV_TRACE_SIZE-1 are dropping real tail edges; default value is byte-identical to a build without this flag." },
	{ "kcov-transition-coverage", 0, "shadow transition-coverage map mode: shadow (default; hash consecutive canonical PCs into a separate 16M-slot map and surface a transition top-N beside the PC top-N in the stats dump, with no effect on reward/frontier/plateau steering) or off (skip the per-PC transition hash entirely)." },
	{ "kcov-transition-reward", 0, "transition-edge reward mode (requires --kcov-transition-coverage=shadow): combined (default; feed the capped transition delta into frontier_cold_weight, bandit_record_pull, and the frontier-edge ring so syscalls producing only transitions earn frontier credit), shadow-only (compute the transition reward and bump per-strategy attribution counters in shm->stats but leave live picker behaviour byte-identical to the pre-knob baseline -- rollback path), or off (skip the reward path entirely). Remote-mode transitions are excluded from live reward under combined until ordering quality is checked." },
	{ "kernel_taint",	'T', "controls which kernel taint flags should be considered (see README)" },
	{ "list",		'L', "list all syscalls known on this architecture" },
	{ "max-runtime",	 0,  "maximum runtime before exit, with optional suffix s/m/h/d (e.g., 30s, 10m, 2h, 1d). Overrides --epoch-timeout." },
	{ "memory-high",	 0,  "children/memory.high back-pressure threshold (workers cgroup). Accepts \"max\", N% of MemTotal, or N[KMG] bytes. Default: 50%." },
	{ "memory-max",		 0,  "total trinity memory budget. Split into children/memory.max=<this>-parent_high and a small parent reservation parent_high=min(200M,this/16) so worker OOM doesn't take the parent. Accepts \"max\", N% of MemTotal, or N[KMG] bytes. Default: 60%." },
	{ "memory-swap-max",	 0,  "children/memory.swap.max cap (workers cgroup). Accepts \"max\", N% of MemTotal, or N[KMG] bytes. Default: 20%." },
	{ "no-canary-queue",	 0,  "disable the dormant-childop canary queue entirely; the dormant gate is consulted as a static compile-time vector and no canary slots are reserved." },
	{ "no-cgroup",		 0,  "skip self-cgroup creation entirely (no in-binary memory containment)" },
	{ "no-cmp-hints-warm-start", 0, "skip loading and saving the persisted kcov CMP-hint pool" },
	{ "no-kcov-warm-start",	 0,  "skip loading and saving the persisted kcov edge bitmap" },
	{ "no-startup-isolation", 0,  "skip the parent-side unshare(CLONE_NEWNET|CLONE_NEWNS) + MS_PRIVATE remount that the root-launched fuzzer does in init_pre_fork() (children then take the per-child unshare path). Default off; non-root runs never attempt parent-side isolation regardless." },
	{ "no-warm-start",	 0,  "skip loading and saving the persisted minicorpus" },
	{ "no_domain",		'E', "specify network domains to be excluded from testing" },
	{ "print-disabled-syscalls", 0, "print syscalls disabled via AVOID_SYSCALL or NEED_ALARM and exit" },
	{ "quiet",		'q', "suppress the per-second progress line (other output unchanged)" },
	{ "random",		'r', "pick N syscalls at random and just fuzz those" },
	{ "redqueen-pending-pick", 0, "Retained for compatibility; no-op.  The RedQueen re-exec consumer at the dispatch_step tail now drains every staged reexec_pending[] entry per parent dispatch, so the 'random' vs 'first' selection no longer alters behaviour.  Still parsed (accepts 'random' or 'first') so existing invocations do not break; per-pending-index success counters (kcov_shm->reexec_pending_pick_success[]) are still bumped at each entry's true index inside redqueen_reexec_step(), so per-slot / per-index re-exec lift remains directly readable." },
	{ "show-unannotated",	 0,  "show unannotated syscalls" },
	{ "stats",		 0,  "show errno distribution per syscall before exiting" },
	{ "stats-json",		 0,  "emit dump_stats output as a single JSON object on stdout (machine-readable)" },
	{ "stats-log-file",	 0,  "path to append periodic stats dumps to (in addition to stdout)" },
	{ "strategy",		 0,  "arm-selection POLICY for the multi-strategy rotation (NOT a specific arm): bandit/ucb1 (default) or round-robin/rr. The set of arms is fixed (heuristic, random, coverage-frontier); this flag picks how the rotation chooses between them." },
	{ "syslog",		'S', "log important info to syslog (useful if syslog is remote)" },
	{ "verbose",		'v', "increase output verbosity. Repeat for more detail (-vv)" },
	{ "victims",		'V', "path to victim files (may be repeated)" },
	{ "warm-start-path",	 0,  "override the on-disk minicorpus path (default: $XDG_CACHE_HOME/trinity/corpus/<arch>)" },
	{ NULL,			 0,  NULL },
};

/* Short-only options that don't appear in longopts. */
static const struct option_help shortonly_descs[] = {
	{ NULL, 'c', "target specific syscall (name, optionally @32 or @64)" },
	{ NULL, 'N', "do N syscalls then exit" },
	{ NULL, 's', "use N as random seed" },
	{ NULL,  0,  NULL },
};

static void usage(void)
{
	const struct option_help *h;

	outputerr("%s\n", progname);

	for (h = option_descs; h->name != NULL; h++) {
		if (h->desc == NULL)
			continue;

		if (h->shortopt)
			outputerr(" --%s, -%c: %s\n", h->name, h->shortopt, h->desc);
		else
			outputerr(" --%s: %s\n", h->name, h->desc);
	}

	enable_disable_fd_usage();

	for (h = shortonly_descs; h->shortopt != 0; h++)
		outputerr(" -%c: %s\n", h->shortopt, h->desc);

	outputerr("\n");
	exit(EXIT_SUCCESS);
}

static const char paramstr[] = "a:b:c:C:dDE:g:hILN:P:qr:s:ST:V:vx:";

static const struct option longopts[] = {
	{ "alt-op-children", required_argument, NULL, 0 },
	{ "arch", required_argument, NULL, 'a' },
	{ "bdev", required_argument, NULL, 'b' },
	{ "canary-seed", required_argument, NULL, 0 },
	{ "canary-slots", required_argument, NULL, 0 },
	{ "canary-window", required_argument, NULL, 0 },
	{ "childop-kcov-attribution", required_argument, NULL, 0 },
	{ "kcov-trace-size", required_argument, NULL, 0 },
	{ "kcov-transition-coverage", required_argument, NULL, 0 },
	{ "kcov-transition-reward", required_argument, NULL, 0 },
	{ "children", required_argument, NULL, 'C' },
	{ "clowntown", no_argument, NULL, 0 },
	{ "dangerous", no_argument, NULL, 'd' },
	{ "debug", no_argument, NULL, 'D' },
	{ "disable-fds", required_argument, NULL, 0 },
	{ "dry-run", no_argument, NULL, 0 },
	{ "enable-fds", required_argument, NULL, 0 },
	{ "epoch-iterations", required_argument, NULL, 0 },
	{ "epoch-timeout", required_argument, NULL, 0 },
	{ "exclude", required_argument, NULL, 'x' },
	{ "explorer-children", required_argument, NULL, 0 },
	{ "group", required_argument, NULL, 'g' },
	{ "group-bias", no_argument, NULL, 0 },
	{ "cred-throttle", no_argument, NULL, 0 },
	{ "frontier-live-cooldown", no_argument, NULL, 0 },
	{ "frontier-saturation-cooldown", required_argument, NULL, 0 },
	{ "guard-shared", optional_argument, NULL, 0 },
	{ "kernel_taint", required_argument, NULL, 'T' },
	{ "help", no_argument, NULL, 'h' },
	{ "list", no_argument, NULL, 'L' },
	{ "max-runtime", required_argument, NULL, 0 },
	{ "memory-high", required_argument, NULL, 0 },
	{ "memory-max", required_argument, NULL, 0 },
	{ "memory-swap-max", required_argument, NULL, 0 },
	{ "no-cgroup", no_argument, NULL, 0 },
	{ "no-canary-queue", no_argument, NULL, 0 },
	{ "fork-pressure-drain", no_argument, NULL, 0 },
	{ "no-startup-isolation", no_argument, NULL, 0 },
	{ "ioctls", no_argument, NULL, 'I' },
	{ "no_domain", required_argument, NULL, 'E' },
	{ "domain", required_argument, NULL, 'P' },
	{ "print-disabled-syscalls", no_argument, NULL, 0 },
	{ "quiet", no_argument, NULL, 'q' },
	{ "random", required_argument, NULL, 'r' },
	{ "redqueen-pending-pick", required_argument, NULL, 0 },
	{ "cmp-recent-pool", required_argument, NULL, 0 },
	{ "stats", no_argument, NULL, 0 },
	{ "stats-json", no_argument, NULL, 0 },
	{ "stats-log-file", required_argument, NULL, 0 },
	{ "strategy", required_argument, NULL, 0 },
	{ "show-unannotated", no_argument, NULL, 0 },
	{ "syslog", no_argument, NULL, 'S' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "victims", required_argument, NULL, 'V' },
	{ "no-warm-start", no_argument, NULL, 0 },
	{ "warm-start-path", required_argument, NULL, 0 },
	{ "no-kcov-warm-start", no_argument, NULL, 0 },
	{ "no-cmp-hints-warm-start", no_argument, NULL, 0 },
	{ "corpus-save-errno-grad-live", no_argument, NULL, 0 },
	{ NULL, 0, NULL, 0 } };

/*
 * Option-family dispatch helpers.  Each helper claims a related cluster
 * of options out of the parse_args() getopt loop: it inspects the
 * already-parsed (opt, name, arg) triple, applies side effects for any
 * option it owns, and returns true to signal the option was consumed.
 * For short options opt is the short char and name is NULL; for
 * long-only options opt is 0 and name is longopts[opt_index].name.
 * The longopts[] table itself remains the single source of truth for
 * option definitions -- helpers only carry the dispatch strings.
 */

static bool parse_child_options(int opt, const char *name, char *arg)
{
	if (opt == 'C') {
		unsigned long val;
		enum max_children_binding b;
		unsigned long cap;

		if (!parse_unsigned(arg, "children", false, &val))
			exit(EXIT_FAILURE);
		cap = derive_max_children_cap(&b);
		if (val > cap) {
			outputerr("--children=%lu exceeds %s cap of %lu\n",
				  val, binding_name(b), cap);
			exit(EXIT_FAILURE);
		}
		user_specified_children = (unsigned int)val;
		max_children = user_specified_children;
		return true;
	}

	if (opt != 0)
		return false;

	if (strcmp("alt-op-children", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "alt-op-children", true, &val))
			exit(EXIT_FAILURE);
		if (val > UINT_MAX) {
			outputerr("--alt-op-children value %lu exceeds UINT_MAX\n", val);
			exit(EXIT_FAILURE);
		}
		alt_op_children = (unsigned int)val;
		user_specified_alt_op_children = true;
		return true;
	}

	if (strcmp("explorer-children", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "explorer-children", true, &val))
			exit(EXIT_FAILURE);
		if (val > UINT_MAX) {
			outputerr("--explorer-children value %lu exceeds UINT_MAX\n", val);
			exit(EXIT_FAILURE);
		}
		explorer_children = (unsigned int)val;
		user_specified_explorer_children = true;
		return true;
	}

	return false;
}

static bool parse_kcov_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("childop-kcov-attribution", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_OFF;
		} else if (strcmp(arg, "dual") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_DUAL;
		} else if (strcmp(arg, "on") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_ON;
		} else {
			outputerr("--childop-kcov-attribution: unknown mode '%s' (expected off, dual, or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("kcov-trace-size", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "kcov-trace-size", false, &val))
			exit(EXIT_FAILURE);
		if (val < (unsigned long)KCOV_TRACE_SIZE) {
			outputerr("--kcov-trace-size=%lu below the lower bound %u (KCOV_TRACE_SIZE)\n",
				val, (unsigned int)KCOV_TRACE_SIZE);
			exit(EXIT_FAILURE);
		}
		if (val > KCOV_TRACE_SIZE_MAX) {
			outputerr("--kcov-trace-size=%lu exceeds upper bound %lu (KCOV_TRACE_SIZE_MAX)\n",
				val, (unsigned long)KCOV_TRACE_SIZE_MAX);
			exit(EXIT_FAILURE);
		}
		/* Power-of-2: matches the historical KCOV_TRACE_SIZE shape
		 * (and keeps the kernel's mmap-page alignment trivial). */
		if ((val & (val - 1)) != 0) {
			outputerr("--kcov-trace-size=%lu is not a power of 2\n",
				val);
			exit(EXIT_FAILURE);
		}
		kcov_trace_size = (unsigned int)val;
		return true;
	}

	if (strcmp("kcov-transition-coverage", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			kcov_transition_coverage_mode = KCOV_TRANSITION_COVERAGE_OFF;
		} else if (strcmp(arg, "shadow") == 0) {
			kcov_transition_coverage_mode = KCOV_TRANSITION_COVERAGE_SHADOW;
		} else {
			outputerr("--kcov-transition-coverage: unknown mode '%s' (expected off or shadow)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("kcov-transition-reward", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_COMBINED;
		} else {
			outputerr("--kcov-transition-reward: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	return false;
}

static bool parse_cmp_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("redqueen-pending-pick", name) == 0) {
		if (!parse_redqueen_pending_pick(arg,
						 &redqueen_pending_pick_mode_arg)) {
			outputerr("--redqueen-pending-pick: unknown policy '%s' (try random or first)\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("cmp-recent-pool", name) == 0) {
		if (!parse_cmp_recent_pool(arg, &cmp_recent_pool_mode_arg)) {
			outputerr("--cmp-recent-pool: unknown policy '%s' (try off or recent-first)\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("corpus-save-errno-grad-live", name) == 0) {
		corpus_save_errno_grad_live = true;
		return true;
	}

	return false;
}

static bool parse_cache_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("no-warm-start", name) == 0) {
		no_warm_start = true;
		return true;
	}

	if (strcmp("warm-start-path", name) == 0) {
		free(warm_start_path);
		warm_start_path = strdup(arg);
		if (!warm_start_path) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("no-kcov-warm-start", name) == 0) {
		no_kcov_warm_start = true;
		return true;
	}

	if (strcmp("no-cmp-hints-warm-start", name) == 0) {
		no_cmp_hints_warm_start = true;
		return true;
	}

	return false;
}

static bool parse_strategy_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("strategy", name) == 0) {
		if (!parse_picker_mode(arg, &picker_mode_arg)) {
			outputerr("--strategy: unknown picker '%s' (try bandit or round-robin)\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("group-bias", name) == 0) {
		group_bias = true;
		return true;
	}

	if (strcmp("cred-throttle", name) == 0) {
		cred_throttle = true;
		return true;
	}

	if (strcmp("frontier-live-cooldown", name) == 0) {
		frontier_live_cooldown = true;
		return true;
	}

	if (strcmp("frontier-saturation-cooldown", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_COMBINED;
		} else {
			outputerr("--frontier-saturation-cooldown: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("canary-slots", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "canary-slots", true, &val))
			exit(EXIT_FAILURE);
		if (val > UINT_MAX) {
			outputerr("--canary-slots value %lu exceeds UINT_MAX\n", val);
			exit(EXIT_FAILURE);
		}
		canary_slots = (unsigned int)val;
		user_specified_canary_slots = true;
		return true;
	}

	if (strcmp("canary-window", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "canary-window", false, &val))
			exit(EXIT_FAILURE);
		if (val < 1000 || val > 1000000) {
			outputerr("--canary-window=%lu out of range (1000..1000000)\n", val);
			exit(EXIT_FAILURE);
		}
		canary_window_iters = (unsigned int)val;
		return true;
	}

	if (strcmp("no-canary-queue", name) == 0) {
		canary_queue_disabled = true;
		return true;
	}

	if (strcmp("fork-pressure-drain", name) == 0) {
		fork_pressure_drain = true;
		return true;
	}

	if (strcmp("canary-seed", name) == 0) {
		/* Parse a comma-separated list of childop names
		 * into canary_seed_override[].  Names match
		 * alt_op_name() output (e.g.
		 * "genetlink_fuzzer,bpf_lifecycle").  Unknown
		 * names are fatal -- the operator typed something
		 * and we owe them a clean error, not a silent
		 * skip that runs the wrong seed list. */
		char *dup = strdup(arg);
		char *tok, *save = NULL;

		if (dup == NULL) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		canary_seed_override_count = 0;
		for (tok = strtok_r(dup, ",", &save);
		     tok != NULL;
		     tok = strtok_r(NULL, ",", &save)) {
			enum child_op_type op;

			if (canary_seed_override_count >=
			    CANARY_SEED_OVERRIDE_MAX) {
				outputerr("--canary-seed: too many entries (max %d)\n",
					CANARY_SEED_OVERRIDE_MAX);
				exit(EXIT_FAILURE);
			}
			op = alt_op_lookup_by_name(tok);
			if (op == NR_CHILD_OP_TYPES ||
			    op == CHILD_OP_SYSCALL) {
				outputerr("--canary-seed: unknown childop name '%s'\n",
					tok);
				exit(EXIT_FAILURE);
			}
			canary_seed_override[canary_seed_override_count++] =
				(unsigned char)op;
		}
		free(dup);
		return true;
	}

	return false;
}

static bool parse_memory_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("memory-max", name) == 0) {
		if (!validate_cgroup_size_arg("--memory-max", arg))
			exit(EXIT_FAILURE);
		free(memory_max_arg);
		memory_max_arg = strdup(arg);
		if (memory_max_arg == NULL) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("memory-high", name) == 0) {
		if (!validate_cgroup_size_arg("--memory-high", arg))
			exit(EXIT_FAILURE);
		free(memory_high_arg);
		memory_high_arg = strdup(arg);
		if (memory_high_arg == NULL) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("memory-swap-max", name) == 0) {
		if (!validate_cgroup_size_arg("--memory-swap-max", arg))
			exit(EXIT_FAILURE);
		free(memory_swap_max_arg);
		memory_swap_max_arg = strdup(arg);
		if (memory_swap_max_arg == NULL) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("no-cgroup", name) == 0) {
		no_cgroup = true;
		return true;
	}

	if (strcmp("no-startup-isolation", name) == 0) {
		no_startup_isolation = true;
		return true;
	}

	return false;
}

void parse_args(int argc, char *argv[])
{
	int opt;
	int opt_index = 0;
	bool epoch_timeout_set = false;

	while ((opt = getopt_long(argc, argv, paramstr, longopts, &opt_index)) != -1) {
		const char *long_name = (opt == 0) ? longopts[opt_index].name : NULL;

		if (parse_child_options(opt, long_name, optarg))
			continue;
		if (parse_kcov_options(opt, long_name, optarg))
			continue;
		if (parse_cmp_options(opt, long_name, optarg))
			continue;
		if (parse_cache_options(opt, long_name, optarg))
			continue;
		if (parse_strategy_options(opt, long_name, optarg))
			continue;
		if (parse_memory_options(opt, long_name, optarg))
			continue;

		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				outputstd("opt:%c\n", opt);
			return;

		case 'a':
			/* One of the architectures selected*/
			do_32_arch = false;
			do_64_arch = false;
			if (strcmp(optarg, "64") == 0) {
				do_32_arch = false;
				do_64_arch = true;
			} else if (strcmp(optarg, "32") == 0) {
				do_32_arch = true;
				do_64_arch = false;
			} else {
				outputstd("can't parse %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			init_bdev_list();
			process_bdev_param(optarg);
			dump_bdev_list();
			outputstd("--bdev doesn't do anything useful yet.\n");
			exit(EXIT_SUCCESS);

		case 'c':
			/* syscalls are all disabled at this point. enable the syscall we care about. */
			do_specific_syscall = true;
			toggle_syscall(optarg, true);
			break;

		case 'd':
			dangerous = true;
			break;

		case 'D':
			set_debug = true;
			break;

		case 'E':
			parse_exclude_domains(optarg);
			break;

		case 'g': {
			unsigned int i;
			bool matched = false;

			for (i = 0; i < ARRAY_SIZE(group_names); i++) {
				if (!strcmp(optarg, group_names[i].name)) {
					desired_group = group_names[i].id;
					matched = true;
					break;
				}
			}
			if (!matched) {
				outputerr("unknown group '%s'. Valid groups are:", optarg);
				for (i = 0; i < ARRAY_SIZE(group_names); i++)
					outputerr(" %s", group_names[i].name);
				outputerr("\n");
				exit(EXIT_FAILURE);
			}
			break;
		}

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'I':
			show_ioctl_list = true;
			break;

		case 'L':
			show_syscall_list = true;
			break;

		/* Set number of syscalls to do */
		case 'N': {
			unsigned long val;

			if (!parse_unsigned(optarg, "N", false, &val))
				exit(EXIT_FAILURE);
			syscalls_todo = val;
			break;
		}

		case 'P':
			/*
			 * -P takes a domain name (e.g. INET, PF_INET6); the
			 * actual lookup happens later in find_specific_domain()
			 * via the domains[] table.  Just stash optarg here.
			 */
			do_specific_domain = true;
			specific_domain_optarg = optarg;
			break;

		case 'q':
			quiet = true;
			break;

		case 'r': {
			unsigned long val;

			if (do_exclude_syscall == true) {
				outputerr("-r needs to be before any -x options.\n");
				exit(EXIT_FAILURE);
			}
			if (!parse_unsigned(optarg, "r", false, &val))
				exit(EXIT_FAILURE);
			if (val > UINT_MAX) {
				outputerr("-r: value %lu exceeds UINT_MAX\n", val);
				exit(EXIT_FAILURE);
			}
			random_selection_num = (unsigned int)val;
			random_selection = true;
			break;
		}

		/* Set seed */
		case 's': {
			unsigned long val;

			if (!parse_unsigned(optarg, "s", true, &val))
				exit(EXIT_FAILURE);
			if (val > UINT_MAX) {
				outputerr("-s: value %lu exceeds UINT_MAX\n", val);
				exit(EXIT_FAILURE);
			}
			seed = (unsigned int)val;
			user_set_seed = true;
			break;
		}


		case 'S':
			do_syslog = true;
			break;

		case 'T':
			//Load mask for kernel taint flags.
			process_taint_arg(optarg);
			if (kernel_taint_mask != 0xFFFFFFFF)
				outputstd("Custom kernel taint mask has been specified: 0x%08x (%d).\n",
					kernel_taint_mask, kernel_taint_mask);
			break;

		case 'v':
			verbosity++;
			break;

		case 'V':
			if (nr_victim_paths >= MAX_VICTIM_PATHS) {
				outputerr("Too many victim paths (max %d).\n", MAX_VICTIM_PATHS);
				exit(EXIT_FAILURE);
			}
			victim_paths[nr_victim_paths] = strdup(optarg);
			if (!victim_paths[nr_victim_paths]) {
				outputerr("strdup failed\n");
				exit(EXIT_FAILURE);
			}
			nr_victim_paths++;
			break;

		case 'x':
			do_exclude_syscall = true;
			toggle_syscall(optarg, false);
			break;

		case 0:
			if (strcmp("clowntown", long_name) == 0)
				clowntown = true;

			if (strcmp("disable-fds", long_name) == 0)
				process_fds_param(optarg, false);

			if (strcmp("dry-run", long_name) == 0)
				dry_run = true;

			if (strcmp("enable-fds", long_name) == 0)
				process_fds_param(optarg, true);

			if (strcmp("epoch-iterations", long_name) == 0) {
				if (!parse_unsigned(optarg, "epoch-iterations", false, &epoch_iterations))
					exit(EXIT_FAILURE);
			}

			if (strcmp("epoch-timeout", long_name) == 0) {
				if (max_runtime_set) {
					outputerr("warning: --max-runtime takes precedence; ignoring --epoch-timeout\n");
				} else {
					unsigned long val;
					if (!parse_unsigned(optarg, "epoch-timeout", false, &val))
						exit(EXIT_FAILURE);
					if (val > UINT_MAX) {
						outputerr("--epoch-timeout: value %lu exceeds UINT_MAX\n", val);
						exit(EXIT_FAILURE);
					}
					epoch_timeout = (unsigned int)val;
					epoch_timeout_set = true;
				}
			}

			if (strcmp("max-runtime", long_name) == 0) {
				unsigned int seconds;
				if (!parse_duration(optarg, &seconds)) {
					outputerr("can't parse '%s' as a duration (use number with optional s/m/h/d suffix)\n", optarg);
					exit(EXIT_FAILURE);
				}
				if (epoch_timeout_set)
					outputerr("warning: --max-runtime overrides previously set --epoch-timeout\n");
				epoch_timeout = seconds;
				max_runtime_set = true;
			}

#ifdef CONFIG_GUARD_SHARED
			if (strcmp("guard-shared", long_name) == 0) {
				/* --guard-shared        -> pools (default)
				 * --guard-shared=pools  -> pools
				 * --guard-shared=all    -> all
				 * --guard-shared=off    -> off (explicit no-op)
				 *
				 * Decided defaults from the 2026-06-09 spec:
				 * pools is the focused scope (kcov_shm, shared
				 * str/obj heap, childdata) and is what an
				 * operator wants the first time they reach for
				 * the flag.  ALL is the wider sweep; warn the
				 * operator that the VMA budget may need a
				 * vm.max_map_count bump so a guarded fleet host
				 * doesn't ENOMEM on its own mprotect splits.
				 */
				if (optarg == NULL ||
				    strcmp(optarg, "pools") == 0) {
					guard_shared_scope = GUARD_SCOPE_POOLS;
				} else if (strcmp(optarg, "all") == 0) {
					guard_shared_scope = GUARD_SCOPE_ALL;
					outputerr("--guard-shared=all: every alloc_shared region is guarded; "
						  "consider raising vm.max_map_count if mprotect splits ENOMEM\n");
				} else if (strcmp(optarg, "off") == 0) {
					guard_shared_scope = GUARD_SCOPE_OFF;
				} else {
					outputerr("--guard-shared: unknown scope '%s' (use pools|all|off)\n",
						  optarg);
					exit(EXIT_FAILURE);
				}
			}
#else
			/*
			 * Build does NOT have CONFIG_GUARD_SHARED.  The
			 * longopt entry above is unconditional (it has to
			 * be, or getopt would reject --guard-shared with a
			 * generic "unrecognised option" line that hides
			 * what actually happened).  Without this branch the
			 * flag is silently accepted and ignored, which has
			 * already misled two corruption-hunt sessions into
			 * believing armour was active when the binary was
			 * built plain.  Loudly diagnose instead so the
			 * operator sees the configure step they need to
			 * re-run.
			 */
			if (strcmp("guard-shared", long_name) == 0) {
				outputerr("WARNING: --guard-shared ignored -- "
					  "binary built without GUARD_SHARED=1; "
					  "rebuild with GUARD_SHARED=1 ./configure && make\n");
			}
#endif

			if (strcmp("show-unannotated", long_name) == 0)
				show_unannotated = true;

			if (strcmp("stats", long_name) == 0)
				show_stats = true;

			if (strcmp("stats-json", long_name) == 0) {
				stats_json = true;
				show_stats = true;
			}

			if (strcmp("stats-log-file", long_name) == 0) {
				free(stats_log_path);
				stats_log_path = strdup(optarg);
				if (!stats_log_path) {
					outputerr("strdup failed\n");
					exit(EXIT_FAILURE);
				}
			}

			if (strcmp("print-disabled-syscalls", long_name) == 0)
				show_disabled_syscalls = true;

			break;
		}
	}

	if (optind < argc) {
		outputerr("unexpected argument(s):");
		while (optind < argc)
			outputerr(" '%s'", argv[optind++]);
		outputerr("\n");
		exit(EXIT_FAILURE);
	}

	if (verbosity > MAX_LOGLEVEL)
		verbosity = MAX_LOGLEVEL;

	output(1, "Done parsing arguments.\n");
}

/*
 * Help/usage output for the params cluster.  option_descs[] and
 * shortonly_descs[] are the single source of truth for the --help
 * text; longopts[] in options.c is the getopt_long() metadata that
 * mirrors them and dispatches into the parse_*_options() helpers.
 * Adding an option means touching both tables (plus a parser helper).
 *
 * Rationale for individual options (why they exist, mode contracts,
 * validation checklists before promoting a shadow arm) lives outside
 * this file -- the --help entries are one-liners, the design notes
 * are in Documentation/:
 *
 *   --alt-op-children              Documentation/childop-canary-queue.md#alt-op-children
 *   --arg-len-semantics            Documentation/params-args.md#arg-len-semantics
 *   --bandit-reward-edge-count     Documentation/strategy.md#bandit-reward-edge-count
 *   --blob-ab-mode                 Documentation/blob-mutator.md#blob-ab-mode
 *   --blob-mutator                 Documentation/blob-mutator.md
 *   --canary-seed                  Documentation/childop-canary-queue.md#canary-seed
 *   --canary-slots                 Documentation/childop-canary-queue.md#canary-slots
 *   --canary-window                Documentation/childop-canary-queue.md#canary-window
 *   --chain-resource-typing        Documentation/params-args.md#chain-resource-typing
 *   --childop-cmp-consume          Documentation/cmp-frontier.md#childop-cmp-consume
 *   --childop-cmp-harvest          Documentation/cmp-frontier.md#childop-cmp-harvest
 *   --childop-kcov-attribution     Documentation/childop-canary-queue.md#childop-kcov-attribution
 *   --cmp-frontier                 Documentation/cmp-frontier.md
 *   --cmp-shared-tier              Documentation/cmp-frontier.md#cmp-shared-tier
 *   --cmsg-richness                Documentation/params-args.md#cmsg-richness
 *   --context-pool                 Documentation/params-picker.md#context-pool
 *   --corpus-save-errno-grad-live  Documentation/params-picker.md#corpus-save-errno-grad-live
 *   --cost-pool-selector           Documentation/params-picker.md#cost-pool-selector
 *   --cred-throttle                Documentation/params-picker.md#cred-throttle
 *   --no-deferred-free-batch       Documentation/params-debug.md#no-deferred-free-batch
 *   --expensive-adaptive           Documentation/params-picker.md#expensive-adaptive
 *   --explorer-children            Documentation/strategy.md#explorer-children
 *   --fork-pressure-drain          Documentation/childop-canary-queue.md#fork-pressure-drain
 *   --frontier-barren-demote       Documentation/params-frontier.md#frontier-barren-demote
 *   --frontier-group-antilock      Documentation/params-frontier.md#frontier-group-antilock
 *   --frontier-live-cooldown-mode  Documentation/params-frontier.md#frontier-live-cooldown-mode
 *   --frontier-noise-sample        Documentation/kcov-shared-layout.md#frontier-noise-sample
 *   --frontier-saturation-cooldown Documentation/params-frontier.md#frontier-saturation-cooldown
 *   --guard-shared                 Documentation/params-debug.md#guard-shared
 *   --hermetic                     Documentation/params-warm-start.md#hermetic
 *   --kcov-trace-size              Documentation/kcov-shared-layout.md#kcov-trace-size
 *   --kcov-transition-coverage     Documentation/kcov-shared-layout.md#kcov-transition-coverage
 *   --kcov-transition-reward       Documentation/kcov-shared-layout.md#kcov-transition-reward
 *   --memory-high, --memory-max, --memory-swap-max
 *                                  Documentation/params-cgroup.md
 *   --no-canary-queue              Documentation/childop-canary-queue.md#no-canary-queue
 *   --no-cgroup                    Documentation/params-cgroup.md#no-cgroup
 *   --no-*-warm-start, --no-warm-start, --warm-start-path
 *                                  Documentation/params-warm-start.md
 *   --no-startup-isolation         Documentation/params-cgroup.md#no-startup-isolation
 *   --reach-band                   Documentation/reach-band.md
 *   --redqueen-pending-pick        Documentation/params-debug.md#redqueen-pending-pick
 *   --self-corrupt-canary          Documentation/params-debug.md#self-corrupt-canary
 *   --strategy                     Documentation/strategy.md#strategy
 *   --writer-pin-stride            Documentation/params-debug.md#writer-pin-stride
 *   --writer-pin-sweep             Documentation/params-debug.md#writer-pin-sweep
 *   --writer-watch                 Documentation/params-debug.md#writer-watch
 */

#include <stdlib.h>
#include <string.h>

#include "arg-len-semantics.h"
#include "bdevs.h"
#include "child.h"
#include "blob_mutator.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cmsg-richness.h"
#include "fd.h"
#include "kcov.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "reach-band.h"
#include "self_cgroup.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"	// progname, max_files_rlimit
#include "utils.h"

#include "kernel/hw_breakpoint.h"
#include "kernel/socket.h"

#include "internal.h"

struct option_help {
	const char *name;	/* long option name (NULL = end of table) */
	char shortopt;		/* short option char, or 0 if none */
	const char *desc;	/* help text */
};

static const struct option_help option_descs[] = {
	{ "alt-op-children",	 0,  "reserve N children for dedicated alt ops (default: max(2, --children/8))" },
	{ "arch",		'a', "selects syscalls for the specified architecture (32 or 64). Both by default." },
	{ "blob-mutator",	 0,  "content-authoring for ARG_BUF_SIZED args: off/fill/havoc/cmpdict (default off)" },
	{ "blob-ab-mode",	 0,  "within-run A/B alternating HAVOC vs CMPDICT per fill (default off)" },
	{ "arg-len-semantics",	 0,  "object-size-relative ARG_LEN draw mode: off/on (default off)" },
	{ "bdev",		'b', "Add /dev node to list of block devices to use for destructive tests." },
	{ "canary-seed",	 0,  "override the built-in priority canary seed list (comma-separated childop names)" },
	{ "canary-slots",	 0,  "reserve N front slots from --alt-op-children for the dormant-op canary queue" },
	{ "canary-window",	 0,  "invocations of active canary op per window (default 10000, range 1k..1M)" },
	{ "childop-kcov-attribution", 0, "per-childop KCOV attribution: off/dual/on (default dual)" },
	{ "childop-kcov-sample", 0, "1-of-N outer-bracket sampler (default 4, N=1 brackets every dispatch)" },
	{ "childop-cmp-harvest", 0, "per-childop KCOV_TRACE_CMP bracket on CMP children: off/on (default off)" },
	{ "childop-cmp-consume", 0, "shadow consume-side resolver at childop field sites: off/on (default off)" },
	{ "children",		'C', "specify number of child processes" },
	{ "clowntown",		 0,  "enable clowntown mode" },
	{ "cmp-frontier", 0, "CMP-weighted alternate picker arm: off/shadow-only/combined (default off)" },
	{ "cmsg-richness", 0, "extended sendmsg/sendmmsg control-message generator: off/on (default off)" },
	{ "corpus-save-errno-grad-live", 0, "enable the errno-gradient corpus save trigger (default off)" },
	{ "context-pool", 0, "regular_suppressed context-axis observer: off/shadow-only/combined (default off)" },
	{ "cost-pool-selector", 0, "cost-pool one-shot selector: off/shadow-only/combined (default off)" },
	{ "cmp-shared-tier", 0, "fleet-wide shared cmp_ip tier rollout: off/shadow/combined (default off)" },
	{ "cred-throttle",	 0,  "throttle credential syscalls under high EPERM+EINVAL (default off)" },
	{ "frontier-live-cooldown-mode", 0, "LIVE cooldown discriminator: off/shadow-only/combined (default off)" },
	{ "frontier-barren-demote", 0, "floored-barren sub-floor demote: off/shadow-only/combined (default off)" },
	{ "frontier-saturation-cooldown", 0, "saturation-cooldown predicate: off/shadow-only/combined (default off)" },
	{ "frontier-group-antilock", 0, "group-bias anti-lock-in damper: off/shadow-only/combined (default off)" },
	{ "dangerous",		'd', "enable dangerous mode" },
	{ "debug",		'D', "enable debug" },
	{ "disable-fds",	 0,  NULL },	/* handled separately */
	{ "guard-shared",	 0,  "PROT_NONE-guard shared mmap regions (needs GUARD_SHARED=1): off/pools/all" },
	{ "domain",		'P', "specify specific network domain for sockets" },
	{ "dry-run",		 0,  "run arg-gen + sanitise but skip the syscall (safe ASAN/repro mode)" },
	{ "enable-fds",		 0,  NULL },	/* handled separately */
	{ "epoch-iterations",	 0,  "syscalls per epoch before restarting (must be > 0; omit to disable)" },
	{ "epoch-timeout",	 0,  "seconds per epoch before restarting (must be > 0; omit to disable)" },
	{ "exclude",		'x', "exclude syscall(s): name or comma-list, each optionally @32 or @64" },
	{ "explorer-children",	 0,  "reserve N STRATEGY_RANDOM explorer children (default max_children/4 for bandit)" },
	{ "fork-pressure-drain", 0, "suppress canary picks of pid-heavy ops under fork() failure (default off)" },
	{ "group",		'g', "only run syscalls from a certain group (vfs,vm,net,ipc,process,signal,io_uring,bpf,sched,time,xattr)" },
	{ "group-bias",		 0,  "bias syscall selection toward the same group as the previous call" },
	{ "help",		'h', "show this help" },
	{ "hermetic",		 0,  "run with no persisted fuzzing state (implies every --no-*-warm-start)" },
	{ "ioctls",		'I', "list all ioctls" },
	{ "kcov-trace-size", 0, "per-child KCOV PC-trace buffer size in ulongs (default 262144, pow2)" },
	{ "frontier-noise-sample", 0, "per-syscall clean-vs-noisy sampler; N>0 samples every Nth bracket (default 0)" },
	{ "kcov-transition-coverage", 0, "shadow transition-coverage map: shadow (default) or off" },
	{ "kcov-transition-reward", 0, "transition-edge reward: combined (default) / shadow-only / off" },
	{ "bandit-reward-edge-count", 0, "blended edge-count reward for UCB1: off/shadow-only/combined (default off)" },
	{ "expensive-adaptive", 0, "adaptive accept-rate for EXPENSIVE gate: off/shadow-only/combined (default off)" },
	{ "kernel_taint",	'T', "controls which kernel taint flags should be considered (see README)" },
	{ "list",		'L', "list all syscalls known on this architecture" },
	{ "max-runtime",	 0,  "maximum runtime before exit (suffix s/m/h/d; overrides --epoch-timeout)" },
	{ "memory-high",	 0,  "children/memory.high threshold: max, N%, or N[KMG] (default 50%)" },
	{ "memory-max",		 0,  "total trinity memory budget: max, N%, or N[KMG] (default 60%)" },
	{ "memory-swap-max",	 0,  "children/memory.swap.max cap: max, N%, or N[KMG] (default 20%)" },
	{ "no-canary-queue",	 0,  "disable the dormant-childop canary queue entirely" },
	{ "no-cgroup",		 0,  "skip self-cgroup creation entirely (no in-binary memory containment)" },
	{ "no-chain-warm-start", 0, "skip loading/saving the persisted sequence chain corpus (see --hermetic)" },
	{ "chain-resource-typing", 0, "bias chain gen: fd producer/consumer pairing (off/shadow/live; default off)" },
	{ "no-cmp-hints-warm-start", 0, "skip loading/saving the persisted kcov CMP-hint pool (see --hermetic)" },
	{ "no-kcov-warm-start",	 0,  "skip loading/saving the persisted kcov edge bitmap (see --hermetic)" },
	{ "no-minicorpus-warm-start", 0, "skip loading/saving the persisted minicorpus (see --hermetic)" },
	{ "no-startup-isolation", 0,  "skip parent-side unshare(CLONE_NEWNET|CLONE_NEWNS) in root fuzzer" },
	{ "no-warm-start",	 0,  "back-compat alias for --no-minicorpus-warm-start (prefer --hermetic)" },
	{ "no_domain",		'E', "specify network domains to be excluded from testing" },
	{ "print-disabled-syscalls", 0, "print syscalls disabled via AVOID_SYSCALL or NEED_ALARM and exit" },
	{ "quiet",		'q', "suppress the per-second progress line (other output unchanged)" },
	{ "self-corrupt-canary", 0, "checksum critical child self-state per dispatch (default off; heavyweight)" },
	{ "no-deferred-free-batch", 0, "bracket every deferred-free metadata mutation with its own mprotect pair (slow; debugging)" },
	{ "random",		'r', "pick N syscalls at random and just fuzz those" },
	{ "reach-band", 0, "reach-banded silent-regime weight: off/shadow-only/combined (default off)" },
	{ "redqueen-pending-pick", 0, "retained for compatibility; no-op (accepts 'random' or 'first')" },
	{ "show-unannotated",	 0,  "show unannotated syscalls" },
	{ "stats",		 0,  "per-syscall errno stats on exit; write stats-timeseries-<ep>.jsonl per window" },
	{ "stats-json",		 0,  "emit dump_stats output as a single JSON object on stdout (machine-readable)" },
	{ "stats-log-file",	 0,  "path to append periodic stats dumps to (in addition to stdout)" },
	{ "strategy",		 0,  "arm-selection policy: bandit/ucb1 (default) or round-robin/rr" },
	{ "sysrq-on-lockup",	 0,  "on fleet wedge (>= max(3, running/2) stuck), fire SysRq w+l once and drain kmsg (default off)" },
	{ "syslog",		'S', "log important info to syslog (useful if syslog is remote)" },
	{ "verbose",		'v', "increase output verbosity. Repeat for more detail (-vv)" },
	{ "victims",		'V', "path to victim files (may be repeated)" },
	{ "warm-start-path",	 0,  "override the on-disk minicorpus path (default: $XDG_CACHE_HOME/trinity/corpus/<arch>)" },
	{ "writer-pin-sweep",	 0,  "sweep minicorpus rings for stomped wp_canary per post-syscall (default off)" },
	{ "writer-pin-stride",	 0,  "sweep every Nth post-syscall validate phase (default 1)" },
	{ "writer-watch",	 0,  "arm HW WRITE breakpoint on the given hex address per-child (default off)" },
	{ NULL,			 0,  NULL },
};

/* Short-only options that don't appear in longopts. */
static const struct option_help shortonly_descs[] = {
	{ NULL, 'c', "target specific syscall(s): name or comma-list, each optionally @32 or @64" },
	{ NULL, 'N', "do N syscalls then exit" },
	{ NULL, 's', "use N as random seed" },
	{ NULL,  0,  NULL },
};

void usage(void)
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

/*
 * getopt_long() metadata for the params cluster.  paramstr holds the
 * short-option string; longopts[] declares every long option and
 * routes it through the parse_*_options() helpers in parse.c.  The
 * help text for each entry lives in option_descs[] in help.c.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

const char paramstr[] = "a:b:c:C:dDE:g:hILN:P:qr:s:ST:V:vx:";

const struct option longopts[] = {
	{ "alt-op-children", required_argument, NULL, 0 },
	{ "arch", required_argument, NULL, 'a' },
	{ "arg-len-semantics", required_argument, NULL, 0 },
	{ "bdev", required_argument, NULL, 'b' },
	{ "canary-seed", required_argument, NULL, 0 },
	{ "canary-slots", required_argument, NULL, 0 },
	{ "canary-window", required_argument, NULL, 0 },
	{ "childop-kcov-attribution", required_argument, NULL, 0 },
	{ "childop-cmp-harvest", required_argument, NULL, 0 },
	{ "childop-cmp-consume", required_argument, NULL, 0 },
	{ "kcov-trace-size", required_argument, NULL, 0 },
	{ "frontier-noise-sample", required_argument, NULL, 0 },
	{ "kcov-transition-coverage", required_argument, NULL, 0 },
	{ "kcov-transition-reward", required_argument, NULL, 0 },
	{ "bandit-reward-edge-count", required_argument, NULL, 0 },
	{ "expensive-adaptive", required_argument, NULL, 0 },
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
	{ "frontier-live-cooldown-mode", required_argument, NULL, 0 },
	{ "frontier-saturation-cooldown", required_argument, NULL, 0 },
	{ "frontier-barren-demote", required_argument, NULL, 0 },
	{ "frontier-group-antilock", required_argument, NULL, 0 },
	{ "cost-pool-selector", required_argument, NULL, 0 },
	{ "context-pool", required_argument, NULL, 0 },
	{ "cmp-shared-tier", required_argument, NULL, 0 },
	{ "cmp-cfactual", required_argument, NULL, 0 },
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
	{ "reach-band", required_argument, NULL, 0 },
	{ "redqueen-pending-pick", required_argument, NULL, 0 },
	{ "blob-mutator", required_argument, NULL, 0 },
	{ "blob-ab-mode", no_argument, NULL, 0 },
	{ "cmp-frontier", required_argument, NULL, 0 },
	{ "cmsg-richness", required_argument, NULL, 0 },
	{ "stats", no_argument, NULL, 0 },
	{ "stats-json", no_argument, NULL, 0 },
	{ "stats-log-file", required_argument, NULL, 0 },
	{ "strategy", required_argument, NULL, 0 },
	{ "self-corrupt-canary", no_argument, NULL, 0 },
	{ "show-unannotated", no_argument, NULL, 0 },
	{ "syslog", no_argument, NULL, 'S' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "victims", required_argument, NULL, 'V' },
	{ "no-warm-start", no_argument, NULL, 0 },
	{ "warm-start-path", required_argument, NULL, 0 },
	{ "no-kcov-warm-start", no_argument, NULL, 0 },
	{ "no-cmp-hints-warm-start", no_argument, NULL, 0 },
	{ "no-chain-warm-start", no_argument, NULL, 0 },
	{ "chain-resource-typing", required_argument, NULL, 0 },
	{ "corpus-save-errno-grad-live", no_argument, NULL, 0 },
	{ "writer-pin-sweep", no_argument, NULL, 0 },
	{ "writer-pin-stride", required_argument, NULL, 0 },
	{ "writer-watch", required_argument, NULL, 0 },
	{ NULL, 0, NULL, 0 } };

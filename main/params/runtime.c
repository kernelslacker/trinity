/*
 * Runtime-envelope options: epoch/max-runtime windowing, stats
 * output, memory-cgroup containment, and warm-start cache toggles.
 * Every helper in here inspects opt/name and applies the operator
 * override to file-scope state defined in state.c or to the module-
 * private epoch_timeout_set latch below.
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

bool parse_cache_options(int opt, const char *name, char *arg)
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

	if (strcmp("no-chain-warm-start", name) == 0) {
		no_chain_warm_start = true;
		return true;
	}

	if (strcmp("chain-resource-typing", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			chain_resource_typing_mode = CHAIN_RESTYPE_MODE_OFF;
		} else if (strcmp(arg, "shadow") == 0) {
			chain_resource_typing_mode = CHAIN_RESTYPE_MODE_SHADOW;
		} else if (strcmp(arg, "live") == 0) {
			chain_resource_typing_mode = CHAIN_RESTYPE_MODE_LIVE;
		} else {
			outputerr("--chain-resource-typing: unknown mode '%s' (expected off, shadow, or live)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	return false;
}

bool parse_memory_options(int opt, const char *name, char *arg)
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

/* --epoch-timeout / --max-runtime interlock: if --max-runtime is seen
 * first, --epoch-timeout must be ignored; if --epoch-timeout is seen
 * first, a later --max-runtime must warn and override.  This latch
 * tracks whether --epoch-timeout has been applied so parse_runtime_
 * options() can emit the override warning at the right moment. */
static bool epoch_timeout_set = false;

bool parse_runtime_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("epoch-iterations", name) == 0) {
		if (!parse_unsigned(arg, "epoch-iterations", false, &epoch_iterations))
			exit(EXIT_FAILURE);
		return true;
	}

	if (strcmp("epoch-timeout", name) == 0) {
		if (max_runtime_set) {
			outputerr("warning: --max-runtime takes precedence; ignoring --epoch-timeout\n");
		} else {
			unsigned long val;
			if (!parse_unsigned(arg, "epoch-timeout", false, &val))
				exit(EXIT_FAILURE);
			if (val > UINT_MAX) {
				outputerr("--epoch-timeout: value %lu exceeds UINT_MAX\n", val);
				exit(EXIT_FAILURE);
			}
			epoch_timeout = (unsigned int)val;
			epoch_timeout_set = true;
		}
		return true;
	}

	if (strcmp("max-runtime", name) == 0) {
		unsigned int seconds;
		if (!parse_duration(arg, &seconds)) {
			outputerr("can't parse '%s' as a duration (use number with optional s/m/h/d suffix)\n", arg);
			exit(EXIT_FAILURE);
		}
		if (epoch_timeout_set)
			outputerr("warning: --max-runtime overrides previously set --epoch-timeout\n");
		epoch_timeout = seconds;
		max_runtime_set = true;
		return true;
	}

	return false;
}

bool parse_stats_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("stats", name) == 0) {
		show_stats = true;
		return true;
	}

	if (strcmp("stats-json", name) == 0) {
		stats_json = true;
		show_stats = true;
		return true;
	}

	if (strcmp("stats-log-file", name) == 0) {
		free(stats_log_path);
		stats_log_path = strdup(arg);
		if (!stats_log_path) {
			outputerr("strdup failed\n");
			exit(EXIT_FAILURE);
		}
		return true;
	}

	return false;
}

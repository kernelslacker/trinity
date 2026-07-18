/*
 * Child-slot sizing + canary/fork-pressure childop knobs:
 *   -C children, --alt-op-children, --explorer-children,
 *   --canary-slots, --canary-window, --no-canary-queue,
 *   --canary-seed, --fork-pressure-drain.
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

bool parse_child_options(int opt, const char *name, char *arg)
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

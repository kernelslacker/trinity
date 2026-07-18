/*
 * Child-slot sizing options: -C children, --alt-op-children,
 * --explorer-children.  Per the phase-2 spec childop.c will also own
 * the canary and fork-pressure knobs currently parked in
 * parse_strategy_options() in coverage.c; this file starts with the
 * pure -C / alt-op / explorer trio and grows in a follow-up commit.
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

	return false;
}

/*
 * Backwards-compat parser helpers and small hooks that don't fit into
 * any option-family bucket: the retained --redqueen-pending-pick
 * name/parser pair (see include/params.h for why they're preserved as
 * no-ops), and the fd-provider help hook enable_disable_fd_usage()
 * that usage() in help.c calls to dump provider names alongside the
 * --enable-fds / --disable-fds rows.
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

/* Redqueen pending-pick name/parser -- see include/params.h. */
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

void enable_disable_fd_usage(void)
{
	dump_fd_provider_names();
}

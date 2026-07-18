/*
 * Selection knobs: which arch (-a), syscalls (-c/-x), groups (-g),
 * network domains (-P/-E), random selection (-r), N-then-exit (-N),
 * and how many -- plus the shared apply_syscall_csv() helper that
 * walks a comma-separated list for -c and -x.  group_names[] is
 * the small lookup table select_group_by_name() consults for -g.
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

static void select_group_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(group_names); i++) {
		if (strcmp(name, group_names[i].name) == 0) {
			desired_group = group_names[i].id;
			return;
		}
	}

	outputerr("unknown group '%s'. Valid groups are:", name);
	for (i = 0; i < ARRAY_SIZE(group_names); i++)
		outputerr(" %s", group_names[i].name);
	outputerr("\n");
	exit(EXIT_FAILURE);
}

/* Walk a comma-separated syscall list (e.g. "read,write,mmap") and invoke
 * cb() per token.  Shared by -c (enable) and -x (exclude); a single bare
 * name still works because strtok_r returns the whole string as one token.
 * flag is used only for the error message. */
static void apply_syscall_csv(const char *arg, const char *flag,
			      void (*cb)(char *name))
{
	char *dup, *tok, *save = NULL;

	dup = strdup(arg);
	if (dup == NULL) {
		outputerr("%s: strdup failed\n", flag);
		exit(EXIT_FAILURE);
	}
	tok = strtok_r(dup, ",", &save);
	while (tok != NULL) {
		cb(tok);
		tok = strtok_r(NULL, ",", &save);
	}
	free(dup);
}

static void csv_enable_syscall(char *name)
{
	toggle_syscall(name, true);
}

static void csv_disable_syscall(char *name)
{
	toggle_syscall(name, false);
}

/* Selection knobs: which arch/syscalls/domains to fuzz and how many. */
bool parse_selection_options(int opt, const char *name, char *arg)
{
	(void)name;

	switch (opt) {
	case 'a':
		do_32_arch = false;
		do_64_arch = false;
		if (strcmp(arg, "64") == 0) {
			do_32_arch = false;
			do_64_arch = true;
		} else if (strcmp(arg, "32") == 0) {
			do_32_arch = true;
			do_64_arch = false;
		} else {
			outputstd("can't parse %s\n", arg);
			exit(EXIT_FAILURE);
		}
		return true;

	case 'c':
		/* arg may be a single name or a comma-separated list,
		 * e.g. -c read,write,mmap. */
		do_specific_syscall = true;
		apply_syscall_csv(arg, "-c", csv_enable_syscall);
		return true;

	case 'E':
		parse_exclude_domains(arg);
		return true;

	case 'g':
		select_group_by_name(arg);
		return true;

	case 'N': {
		unsigned long val;

		if (!parse_unsigned(arg, "N", false, &val))
			exit(EXIT_FAILURE);
		syscalls_todo = val;
		return true;
	}

	case 'P':
		/*
		 * -P takes a domain name (e.g. INET, PF_INET6); the
		 * actual lookup happens later in find_specific_domain()
		 * via the domains[] table.  Just stash arg here.
		 */
		do_specific_domain = true;
		specific_domain_optarg = arg;
		return true;

	case 'r': {
		unsigned long val;

		if (do_exclude_syscall == true) {
			outputerr("-r needs to be before any -x options.\n");
			exit(EXIT_FAILURE);
		}
		if (!parse_unsigned(arg, "r", false, &val))
			exit(EXIT_FAILURE);
		if (val > UINT_MAX) {
			outputerr("-r: value %lu exceeds UINT_MAX\n", val);
			exit(EXIT_FAILURE);
		}
		random_selection_num = (unsigned int)val;
		random_selection = true;
		return true;
	}

	case 'x':
		/* arg may be a single name or a comma-separated list,
		 * e.g. -x read,write,mmap. */
		do_exclude_syscall = true;
		apply_syscall_csv(arg, "-x", csv_disable_syscall);
		return true;
	}

	return false;
}

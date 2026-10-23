/*
 * Process struct-catalog registrations.
 *
 * clone3 is read by the paired-descriptor lookup behind its
 * ARG_STRUCT_SIZE argument, getrlimit fills an output buffer, and
 * perf_event_open has the pointers nested in its attr scrubbed before
 * the call.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>

#include "config.h"

#include "struct_catalog.h"

const struct syscall_struct_arg struct_catalog_registry_process[] = {
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[SC_CLONE_ARGS] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[SC_PERF_EVENT_ATTR] },
	/* sentinel */
	{ NULL, 0, NULL },
};

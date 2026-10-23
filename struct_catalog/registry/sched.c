/*
 * Scheduler struct-catalog registrations.
 *
 * sched_getattr onto struct sched_attr.
 */

#include <stddef.h>

#include "config.h"

#include "struct_catalog.h"

const struct syscall_struct_arg struct_catalog_registry_sched[] = {
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* sentinel */
	{ NULL, 0, NULL },
};

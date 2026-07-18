/*
 * Scheduler struct-catalog registrations.
 *
 * sched_setattr / sched_getattr onto struct sched_attr, and
 * sched_setparam / sched_setscheduler onto struct sched_param.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <sched.h>
#include <linux/sched.h>
#include <linux/sched/types.h>

#include "config.h"

#include "struct_catalog.h"
#include "trinity.h"

const struct syscall_struct_arg struct_catalog_registry_sched[] = {
	/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
	{ "sched_setattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* sched_setparam(pid_t, struct sched_param *) */
	{ "sched_setparam",	2, &struct_catalog[SC_SCHED_PARAM] },
	/* sched_setscheduler(pid_t, int, struct sched_param *) */
	{ "sched_setscheduler",	3, &struct_catalog[SC_SCHED_PARAM] },
	/* sentinel */
	{ NULL, 0, NULL },
};

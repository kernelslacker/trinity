/*
 * struct_catalog/sched.c -- sched-shaped struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <sched.h>
#include <linux/sched.h>
#include <linux/sched/types.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#include "kernel/sched.h"
/* ------------------------------------------------------------------ */
/* struct sched_attr (sched_setattr, sched_getattr)                    */
/* ------------------------------------------------------------------ */

const struct struct_field sched_attr_fields[SCHED_ATTR_FIELDS_N] = {
	FIELD(struct sched_attr, size),
	FIELD(struct sched_attr, sched_policy),
	FIELD(struct sched_attr, sched_flags),
	FIELD(struct sched_attr, sched_nice),
	FIELD(struct sched_attr, sched_priority),
	FIELD(struct sched_attr, sched_runtime),
	FIELD(struct sched_attr, sched_deadline),
	FIELD(struct sched_attr, sched_period),
	FIELD(struct sched_attr, sched_util_min),
	FIELD(struct sched_attr, sched_util_max),
};

/* ------------------------------------------------------------------ */
/* struct clone_args (clone3)                                          */
/* ------------------------------------------------------------------ */

const struct struct_field clone_args_fields[CLONE_ARGS_FIELDS_N] = {
	FIELD(struct clone_args, flags),
	FIELD(struct clone_args, pidfd),
	FIELD(struct clone_args, child_tid),
	FIELD(struct clone_args, parent_tid),
	FIELD(struct clone_args, exit_signal),
	FIELD(struct clone_args, stack),
	FIELD(struct clone_args, stack_size),
	FIELD(struct clone_args, tls),
	FIELD(struct clone_args, set_tid),
	FIELD(struct clone_args, set_tid_size),
	FIELD(struct clone_args, cgroup),
};

/* ------------------------------------------------------------------ */
/* struct sched_param (sched_setparam, sched_setscheduler)              */
/* ------------------------------------------------------------------ */

const struct struct_field sched_param_fields[SCHED_PARAM_FIELDS_N] = {
	FIELD(struct sched_param, sched_priority),
};

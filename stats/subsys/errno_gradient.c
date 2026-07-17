#include <stddef.h>
#include "stats-internal.h"

/* errno_gradient: SHADOW measurement of upward errno-class crossings (no
 * fuzzer-behaviour change -- see stats/subsys/errno_gradient.h for the
 * class axis and the SHADOW contract).  Aggregate scalars only; the
 * per-syscall last_class array is deliberately unrendered (internal to
 * the predicate, matching the other per-syscall shadow arrays).  Text
 * render gates on crossings so a run that never observed an upward
 * transition emits nothing in the text dump; JSON renders
 * unconditionally for schema stability. */
static const struct stat_field errno_gradient_fields[] = {
	STAT_FIELD_SUB(errno_gradient, crossings),
	STAT_FIELD_SUB(errno_gradient, to_permstate),
	STAT_FIELD_SUB(errno_gradient, to_success),
};

const struct stat_category errno_gradient_category =
	STAT_CATEGORY("errno_gradient",
	              errno_gradient.crossings,
	              errno_gradient_fields);

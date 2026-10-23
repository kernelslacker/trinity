/*
 * struct_catalog/resource.c -- resource-limit struct field table.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <sys/resource.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct rlimit (getrlimit)                                           */
/* ------------------------------------------------------------------ */

const struct struct_field rlimit_fields[RLIMIT_FIELDS_N] = {
	FIELD(struct rlimit, rlim_cur),
	FIELD(struct rlimit, rlim_max),
};

/*
 * struct_catalog/resource.c -- resource-limit / cachestat-range struct
 * field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 *
 * The cachestat_range registration is attribution-only: cachestat's
 * argtype slot is not ARG_STRUCT_PTR_*, so the schema-aware fill path
 * never fires and the bespoke pick_range() in syscalls/cachestat.c
 * continues to own the live (off, len) values.  The FT_RANGE
 * annotations stay so KCOV CMP constants are attributed to off or len
 * rather than a coincidentally-same-width slot.  Bounds mirror the
 * timespec precedent's u32-fitting ceiling so the catalog stays
 * portable on 32-bit unsigned long builds.
 */

#include <stddef.h>
#include <sys/resource.h>
#include <linux/mman.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct rlimit (setrlimit, getrlimit, prlimit64)                     */
/* ------------------------------------------------------------------ */

const struct struct_field rlimit_fields[RLIMIT_FIELDS_N] = {
	FIELD(struct rlimit, rlim_cur),
	FIELD(struct rlimit, rlim_max),
};

/* ------------------------------------------------------------------ */
/* struct cachestat_range (cachestat)                                  */
/* ------------------------------------------------------------------ */

const struct struct_field cachestat_range_fields[CACHESTAT_RANGE_FIELDS_N] = {
	FIELDX(struct cachestat_range, off, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct cachestat_range, len, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
};

/*
 * struct_catalog/resource.c -- resource-limit / cachestat-range struct
 * field tables.
 *
 * Carved out of struct_catalog.c as another leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the
 * resource-shaped leaf data only -- struct rlimit (setrlimit /
 * getrlimit / prlimit64) and struct cachestat_range (cachestat).
 * Symbols flip from static const to const so the spine's
 * .fields = rlimit_fields / cachestat_range_fields references resolve
 * via the externs in struct_catalog-internal.h.
 *
 * The cachestat_range registration is attribution-only: cachestat's
 * argtype slot is not ARG_STRUCT_PTR_*, so the schema-aware fill path
 * never fires and the bespoke pick_range() in syscalls/cachestat.c
 * continues to own the live (off, len) values.  The FT_RANGE
 * annotations stay so KCOV CMP constants are attributed to off or len
 * rather than a coincidentally-same-width slot.  Bounds mirror the
 * timespec precedent's u32-fitting ceiling so the catalog stays
 * portable on 32-bit unsigned long builds.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.  <sys/resource.h> brings struct rlimit and
 * <linux/mman.h> brings struct cachestat_range.
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

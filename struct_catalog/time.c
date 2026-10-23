/*
 * struct_catalog/time.c -- time-shaped struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <utime.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct timespec (clock_nanosleep, nanosleep, utimensat)             */
/* ------------------------------------------------------------------ */

/*
 * tv_nsec is rejected by the kernel for values outside [0, 1e9) before
 * the syscall does any real work, so an FT_RAW splat almost never lands
 * on the wait/update path.  Keep tv_sec as an unbounded FT_RANGE so
 * absolute / past / future buckets stay reachable; pin tv_nsec to the
 * legal nanosecond range so the request actually clears the kernel's
 * input check.  Callers that want UTIME_NOW / UTIME_OMIT (utimensat)
 * still construct those values in their own sanitise callback.
 */
const struct struct_field timespec_fields[TIMESPEC_FIELDS_N] = {
	FIELDX(struct timespec, tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct timespec, tv_nsec, FT_RANGE,
	       .u.range = { 0, 999999999UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct utimbuf (utime)                                              */
/* ------------------------------------------------------------------ */

/*
 * utime(const char *filename, const struct utimbuf __user *times) passes
 * the utimbuf at a2.  utime has no bespoke .sanitise -- argtype[1] was
 * ARG_ADDRESS, so the times buffer was filled as an undifferentiated
 * address slot with no schema path of its own.  Flipping argtype[1] to
 * ARG_STRUCT_PTR_IN routes the slot through the schema-aware fill so it
 * lands on a dedicated sized buffer, and the catalog entry below names
 * the (actime, modtime) layout for CMP attribution.
 *
 * Both members are time_t and currently FT_RAW: the bytes match the
 * historical random splat -- the win is the dedicated sized buffer and
 * letting struct_field_for_cmp attribute KCOV CMP constants at the named
 * actime / modtime fields rather than at a coincidentally-same-width
 * slot.  No FT_TIME tag exists in the catalog vocabulary today; adding
 * one is deferred until a precedent for time_t-shaped semantic tagging
 * lands across the other timespec / timeval consumers.
 */
const struct struct_field utimbuf_fields[UTIMBUF_FIELDS_N] = {
	FIELD(struct utimbuf, actime),
	FIELD(struct utimbuf, modtime),
};

/* ------------------------------------------------------------------ */
/* struct timeval (settimeofday, select)                               */
/* ------------------------------------------------------------------ */

/*
 * struct timeval is the (tv_sec, tv_usec) pair the kernel takes at
 * settimeofday's a1 (INPUT wall-clock value) and at select's a5
 * (INOUT timeout).  Both syscalls already carry a bespoke .sanitise
 * that owns the live fill via get_writable_address(): settimeofday
 * biases 70% near-now / 30% random with an explicit invalid-tv_usec
 * leg, and select stamps a deterministic short {0, 10us} timeout.
 * Without a catalog entry the slots were filled but had no schema
 * path of their own, so struct_field_for_cmp() had nothing to hang
 * KCOV-CMP attribution against and learned constants fell at a
 * coincidentally-same-width slot rather than at a named field.
 *
 * Registration is attribution-only, mirroring the in-tree timespec /
 * utimensat handling and the landed utimbuf / flock / sigevent
 * commits: the bespoke sanitisers keep owning the fill -- this only
 * feeds the CMP-attribution path.  tv_sec stays FT_RAW so the
 * near-now / random / wraparound bytes the bespoke fills already
 * produce are preserved; tv_usec is pinned to the legal microsecond
 * range so attribution at the named tv_usec slot lines up with the
 * kernel's timeval_valid() check rather than landing on a
 * coincidentally-same-width neighbour.
 */
const struct struct_field timeval_fields[TIMEVAL_FIELDS_N] = {
	FIELD(struct timeval, tv_sec),
	FIELDX(struct timeval, tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
};


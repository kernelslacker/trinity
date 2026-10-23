/*
 * struct_catalog/time.c -- time-shaped struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <sys/time.h>
#include <utime.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

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
/* struct timeval (setsockopt SO_RCVTIMEO / SO_SNDTIMEO)               */
/* ------------------------------------------------------------------ */

/*
 * tv_usec is pinned to the legal microsecond range: sock_set_timeout()
 * answers -EDOM to anything outside it before it reads tv_sec.  tv_sec
 * stays FT_RAW, since the kernel also accepts a negative value (the
 * timeout becomes zero) and a huge one (no timeout at all).
 */
const struct struct_field timeval_fields[TIMEVAL_FIELDS_N] = {
	FIELD(struct timeval, tv_sec),
	FIELDX(struct timeval, tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
};

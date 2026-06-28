/*
 * struct_catalog/time.c -- time-shaped struct field tables.
 *
 * Carved out of struct_catalog.c as the sixth leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the timex /
 * itimerspec / timespec / itimerval / utimbuf / timeval / timezone
 * leaf data only.  Symbols flip from static const to const so the
 * spine's .fields = timex_fields / .fields = itimerspec_fields /
 * etc. references resolve via the externs in
 * struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.
 */

#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <utime.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct timex (adjtimex, clock_adjtime)                               */
/* ------------------------------------------------------------------ */

/*
 * ADJ_* mode-bit vocabulary for timex.modes.  Anything outside the
 * mask causes the kernel to reject the call before any clock state is
 * read, so an FT_RAW splat almost never reaches the do_adjtimex()
 * dispatch.  Mask values are stable in linux/timex.h; new ADJ_* bits
 * are rare and caught by reviewer reading the uapi diff.
 */
#define TIMEX_MODES_MASK \
	(ADJ_OFFSET | ADJ_FREQUENCY | ADJ_MAXERROR | ADJ_ESTERROR | \
	 ADJ_STATUS | ADJ_TIMECONST | ADJ_TAI    | ADJ_SETOFFSET | \
	 ADJ_MICRO  | ADJ_NANO      | ADJ_TICK)

const struct struct_field timex_fields[TIMEX_FIELDS_N] = {
	FIELDX(struct timex, modes, FT_FLAGS,
	       .u.flags.mask = TIMEX_MODES_MASK,
	       .mutate_weight = 80),
	FIELD(struct timex, offset),
	FIELD(struct timex, freq),
	FIELD(struct timex, maxerror),
	FIELD(struct timex, esterror),
	FIELD(struct timex, status),
	FIELD(struct timex, constant),
	FIELD(struct timex, precision),
	FIELD(struct timex, tolerance),
	FIELD(struct timex, tick),
	FIELD(struct timex, ppsfreq),
	FIELD(struct timex, jitter),
	FIELD(struct timex, shift),
	FIELD(struct timex, stabil),
	FIELD(struct timex, jitcnt),
	FIELD(struct timex, calcnt),
	FIELD(struct timex, errcnt),
	FIELD(struct timex, stbcnt),
};

/* ------------------------------------------------------------------ */
/* struct itimerspec (timer_settime, timerfd_settime)                  */
/* ------------------------------------------------------------------ */

const struct struct_field itimerspec_fields[ITIMERSPEC_FIELDS_N] = {
	FIELD(struct itimerspec, it_interval.tv_sec),
	FIELD(struct itimerspec, it_interval.tv_nsec),
	FIELD(struct itimerspec, it_value.tv_sec),
	FIELD(struct itimerspec, it_value.tv_nsec),
};

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
/* struct itimerval (setitimer)                                        */
/* ------------------------------------------------------------------ */

/*
 * setitimer(int which, const struct itimerval __user *value,
 *           struct itimerval __user *ovalue) passes the input itimerval
 * at a2.  The bespoke sanitise_setitimer() in syscalls/setitimer.c
 * continues to own the live fill: it get_writable_address()es a struct
 * itimerval, walks both embedded timevals through fill_timeval() (zero
 * / sub-second / small-positive / random tv_sec buckets paired with a
 * legal tv_usec), half the time disarms the timer by zeroing it_value,
 * routes a2 to the writable buffer, and runs a3 through
 * avoid_shared_buffer_out().  setitimer's argtype[1] is not
 * ARG_STRUCT_PTR_*, so the schema-aware fill path never runs against
 * it -- mirrors itimerspec / robust_list_head / rseq / pollfd / sembuf
 * / open_how / sigevent above.
 *
 * Registration is attribution-only: struct_field_for_cmp() uses the
 * FT_RANGE tags to attribute small-int CMP constants at the named
 * tv_sec / tv_usec slots rather than at a coincidentally-same-width
 * slot.  Bounds mirror the timespec_fields[] precedent: tv_sec is left
 * unbounded so absolute / past / future buckets stay reachable; tv_usec
 * is pinned to the legal microsecond range so the request actually
 * clears timeval_valid() inside the kernel's setitimer entry.  Only
 * setitimer's INPUT a2 is mapped below -- a3 (ovalue) is a kernel-
 * written output, and getitimer's a2 is likewise an output, so neither
 * is mapped.
 */
const struct struct_field itimerval_fields[ITIMERVAL_FIELDS_N] = {
	FIELDX(struct itimerval, it_interval.tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_interval.tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_value.tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_value.tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
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
 * coincidentally-same-width neighbour.  Bound mirrors the
 * itimerval_fields[] tv_usec precedent (0..999999).
 */
const struct struct_field timeval_fields[TIMEVAL_FIELDS_N] = {
	FIELD(struct timeval, tv_sec),
	FIELDX(struct timeval, tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct timezone (settimeofday)                                      */
/* ------------------------------------------------------------------ */

/*
 * struct timezone is the (tz_minuteswest, tz_dsttime) pair settimeofday
 * takes at a2.  The bespoke sanitise_settimeofday() owns the live fill
 * via get_writable_address(): a 50/50 zero-vs-random leg producing
 * tz_minuteswest in [-780, +780] (-13h..+13h in minutes) and tz_dsttime
 * in [0, 3].  Without a catalog entry the slot was filled but had no
 * schema path of its own, so struct_field_for_cmp() had nothing to
 * hang KCOV-CMP attribution against and learned constants fell at a
 * coincidentally-same-width slot rather than at a named field.
 *
 * Registration is attribution-only, mirroring the in-tree timespec /
 * utimensat handling and the landed timeval / utimbuf / flock commits:
 * the bespoke sanitiser keeps owning the fill -- this only feeds the
 * CMP-attribution path.  tz_minuteswest is left FT_RAW: the live fill
 * spans a signed window [-780, +780] and the FT_RANGE union carries
 * unsigned bounds (struct { unsigned long lo, hi; } range), so a
 * literal {-780, 780} would wrap to a garbage upper bound; the signed
 * bytes the bespoke fill produces are preserved verbatim.  tz_dsttime
 * is all-positive [0, 3] and pins cleanly to FT_RANGE so attribution
 * at the named slot lines up with the kernel's narrow legal window.
 */
const struct struct_field timezone_fields[TIMEZONE_FIELDS_N] = {
	/*
	 * FT_RANGE's bounds are unsigned long, so this signed
	 * [-780, +780] minutes-west window cannot be expressed as a
	 * range; keep FT_RAW and let the bespoke fill own the value.
	 */
	FIELD(struct timezone, tz_minuteswest),
	FIELDX(struct timezone, tz_dsttime, FT_RANGE,
	       .u.range = { 0, 3 },
	       .mutate_weight = 40),
};

/*
 * Self-check for the time-argument generators (args/gen_arg_time.c): a
 * compat call numbered below the y2038 calls reads its time structs as
 * 32-bit fields (struct old_timespec32, old_itimerspec32), so the
 * generators write that layout for one and the native struct for any
 * other call, as does timer_settime's sanitiser when it rewrites the
 * generated struct.  Each case draws until the buffer shows a value only
 * the right layout can hold.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>

#include "args-internal.h"	/* gen_arg_timespec */
#include "blob_mutator.h"	/* blob_mutator_mode */
#include "debug.h"		/* BUG */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_timer_settime */

/* gen_arg_buf_sized(), which shares gen_arg_time.c, reaches these; no
 * case here draws it. */
enum blob_mutator_mode blob_mutator_mode;
bool blob_ab_mode;

void blob_fill(unsigned char *buf, size_t len, unsigned int nr, bool do32)
{
	(void) buf;
	(void) len;
	(void) nr;
	(void) do32;
	BUG("gen_arg_time: blob_fill() reached");
}

void publish_paired_length(struct syscallentry *entry,
			   struct syscallrecord *rec,
			   unsigned int argnum, unsigned long len)
{
	(void) entry;
	(void) rec;
	(void) argnum;
	(void) len;
	BUG("gen_arg_time: publish_paired_length() reached");
}

/* timer_settime's sanitiser seeds a timer when the pool has none; the
 * pool stays empty here. */
int32_t seed_timerid_if_empty(void)
{
	return -1;
}

/* clock_nanosleep on i386, and its y2038 twin; timer_settime on i386. */
#define NR_CLOCK_NANOSLEEP_TIME32	267
#define NR_CLOCK_NANOSLEEP_TIME64	407
#define NR_TIMER_SETTIME_TIME32		260

typedef unsigned long (*generator)(struct syscallentry *entry,
				   struct syscallrecord *rec,
				   unsigned int argnum);

/* Draws, all of which miss a 1-in-19 bucket one time in about 10^23. */
#define DRAWS	1000

/* Draw until a buffer @gen hands back for @rec passes @hit. */
static bool drawn(generator gen, struct syscallrecord *rec,
		  bool (*hit)(const void *buf))
{
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		const void *buf = (const void *) gen(NULL, rec, 0);

		if (buf != NULL && hit(buf))
			return true;
	}
	return false;
}

static bool compat_last_nsec(const void *buf)
{
	const struct old_timespec32 *ts = buf;

	return ts->tv_sec == 0 && ts->tv_nsec == 999999999;
}

static bool compat_max_sec(const void *buf)
{
	return ((const struct old_timespec32 *) buf)->tv_sec == INT32_MAX;
}

static bool native_last_nsec(const void *buf)
{
	const struct timespec *ts = buf;

	return ts->tv_sec == 0 && ts->tv_nsec == 999999999;
}

static bool compat_interval_last_nsec(const void *buf)
{
	const struct old_itimerspec32 *its = buf;

	return its->it_interval.tv_sec == 0 &&
	       its->it_interval.tv_nsec == 999999999;
}

/* timer_settime's sanitiser rewrites the generated struct with a valid
 * it_value three calls in four, tv_sec under 5 but for TIMER_ABSTIME's
 * deadline and tv_nsec under a second, which a time32 call must find
 * where it reads it_value. */
static bool timer_settime_compat_value(void)
{
	struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		struct old_itimerspec32 *its =
			get_writable_struct(sizeof(struct itimerspec));
		bool valid;

		memset(its, 0, sizeof(struct itimerspec));
		memset(&rec, 0, sizeof(rec));
		rec.do32bit = true;
		rec.nr = NR_TIMER_SETTIME_TIME32;
		rec.a3 = (unsigned long) its;
		rec.a4 = (unsigned long) get_writable_struct(sizeof(struct itimerspec));
		syscall_timer_settime.sanitise(&rec);
		free((void *) rec.post_state);

		valid = its->it_value.tv_sec >= 0 && its->it_value.tv_sec < 5 &&
			its->it_value.tv_nsec > 0 &&
			its->it_value.tv_nsec < 1000000000;
		if (valid)
			return true;
	}
	return false;
}

void gen_arg_time_self_check(void);
void gen_arg_time_self_check(void)
{
	struct syscallrecord rec;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(1) == NULL)
		writable_pool_init();

	memset(&rec, 0, sizeof(rec));
	rec.do32bit = true;
	rec.nr = NR_CLOCK_NANOSLEEP_TIME32;
	if (!drawn(gen_arg_timespec, &rec, compat_last_nsec))
		BUG("gen_arg_time: a time32 call never got the 999999999 ns bucket");
	/* The LONG_MAX bucket, held to the largest count the field takes. */
	if (!drawn(gen_arg_timespec, &rec, compat_max_sec))
		BUG("gen_arg_time: a time32 call never got the largest second count");

	rec.nr = NR_CLOCK_NANOSLEEP_TIME64;
	if (!drawn(gen_arg_timespec, &rec, native_last_nsec))
		BUG("gen_arg_time: a time64 compat call lost the native layout");

	rec.do32bit = false;
	rec.nr = __NR_clock_nanosleep;
	if (!drawn(gen_arg_timespec, &rec, native_last_nsec))
		BUG("gen_arg_time: a native call lost the native layout");

	rec.do32bit = true;
	rec.nr = NR_TIMER_SETTIME_TIME32;
	if (!drawn(gen_arg_itimerspec, &rec, compat_interval_last_nsec))
		BUG("gen_arg_time: a time32 itimerspec never got the 999999999 ns bucket");
	if (!timer_settime_compat_value())
		BUG("gen_arg_time: timer_settime's rewrite missed a time32 call's it_value");
}

/*
 * Self-check for the time-argument generators (args/gen_arg_time.c): a
 * compat call numbered below the y2038 calls reads a struct
 * old_timespec32 of 32-bit fields, so the generator writes that layout
 * for one and the native struct timespec for any other call.  Each case
 * draws until the buffer shows a bucket only the right layout can hold.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>

#include "args-internal.h"	/* gen_arg_timespec */
#include "blob_mutator.h"	/* blob_mutator_mode */
#include "debug.h"		/* BUG */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */

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

/* clock_nanosleep on i386, and its y2038 twin. */
#define NR_CLOCK_NANOSLEEP_TIME32	267
#define NR_CLOCK_NANOSLEEP_TIME64	407

/* Draws, all of which miss a 1-in-19 bucket one time in about 10^23. */
#define DRAWS	1000

/* Draw until a buffer the generator hands back for @rec passes @hit. */
static bool drawn(struct syscallrecord *rec, bool (*hit)(const void *buf))
{
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		const void *buf = (const void *) gen_arg_timespec(NULL, rec, 0);

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
	if (!drawn(&rec, compat_last_nsec))
		BUG("gen_arg_time: a time32 call never got the 999999999 ns bucket");
	/* The LONG_MAX bucket, held to the largest count the field takes. */
	if (!drawn(&rec, compat_max_sec))
		BUG("gen_arg_time: a time32 call never got the largest second count");

	rec.nr = NR_CLOCK_NANOSLEEP_TIME64;
	if (!drawn(&rec, native_last_nsec))
		BUG("gen_arg_time: a time64 compat call lost the native layout");

	rec.do32bit = false;
	rec.nr = __NR_clock_nanosleep;
	if (!drawn(&rec, native_last_nsec))
		BUG("gen_arg_time: a native call lost the native layout");
}

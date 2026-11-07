/*
 * Self-check for the time structs trinity builds (args/gen_arg_time.c
 * and the sanitisers that build their own): a compat call numbered below
 * the y2038 calls reads them as 32-bit fields (struct old_timespec32,
 * old_timeval32 and the itimer pairs of them), so each is written in
 * that layout for one and as the native struct for any other call.
 * pselect6's sigset argpack, which every compat call reads as 32-bit
 * words, is held to its layout too.  Each case draws until the buffer
 * shows a value only the right layout can hold.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <time.h>

#include "args-internal.h"	/* gen_arg_timespec */
#include "blob_mutator.h"	/* blob_mutator_mode */
#include "debug.h"		/* BUG */
#include "fd.h"			/* get_pollable_random_fd */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "kernel/stat.h"	/* UTIME_NOW */
#include "objects.h"		/* struct objhead */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_timer_settime, ... */
#include "utils-macros.h"	/* ARRAY_SIZE */

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

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/* timerfd_settime's sanitiser looks the timerfd's clock up in its pool,
 * which stays empty here too. */
static struct objhead *no_pool(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return NULL;
}

/* pselect6's sanitiser draws pollable fds, of which there are none, and
 * looks up the object behind each other fd it sets, which finds none. */
int get_pollable_random_fd(void)
{
	return -1;
}

extern struct object *(*fake_find_object_by_fd)(int fd);	/* fake_fds.c */
extern bool fake_pid_draws;	/* dup_pool_test.c */

static struct object *no_object(int fd)
{
	(void) fd;
	return NULL;
}

/* The calls' numbers on i386: their time32 entries, and two y2038
 * twins. */
#define NR_CLOCK_NANOSLEEP_TIME32	267
#define NR_CLOCK_NANOSLEEP_TIME64	407
#define NR_TIMER_SETTIME_TIME32		260
#define NR_SETTIMEOFDAY_TIME32		79
#define NR_SETITIMER_TIME32		104
#define NR_UTIMENSAT_TIME32		320
#define NR_TIMERFD_SETTIME_TIME32	325
#define NR_NEWSELECT_TIME32		142
#define NR_PSELECT6_TIME32		308
#define NR_PSELECT6_TIME64		413
#define NR_ADJTIMEX_TIME32		124
#define NR_CLOCK_ADJTIME_TIME32		343

typedef unsigned long (*generator)(struct syscallentry *entry,
				   struct syscallrecord *rec,
				   unsigned int argnum);

/* Draws, all of which miss a 1-in-32 bucket one time in about 10^14. */
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

static bool compat_last_usec(const void *buf)
{
	const struct old_timeval32 *tv = buf;

	return tv->tv_sec == 0 && tv->tv_usec == 999999;
}

static bool compat_interval_last_usec(const void *buf)
{
	const struct old_itimerval32 *itv = buf;

	return itv->it_interval.tv_sec == 0 &&
	       itv->it_interval.tv_usec == 999999;
}

/* Run @entry's sanitiser as a compat call numbered @nr, its six slots
 * handed zeroed pool buffers, until the buffer it leaves in slot @slot
 * passes @hit. */
static bool sanitised(const struct syscallentry *entry, unsigned int nr,
		      unsigned int slot, bool (*hit)(const void *buf))
{
	struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3,
				   &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k;

	for (i = 0; i < DRAWS; i++) {
		bool found;

		memset(&rec, 0, sizeof(rec));
		rec.do32bit = true;
		rec.nr = nr;
		for (k = 0; k < ARRAY_SIZE(slots); k++) {
			void *buf = get_writable_struct(sizeof(struct itimerspec));

			memset(buf, 0, sizeof(struct itimerspec));
			*slots[k] = (unsigned long) buf;
		}
		entry->sanitise(&rec);

		found = *slots[slot - 1] != 0 &&
			hit((const void *) *slots[slot - 1]);
		free((void *) rec.post_state);
		if (found)
			return true;
	}
	return false;
}

/* An it_value a sanitiser arms: tv_sec under 5 and tv_nsec inside a
 * second, but not 0, which a misplaced read leaves there. */
static bool compat_value_armed(const void *buf)
{
	const struct old_itimerspec32 *its = buf;

	return its->it_value.tv_sec >= 0 && its->it_value.tv_sec < 5 &&
	       its->it_value.tv_nsec > 0 &&
	       its->it_value.tv_nsec < 1000000000;
}

static bool compat_first_now(const void *buf)
{
	const struct old_timespec32 *ts = buf;

	return ts[0].tv_sec == 0 && ts[0].tv_nsec == UTIME_NOW;
}

/* A wait under a second, but not 0, which a misplaced read leaves. */
static bool compat_short_wait(const void *buf)
{
	const struct old_timespec32 *ts = buf;

	return ts->tv_sec == 0 && ts->tv_nsec > 0 &&
	       ts->tv_nsec < 1000000000;
}

static bool compat_short_usec_wait(const void *buf)
{
	const struct old_timeval32 *tv = buf;

	return tv->tv_sec == 0 && tv->tv_usec > 0 && tv->tv_usec < 1000000;
}

/* An ADJ_TICK of 9000 to 11000 us, where a time32 call reads the tick;
 * the native layout leaves 0 there. */
static bool compat_tick_set(const void *buf)
{
	const struct old_timex32 *tx = buf;

	return tx->modes == ADJ_TICK && tx->tick >= 9000 && tx->tick <= 11000;
}

/* A mask, and the 8 bytes set_compat_user_sigmask() wants for one. */
static bool compat_argpack_sized(const void *buf)
{
	const struct compat_sigset_argpack *pack = buf;

	return pack->p != 0 && pack->size == 8;
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
	/* timer_settime's sanitiser rewrites the generated struct with a
	 * valid it_value three calls in four. */
	if (!sanitised(&syscall_timer_settime, NR_TIMER_SETTIME_TIME32, 3,
		       compat_value_armed))
		BUG("gen_arg_time: timer_settime's rewrite missed a time32 call's it_value");

	rec.nr = NR_SETTIMEOFDAY_TIME32;
	if (!drawn(gen_arg_timeval, &rec, compat_last_usec))
		BUG("gen_arg_time: a time32 timeval never got the 999999 us bucket");
	rec.nr = NR_SETITIMER_TIME32;
	if (!drawn(gen_arg_itimerval, &rec, compat_interval_last_usec))
		BUG("gen_arg_time: a time32 itimerval never got the 999999 us bucket");

	if (!sanitised(&syscall_utimensat, NR_UTIMENSAT_TIME32, 3,
		       compat_first_now))
		BUG("gen_arg_time: utimensat's UTIME_NOW never reached a time32 call");
	fake_get_objhead = no_pool;
	if (!sanitised(&syscall_timerfd_settime, NR_TIMERFD_SETTIME_TIME32, 3,
		       compat_value_armed))
		BUG("gen_arg_time: timerfd_settime's timer never reached a time32 call");
	fake_get_objhead = NULL;

	fake_find_object_by_fd = no_object;
	if (!sanitised(&syscall_select, NR_NEWSELECT_TIME32, 5,
		       compat_short_usec_wait))
		BUG("gen_arg_time: select's timeout never reached a time32 call");
	if (!sanitised(&syscall_pselect6, NR_PSELECT6_TIME32, 5,
		       compat_short_wait))
		BUG("gen_arg_time: pselect6's timeout never reached a time32 call");
	/* A time64 call, as the argpack is 32-bit on either. */
	if (!sanitised(&syscall_pselect6, NR_PSELECT6_TIME64, 6,
		       compat_argpack_sized))
		BUG("gen_arg_time: pselect6's sigset argpack never reached a compat call");
	fake_find_object_by_fd = NULL;

	if (!sanitised(&syscall_adjtimex, NR_ADJTIMEX_TIME32, 1,
		       compat_tick_set))
		BUG("gen_arg_time: adjtimex's tick never reached a time32 call");
	/* clock_adjtime's sanitiser picks a clock, a process CPU clock
	 * among them, which names the test's own pid. */
	fake_pid_draws = true;
	if (!sanitised(&syscall_clock_adjtime, NR_CLOCK_ADJTIME_TIME32, 2,
		       compat_tick_set))
		BUG("gen_arg_time: clock_adjtime's tick never reached a time32 call");
	fake_pid_draws = false;
}

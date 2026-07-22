#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "args-internal.h"
#include "blob_mutator.h"
#include "cmp_hints.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"

/*
 * ARG_TIMESPEC: a writable pool buffer filled with a struct timespec.
 *
 * The kernel runs every timespec arrival through get_timespec64() ->
 * timespec64_valid(), which rejects tv_nsec >= NSEC_PER_SEC or < 0
 * before the timer / wait / IPC body runs.  Random bytes (the bare
 * ARG_UNDEFINED fill) collapse to tv_nsec ~ 2^63 -> certain -EINVAL
 * at the gate -- the actual subsystem code never executes.
 *
 * Mix:
 *   - ~10% NULL (legal "no timeout" arm for clock_nanosleep, semtimedop,
 *     io_getevents, futex_waitv, mq_timed*, ...)
 *   - ~5% raw bytes (keep the timespec64_valid reject path warm)
 *   - 85% bucketed legal / boundary / overflow shapes
 *
 * Pool buffer (get_writable_struct), off the shared region / libc heap
 * so the blanket address scrub is a no-op.  No .cleanup needed.
 *
 * Note: trinity is built largely as a 64-bit binary; struct timespec
 * and the kernel's struct __kernel_timespec share an identical layout
 * on 64-bit so the bespoke sanitisers being folded into this generator
 * (clock_nanosleep, clock_settime, semtimedop, ...) already type their
 * locals as struct timespec.  Match that convention.
 */
unsigned long gen_arg_timespec(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec,
				      unsigned int argnum)
{
	struct timespec *ts;
	const struct struct_desc *desc;
	unsigned long hint;

	if (rnd_modulo_u32(10) == 0)
		return 0;

	ts = (struct timespec *) get_writable_struct(sizeof(*ts));
	if (ts == NULL)
		return 0;

	if (rnd_modulo_u32(20) == 0) {
		ts->tv_sec = (time_t) rand64();
		ts->tv_nsec = (long) rand64();
		return (unsigned long) ts;
	}

	switch (rnd_modulo_u32(8)) {
	case 0:
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
		break;
	case 1:
		ts->tv_sec = 0;
		ts->tv_nsec = 1;
		break;
	case 2:
		ts->tv_sec = 0;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000);
		break;
	case 3:
		ts->tv_sec = (time_t) rnd_modulo_u32(60);
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	case 4:
		ts->tv_sec = (time_t) time(NULL) +
			(time_t) rnd_modulo_u32(120) - (time_t) 60;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	case 5:
		ts->tv_sec = 0;
		ts->tv_nsec = 999999999L;
		break;
	case 6:
		ts->tv_sec = 0;
		ts->tv_nsec = 1000000000L;
		break;
	default:
		if (RAND_BOOL())
			ts->tv_sec = -(time_t)(1 + rnd_modulo_u32(1u << 20));
		else
			ts->tv_sec = (time_t) LONG_MAX;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	}

	/*
	 * Field-scoped hint pull (SHADOW today, LIVE on the follow-up
	 * flip).  Both fields of the cataloged timespec layout
	 * (timespec_fields[]: tv_sec at index 0, tv_nsec at index 1) are
	 * 8-byte FT_RANGE entries; size matches the operand width
	 * cmp_hints_field_record() insists on for the recorder side.
	 * Probes against the (timespec desc, rec->nr, do32, argnum)
	 * bucket bump the shadow would-pick / would-miss / key-absent
	 * counters; the in-buffer overwrite only fires once the LIVE arm
	 * is flipped on, so today the post-bucketed values above stand.
	 * CMP_HINT_FIELD shares the bare-C transform with CMP_HINT_EXACT
	 * (cmp_hint_apply_transform) -- equality-gated field validators
	 * want the constant unmolested.
	 */
	desc = struct_catalog_lookup("timespec");
	if (desc != NULL) {
		/*
		 * Pass the pre-injection field value as fallback so the
		 * SHADOW cmp_field_consumer_would_value_differs measurement
		 * has a byte-accurate comparison target: the value the
		 * generator would OTHERWISE write to the slot if the pull
		 * did not fire.  Consumed only inside the field consumer's
		 * shadow branch; does not steer pick / miss counting and
		 * does not affect the returned value.
		 */
		if (cmp_hints_field_try_get(rec->nr, rec->do32bit, argnum,
					    desc, 0, sizeof(ts->tv_sec),
					    CMP_HINT_FIELD, 0,
					    (unsigned long) ts->tv_sec, &hint))
			ts->tv_sec = (time_t) hint;
		if (cmp_hints_field_try_get(rec->nr, rec->do32bit, argnum,
					    desc, 1, sizeof(ts->tv_nsec),
					    CMP_HINT_FIELD, 0,
					    (unsigned long) ts->tv_nsec, &hint))
			ts->tv_nsec = (long) hint;
	}

	return (unsigned long) ts;
}

/*
 * ARG_BUF_SIZED: a writable input-buffer slot whose paired ARG_BUF_LEN
 * sibling publishes the byte length the kernel will copy_from_user().
 * Models the generic `const void __user *buf, size_t len` pair some
 * syscalls take for an opaque blob whose layout is not a fixed struct
 * (mq_timedsend's msg_ptr+msg_len, splice/sendfile-shaped payloads,
 * ...).  ARG_STRUCT_PTR_IN exists for typed structs; this is its
 * untyped sibling, and the paired-length wiring mirrors
 * ARG_IOVEC/ARG_IOVECLEN exactly.
 *
 * Mix:
 *   - ~10% NULL (publish 0, return NULL: legal "no buffer" arm /
 *     EFAULT-with-len reject arm)
 *   - ~1/16 deliberate pointer/length mismatch (alloc S, publish
 *     S' != S; biased S' > S to keep the copy_from_user EFAULT /
 *     size-check reject path warm, occasionally S' < S for the
 *     short-copy arm)
 *   - rest: coherent buf+len at one of seven boundary size buckets
 *     (0, 1, page-1, page, page+1, mid-range, large-with-real-backing
 *     capped at ~64 KiB so get_writable_address's residency probe
 *     stays cheap)
 *
 * Pool buffer (get_writable_struct == get_writable_address), off the
 * shared region / libc heap so the blanket address scrub is a no-op
 * and no .cleanup is required -- mirror ARG_TIMESPEC.
 */
unsigned long gen_arg_buf_sized(struct syscallentry *entry,
				       struct syscallrecord *rec,
				       unsigned int argnum)
{
	unsigned long size;
	void *buf;

	if (rnd_modulo_u32(10) == 0) {
		publish_paired_length(entry, rec, argnum, 0);
		return 0;
	}

	switch (rnd_modulo_u32(7)) {
	case 0:
		size = 0;
		break;
	case 1:
		size = 1;
		break;
	case 2:
		size = page_size - 1;
		break;
	case 3:
		size = page_size;
		break;
	case 4:
		size = page_size + 1;
		break;
	case 5:
		size = 1UL + rnd_modulo_u32(8192);
		break;
	default:
		size = 1UL + rnd_modulo_u32(65536);
		break;
	}

	buf = get_writable_struct(size);
	if (buf == NULL) {
		publish_paired_length(entry, rec, argnum, 0);
		return 0;
	}

	/*
	 * Author content into the owned buffer before the length is
	 * published.  get_writable_struct() hands back a bump-pool slice
	 * whose bytes are whatever the previous syscall left behind, so
	 * the buffer MUST be overwritten -- otherwise the paired
	 * copy_from_user() replays stale prior payload (potential
	 * prior-pointer-as-length info-leak into the kernel).
	 *
	 * --blob-mutator / --blob-ab-mode: when either gate fires, the
	 * per-fill coin-flip inside blob_fill() picks HAVOC / CMPDICT /
	 * ... and authors the buffer.  When both are off (default) fall
	 * through to a plain random fill so the freshness invariant
	 * still holds.
	 */
	if (blob_mutator_mode != BLOB_MUTATOR_OFF || blob_ab_mode)
		blob_fill((unsigned char *) buf, (size_t) size, rec->nr, false);
	else
		generate_rand_bytes((unsigned char *) buf, (unsigned int) size);

	if (rnd_modulo_u32(16) == 0) {
		unsigned long pub;

		/*
		 * Bias S' > S to drive the kernel's copy_from_user
		 * EFAULT / size-check reject path; the occasional
		 * S' < S keeps the short-copy arm warm.
		 */
		if (rnd_modulo_u32(4) != 0)
			pub = size + 1UL + rnd_modulo_u32(8192);
		else if (size > 0)
			pub = rnd_modulo_u32((uint32_t) size);
		else
			pub = 1UL + rnd_modulo_u32(8192);
		publish_paired_length(entry, rec, argnum, pub);
		return (unsigned long) buf;
	}

	publish_paired_length(entry, rec, argnum, size);
	return (unsigned long) buf;
}

/*
 * Bucketed fill for a single struct timeval, shared by gen_arg_timeval()
 * and gen_arg_itimerval() (which is two timevals back-to-back).
 *
 * Mirrors the setitimer bespoke bucket set: zero / sub-ms / sec+usec /
 * raw, plus an explicit invalid-tv_usec (>= 1e6) bucket so the kernel's
 * timeval legality validator stays warm.
 */
static void fill_timeval_bucket(struct timeval *tv)
{
	switch (rnd_modulo_u32(8)) {
	case 0:
		tv->tv_sec = 0;
		tv->tv_usec = 0;
		break;
	case 1:
		tv->tv_sec = 0;
		tv->tv_usec = 1 + (suseconds_t) rnd_modulo_u32(1000);
		break;
	case 2:
		tv->tv_sec = (time_t) (1 + rnd_modulo_u32(10));
		tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
		break;
	case 3:
		tv->tv_sec = (time_t) rand32();
		tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
		break;
	case 4:
		/* Invalid tv_usec (>= 1e6) -- exercises the legality reject. */
		tv->tv_sec = (time_t) rnd_modulo_u32(60);
		tv->tv_usec = (suseconds_t) (1000000 + rnd_modulo_u32(1000000));
		break;
	case 5:
		tv->tv_sec = 0;
		tv->tv_usec = 999999;
		break;
	case 6:
		tv->tv_sec = (time_t) LONG_MAX;
		tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
		break;
	default:
		tv->tv_sec = -(time_t) (1 + rnd_modulo_u32(1u << 20));
		tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
		break;
	}
}

/*
 * Bucketed fill for a single struct timespec, shared by gen_arg_itimerspec()
 * (two back-to-back).  Same mix as gen_arg_timespec()'s 8-way switch minus
 * its outer NULL / raw arms (those live on the top-level argtype generator).
 */
static void fill_timespec_bucket(struct timespec *ts)
{
	switch (rnd_modulo_u32(8)) {
	case 0:
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
		break;
	case 1:
		ts->tv_sec = 0;
		ts->tv_nsec = 1;
		break;
	case 2:
		ts->tv_sec = 0;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000);
		break;
	case 3:
		ts->tv_sec = (time_t) rnd_modulo_u32(60);
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	case 4:
		ts->tv_sec = (time_t) time(NULL) +
			(time_t) rnd_modulo_u32(120) - (time_t) 60;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	case 5:
		ts->tv_sec = 0;
		ts->tv_nsec = 999999999L;
		break;
	case 6:
		ts->tv_sec = 0;
		ts->tv_nsec = 1000000000L;
		break;
	default:
		if (RAND_BOOL())
			ts->tv_sec = -(time_t)(1 + rnd_modulo_u32(1u << 20));
		else
			ts->tv_sec = (time_t) LONG_MAX;
		ts->tv_nsec = (long) rnd_modulo_u32(1000000000u);
		break;
	}
}

/*
 * ARG_ITIMERVAL: a writable pool buffer filled with a struct itimerval
 * (two struct timevals: it_interval, it_value).  Folds the bespoke
 * sanitise_setitimer() bucket set into a declarative argtype.
 *
 * Mix:
 *   - ~10% NULL (legal "no-op" / out-pointer arm)
 *   - ~5% raw bytes (keep the timeval legality reject path warm)
 *   - ~20% DISARM (it_value zeroed; preserves setitimer's disarm flow)
 *   - balance: bucketed fill for both timevals
 *
 * Pool buffer (get_writable_struct), off the shared region / libc heap
 * so the blanket address scrub is a no-op.  No .cleanup needed.
 */
unsigned long gen_arg_itimerval(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	struct itimerval *itv;

	if (rnd_modulo_u32(10) == 0)
		return 0;

	itv = (struct itimerval *) get_writable_struct(sizeof(*itv));
	if (itv == NULL)
		return 0;

	if (rnd_modulo_u32(20) == 0) {
		itv->it_interval.tv_sec = (time_t) rand64();
		itv->it_interval.tv_usec = (suseconds_t) rand64();
		itv->it_value.tv_sec = (time_t) rand64();
		itv->it_value.tv_usec = (suseconds_t) rand64();
		return (unsigned long) itv;
	}

	fill_timeval_bucket(&itv->it_interval);
	fill_timeval_bucket(&itv->it_value);

	/* ~20% disarm: it_value zeroed (preserves sanitise_setitimer's path). */
	if (rnd_modulo_u32(5) == 0) {
		itv->it_value.tv_sec = 0;
		itv->it_value.tv_usec = 0;
	}

	return (unsigned long) itv;
}

/*
 * ARG_ITIMERSPEC: a writable pool buffer filled with a struct itimerspec
 * (two struct timespecs: it_interval, it_value).  Folds the bespoke
 * sanitise_timer_settime() bucket set into a declarative argtype.
 *
 * Mix:
 *   - ~10% NULL (legal "no-op" / out-pointer arm)
 *   - ~5% raw bytes (keep the timespec64_valid reject path warm)
 *   - ~20% DISARM (it_value zeroed; the timer_settime disarm flow)
 *   - ~15% near-now (time(NULL)+1) it_value so TIMER_ABSTIME callers
 *     reach a deadline-in-the-future instead of fire-immediately
 *   - balance: bucketed fill for both timespecs
 *
 * Pool buffer (get_writable_struct), off the shared region / libc heap
 * so the blanket address scrub is a no-op.  No .cleanup needed.
 */
unsigned long gen_arg_itimerspec(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	struct itimerspec *its;
	uint32_t bucket;

	if (rnd_modulo_u32(10) == 0)
		return 0;

	its = (struct itimerspec *) get_writable_struct(sizeof(*its));
	if (its == NULL)
		return 0;

	if (rnd_modulo_u32(20) == 0) {
		its->it_interval.tv_sec = (time_t) rand64();
		its->it_interval.tv_nsec = (long) rand64();
		its->it_value.tv_sec = (time_t) rand64();
		its->it_value.tv_nsec = (long) rand64();
		return (unsigned long) its;
	}

	fill_timespec_bucket(&its->it_interval);
	fill_timespec_bucket(&its->it_value);

	bucket = rnd_modulo_u32(100);
	if (bucket < 20) {
		/* Disarm: it_value zeroed. */
		its->it_value.tv_sec = 0;
		its->it_value.tv_nsec = 0;
	} else if (bucket < 35) {
		/* Near-now (+1s) it_value so TIMER_ABSTIME deadlines actually
		 * land in the future and the timer schedules instead of firing
		 * immediately. */
		its->it_value.tv_sec = (time_t) time(NULL) + 1;
		its->it_value.tv_nsec = (long) rnd_modulo_u32(1000000000u);
	}

	return (unsigned long) its;
}

/*
 * ARG_TIMEVAL: a writable pool buffer filled with a struct timeval.
 * Folds the bespoke sanitise_settimeofday() bias (~70% near-now) into a
 * declarative argtype: settimeofday EPERMs random tv_sec before parsing
 * tv_usec, so a uniform random mix wastes draws -- bias near-now so the
 * tv_usec / monotonic-step validators actually run.
 *
 * Mix:
 *   - ~10% NULL (legal out-pointer / "skip" arm)
 *   - ~5% raw bytes (keep the timeval legality reject path warm)
 *   - ~70% near-now tv_sec (settimeofday-shaped bias)
 *   - balance: full bucketed fill (includes invalid tv_usec >= 1e6)
 *
 * Pool buffer (get_writable_struct), off the shared region / libc heap
 * so the blanket address scrub is a no-op.  No .cleanup needed.
 */
unsigned long gen_arg_timeval(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	struct timeval *tv;
	struct timespec snap;

	if (rnd_modulo_u32(10) == 0)
		return 0;

	tv = (struct timeval *) get_writable_struct(sizeof(*tv));
	if (tv == NULL)
		return 0;

	if (rnd_modulo_u32(20) == 0) {
		tv->tv_sec = (time_t) rand64();
		tv->tv_usec = (suseconds_t) rand64();
		return (unsigned long) tv;
	}

	if (rnd_modulo_u32(100) < 70) {
		/* Near-now: ±60s around current wall clock. */
		if (clock_gettime(CLOCK_REALTIME, &snap) == 0)
			tv->tv_sec = snap.tv_sec +
				(time_t) rnd_modulo_u32(120) - (time_t) 60;
		else
			tv->tv_sec = time(NULL) +
				(time_t) rnd_modulo_u32(120) - (time_t) 60;
		tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
	} else {
		fill_timeval_bucket(tv);
	}

	return (unsigned long) tv;
}


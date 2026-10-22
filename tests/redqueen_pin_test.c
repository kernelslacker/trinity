/*
 * Self-check for the pointer guard in redqueen_pin_field(): a field is
 * pinned only through a well-formed pointer to a struct timespec wholly
 * inside the writable pool, and any other slot is left untouched.
 * range_in_writable_pool() also gets its edge cases checked directly.
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cmp_hints/redqueen.h"
#include "debug.h"			/* BUG */
#include "random-syscall-internal.h"	/* redqueen_pin_field */
#include "sanitise.h"			/* writable pool */
#include "syscall.h"			/* struct syscallrecord */
#include "utils.h"			/* ARRAY_SIZE, is_corrupt_ptr_shape */

#define PIN_VALUE	0x0123456789abcdefUL
#define FILL		0xa5

static const enum reexec_field_kind kinds[] = {
	REEXEC_FIELD_TIMESPEC_SEC, REEXEC_FIELD_TIMESPEC_NSEC,
};

static struct syscallrecord rec;

/* Writable, aligned and canonical: only the pool check can refuse it. */
static struct timespec outside_ts __attribute__((aligned(16)));

/* Pin @kind through @slot with @ptr in that slot and @decoy in the
 * other five, so a pin through the wrong slot lands on the decoy. */
static void pin(unsigned int slot, unsigned long ptr, unsigned long decoy,
		enum reexec_field_kind kind)
{
	unsigned long *const slots[6] = {
		&rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6,
	};
	struct reexec_pending p = {
		.value = PIN_VALUE,
		.size = sizeof(long),
		.slot = slot,
		.field_kind = kind,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(slots); i++)
		*slots[i] = decoy;
	*slots[slot - 1] = ptr;

	redqueen_pin_field(&rec, &p);
}

/* Every buffer gen_arg_timespec() can be handed passes both checks of
 * the guard, including after the bump cursor has wrapped. */
static void pool_buffers_accepted(void)
{
	unsigned long i;

	for (i = 0; i < 2 * WRITABLE_POOL_BYTES / sizeof(struct timespec); i++) {
		struct timespec *ts = get_writable_struct(sizeof(*ts));

		if (is_corrupt_ptr_shape(ts) ||
		    !range_in_writable_pool((unsigned long) ts, sizeof(*ts)))
			BUG("redqueen pin: the guard refuses a get_writable_struct() buffer");
	}
}

static void pool_edges(unsigned long base)
{
	const unsigned long end = base + WRITABLE_POOL_BYTES;

	if (!range_in_writable_pool(base, WRITABLE_POOL_BYTES))
		BUG("redqueen pin: the whole pool is not in the pool");
	if (!range_in_writable_pool(end - sizeof(struct timespec),
				    sizeof(struct timespec)))
		BUG("redqueen pin: the last slot of the pool is not in the pool");

	if (range_in_writable_pool(end - sizeof(struct timespec) + 1,
				   sizeof(struct timespec)))
		BUG("redqueen pin: a range running one byte past the pool end was accepted");
	if (range_in_writable_pool(base - 8, sizeof(struct timespec)))
		BUG("redqueen pin: a range starting below the pool was accepted");
	if (range_in_writable_pool(end, 1))
		BUG("redqueen pin: the address just past the pool was accepted");
	if (range_in_writable_pool(base, WRITABLE_POOL_BYTES + 1))
		BUG("redqueen pin: a range longer than the pool was accepted");
	if (range_in_writable_pool(base, 0))
		BUG("redqueen pin: an empty range was accepted");
	if (range_in_writable_pool(ULONG_MAX - 7, sizeof(struct timespec)))
		BUG("redqueen pin: a range wrapping the address space was accepted");
}

/* A pool buffer takes the pin in the one field the kind names, from
 * whichever slot holds it, and nothing else changes. */
static void pool_buffer_pinned(void)
{
	unsigned char fill[sizeof(struct timespec)];
	unsigned int slot, k;

	memset(fill, FILL, sizeof(fill));

	for (slot = 1; slot <= 6; slot++) {
		for (k = 0; k < ARRAY_SIZE(kinds); k++) {
			struct timespec *target = get_writable_struct(sizeof(*target));
			struct timespec *decoy = get_writable_struct(sizeof(*decoy));

			memset(target, FILL, sizeof(*target));
			memset(decoy, FILL, sizeof(*decoy));

			pin(slot, (unsigned long) target, (unsigned long) decoy,
			    kinds[k]);

			if (memcmp(decoy, fill, sizeof(fill)) != 0)
				BUG("redqueen pin: pinned through the wrong slot");

			if (kinds[k] == REEXEC_FIELD_TIMESPEC_SEC) {
				if (target->tv_sec != (time_t) PIN_VALUE ||
				    memcmp(&target->tv_nsec, fill,
					   sizeof(target->tv_nsec)) != 0)
					BUG("redqueen pin: tv_sec pin missed or hit tv_nsec");
			} else {
				if (target->tv_nsec != (long) PIN_VALUE ||
				    memcmp(&target->tv_sec, fill,
					   sizeof(target->tv_sec)) != 0)
					BUG("redqueen pin: tv_nsec pin missed or hit tv_sec");
			}
		}
	}
}

/* None of these may be written through, from any slot, whichever field
 * is pinned.  The pool-end one has tv_sec in the pool's last bytes and
 * tv_nsec off its end, so only tv_sec is pinned: a guard that checked
 * too short a length would let that write land inside the pool, where
 * the tv_nsec write would run off it.  0x2000 stands for a small integer
 * such as a pid left in the slot; it is last so that a broken guard
 * fails on one of the writable targets before it faults on this one. */
static void bad_pointer_not_written(unsigned long pool_end)
{
	unsigned char fill[2 * sizeof(struct timespec)];
	unsigned char *pool_buf = get_writable_struct(sizeof(fill));
	unsigned char *pool_last = (unsigned char *) pool_end -
				   sizeof(struct timespec);
	struct timespec *decoy = get_writable_struct(sizeof(*decoy));
	struct timespec *heap_ts = malloc(sizeof(*heap_ts));
	struct {
		unsigned long ptr;
		bool sec_only;
	} bad[] = {
		{ 0 },
		{ (unsigned long) pool_buf + 4 },	/* inside the pool, misaligned */
		{ (unsigned long) &outside_ts },
		{ (unsigned long) heap_ts },
		{ pool_end - sizeof(outside_ts.tv_sec), true },
		{ 0x2000 },
	};
	unsigned int i, slot, k;

	if (heap_ts == NULL)
		BUG("redqueen pin: malloc failed");
	memset(fill, FILL, sizeof(fill));

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		for (slot = 1; slot <= 6; slot++) {
			for (k = 0; k < ARRAY_SIZE(kinds); k++) {
				if (bad[i].sec_only &&
				    kinds[k] != REEXEC_FIELD_TIMESPEC_SEC)
					continue;

				memset(pool_buf, FILL, sizeof(fill));
				memset(pool_last, FILL, sizeof(struct timespec));
				memset(decoy, FILL, sizeof(*decoy));
				memset(&outside_ts, FILL, sizeof(outside_ts));
				memset(heap_ts, FILL, sizeof(*heap_ts));

				pin(slot, bad[i].ptr, (unsigned long) decoy,
				    kinds[k]);

				if (memcmp(pool_buf, fill, sizeof(fill)) != 0 ||
				    memcmp(pool_last, fill, sizeof(struct timespec)) != 0 ||
				    memcmp(decoy, fill, sizeof(*decoy)) != 0 ||
				    memcmp(&outside_ts, fill, sizeof(outside_ts)) != 0 ||
				    memcmp(heap_ts, fill, sizeof(*heap_ts)) != 0)
					BUG("redqueen pin: wrote through a slot pointer that is not a pool buffer");
			}
		}
	}
	free(heap_ts);
}

void redqueen_pin_self_check(void);
void redqueen_pin_self_check(void)
{
	unsigned long base;

	/* A NULL slot must not read as the base of a pool that is not there. */
	if (range_in_writable_pool(0, sizeof(struct timespec)))
		BUG("redqueen pin: an uninitialised pool contains NULL");

	writable_pool_init();

	/* A request for the whole pool can only start at its base, whatever
	 * the allocation cursor holds. */
	base = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	if (base == 0)
		BUG("redqueen pin: the pool cannot hand out its whole extent");

	pool_edges(base);
	pool_buffers_accepted();
	pool_buffer_pinned();
	bad_pointer_not_written(base + WRITABLE_POOL_BYTES);
}

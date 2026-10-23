/*
 * Self-check for the pointer guard in redqueen_pin_field(): a field is
 * pinned only through a well-formed pointer to a struct timespec wholly
 * inside the writable pool, and any other slot is left untouched.
 * range_in_writable_pool() also gets its edge cases checked directly.
 * The value mask a scalar pin and chain substitution share keeps
 * protected fds out of fd slots and the parent's pid out of pid slots.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cmp_hints/redqueen.h"
#include "debug.h"			/* BUG */
#include "fd.h"				/* fd_is_protected */
#include "pids.h"			/* mainpid */
#include "random-syscall-internal.h"	/* redqueen_pin_field */
#include "sanitise.h"			/* writable pool */
#include "syscall.h"			/* struct syscallrecord */
#include "type-graph.h"			/* type_graph_observe_consume */
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

/* Stands in for the type-graph consume observer apply_chain_substitution()
 * feeds; nothing here reads it. */
void type_graph_observe_consume(unsigned int consumer_nr, bool do32bit,
				unsigned int consumer_arg,
				unsigned long substitute_retval)
{
	(void) consumer_nr;
	(void) do32bit;
	(void) consumer_arg;
	(void) substitute_retval;
}

/* Not stderr, and none of the other protected fds is open in this binary. */
#define INNOCENT_FD	1000UL

/* Slots 1 and 4 take an fd, slot 2 a pid. */
static struct syscallentry mask_entry = {
	.name = "value_mask_test",
	.num_args = 5,
	.argtype = { ARG_FD, ARG_PID, ARG_LEN, ARG_FD_PIPE, ARG_UNDEFINED },
};

static bool pin_refused(unsigned int slot, unsigned long value,
			unsigned int size, enum reexec_field_kind kind)
{
	struct reexec_pending p = {
		.value = value,
		.size = size,
		.slot = slot,
		.field_kind = kind,
	};

	return redqueen_pin_refused(&mask_entry, &p);
}

/* A scalar pin may not put a protected fd in an fd slot or the parent's pid
 * in a pid slot, and judges the number the way the kernel reads it: by its
 * low 32 bits. */
static void pin_value_mask(void)
{
	const unsigned long parent = (unsigned long) mainpid;
	static const unsigned int widths[] = { 0, 4, 8 };
	unsigned int w, slot, size;

	if (fd_is_protected((int) INNOCENT_FD) || fd_is_protected((int) parent))
		BUG("redqueen pin: the test's innocent numbers are protected");

	for (w = 0; w < ARRAY_SIZE(widths); w++) {
		size = widths[w];

		for (slot = 1; slot <= 4; slot += 3) {
			if (!pin_refused(slot, STDERR_FILENO, size, REEXEC_FIELD_NONE))
				BUG("redqueen pin: stderr was pinned into an fd slot");
			if (!pin_refused(slot, STDERR_FILENO | (1UL << 40), size,
					 REEXEC_FIELD_NONE))
				BUG("redqueen pin: stderr with upper bits was pinned into an fd slot");
			if (pin_refused(slot, INNOCENT_FD, size, REEXEC_FIELD_NONE))
				BUG("redqueen pin: an unprotected fd was refused");
			if (pin_refused(slot, parent, size, REEXEC_FIELD_NONE))
				BUG("redqueen pin: the parent's pid was refused in an fd slot");
		}

		if (!pin_refused(2, parent, size, REEXEC_FIELD_NONE))
			BUG("redqueen pin: the parent's pid was pinned into a pid slot");
		if (!pin_refused(2, parent | (1UL << 32), size, REEXEC_FIELD_NONE))
			BUG("redqueen pin: the parent's pid with upper bits was pinned into a pid slot");
		if (pin_refused(2, 1, size, REEXEC_FIELD_NONE) ||
		    pin_refused(2, STDERR_FILENO, size, REEXEC_FIELD_NONE))
			BUG("redqueen pin: a pid that is not the parent's was refused");

		for (slot = 3; slot <= 5; slot += 2) {
			if (pin_refused(slot, STDERR_FILENO, size, REEXEC_FIELD_NONE) ||
			    pin_refused(slot, parent, size, REEXEC_FIELD_NONE))
				BUG("redqueen pin: a slot that is neither fd nor pid was refused");
		}
	}

	/* The bytes a narrow compare leaves out come from the regenerated
	 * argument, so an fd or pid slot cannot be judged. */
	for (size = 1; size < sizeof(unsigned int); size++) {
		if (!pin_refused(1, INNOCENT_FD, size, REEXEC_FIELD_NONE) ||
		    !pin_refused(2, 1, size, REEXEC_FIELD_NONE))
			BUG("redqueen pin: a narrow pin into an fd or pid slot was not refused");
		if (pin_refused(3, STDERR_FILENO, size, REEXEC_FIELD_NONE))
			BUG("redqueen pin: a narrow pin into a length slot was refused");
	}

	/* A field pin writes inside a struct, and a slot the entry does not
	 * have is for the caller to turn away. */
	if (pin_refused(1, STDERR_FILENO, sizeof(long), REEXEC_FIELD_TIMESPEC_SEC))
		BUG("redqueen pin: a field pin was refused for its slot's argtype");
	if (pin_refused(0, STDERR_FILENO, sizeof(long), REEXEC_FIELD_NONE) ||
	    pin_refused(6, STDERR_FILENO, sizeof(long), REEXEC_FIELD_NONE))
		BUG("redqueen pin: a slot past the entry was judged");
}

/* Chain substitution asks the same question: a value refused for a slot is
 * never written there, and still reaches the slots that may hold it. */
static void substitution_value_mask(void)
{
	const unsigned long parent = (unsigned long) mainpid;
	const unsigned long cases[] = {
		STDERR_FILENO, parent, parent | (1UL << 32), INNOCENT_FD,
	};
	/* a1 fd, a2 pid, a3 length: all three take a number. */
	struct syscallentry entry = {
		.name = "substitution_mask_test",
		.num_args = 3,
		.argtype = { ARG_FD, ARG_PID, ARG_LEN },
	};
	struct syscallrecord sr;
	unsigned int c, i, wrote_allowed;

	entry.numeric_substitute_mask = compute_numeric_substitute_mask(&entry);

	for (c = 0; c < ARRAY_SIZE(cases); c++) {
		unsigned long v = cases[c];
		bool fd_refused = (int) v == STDERR_FILENO;
		bool pid_refused = (pid_t) v == mainpid;

		wrote_allowed = 0;
		for (i = 0; i < 4000; i++) {
			memset(&sr, 0, sizeof(sr));
			sr.a1 = sr.a2 = sr.a3 = 0x1111;

			apply_chain_substitution(&sr, &entry, true, v);

			if (fd_refused && sr.a1 != 0x1111)
				BUG("substitution: a protected fd was written into an fd slot");
			if (pid_refused && sr.a2 != 0x1111)
				BUG("substitution: the parent's pid was written into a pid slot");
			if ((!fd_refused && sr.a1 == v) ||
			    (!pid_refused && sr.a2 == v) || sr.a3 == v)
				wrote_allowed++;
		}
		if (wrote_allowed == 0)
			BUG("substitution: no value reached a slot that may hold it");
	}
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
	pin_value_mask();
	substitution_value_mask();
}

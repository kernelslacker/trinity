/*
 * Self-check for futex's sanitiser: a WAIT-family op leaves it with the
 * short timeout utime is clamped to, whichever futex words were picked,
 * never the address the generator drew, whose bytes the kernel would
 * take as a wait of any length.  A compat call reads the slot as its low
 * 32 bits, and a time32 one the timeout as an old_timespec32, so the
 * clamp must sit below 4 GiB in that layout for one, and so must the
 * futex words, where a mapping there can hold them.
 */

#include <limits.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "arch.h"		/* page_size */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "maps.h"		/* struct map */
#include "objects.h"		/* struct objhead */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_futex */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern struct childdata *fake_this_child;	/* fake_shm.c */
extern unsigned long fake_heap_start, fake_heap_size;	/* fake_shm.c */

/* futex on i386, which takes time32. */
#define NR_FUTEX_TIME32	240

/* The lock and mapping pools stay empty, as does the shared word pool,
 * so every branch of the sanitiser finds no futex word to use. */
static struct objhead *no_pool(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return NULL;
}

uint32_t *get_shared_futex_word(void)
{
	return NULL;
}

/* A child's mappings, one past 4 GiB and one below, which the futex
 * words are drawn from; no lock pool still. */
#define HIGH_MAP	0x7e0000000000UL
#define LOW_MAP		0x40000000UL

static struct objhead anon_pool;

/* The heap probe takes this, so the pool readers accept it as storage. */
static struct {
	struct object *array[2];
	struct object objs[2];
} store;

static struct objhead *maps_only(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_LOCAL && type == OBJ_MMAP_ANON)
		return &anon_pool;
	return NULL;
}

static void fill_anon_pool(void)
{
	unsigned long ptrs[2] = { HIGH_MAP, LOW_MAP };
	unsigned int i;

	memset(&store, 0, sizeof(store));
	for (i = 0; i < 2; i++) {
		store.objs[i].obj_type = OBJ_MMAP_ANON;
		store.objs[i].map.ptr = (void *) ptrs[i];
		store.objs[i].map.size = 16 * page_size;
		store.array[i] = &store.objs[i];
	}
	anon_pool.array = store.array;
	anon_pool.num_entries = 2;
	anon_pool.array_capacity = 2;
}

/* Runs, which take the rarest branch, one in four, all but one time in
 * about 10^8. */
#define RUNS	64

void futex_self_check(void);
void futex_self_check(void)
{
	static const struct timespec drawn = { .tv_sec = LONG_MAX };
	static struct childdata compat;
	struct syscallrecord rec, *crec = &compat.syscall;
	bool armed = false, low = false;
	unsigned int i;

	fake_get_objhead = no_pool;
	for (i = 0; i < RUNS; i++) {
		const struct timespec *ts;

		memset(&rec, 0, sizeof(rec));
		rec.a2 = FUTEX_WAIT;
		rec.a4 = (unsigned long) &drawn;
		syscall_futex.sanitise(&rec);

		ts = (const struct timespec *) rec.a4;
		if (ts == &drawn || ts->tv_sec > 1 || ts->tv_nsec >= 5000000)
			BUG("futex: a FUTEX_WAIT kept the timeout the generator drew");
	}

	/* A sanitiser builds the call in this_child()'s record, whose
	 * being compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < RUNS && !armed; i++) {
		const struct old_timespec32 *ts32;

		memset(crec, 0, sizeof(*crec));
		crec->do32bit = true;
		crec->nr = NR_FUTEX_TIME32;
		crec->a2 = FUTEX_WAIT;
		crec->a4 = (unsigned long) &drawn;
		syscall_futex.sanitise(crec);

		if (crec->a4 > UINT32_MAX)
			BUG("futex: a compat call's timeout lies past 4 GiB");
		ts32 = (const struct old_timespec32 *) crec->a4;
		armed = ts32->tv_sec <= 1 && ts32->tv_nsec > 0 &&
			ts32->tv_nsec < 5000000;
	}
	fake_this_child = NULL;
	/* tv_nsec is 0 one time in 5 million, but every time where the
	 * native layout puts tv_sec's high half. */
	if (!armed)
		BUG("futex: a time32 call never read the clamp's nanoseconds");

	fill_anon_pool();
	fake_heap_start = (unsigned long) &store;
	fake_heap_size = sizeof(store);
	fake_get_objhead = maps_only;
	compat.mmap_pool_nonempty_mask = 1u << 0;	/* the ANON pool */
	fake_this_child = &compat;
	for (i = 0; i < RUNS; i++) {
		memset(crec, 0, sizeof(*crec));
		crec->do32bit = true;
		crec->nr = NR_FUTEX_TIME32;
		crec->a2 = FUTEX_WAKE;
		syscall_futex.sanitise(crec);

		if (crec->a1 == HIGH_MAP || crec->a5 == HIGH_MAP)
			BUG("futex: a compat call was handed a futex word past 4 GiB");
		low |= crec->a1 == LOW_MAP;
	}
	fake_this_child = NULL;
	/* The mapping branch, one call in four, drew the word below. */
	if (!low)
		BUG("futex: a compat call never drew the futex word below 4 GiB");
	fake_heap_size = 0;
	fake_get_objhead = NULL;
}

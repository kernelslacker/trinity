/*
 * Self-check for futex's sanitiser: a WAIT-family op leaves it with the
 * short timeout utime is clamped to, whichever futex words were picked,
 * never the address the generator drew, whose bytes the kernel would
 * take as a wait of any length.
 */

#include <limits.h>
#include <linux/futex.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "debug.h"		/* BUG */
#include "objects.h"		/* struct objhead */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_futex */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

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

/* Runs, which take the rarest branch, one in four, all but one time in
 * about 10^8. */
#define RUNS	64

void futex_self_check(void);
void futex_self_check(void)
{
	static const struct timespec drawn = { .tv_sec = LONG_MAX };
	struct syscallrecord rec;
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
	fake_get_objhead = NULL;
}

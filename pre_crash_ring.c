/*
 * Per-child pre-crash syscall history ring.
 *
 * One ring per child, written by the child itself after every syscall
 * return, drained by __BUG() to recover the syscall sequence that
 * preceded an assertion failure.  See include/pre_crash_ring.h for the
 * full rationale.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

void pre_crash_ring_record(struct childdata *child,
			   const struct syscallrecord *rec,
			   const struct timespec *now)
{
	struct pre_crash_ring *ring;
	struct pre_crash_entry *e;
	uint32_t head;

	if (child == NULL || rec == NULL)
		return;

	ring = &child->pre_crash;

	/* Single-producer relaxed load: only this child writes head. */
	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	e = &ring->entries[head & (PRE_CRASH_RING_SIZE - 1)];

	e->syscall_nr = rec->nr;
	e->do32bit = rec->do32bit;
	e->args[0] = rec->a1;
	e->args[1] = rec->a2;
	e->args[2] = rec->a3;
	e->args[3] = rec->a4;
	e->args[4] = rec->a5;
	e->args[5] = rec->a6;
	e->retval = (long) rec->retval;
	e->errno_post = rec->errno_post;
	e->ts = (now != NULL) ? *now : rec->tp;

	/* Publish only after the entry is fully populated, so a post-mortem
	 * reader that acquire-loads head and walks back N slots never sees
	 * a torn entry. */
	atomic_store_explicit(&ring->head, head + 1, memory_order_release);
}

static void format_ts_relative(char *out, size_t outlen,
			       const struct timespec *entry,
			       const struct timespec *anchor)
{
	long ds = (long) entry->tv_sec - (long) anchor->tv_sec;
	long dns = (long) entry->tv_nsec - (long) anchor->tv_nsec;

	if (dns < 0) {
		ds -= 1;
		dns += 1000000000L;
	}
	snprintf(out, outlen, "T%+ld.%09lds", ds, dns);
}

static void dump_one_ring(struct childdata *child,
			  const struct timespec *anchor)
{
	struct pre_crash_ring *ring = &child->pre_crash;
	uint32_t head, count, i;

	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	if (head == 0) {
		outputerr("pre-crash ring (child %u): empty\n", child->num);
		return;
	}

	count = head < PRE_CRASH_RING_SIZE ? head : PRE_CRASH_RING_SIZE;

	outputerr("pre-crash ring (child %u): last %u syscall(s), oldest first\n",
		  child->num, count);

	for (i = 0; i < count; i++) {
		uint32_t slot = (head - count + i) & (PRE_CRASH_RING_SIZE - 1);
		struct pre_crash_entry *e = &ring->entries[slot];
		struct syscallentry *entry = get_syscall_entry(e->syscall_nr,
							       e->do32bit);
		const char *name = entry ? entry->name : "?";
		char tsbuf[32];

		format_ts_relative(tsbuf, sizeof(tsbuf), &e->ts, anchor);
		outputerr("  [%s] nr=%u (%s%s) a1=%lx a2=%lx a3=%lx a4=%lx a5=%lx a6=%lx retval=%ld errno=%d\n",
			  tsbuf, e->syscall_nr, name,
			  e->do32bit ? ",32" : "",
			  e->args[0], e->args[1], e->args[2],
			  e->args[3], e->args[4], e->args[5],
			  e->retval, e->errno_post);
	}
}

void pre_crash_ring_dump(struct childdata *child)
{
	struct timespec now;

	if (child == NULL)
		return;
	clock_gettime(CLOCK_MONOTONIC, &now);
	dump_one_ring(child, &now);
}

void pre_crash_ring_dump_all(void)
{
	struct timespec now;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);
	for_each_child(i) {
		if (children[i] == NULL)
			continue;
		dump_one_ring(children[i], &now);
	}
}

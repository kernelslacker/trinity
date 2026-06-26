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
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "shm.h"
#include "spsc-ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

static void publish(struct pre_crash_ring *ring,
		    const struct pre_crash_entry *e)
{
	spsc_ring_overwrite_enqueue(&ring->base, ring->entries,
				    PRE_CRASH_RING_SIZE,
				    sizeof(ring->entries[0]), e);
}

void pre_crash_ring_record(struct childdata *child,
			   const struct syscallrecord *rec,
			   const struct timespec *now)
{
	struct pre_crash_entry e = {};

	if (child == NULL || rec == NULL)
		return;

	e.syscall_nr = rec->nr;
	e.do32bit = rec->do32bit;
	e.args[0] = rec->a1;
	e.args[1] = rec->a2;
	e.args[2] = rec->a3;
	e.args[3] = rec->a4;
	e.args[4] = rec->a5;
	e.args[5] = rec->a6;
	e.retval = (long) rec->retval;
	e.errno_post = rec->errno_post;
	e.ts = (now != NULL) ? *now : rec->tp;
	e.kind = PRE_CRASH_KIND_SYSCALL;

	publish(&child->pre_crash, &e);
}

void pre_crash_ring_record_taint(struct childdata *child,
				 unsigned long delta,
				 unsigned long tainted_now,
				 unsigned int op_type,
				 unsigned long op_nr)
{
	struct pre_crash_entry e = {};

	if (child == NULL)
		return;

	e.args[0] = delta;
	e.args[1] = tainted_now;
	e.args[2] = (unsigned long) op_type;
	e.args[3] = op_nr;
	e.kind = PRE_CRASH_KIND_TAINT;
	clock_gettime(CLOCK_MONOTONIC, &e.ts);

	publish(&child->pre_crash, &e);
}

void pre_crash_ring_record_canary(struct childdata *child,
				  const struct syscallrecord *rec,
				  uint64_t observed)
{
	struct pre_crash_entry e = {};

	if (child == NULL || rec == NULL)
		return;

	/* Preserve the nominal call context (post-mortem usually wants
	 * the syscall name, even though the args themselves are now
	 * untrustworthy) and stash the observed canary in a slot we can
	 * pretty-print at dump time. */
	e.syscall_nr = rec->nr;
	e.do32bit = rec->do32bit;
	e.args[0] = rec->a1;
	e.args[1] = rec->a2;
	e.args[2] = rec->a3;
	e.args[3] = rec->a4;
	e.args[4] = rec->a5;
	e.args[5] = (unsigned long) observed;
	e.retval = (long) rec->retval;
	e.errno_post = rec->errno_post;
	e.kind = PRE_CRASH_KIND_CANARY;
	clock_gettime(CLOCK_MONOTONIC, &e.ts);

	publish(&child->pre_crash, &e);
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
			  const struct timespec *anchor,
			  pre_crash_emit_fn emit)
{
	struct pre_crash_ring *ring = &child->pre_crash;
	uint32_t head, count, i;

	head = __atomic_load_n(&ring->base.head, __ATOMIC_ACQUIRE);
	if (head == 0) {
		emit("pre-crash ring (child %u): empty\n", child->num);
		return;
	}

	count = head < PRE_CRASH_RING_SIZE ? head : PRE_CRASH_RING_SIZE;

	emit("pre-crash ring (child %u): last %u syscall(s), oldest first\n",
	     child->num, count);

	for (i = 0; i < count; i++) {
		uint32_t slot = (head - count + i) & (PRE_CRASH_RING_SIZE - 1);
		struct pre_crash_entry *e = &ring->entries[slot];
		char tsbuf[32];

		format_ts_relative(tsbuf, sizeof(tsbuf), &e->ts, anchor);

		if (e->kind == PRE_CRASH_KIND_TAINT) {
			emit("  [%s] taint delta=0x%lx now=0x%lx op_type=%lu op_nr=%lu\n",
			     tsbuf, e->args[0], e->args[1],
			     e->args[2], e->args[3]);
			continue;
		}

		if (e->kind == PRE_CRASH_KIND_CANARY) {
			struct syscallentry *centry = get_syscall_entry(e->syscall_nr,
									e->do32bit);
			const char *cname = centry ? centry->name : "?";

			emit("  [%s] CANARY-STOMP nr=%u (%s%s) observed=0x%lx a1=%lx a2=%lx a3=%lx a4=%lx a5=%lx retval=%ld\n",
			     tsbuf, e->syscall_nr, cname,
			     e->do32bit ? ",32" : "",
			     e->args[5], e->args[0], e->args[1],
			     e->args[2], e->args[3], e->args[4],
			     e->retval);
			continue;
		}

		struct syscallentry *entry = get_syscall_entry(e->syscall_nr,
							       e->do32bit);
		const char *name = entry ? entry->name : "?";

		emit("  [%s] nr=%u (%s%s) a1=%lx a2=%lx a3=%lx a4=%lx a5=%lx a6=%lx retval=%ld errno=%d\n",
		     tsbuf, e->syscall_nr, name,
		     e->do32bit ? ",32" : "",
		     e->args[0], e->args[1], e->args[2],
		     e->args[3], e->args[4], e->args[5],
		     e->retval, e->errno_post);
	}
}

void pre_crash_ring_reset(struct pre_crash_ring *ring)
{
	const long pagesize = sysconf(_SC_PAGESIZE);
	uintptr_t start, end, aligned_start, aligned_end;

	if (ring == NULL || pagesize <= 0)
		return;

	/* Reset head BEFORE dropping the pages.  Most callers satisfy the
	 * "child fully gone" precondition documented in the header, but the
	 * deferred-reap path runs reset while the kernel may still resume the
	 * task to finish its in-flight syscall -- one more producer call can
	 * land between the madvise and the head store.  Publishing head=0
	 * first means any such late producer reloads head as 0, writes slot 0,
	 * and republishes head=1 on top of a slot the madvise is about to
	 * drop; the dumper then sees either an empty ring or that single slot
	 * in a fresh page.  Doing this in the other order would let the
	 * producer write at the old (high) head into a freshly-faulted zero
	 * page, then have the reset stomp head back to 0, leaving the next
	 * occupant's ring with a stranded high-offset entry visible to the
	 * dumper once head wraps back around. */
	__atomic_store_n(&ring->base.head, 0, __ATOMIC_RELEASE);

	/* Drop the rolling-history entries pages.  The childdata mapping is
	 * MAP_ANON | MAP_SHARED, so MADV_DONTNEED frees the resident pages
	 * and the next producer faults clean zero pages on demand -- the
	 * parent's RSS no longer carries one slot's worth of stale ring per
	 * recycled child for the rest of the run.  Only the page-aligned
	 * interior of entries[] is dropped; bytes sharing the head/tail
	 * boundary pages with other childdata fields stay resident but are
	 * unreachable once head is reset to 0 above. */
	start = (uintptr_t) ring->entries;
	end = start + sizeof(ring->entries);
	aligned_start = (start + (uintptr_t) pagesize - 1) &
			~((uintptr_t) pagesize - 1);
	aligned_end = end & ~((uintptr_t) pagesize - 1);
	if (aligned_end > aligned_start) {
		(void) madvise((void *) aligned_start,
			       (size_t) (aligned_end - aligned_start),
			       MADV_DONTNEED);
	}
}

void pre_crash_ring_dump(struct childdata *child, pre_crash_emit_fn emit)
{
	struct timespec now;

	if (child == NULL)
		return;
	clock_gettime(CLOCK_MONOTONIC, &now);
	dump_one_ring(child, &now, emit);
}

void pre_crash_ring_dump_all(pre_crash_emit_fn emit)
{
	struct timespec now;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);
	for_each_child(i) {
		if (children[i] == NULL)
			continue;
		dump_one_ring(children[i], &now, emit);
	}
}

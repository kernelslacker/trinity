/*
 * Routines to update the results counters
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include "debug.h"
#include "locks.h"
#include "results.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

unsigned long get_argval(struct syscallrecord *rec, unsigned int argnum)
{
	switch (argnum) {
	case 1:	return rec->a1;
	case 2:	return rec->a2;
	case 3:	return rec->a3;
	case 4:	return rec->a4;
	case 5:	return rec->a5;
	case 6:	return rec->a6;
	}
	unreachable();
}

static struct results * get_results_ptr(struct syscallentry *entry, unsigned int argnum)
{
	return &entry->results[argnum - 1];
}

static void store_successful_len(struct results *results, unsigned long value)
{
	uint32_t len = (uint32_t) value;
	union len_score_u cur, new;

	/* Lock-free range update on the packed (min, max) word.  Decode the
	 * sentinel (min==UINT32_MAX, max==0) as not-seen and seed both bounds
	 * with the first observation; otherwise extend the existing range.
	 * The early-out when nothing changes keeps the hot path (a duplicate
	 * length on a settled slot) off the CAS bus entirely. */
	do {
		cur.raw = __atomic_load_n(&results->len_score.raw,
					  __ATOMIC_RELAXED);
		new = cur;
		if (cur.u.min == UINT32_MAX && cur.u.max == 0) {
			new.u.min = len;
			new.u.max = len;
		} else {
			if (len < cur.u.min)
				new.u.min = len;
			if (len > cur.u.max)
				new.u.max = len;
		}
		if (new.raw == cur.raw)
			return;
	} while (!__atomic_compare_exchange_n(&results->len_score.raw,
					      &cur.raw, new.raw, false,
					      __ATOMIC_RELEASE,
					      __ATOMIC_RELAXED));
}

static void store_successful_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;
	unsigned char mask;

	if (fd < 0 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;
	mask = (unsigned char)(1U << (fd & 7));
	/* Bitmap RMWs from many children: lock-free atomic_fetch_or /
	 * atomic_fetch_and on the touched byte so concurrent stores to
	 * different bits of the same byte don't drop each other's
	 * updates.  Readers in pick_successful_fd / fd_recently_failed
	 * stay plain — the exact byte value is best-effort heuristic
	 * input, not a coherence boundary. */
	__atomic_fetch_or(&results->success_fds[fd >> 3], mask,
			  __ATOMIC_RELAXED);

	/* fd is alive again on this slot -- forget any previously-recorded
	 * consecutive failure run and clear the failed-fds bit. */
	__atomic_fetch_and(&results->failed_fds[fd >> 3],
			   (unsigned char)~mask, __ATOMIC_RELAXED);
	/* Pair (fd, count) lives in the packed fail_run word; clear it
	 * lock-free with a CAS so concurrent store_failed_fd bumps either
	 * win the race (the bump's CAS lands first, the load below sees
	 * fresh state and either re-clears or no-ops) or lose to the
	 * cleared state.  Early-out when the load shows our entry is
	 * already gone -- common in the hot path. */
	{
		union fail_run_u cur, new;
		do {
			cur.raw = __atomic_load_n(&results->fail_run.raw,
						  __ATOMIC_RELAXED);
			if (cur.u.fd != (unsigned char) fd || cur.u.count == 0)
				break;
			new = cur;
			new.u.fd = 0;
			new.u.count = 0;
		} while (!__atomic_compare_exchange_n(&results->fail_run.raw,
						      &cur.raw, new.raw, false,
						      __ATOMIC_RELEASE,
						      __ATOMIC_RELAXED));
	}
}

static void store_failed_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;
	bool set_failed_bit;

	if (fd < 3 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;

	/* The packed (fd, count) tuple in fail_run is the canonical state
	 * now (legacy fail_run_fd / fail_run_count are no longer read or
	 * written).  Reads and the bump still run under results->lock so
	 * two children can't race the !run-in-flight branch and end up
	 * with one child's fd alongside the other child's count, blowing
	 * past FAIL_RUN_THRESHOLD against the wrong fd.  The committed
	 * pair is published with a single atomic store so concurrent
	 * lock-free clears in store_successful_fd observe a coherent
	 * (fd, count) word.  Step 4 converts this bump to a CAS loop and
	 * drops the lock. */
	{
		union fail_run_u cur, new;
		lock(&results->lock);
		cur.raw = __atomic_load_n(&results->fail_run.raw,
					  __ATOMIC_RELAXED);
		new = cur;
		if (cur.u.count > 0 && cur.u.fd == (unsigned char) fd) {
			if (cur.u.count < 0xFF)
				new.u.count = cur.u.count + 1;
		} else {
			new.u.fd = (unsigned char) fd;
			new.u.count = 1;
			new.u.pad = 0;
		}
		__atomic_store_n(&results->fail_run.raw, new.raw,
				 __ATOMIC_RELEASE);
		set_failed_bit = (new.u.count >= FAIL_RUN_THRESHOLD);
		unlock(&results->lock);
	}

	if (set_failed_bit)
		__atomic_fetch_or(&results->failed_fds[fd >> 3],
				  (unsigned char)(1U << (fd & 7)),
				  __ATOMIC_RELAXED);
}

bool fd_recently_failed(struct results *results, int fd)
{
	if (fd < 0 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return false;
	return (results->failed_fds[fd >> 3] & (unsigned char)(1U << (fd & 7))) != 0;
}

/*
 * Return a randomly chosen fd whose bit is set in the slot's scoreboard,
 * or -1 if no fd has succeeded for this slot yet.  Skips 0/1/2 defensively
 * even though store_successful_fd() never sets them (get_random_fd /
 * get_typed_fd refuse to hand them out).
 *
 * Sample a random byte of the bitmap and find a set bit with ctz; retry a
 * bounded number of times so the common case (a handful of low fds set)
 * costs O(1) instead of scanning all 256 bits.  Fall back to a linear scan
 * when sampling keeps hitting zero bytes -- preserves correctness in the
 * sparse case and the all-empty case (returns -1).
 */
#define PICK_FD_SAMPLE_ATTEMPTS 8

int pick_successful_fd(struct results *results)
{
	int attempt;
	int fd;

	for (attempt = 0; attempt < PICK_FD_SAMPLE_ATTEMPTS; attempt++) {
		unsigned int bidx = rnd_modulo_u32(SUCCESS_FD_SCOREBOARD_BYTES);
		unsigned int byte = results->success_fds[bidx];
		unsigned int rot, rb;
		int bit;

		if (byte == 0)
			continue;

		/* Pick a uniformly-random set bit within the byte by rotating
		 * by a random shift before taking ctz. */
		rot = rnd_u32() & 7;
		rb = ((byte >> rot) | (byte << (8 - rot))) & 0xff;
		bit = __builtin_ctz(rb);
		bit = (bit + (int)rot) & 7;
		fd = (int)(bidx << 3) + bit;
		if (fd >= 3)
			return fd;
	}

	for (fd = 3; fd < SUCCESS_FD_SCOREBOARD_BITS; fd++) {
		if (results->success_fds[fd >> 3] & (unsigned char)(1U << (fd & 7)))
			return fd;
	}
	return -1;
}

void handle_success(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;
	uint8_t mask;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	/* Walk only the slots that feed a scoreboard.  fd_arg_mask is the
	 * is_fdarg() projection and len_arg_mask is the ARG_LEN projection;
	 * they are disjoint by construction (ARG_LEN is neither ARG_FD nor
	 * a typed-fd argtype), so OR-ing them gives every eligible slot.
	 * Most syscalls have no fd/len args -- mask==0 short-circuits the
	 * loop entirely. */
	mask = (uint8_t)(entry->fd_arg_mask | entry->len_arg_mask);
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		uint8_t bit = (uint8_t)(1u << (i - 1));
		struct results *results = get_results_ptr(entry, i);
		unsigned long value = get_argval(rec, i);

		if (entry->len_arg_mask & bit)
			store_successful_len(results, value);
		else
			store_successful_fd(results, value);
		mask &= (uint8_t)(mask - 1);
	}
}

void handle_failure(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;
	uint8_t mask;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	/* Only fd args feed the failed-fd scoreboard.  Skip the walk
	 * entirely when no slot is an fd. */
	mask = entry->fd_arg_mask;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		struct results *results = get_results_ptr(entry, i);
		unsigned long value = get_argval(rec, i);

		store_failed_fd(results, value);
		mask &= (uint8_t)(mask - 1);
	}
}

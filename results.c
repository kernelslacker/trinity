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
	/* All three fields (seen, min, max) move together; without the
	 * lock two children racing past the !seen test can leave the slot
	 * with min > max (each child seeds min and max to its own value
	 * independently), and the update branch can drop concurrent
	 * extrema entirely.  The hot path is the comparison-only update
	 * once seen flips true, which is single-store-per-child under the
	 * lock and not on any latency-sensitive call. */
	lock(&results->lock);
	if (!results->seen) {
		results->seen = true;
		results->min = value;
		results->max = value;
	} else {
		if (value < results->min)
			results->min = value;
		if (value > results->max)
			results->max = value;
	}
	unlock(&results->lock);
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
	/* fail_run_fd and fail_run_count must be observed together to be
	 * meaningful (count is the run length for the fd in fail_run_fd),
	 * so the pair shares the per-results lock with store_failed_fd. */
	lock(&results->lock);
	if (results->fail_run_count > 0 && results->fail_run_fd == (unsigned char) fd)
		results->fail_run_count = 0;
	unlock(&results->lock);
}

static void store_failed_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;
	bool set_failed_bit;

	if (fd < 3 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;

	/* fail_run_fd and fail_run_count are a paired (fd, count) tuple
	 * — without the lock, two children can race the !run-in-flight
	 * branch and end up with one child's fd alongside the other
	 * child's count, blowing past FAIL_RUN_THRESHOLD against the
	 * wrong fd.  Capture the threshold-crossing test under the lock
	 * so the conditional bitmap update reflects the just-committed
	 * count, not a stale racy read. */
	lock(&results->lock);
	if (results->fail_run_count > 0 &&
	    results->fail_run_fd == (unsigned char) fd) {
		if (results->fail_run_count < 0xFF)
			results->fail_run_count++;
	} else {
		results->fail_run_fd = (unsigned char) fd;
		results->fail_run_count = 1;
	}
	set_failed_bit = (results->fail_run_count >= FAIL_RUN_THRESHOLD);
	unlock(&results->lock);

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

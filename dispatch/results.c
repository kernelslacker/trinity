/*
 * Routines to update the results counters
 */

#include <errno.h>
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

/* The mask walks in handle_success/handle_failure clamp to 0x3f so
 * __builtin_ctz can only return 0..5 and this indexes results[0..5].  If
 * the results[] array ever grows past six slots, that clamp needs to grow
 * with it (or the callers need to widen their arg masks).  Anchor the
 * invariant here so a stale clamp fires a compile error. */
_Static_assert(ARRAY_SIZE(((struct syscallentry *)0)->results) == 6,
	       "results[] must have six slots to match the 0x3f arg-mask clamp");

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
	union fail_run_u cur, new;
	uint8_t committed_count;

	if (fd < 3 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;

	/* Bump the (fd, count) run-length tracker lock-free with a CAS loop
	 * on fail_run.raw.  On fd match, increment count saturating at
	 * UINT8_MAX so a 256-fail run before any clear can't wrap to zero
	 * and silence the bad-fd marker; on fd change, reseed (fd, 1).  No
	 * early-out: by construction new != cur on every iteration (count
	 * incremented or fd changed), so the CAS always carries useful
	 * work.  A concurrent store_successful_fd clear that lands between
	 * our load and our CAS just forces us to retry against the cleared
	 * state and reseed. */
	do {
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
	} while (!__atomic_compare_exchange_n(&results->fail_run.raw,
					      &cur.raw, new.raw, false,
					      __ATOMIC_RELEASE,
					      __ATOMIC_RELAXED));

	/* Test the value we definitely wrote, not a fresh load: a
	 * concurrent clear between our CAS commit and a re-read could
	 * show 0 here and miss firing the bad-fd marker for a run we
	 * just observed crossing the threshold. */
	committed_count = new.u.count;
	if (committed_count >= FAIL_RUN_THRESHOLD)
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
	 * loop entirely.
	 *
	 * Read via get_arg_snapshot(): for any slot in this entry's
	 * arg_snapshot_mask we scoreboard the dispatch-time value the
	 * kernel actually saw rather than the live rec->aN, which a sibling
	 * may have stomped between the syscall returning and this scoreboard
	 * pass.  Slots that did not opt into the snapshot fall through the
	 * accessor's mask gate to the live read, so unopted syscalls keep
	 * their current behaviour. */
	mask = (uint8_t)(entry->fd_arg_mask | entry->len_arg_mask);
	/* Clamp to the six valid arg slots before iterating: a stray bit
	 * 6/7 -- whether from a mask-gen bug or future growth past 6 args
	 * without bumping the results[] table -- would let __builtin_ctz
	 * return 6 or 7 and the get_results_ptr() lookup below would
	 * index past the per-entry six-result array.  Mirrors the same
	 * clamp at syscall.c:255 for arg_snapshot_mask. */
	mask &= 0x3f;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		uint8_t bit = (uint8_t)(1u << (i - 1));
		struct results *results = get_results_ptr(entry, i);
		unsigned long value = get_arg_snapshot(rec, i);

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
	 * entirely when no slot is an fd.  Same snapshot gate as
	 * handle_success: shadow-when-opted, live-when-not. */
	mask = entry->fd_arg_mask;
	/* Clamp to the six valid arg slots for the same reason as
	 * handle_success above: a stray bit 6/7 would let __builtin_ctz
	 * return 6/7 and the get_results_ptr() lookup below would index
	 * past the per-entry six-result array.  compute_fd_arg_mask() only
	 * sets bits 0..5 today so this is defensive parity, not a live OOB. */
	mask &= 0x3f;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		struct results *results = get_results_ptr(entry, i);
		unsigned long value = get_arg_snapshot(rec, i);

		store_failed_fd(results, value);
		mask &= (uint8_t)(mask - 1);
	}
}

/*
 * Routines to update the results counters
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include "debug.h"
#include "locks.h"
#include "results.h"
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
	if (!results->seen) {
		results->seen = true;
		results->min = value;
		results->max = value;
		return;
	}
	if (value < results->min)
		results->min = value;
	if (value > results->max)
		results->max = value;
}

static void store_successful_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;
	unsigned char mask;

	if (fd < 0 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;
	mask = (unsigned char)(1U << (fd & 7));
	results->success_fds[fd >> 3] |= mask;

	/* fd is alive again on this slot -- forget any previously-recorded
	 * consecutive failure run and clear the failed-fds bit. */
	results->failed_fds[fd >> 3] &= (unsigned char)~mask;
	if (results->fail_run_count > 0 && results->fail_run_fd == (unsigned char) fd)
		results->fail_run_count = 0;
}

static void store_failed_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;

	if (fd < 3 || fd >= SUCCESS_FD_SCOREBOARD_BITS)
		return;

	if (results->fail_run_count > 0 &&
	    results->fail_run_fd == (unsigned char) fd) {
		if (results->fail_run_count < 0xFF)
			results->fail_run_count++;
	} else {
		results->fail_run_fd = (unsigned char) fd;
		results->fail_run_count = 1;
	}

	if (results->fail_run_count >= FAIL_RUN_THRESHOLD)
		results->failed_fds[fd >> 3] |= (unsigned char)(1U << (fd & 7));
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
		unsigned int bidx = (unsigned int)rand() % SUCCESS_FD_SCOREBOARD_BYTES;
		unsigned int byte = results->success_fds[bidx];
		unsigned int rot, rb;
		int bit;

		if (byte == 0)
			continue;

		/* Pick a uniformly-random set bit within the byte by rotating
		 * by a random shift before taking ctz. */
		rot = (unsigned int)rand() & 7;
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
	unsigned int i, call;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	for_each_arg(entry, i) {
		struct results *results;
		enum argtype argtype = get_argtype(entry, i);
		unsigned long value = get_argval(rec, i);

		results = get_results_ptr(entry, i);

		if (argtype == ARG_LEN)
			store_successful_len(results, value);
		else if (is_fdarg(argtype))
			store_successful_fd(results, value);
	}
}

void handle_failure(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int i, call;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	for_each_arg(entry, i) {
		struct results *results;
		enum argtype argtype = get_argtype(entry, i);
		unsigned long value = get_argval(rec, i);

		if (!is_fdarg(argtype))
			continue;

		results = get_results_ptr(entry, i);
		store_failed_fd(results, value);
	}
}

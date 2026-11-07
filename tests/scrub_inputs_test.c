/*
 * Self-check that the inputs a sanitiser builds reach the kernel.  The
 * blanket address scrub moves a heap range in an address slot into the
 * writable pool without a copy, so a sanitiser that builds a kernel input
 * on the heap has to make the move itself, copying.  Each case runs the
 * sanitiser with every range counted as libc heap, as a zmalloc()'d buffer
 * is in a run, then the scrub, and checks that the slot still points at
 * the bytes the sanitiser left there.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "sanitise.h"		/* blanket_address_scrub, writable_pool_init */
#include "syscall.h"		/* compute_address_scrub_mask */
#include "syscalls/syscalls.h"

extern bool fake_overlaps_libc_heap;	/* fake_shm.c */
extern bool fake_socket_fd_none;	/* post_oracle_test.c */

/* Enough draws to take each sanitiser down its branches. */
#define DRAWS	64

static struct syscallrecord rec;

static void sanitise(struct syscallentry *entry)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = entry;
	entry->sanitise(&rec);
}

/*
 * Scrub @entry's slots as the dispatcher does and check that @slot still
 * points at the @len bytes it pointed at after the sanitiser.
 */
static void survives_scrub(struct syscallentry *entry, unsigned long *slot,
			   size_t len, const char *what)
{
	struct syscallentry scrubbed = *entry;
	void *built = malloc(len);

	if (built == NULL)
		BUG("scrub inputs: out of memory");
	memcpy(built, (void *) *slot, len);
	scrubbed.address_scrub_mask = compute_address_scrub_mask(entry);
	blanket_address_scrub(&scrubbed, &rec);
	if (memcmp((void *) *slot, built, len) != 0) {
		fprintf(stderr, "%s: the kernel gets other bytes\n", what);
		BUG("scrub inputs: the scrub threw away a sanitiser's input");
	}
	free(built);
}

/* What the dispatcher's drain and the post handler free.  The fake
 * allocator tracks nothing, so they are freed by hand. */
static void end_call(void)
{
	while (rec.owned_count > 0)
		free(rec.owned[--rec.owned_count]);
	free((void *) rec.post_state);
}

static void recv_headers(void)
{
	unsigned int i;

	fake_socket_fd_none = true;
	for (i = 0; i < DRAWS; i++) {
		sanitise(&syscall_recvmsg);
		survives_scrub(&syscall_recvmsg, &rec.a2, sizeof(struct msghdr),
			       "recvmsg's msghdr");
		end_call();

		sanitise(&syscall_recvmmsg);
		survives_scrub(&syscall_recvmmsg, &rec.a2,
			       rec.a3 * sizeof(struct mmsghdr),
			       "recvmmsg's mmsghdr array");
		end_call();
	}
	fake_socket_fd_none = false;
}

void scrub_inputs_self_check(void);
void scrub_inputs_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(1) == NULL)
		writable_pool_init();

	fake_overlaps_libc_heap = true;
	recv_headers();
	fake_overlaps_libc_heap = false;
}

/*
 * Self-check that the inputs a sanitiser builds reach the kernel.  The
 * blanket address scrub moves a heap range in an address slot into the
 * writable pool without a copy, so a sanitiser that builds a kernel input
 * on the heap has to make the move itself, copying.  Each case runs the
 * sanitiser with every range counted as libc heap, as a zmalloc()'d buffer
 * is in a run, then the scrub, and checks that the slot still points at
 * the bytes the sanitiser left there.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/net.h>

#include "arch.h"		/* ARCH_IS_BIARCH */
#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "kernel/seccomp.h"	/* SECCOMP_* ops */
#include "sanitise.h"		/* blanket_address_scrub, writable_pool_init */
#include "syscall.h"		/* compute_address_scrub_mask */
#include "syscalls/syscalls.h"

extern bool fake_overlaps_libc_heap;	/* fake_shm.c */
extern struct childdata *fake_this_child;	/* fake_shm.c */
extern bool fake_socket_fd_none;	/* post_oracle_test.c */
extern bool fake_no_random_socket;	/* dup_pool_test.c */

/* Enough draws to take each sanitiser down its branches. */
#define DRAWS	64

static struct syscallrecord rec;

/* @a1 is what the generator left in the first slot. */
static void sanitise(struct syscallentry *entry, unsigned long a1)
{
	bool do32bit = rec.do32bit;

	memset(&rec, 0, sizeof(rec));
	rec.entry = entry;
	rec.do32bit = do32bit;
	rec.a1 = a1;
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
	void *built;

	if (len == 0)
		return;
	built = malloc(len);
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
		sanitise(&syscall_recvmsg, 0);
		survives_scrub(&syscall_recvmsg, &rec.a2, sizeof(struct msghdr),
			       "recvmsg's msghdr");
		end_call();

		sanitise(&syscall_recvmmsg, 0);
		survives_scrub(&syscall_recvmmsg, &rec.a2,
			       rec.a3 * sizeof(struct mmsghdr),
			       "recvmmsg's mmsghdr array");
		end_call();
	}
	fake_socket_fd_none = false;
}

/* An fd above stdio, which the sanitiser keeps. */
#define WRITE_FD	100

static void write_buffer(void)
{
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		sanitise(&syscall_write, WRITE_FD);
		survives_scrub(&syscall_write, &rec.a2, rec.a3,
			       "write's buffer");
		end_call();
	}
}

/*
 * seccomp's sanitiser runs with no range counted as heap, so the buffers
 * the other ops build stay where it put them and can be freed here:
 * FILTER's program and GET_NOTIF_SIZES's buffer, both in a3.
 */
static void seccomp_action(void)
{
	unsigned int draws, seen = 0;

	for (draws = 0; seen < DRAWS; draws++) {
		if (draws == 100 * DRAWS)
			BUG("scrub inputs: seccomp never drew GET_ACTION_AVAIL");
		fake_overlaps_libc_heap = false;
		sanitise(&syscall_seccomp, 0);
		fake_overlaps_libc_heap = true;

		switch (rec.a1) {
		case SECCOMP_GET_ACTION_AVAIL:
			survives_scrub(&syscall_seccomp, &rec.a3,
				       sizeof(uint32_t), "seccomp's action word");
			seen++;
			break;
		case SECCOMP_SET_MODE_FILTER: {
			struct sock_fprog *prog = (struct sock_fprog *) rec.a3;

			if (prog != NULL)
				free(prog->filter);
			free(prog);
			break;
		}
		case SECCOMP_GET_NOTIF_SIZES:
			free((void *) rec.a3);
			break;
		}
		end_call();
	}
}

/* The head links to itself, as a copy of it made elsewhere would not. */
static void robust_list_head(void)
{
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		struct robust_list_head *head;

		sanitise(&syscall_set_robust_list, 0);
		survives_scrub(&syscall_set_robust_list, &rec.a1,
			       sizeof(struct robust_list_head),
			       "set_robust_list's head");
		head = (struct robust_list_head *) rec.a1;
		if (head->list.next != &head->list)
			BUG("scrub inputs: set_robust_list's head does not link to itself");
		end_call();
	}
}

/*
 * socketcall's six words, at the width its kernel reads them: unsigned
 * longs for a native call, u32s below 4 GiB for a compat one, holding the
 * values post_socketcall() reads from its snapshot.
 */
static void socketcall_words(bool compat)
{
	unsigned int i, w;

	fake_no_random_socket = true;
	for (i = 0; i < DRAWS; i++) {
		const unsigned long *vals;

		rec.do32bit = compat;
		sanitise(&syscall_socketcall, 0);
		vals = (const unsigned long *) rec.post_state;
		if (!compat) {
			survives_scrub(&syscall_socketcall, &rec.a2,
				       6 * sizeof(unsigned long),
				       "socketcall's args");
			if (memcmp((void *) rec.a2, vals,
				   6 * sizeof(unsigned long)) != 0)
				BUG("scrub inputs: socketcall's words are not its snapshot's");
		} else {
			const uint32_t *words = (const uint32_t *) rec.a2;

			if (rec.a2 > UINT_MAX - 6 * sizeof(uint32_t))
				BUG("scrub inputs: a compat socketcall's words are past 4 GiB");
			survives_scrub(&syscall_socketcall, &rec.a2,
				       6 * sizeof(uint32_t),
				       "a compat socketcall's args");
			for (w = 0; w < 6; w++)
				if (words[w] != (uint32_t) vals[w])
					BUG("scrub inputs: a compat socketcall's words are not its snapshot's");
			if (rec.a1 == SYS_SOCKETPAIR && vals[3] > UINT_MAX)
				BUG("scrub inputs: a compat socketpair's fds are past 4 GiB");
		}
		end_call();
	}
	rec.do32bit = false;
	fake_no_random_socket = false;
}

/*
 * listns builds its request on the heap and moves it into the pool for the
 * kernel, so the record has to own the heap original: the copy in a1 is
 * not an allocation, and handing it to deferred free only gets it refused.
 */
static void listns_request(void)
{
	unsigned int i;

	for (i = 0; i < DRAWS; i++) {
		sanitise(&syscall_listns, 0);
		if (rec.owned_count != 1 || rec.owned[0] == (void *) rec.a1)
			BUG("scrub inputs: the record does not own listns's request");
		end_call();
	}
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
	write_buffer();
	seccomp_action();
	robust_list_head();
	listns_request();
	socketcall_words(false);
#ifdef ARCH_IS_BIARCH
	{
		static struct childdata compat;

		/* The pool a compat call's buffers come from goes by the
		 * record this_child() has. */
		compat.syscall.do32bit = true;
		fake_this_child = &compat;
		socketcall_words(true);
		fake_this_child = NULL;
	}
#endif
	fake_overlaps_libc_heap = false;
}

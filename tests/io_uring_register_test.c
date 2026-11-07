/*
 * Self-check for io_uring_register's sanitiser
 * (syscalls/io_uring/io_uring_register.c): its picker reaches every
 * opcode the descriptor lists, and, since the kernel masks the
 * registered-ring modifier off the opcode before it dispatches, a draw
 * carrying the modifier gets its base opcode's payload.  A payload's
 * nr_args is the one the kernel checks for before the handler runs.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/io_uring.h"	/* IORING_REGISTER_* */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_io_uring_register */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_random_fd_empty;	/* fake_stubs.c */

/* Draws, all of which miss a 1-in-160 opcode one time in about 10^11. */
#define DRAWS	4096

/* Run the sanitiser until it draws @opcode.  The payloads of the opcodes
 * drawn on the way pick their fds from an empty pool. */
static bool draw(struct syscallrecord *rec, unsigned long opcode)
{
	unsigned int i;

	fake_random_fd_empty = true;
	for (i = 0; i < DRAWS; i++) {
		memset(rec, 0, sizeof(*rec));
		syscall_io_uring_register.sanitise(rec);
		if (rec->a2 == opcode)
			break;
		free((void *) rec->post_state);
	}
	fake_random_fd_empty = false;
	return i < DRAWS;
}

/* The nr_args __io_uring_register() insists on for each, or io_query()
 * and io_zcrx_ctrl() for the two it hands the count. */
static const struct {
	unsigned long opcode;
	unsigned long nr_args;
} counts[] = {
	{ IORING_REGISTER_NAPI, 1 },
	{ IORING_UNREGISTER_NAPI, 1 },
	{ IORING_REGISTER_RESIZE_RINGS, 1 },
	{ IORING_REGISTER_QUERY, 0 },
	{ IORING_REGISTER_ZCRX_CTRL, 0 },
};

void io_uring_register_self_check(void);
void io_uring_register_self_check(void)
{
	const struct arglist *ops = &syscall_io_uring_register.arg_params[1].list;
	struct syscallrecord rec;
	unsigned int i;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(1) == NULL)
		writable_pool_init();

	/* PERSONALITY takes no arg and no count (__io_uring_register()). */
	if (!draw(&rec, IORING_REGISTER_PERSONALITY |
			IORING_REGISTER_USE_REGISTERED_RING))
		BUG("io_uring_register: no PERSONALITY draw carried the modifier");
	free((void *) rec.post_state);
	if (rec.a3 != 0 || rec.a4 != 0)
		BUG("io_uring_register: a modifier draw of PERSONALITY got another opcode's payload");

	/* The picker, not only a chain substitution onto the opcode slot,
	 * reaches each opcode the slot lists. */
	for (i = 0; i < ops->num; i++) {
		if (!draw(&rec, ops->values[i])) {
			fprintf(stderr, "opcode %#lx never drawn\n", ops->values[i]);
			BUG("io_uring_register: the picker leaves out a listed opcode");
		}
		free((void *) rec.post_state);
	}

	for (i = 0; i < ARRAY_SIZE(counts); i++) {
		if (!draw(&rec, counts[i].opcode))
			BUG("io_uring_register: an opcode with a fixed count was never drawn");
		free((void *) rec.post_state);
		if (rec.a4 != counts[i].nr_args) {
			fprintf(stderr, "opcode %#lx: nr_args %lu, the kernel takes %lu\n",
				counts[i].opcode, rec.a4, counts[i].nr_args);
			BUG("io_uring_register: a payload hands nr_args the kernel refuses");
		}
	}
}

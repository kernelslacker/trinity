/*
 * Self-check for io_uring_register's sanitiser
 * (syscalls/io_uring/io_uring_register.c): the kernel masks the
 * registered-ring modifier off the opcode before it dispatches, so a draw
 * carrying the modifier gets its base opcode's payload.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/io_uring.h"	/* IORING_REGISTER_* */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_io_uring_register */

extern bool fake_random_fd_empty;	/* fake_stubs.c */

/* Draws, all of which miss a 1-in-120 opcode one time in about 10^15. */
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

void io_uring_register_self_check(void);
void io_uring_register_self_check(void)
{
	struct syscallrecord rec;

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
}

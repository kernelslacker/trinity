/*
 * Self-check for io_uring_register's sanitiser
 * (syscalls/io_uring/io_uring_register.c): its picker reaches every
 * opcode the descriptor lists, and, since the kernel masks the
 * registered-ring modifier off the opcode before it dispatches, a draw
 * carrying the modifier gets its base opcode's payload.  A payload's
 * nr_args is the one the kernel checks for before the handler runs.
 */

#include <limits.h>
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

/* Draws of BUFFERS_UPDATE: the extended format comes in half of them,
 * and with one to eight descriptors each about 2000 descriptors in all. */
#define UPDATE_DRAWS	512

/* What io_sqe_buffer_register() takes of an extended descriptor: a type
 * it knows, no flags or reserved words, no address or size beside a
 * dma-buf, and no fd without one. */
static bool desc_registers(const struct trinity_io_uring_regbuf_desc *d)
{
	unsigned int i;

	if (d->type >= TRINITY_IO_REGBUF_TYPE_MAX || d->flags != 0)
		return false;
	for (i = 0; i < ARRAY_SIZE(d->__resv); i++) {
		if (d->__resv[i] != 0)
			return false;
	}
	if (d->type == TRINITY_IO_REGBUF_TYPE_DMABUF)
		return d->uaddr == 0 && d->size == 0;
	if (d->dmabuf_fd != 0 || d->target_fd != 0)
		return false;
	if (d->type == TRINITY_IO_REGBUF_TYPE_EMPTY)
		return d->uaddr == 0 && d->size == 0;
	return d->uaddr != 0 && d->size != 0;
}

/* BUFFERS_UPDATE sends iovecs, or with IORING_RSRC_UPDATE_EXTENDED in the
 * update's flags descriptors, nearly all of which the kernel takes, of
 * every type; FILES_UPDATE2 refuses any flag. */
static void rsrc_update_cases(void)
{
	const struct trinity_io_uring_regbuf_desc *descs;
	const struct trinity_io_uring_rsrc_update2 *up;
	unsigned int iovecs = 0, extended = 0, n_descs = 0, taken = 0;
	unsigned int types = 0, i, j;
	struct syscallrecord rec;

	for (i = 0; i < UPDATE_DRAWS; i++) {
		if (!draw(&rec, IORING_REGISTER_BUFFERS_UPDATE))
			BUG("io_uring_register: BUFFERS_UPDATE was never drawn");
		free((void *) rec.post_state);
		up = (const struct trinity_io_uring_rsrc_update2 *) rec.a3;
		if (up == NULL)
			continue;
		if (up->flags == 0) {
			iovecs++;
			continue;
		}
		if (up->flags != TRINITY_IORING_RSRC_UPDATE_EXTENDED)
			BUG("io_uring_register: BUFFERS_UPDATE carries a flag the kernel refuses");
		extended++;
		descs = (const struct trinity_io_uring_regbuf_desc *)
			(unsigned long) up->data;
		for (j = 0; j < up->nr; j++) {
			n_descs++;
			if (desc_registers(&descs[j])) {
				taken++;
				types |= 1U << descs[j].type;
			}
		}
	}
	if (iovecs == 0 || extended == 0)
		BUG("io_uring_register: BUFFERS_UPDATE sends iovecs or descriptors, not both");
	if (taken * 10 < n_descs * 8 || taken == n_descs)
		BUG("io_uring_register: BUFFERS_UPDATE's descriptors are not mostly ones the kernel takes");
	if (types != (1U << TRINITY_IO_REGBUF_TYPE_MAX) - 1)
		BUG("io_uring_register: BUFFERS_UPDATE leaves out a descriptor type");

	for (i = 0; i < UPDATE_DRAWS / 8; i++) {
		if (!draw(&rec, IORING_REGISTER_FILES_UPDATE2))
			BUG("io_uring_register: FILES_UPDATE2 was never drawn");
		free((void *) rec.post_state);
		up = (const struct trinity_io_uring_rsrc_update2 *) rec.a3;
		if (up != NULL && up->flags != 0)
			BUG("io_uring_register: FILES_UPDATE2 carries a flag");
	}
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
	const struct io_uring_rsrc_update *up;
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

	/* UNREGISTER_PERSONALITY names the id in nr_args, with no arg; the
	 * personalities xarray is XA_FLAGS_ALLOC1, so ids start at 1, and
	 * io_register_personality() allocates no higher than USHRT_MAX. */
	if (!draw(&rec, IORING_UNREGISTER_PERSONALITY))
		BUG("io_uring_register: UNREGISTER_PERSONALITY was never drawn");
	free((void *) rec.post_state);
	if (rec.a3 != 0 || rec.a4 == 0 || rec.a4 > USHRT_MAX)
		BUG("io_uring_register: UNREGISTER_PERSONALITY names an id the kernel never hands out");

	/* FILES_UPDATE's arg is a struct io_uring_rsrc_update whose data
	 * holds the nr_args fds __io_sqe_files_update() swaps in, and whose
	 * resv it reads as the update's flags, which must be 0. */
	if (!draw(&rec, IORING_REGISTER_FILES_UPDATE))
		BUG("io_uring_register: FILES_UPDATE was never drawn");
	free((void *) rec.post_state);
	up = (const struct io_uring_rsrc_update *) rec.a3;
	if (up == NULL || up->resv != 0 || up->data == 0 || rec.a4 == 0)
		BUG("io_uring_register: FILES_UPDATE got no update of an fd array");
	for (i = 0; i < rec.a4; i++) {
		if (((const int *)(unsigned long) up->data)[i] < -1)
			BUG("io_uring_register: FILES_UPDATE's fd array holds a stray value");
	}

	/* The picker, not only a chain substitution onto the opcode slot,
	 * reaches each opcode the slot lists. */
	for (i = 0; i < ops->num; i++) {
		if (!draw(&rec, ops->values[i])) {
			fprintf(stderr, "opcode %#lx never drawn\n", ops->values[i]);
			BUG("io_uring_register: the picker leaves out a listed opcode");
		}
		free((void *) rec.post_state);
	}

	rsrc_update_cases();

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

/*
 * io_uring struct-catalog registrations.
 *
 * Setup and register paths only.  io_uring_enter's opcode-dispatched
 * struct payloads (SQE bodies) resolve through their own opcode table
 * and do not travel through syscall_struct_args[].
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <linux/io_uring.h>

#include "config.h"

#include "struct_catalog.h"
#include "trinity.h"

const struct syscall_struct_arg struct_catalog_registry_io_uring[] = {
	/* io_uring_setup(u32, struct io_uring_params *) */
	{ "io_uring_setup",	2, &struct_catalog[SC_IO_URING_PARAMS] },
	/* io_uring_register(int fd, unsigned op, void *arg, unsigned nr_args) */
	{ "io_uring_register",	3, &struct_catalog[SC_IO_URING_REGISTER_ARGS] },
	/* sentinel */
	{ NULL, 0, NULL },
};

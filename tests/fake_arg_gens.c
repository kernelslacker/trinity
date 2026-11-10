/*
 * Stand-ins for the generators args/argtype_table.c names in its rows
 * whose files the tests do not link.  The table is linked for the replay
 * class on each row, so a call to any of these is a test bug.
 */

#include <stdio.h>
#include <stdlib.h>

#include "args-internal.h"

#define FAKE_GENERATOR(name)						\
	unsigned long name(struct syscallentry *entry,			\
			   struct syscallrecord *rec,			\
			   unsigned int argnum)				\
	{								\
		(void) entry;						\
		(void) rec;						\
		(void) argnum;						\
		fprintf(stderr, "fake " #name " called unexpectedly\n");	\
		abort();						\
	}

FAKE_GENERATOR(gen_undefined_arg)
FAKE_GENERATOR(gen_arg_fd)
FAKE_GENERATOR(gen_arg_typed_fd)
FAKE_GENERATOR(gen_arg_len)
FAKE_GENERATOR(gen_arg_non_null_address)
FAKE_GENERATOR(gen_arg_mmap)
FAKE_GENERATOR(gen_arg_pid)
FAKE_GENERATOR(gen_arg_key_serial)
FAKE_GENERATOR(gen_arg_timerid)
FAKE_GENERATOR(gen_arg_aio_ctx)
FAKE_GENERATOR(gen_arg_sem_id)
FAKE_GENERATOR(gen_arg_msg_id)
FAKE_GENERATOR(gen_arg_sysv_shm)
FAKE_GENERATOR(gen_arg_cpu)
FAKE_GENERATOR(gen_arg_numa_node)
FAKE_GENERATOR(gen_arg_pathname)
FAKE_GENERATOR(gen_arg_xattr_name)
FAKE_GENERATOR(gen_arg_fstype_name)
FAKE_GENERATOR(gen_arg_nodemask)
FAKE_GENERATOR(gen_arg_cpumask)
FAKE_GENERATOR(gen_arg_paired_length)
FAKE_GENERATOR(gen_arg_socketinfo)
FAKE_GENERATOR(gen_arg_struct_ptr_in)
FAKE_GENERATOR(gen_arg_struct_ptr_out)
FAKE_GENERATOR(gen_arg_struct_ptr_inout)
FAKE_GENERATOR(gen_arg_struct_size)

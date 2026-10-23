/*
 * Stand-ins for the generators args/argtype_table.c names in its rows.
 * The table is linked for the replay class on each row, and no test
 * generates an argument, so a call to any of these is a test bug.
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
FAKE_GENERATOR(gen_arg_timespec)
FAKE_GENERATOR(gen_arg_itimerval)
FAKE_GENERATOR(gen_arg_itimerspec)
FAKE_GENERATOR(gen_arg_timeval)
FAKE_GENERATOR(gen_arg_nodemask)
FAKE_GENERATOR(gen_arg_cpumask)
FAKE_GENERATOR(gen_arg_buf_sized)
FAKE_GENERATOR(gen_arg_paired_length)
FAKE_GENERATOR(gen_arg_socketinfo)
FAKE_GENERATOR(gen_arg_struct_ptr_in)
FAKE_GENERATOR(gen_arg_struct_ptr_out)
FAKE_GENERATOR(gen_arg_struct_ptr_inout)
FAKE_GENERATOR(gen_arg_struct_size)
FAKE_GENERATOR(handle_arg_address)
FAKE_GENERATOR(handle_arg_mode_t)
FAKE_GENERATOR(handle_arg_range)
FAKE_GENERATOR(handle_arg_op)
FAKE_GENERATOR(handle_arg_list)
FAKE_GENERATOR(handle_arg_iovec)
FAKE_GENERATOR(handle_arg_iovec_in)
FAKE_GENERATOR(handle_arg_sockaddr)

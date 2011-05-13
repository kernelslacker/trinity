/*
 * SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_madvise = {
	.name = "madvise",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len_in",
	.arg2type = ARG_LEN,
	.arg3name = "behaviour",
};

/*
 * SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
 */
#include "maps.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_munlock(__unused__ struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
}

struct syscallentry syscall_munlock = {
	.name = "munlock",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_munlock,
};

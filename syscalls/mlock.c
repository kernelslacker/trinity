/*
 * SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
 */
#include <stdlib.h>
#include "maps.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_mlock(__unused__ struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
}

struct syscallentry syscall_mlock = {
	.name = "mlock",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
};

/*
 * SYSCALL_DEFINE3(mlock2, unsigned long, start, size_t, len, int, flags)
 */

static unsigned long mlock2_flags[] = { MLOCK_ONFAULT };

struct syscallentry syscall_mlock2 = {
	.name = "mlock2",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.arg_params[2].list = ARGLIST(mlock2_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
};

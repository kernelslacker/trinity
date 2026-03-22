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
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
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
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(mlock2_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
};

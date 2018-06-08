/*
 * SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
 */
#include "maps.h"
#include "sanitise.h"
#include "syscall.h"
#include "trinity.h"

static void sanitise_munlock(__unused__ struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
}

struct syscallentry syscall_munlock = {
	.name = "munlock",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.group = GROUP_VM,
	.sanitise = sanitise_munlock,
};
